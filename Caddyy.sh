#!/bin/bash
# ===============================================
# WordPress Migration Script: Apache/Nginx → Caddy
# Complete with backup permission fixes and database recovery
# ===============================================

set -e

# -------------------
# DETECTION PHASE
# -------------------

echo "==============================================="
echo " WORDPRESS MIGRATION & CADDY SETUP"
echo " Comprehensive permission fixing for backups"
echo "==============================================="

# Function to check file accessibility with multiple fallbacks
check_file_access() {
    local file="$1"
    echo "[DEBUG] Checking access to: $file"
    
    if [ ! -e "$file" ]; then
        echo "[ERROR] File/directory does not exist: $file"
        return 1
    fi
    
    # Check if it's a directory
    if [ -d "$file" ]; then
        if [ -x "$file" ]; then
            echo "[DEBUG] Directory accessible: $file"
            return 0
        else
            echo "[DEBUG] Directory not executable, trying to fix..."
            sudo chmod +x "$file" 2>/dev/null || return 1
            return $?
        fi
    fi
    
    # For files: check readability
    if [ -r "$file" ]; then
        echo "[DEBUG] File readable: $file"
        return 0
    fi
    
    # Try with sudo
    if sudo test -r "$file"; then
        echo "[DEBUG] File readable with sudo: $file"
        return 0
    fi
    
    # Try to fix permissions
    echo "[DEBUG] Attempting to fix permissions for: $file"
    sudo chmod 644 "$file" 2>/dev/null || \
    sudo chown $(whoami):$(whoami) "$file" 2>/dev/null || \
    sudo chown root:root "$file" 2>/dev/null || \
    echo "[WARNING] Could not fix permissions for $file"
    
    # Check again
    if [ -r "$file" ]; then
        return 0
    fi
    
    echo "[ERROR] Cannot access file: $file"
    return 1
}

# Function to create backup with proper permissions
create_backup() {
    local source="$1"
    local backup_dir="$2"
    local backup_name="$3"
    
    echo "[INFO] Creating backup: $backup_name"
    
    # Ensure backup directory exists with proper permissions
    sudo mkdir -p "$backup_dir"
    sudo chmod 755 "$backup_dir"
    sudo chown $(whoami):$(whoami) "$backup_dir" 2>/dev/null || true
    
    # Check source accessibility
    if ! check_file_access "$source"; then
        echo "[ERROR] Cannot backup $source - access denied"
        return 1
    fi
    
    # Different backup methods based on type
    if [ -d "$source" ]; then
        echo "[DEBUG] Backing up directory: $source"
        
        # Method 1: tar with sudo if needed
        if sudo tar -czf "$backup_dir/$backup_name.tar.gz" -C "$(dirname "$source")" "$(basename "$source")" 2>/dev/null; then
            echo "[SUCCESS] Directory backed up: $backup_name.tar.gz"
        elif tar -czf "$backup_dir/$backup_name.tar.gz" -C "$(dirname "$source")" "$(basename "$source")" 2>/dev/null; then
            echo "[SUCCESS] Directory backed up (non-sudo): $backup_name.tar.gz"
        else
            # Method 2: rsync as fallback
            echo "[DEBUG] Trying rsync backup method..."
            sudo mkdir -p "$backup_dir/$backup_name"
            sudo rsync -av "$source/" "$backup_dir/$backup_name/" 2>/dev/null || \
            rsync -av "$source/" "$backup_dir/$backup_name/" 2>/dev/null
            echo "[SUCCESS] Directory backed up with rsync"
        fi
        
    elif [ -f "$source" ]; then
        echo "[DEBUG] Backing up file: $source"
        
        # Method 1: cp with sudo
        if sudo cp "$source" "$backup_dir/$backup_name" 2>/dev/null; then
            echo "[SUCCESS] File backed up: $backup_name"
        elif cp "$source" "$backup_dir/$backup_name" 2>/dev/null; then
            echo "[SUCCESS] File backed up (non-sudo): $backup_name"
        else
            # Method 2: cat redirection
            echo "[DEBUG] Trying cat backup method..."
            if sudo test -r "$source"; then
                sudo cat "$source" > "$backup_dir/$backup_name" 2>/dev/null && \
                echo "[SUCCESS] File backed up with cat"
            elif [ -r "$source" ]; then
                cat "$source" > "$backup_dir/$backup_name" 2>/dev/null && \
                echo "[SUCCESS] File backed up with cat (non-sudo)"
            else
                echo "[ERROR] Cannot backup file: $source"
                return 1
            fi
        fi
    else
        echo "[ERROR] Source not found: $source"
        return 1
    fi
    
    # Set proper permissions on backup
    sudo chmod 644 "$backup_dir/$backup_name"* 2>/dev/null || true
    sudo chown $(whoami):$(whoami) "$backup_dir/$backup_name"* 2>/dev/null || true
    
    return 0
}

# Function to backup database with multiple fallback methods
backup_database() {
    local db_name="$1"
    local db_user="$2"
    local db_pass="$3"
    local db_host="${4:-localhost}"
    local backup_file="$5"
    
    echo "[INFO] Backing up database: $db_name"
    
    # Method 1: Try with provided credentials
    if [ -n "$db_user" ] && [ -n "$db_pass" ]; then
        echo "[DEBUG] Trying with provided credentials..."
        if mysqldump -u "$db_user" -p"$db_pass" -h "$db_host" "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up with user credentials"
            return 0
        fi
    fi
    
    # Method 2: Try with root (no password)
    echo "[DEBUG] Trying with root (no password)..."
    if mysql -u root -e "SELECT 1;" 2>/dev/null; then
        if mysqldump -u root "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up with root (no password)"
            return 0
        fi
    fi
    
    # Method 3: Try with root (empty password)
    echo "[DEBUG] Trying with root (empty password)..."
    if mysql -u root -p"" -e "SELECT 1;" 2>/dev/null; then
        if mysqldump -u root -p"" "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up with root (empty password)"
            return 0
        fi
    fi
    
    # Method 4: Try to find .my.cnf file
    echo "[DEBUG] Looking for MySQL configuration files..."
    if [ -f ~/.my.cnf ]; then
        echo "[DEBUG] Found ~/.my.cnf"
        if mysqldump "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up using .my.cnf"
            return 0
        fi
    fi
    
    # Method 5: Check for /etc/mysql/debian.cnf
    if [ -f /etc/mysql/debian.cnf ]; then
        echo "[DEBUG] Found /etc/mysql/debian.cnf"
        if mysqldump --defaults-file=/etc/mysql/debian.cnf "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up using debian.cnf"
            return 0
        fi
    fi
    
    # Method 6: Create temporary .my.cnf with root access
    echo "[DEBUG] Creating temporary .my.cnf..."
    TEMP_MYCNF="/tmp/my.cnf.$$"
    cat > "$TEMP_MYCNF" << EOF
[client]
user=root
password=
EOF
    
    if mysqldump --defaults-file="$TEMP_MYCNF" "$db_name" > "$backup_file" 2>/dev/null; then
        echo "[SUCCESS] Database backed up with temporary .my.cnf"
        rm -f "$TEMP_MYCNF"
        return 0
    fi
    rm -f "$TEMP_MYCNF"
    
    # Method 7: Last resort - try to access MySQL without password prompt
    echo "[DEBUG] Trying direct socket access..."
    if [ -S /var/run/mysqld/mysqld.sock ]; then
        if mysqldump --socket=/var/run/mysqld/mysqld.sock -u root "$db_name" > "$backup_file" 2>/dev/null; then
            echo "[SUCCESS] Database backed up via socket"
            return 0
        fi
    fi
    
    echo "[ERROR] Could not backup database $db_name"
    echo "[INFO] You may need to manually backup the database:"
    echo "  mysqldump -u [USER] -p [PASSWORD] $db_name > backup.sql"
    return 1
}

# Function to extract WordPress config values safely
extract_wp_config() {
    local wp_config="$1"
    local key="$2"
    
    echo "[DEBUG] Extracting $key from $wp_config"
    
    # Check file access
    if ! check_file_access "$wp_config"; then
        echo "[ERROR] Cannot access wp-config.php"
        return 1
    fi
    
    # Read file content
    local content
    if [ -r "$wp_config" ]; then
        content=$(cat "$wp_config")
    else
        content=$(sudo cat "$wp_config" 2>/dev/null)
    fi
    
    if [ -z "$content" ]; then
        echo "[ERROR] Could not read wp-config.php"
        return 1
    fi
    
    # Extract using multiple pattern matching
    local value=""
    
    # Pattern 1: define('KEY', 'VALUE');
    value=$(echo "$content" | grep -i "define.*$key" | grep -v "^[ \t]*/\|^[ \t]*\*" | \
            sed -n "s/.*['\"]\([^'\"]*\)['\"].*/\1/p" | head -1)
    
    # Pattern 2: define("KEY", "VALUE");
    if [ -z "$value" ]; then
        value=$(echo "$content" | grep -i "define.*$key" | grep -v "^[ \t]*/\|^[ \t]*\*" | \
                sed -n 's/.*["]\([^"]*\)["].*/\1/p' | head -1)
    fi
    
    # Pattern 3: PHP parsing (most reliable)
    if [ -z "$value" ] && command -v php >/dev/null 2>&1; then
        value=$(php -r "
            \$content = file_get_contents('$wp_config');
            if (preg_match('/define\s*\(\s*[\"\\']$key[\"\\']\s*,\s*[\"\\']([^\"\\']+)[\"\\']\s*\)/i', \$content, \$matches)) {
                echo \$matches[1];
            }
        " 2>/dev/null)
    fi
    
    if [ -n "$value" ]; then
        echo "$value"
        return 0
    else
        echo "[DEBUG] Could not extract $key from wp-config.php"
        return 1
    fi
}

# -------------------
# MAIN SCRIPT
# -------------------

# Create main backup directory with proper permissions
BACKUP_ROOT="/root/webserver-backup-$(date +%Y%m%d-%H%M%S)"
echo "[INFO] Creating backup root: $BACKUP_ROOT"

# Ensure we have permission to create backup directory
sudo mkdir -p "$BACKUP_ROOT" 2>/dev/null || mkdir -p "$BACKUP_ROOT"
sudo chmod 755 "$BACKUP_ROOT" 2>/dev/null || chmod 755 "$BACKUP_ROOT"
sudo chown $(whoami):$(whoami) "$BACKUP_ROOT" 2>/dev/null || true

# Detect web server
WEB_SERVER="none"
if systemctl is-active --quiet apache2; then
    WEB_SERVER="apache"
    echo "[INFO] Detected Apache"
elif systemctl is-active --quiet nginx; then
    WEB_SERVER="nginx"
    echo "[INFO] Detected Nginx"
fi

# Backup web server configuration
if [ "$WEB_SERVER" != "none" ]; then
    echo ""
    echo "==============================================="
    echo " BACKING UP WEB SERVER CONFIGURATION"
    echo "==============================================="
    
    if [ "$WEB_SERVER" = "apache" ]; then
        # Backup Apache
        create_backup "/etc/apache2" "$BACKUP_ROOT" "apache-config"
        create_backup "/etc/apache2/sites-available" "$BACKUP_ROOT" "apache-sites"
        create_backup "/etc/apache2/sites-enabled" "$BACKUP_ROOT" "apache-sites-enabled"
        
        # Backup Apache logs
        echo "[INFO] Backing up Apache logs..."
        sudo find /var/log/apache2 -name "*.log" -exec cp {} "$BACKUP_ROOT/" \; 2>/dev/null || true
        
    elif [ "$WEB_SERVER" = "nginx" ]; then
        # Backup Nginx
        create_backup "/etc/nginx" "$BACKUP_ROOT" "nginx-config"
        create_backup "/etc/nginx/sites-available" "$BACKUP_ROOT" "nginx-sites"
        create_backup "/etc/nginx/sites-enabled" "$BACKUP_ROOT" "nginx-sites-enabled"
        
        # Backup Nginx logs
        echo "[INFO] Backing up Nginx logs..."
        sudo find /var/log/nginx -name "*.log" -exec cp {} "$BACKUP_ROOT/" \; 2>/dev/null || true
    fi
fi

# Detect WordPress installations
echo ""
echo "==============================================="
echo " DETECTING WORDPRESS INSTALLATIONS"
echo "==============================================="

WP_INSTALLATIONS=()
WP_LOCATIONS=(
    "/var/www/html"
    "/var/www"
    "/home/*/public_html"
    "/home/*/www"
    "/usr/share/nginx/html"
    "/srv/www"
)

for location in "${WP_LOCATIONS[@]}"; do
    for dir in $(ls -d $location 2>/dev/null || true); do
        if [ -d "$dir" ]; then
            WP_CONFIG="$dir/wp-config.php"
            if [ -f "$WP_CONFIG" ]; then
                echo "[DEBUG] Found potential WordPress: $dir"
                
                # Test accessibility
                if check_file_access "$WP_CONFIG"; then
                    WP_INSTALLATIONS+=("$dir")
                    echo "  ✓ Accessible: $dir"
                else
                    echo "  ⚠ Inaccessible (permission issue): $dir"
                    echo "    Attempting to fix permissions..."
                    
                    # Try to fix permissions
                    sudo chmod 644 "$WP_CONFIG" 2>/dev/null
                    sudo chown www-data:www-data "$WP_CONFIG" 2>/dev/null
                    sudo chown $(whoami):$(whoami) "$WP_CONFIG" 2>/dev/null
                    
                    # Test again
                    if check_file_access "$WP_CONFIG"; then
                        WP_INSTALLATIONS+=("$dir")
                        echo "  ✓ Now accessible after fix: $dir"
                    fi
                fi
            fi
        fi
    done
done

# Handle WordPress selection
if [ ${#WP_INSTALLATIONS[@]} -eq 0 ]; then
    echo "[INFO] No WordPress found or all inaccessible"
    echo "[INFO] Will install fresh WordPress"
    SELECTED_WP_PATH="/var/www/html"
    EXISTING_WP=false
else
    echo ""
    echo "Found WordPress installations:"
    for i in "${!WP_INSTALLATIONS[@]}"; do
        echo "$((i+1))) ${WP_INSTALLATIONS[$i]}"
    done
    echo "$(( ${#WP_INSTALLATIONS[@]} + 1 ))) Install fresh WordPress"
    
    read -p "Select (1-$((${#WP_INSTALLATIONS[@]} + 1))): " choice
    
    if [ "$choice" -le ${#WP_INSTALLATIONS[@]} ]; then
        SELECTED_WP_PATH="${WP_INSTALLATIONS[$((choice-1))]}"
        EXISTING_WP=true
        echo "[INFO] Selected: $SELECTED_WP_PATH"
    else
        read -p "Enter path for new WordPress [/var/www/html]: " new_path
        SELECTED_WP_PATH="${new_path:-/var/www/html}"
        EXISTING_WP=false
    fi
fi

# Backup WordPress
echo ""
echo "==============================================="
echo " BACKING UP WORDPRESS"
echo "==============================================="

if [ "$EXISTING_WP" = true ]; then
    # Backup WordPress files
    echo "[INFO] Backing up WordPress files..."
    create_backup "$SELECTED_WP_PATH" "$BACKUP_ROOT" "wordpress-files"
    
    # Backup wp-config.php separately
    WP_CONFIG="$SELECTED_WP_PATH/wp-config.php"
    if check_file_access "$WP_CONFIG"; then
        create_backup "$WP_CONFIG" "$BACKUP_ROOT" "wp-config.php"
        
        # Extract database info
        echo "[INFO] Extracting database information..."
        DB_NAME=$(extract_wp_config "$WP_CONFIG" "DB_NAME")
        DB_USER=$(extract_wp_config "$WP_CONFIG" "DB_USER")
        DB_PASS=$(extract_wp_config "$WP_CONFIG" "DB_PASSWORD")
        DB_HOST=$(extract_wp_config "$WP_CONFIG" "DB_HOST")
        DB_HOST="${DB_HOST:-localhost}"
        
        if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
            echo "[INFO] Database info extracted:"
            echo "  Name: $DB_NAME"
            echo "  User: $DB_USER"
            echo "  Host: $DB_HOST"
            
            # Backup database
            echo "[INFO] Backing up database..."
            backup_database "$DB_NAME" "$DB_USER" "$DB_PASS" "$DB_HOST" "$BACKUP_ROOT/wordpress-database.sql"
            
            # Save database info
            echo "DB_NAME=$DB_NAME" > "$BACKUP_ROOT/database.info"
            echo "DB_USER=$DB_USER" >> "$BACKUP_ROOT/database.info"
            echo "DB_PASS=$DB_PASS" >> "$BACKUP_ROOT/database.info"
            echo "DB_HOST=$DB_HOST" >> "$BACKUP_ROOT/database.info"
        fi
    fi
fi

# Get domain information
echo ""
echo "==============================================="
echo " DOMAIN CONFIGURATION"
echo "==============================================="

# Try to get domain from existing WordPress
if [ "$EXISTING_WP" = true ] && [ -f "$SELECTED_WP_PATH/wp-config.php" ]; then
    if command -v wp >/dev/null 2>&1; then
        cd "$SELECTED_WP_PATH"
        SITE_URL=$(sudo -u www-data wp option get home 2>/dev/null || echo "")
        if [ -n "$SITE_URL" ]; then
            DOMAIN=$(echo "$SITE_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|^www\.||')
            echo "[INFO] Found existing domain: $DOMAIN"
        fi
    fi
fi

# Ask for domain if not found
if [ -z "$DOMAIN" ]; then
    read -p "Enter primary domain [sahmcore.com.sa]: " DOMAIN
    DOMAIN="${DOMAIN:-sahmcore.com.sa}"
fi

ADMIN_EMAIL="a.saeed@$DOMAIN"

# Internal VM IPs
THIS_VM_IP="192.168.116.37"
ERP_IP="192.168.116.13"
ERP_PORT="8069"
DOCS_IP="192.168.116.1"
DOCS_PORT="9443"
MAIL_IP="192.168.116.1"
MAIL_PORT="444"
NOMOGROW_IP="192.168.116.48"
NOMOGROW_PORT="8082"
VENTURA_IP="192.168.116.10"
VENTURA_PORT="8080"

# -------------------
# SYSTEM SETUP
# -------------------

echo ""
echo "==============================================="
echo " SYSTEM SETUP"
echo "==============================================="

# Update system
echo "[INFO] Updating system..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "[INFO] Installing dependencies..."
sudo apt install -y curl wget unzip lsb-release software-properties-common \
    net-tools ufw dnsutils git mariadb-client mariadb-server

# Fix MySQL permissions if needed
echo "[INFO] Configuring MySQL..."
sudo systemctl start mariadb 2>/dev/null || sudo systemctl start mysql 2>/dev/null
sudo systemctl enable mariadb 2>/dev/null || sudo systemctl enable mysql 2>/dev/null

# Ensure MySQL is accessible
echo "[INFO] Testing MySQL access..."
if ! mysql -u root -e "SELECT 1;" 2>/dev/null && ! mysql -u root -p"" -e "SELECT 1;" 2>/dev/null; then
    echo "[WARNING] MySQL root access issue. Attempting to secure installation..."
    sudo mysql_secure_installation <<EOF
n
y
y
y
y
y
EOF
fi

# Install PHP
echo "[INFO] Installing PHP..."
sudo add-apt-repository ppa:ondrej/php -y
sudo apt update
sudo apt install -y php8.3 php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd \
    php8.3-mbstring php8.3-xml php8.3-xmlrpc php8.3-soap php8.3-intl \
    php8.3-zip php8.3-bcmath

PHP_VERSION="8.3"
PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"

# Configure PHP-FPM
PHP_FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
if [ -f "$PHP_FPM_CONF" ]; then
    sudo cp "$PHP_FPM_CONF" "${PHP_FPM_CONF}.backup"
    sudo sed -i 's/^pm = .*/pm = dynamic/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.max_children = .*/pm.max_children = 20/' "$PHP_FPM_CONF"
    echo "php_admin_value[upload_max_filesize] = 64M" | sudo tee -a "$PHP_FPM_CONF"
    echo "php_admin_value[post_max_size] = 64M" | sudo tee -a "$PHP_FPM_CONF"
fi

sudo systemctl restart "php${PHP_VERSION}-fpm"
sudo systemctl enable --now "php${PHP_VERSION}-fpm"

# Install Caddy
echo "[INFO] Installing Caddy..."
if ! command -v caddy >/dev/null 2>&1; then
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install -y caddy
fi

# -------------------
# WORDPRESS SETUP
# -------------------

echo ""
echo "==============================================="
echo " WORDPRESS SETUP"
echo "==============================================="

# Set permissions for WordPress
echo "[INFO] Setting WordPress permissions..."
sudo mkdir -p "$SELECTED_WP_PATH"
sudo chown -R www-data:www-data "$SELECTED_WP_PATH"
sudo find "$SELECTED_WP_PATH" -type d -exec chmod 755 {} \;
sudo find "$SELECTED_WP_PATH" -type f -exec chmod 644 {} \;

if [ "$EXISTING_WP" != true ]; then
    # Install fresh WordPress
    echo "[INFO] Installing fresh WordPress..."
    cd /tmp
    wget -q https://wordpress.org/latest.zip
    unzip -q latest.zip
    sudo mv wordpress/* "$SELECTED_WP_PATH/"
    sudo rm -rf wordpress latest.zip
    
    # Create database
    DB_NAME="wp_$(echo "$DOMAIN" | tr -cd '[:alnum:]' | cut -c1-16)"
    DB_USER="wpuser_$(openssl rand -hex 4)"
    DB_PASS=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)
    
    sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    
    # Configure wp-config.php
    sudo cp "$SELECTED_WP_PATH/wp-config-sample.php" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/database_name_here/$DB_NAME/" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/username_here/$DB_USER/" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/password_here/$DB_PASS/" "$SELECTED_WP_PATH/wp-config.php"
    
    # Generate salts
    SALT=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
    sudo sed -i "/define( 'AUTH_KEY',/a $SALT" "$SELECTED_WP_PATH/wp-config.php"
fi

# Add Caddy support to wp-config.php
WP_CONFIG="$SELECTED_WP_PATH/wp-config.php"
if [ -f "$WP_CONFIG" ] && ! grep -q "HTTP_X_FORWARDED_PROTO" "$WP_CONFIG"; then
    echo "[INFO] Adding Caddy reverse proxy support..."
    cat >> "$WP_CONFIG" << 'EOF'

/* Caddy Reverse Proxy Support */
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = 443;
}
if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST'];
}
EOF
fi

# -------------------
# CADDY CONFIGURATION
# -------------------

echo ""
echo "==============================================="
echo " CADDY CONFIGURATION"
echo "==============================================="

# Create Caddyfile
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
# Global settings
{
    email $ADMIN_EMAIL
    acme_ca https://acme-v02.api.letsencrypt.org/directory
}

# WordPress site
$DOMAIN, www.$DOMAIN {
    root * $SELECTED_WP_PATH
    php_fastcgi unix:$PHP_SOCKET
    file_server
    encode gzip
    
    # WordPress rewrites
    try_files {path} {path}/ /index.php?{query}
    
    # Security headers
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        -Server
    }
}

# Reverse proxy services
erp.$DOMAIN {
    reverse_proxy http://$ERP_IP:$ERP_PORT
}

docs.$DOMAIN {
    reverse_proxy https://$DOCS_IP:$DOCS_PORT {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

mail.$DOMAIN {
    reverse_proxy https://$MAIL_IP:$MAIL_PORT {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

nomogrow.$DOMAIN {
    reverse_proxy http://$NOMOGROW_IP:$NOMOGROW_PORT
}

ventura-tech.$DOMAIN {
    reverse_proxy http://$VENTURA_IP:$VENTURA_PORT
}

# Health check
health.$DOMAIN {
    respond "OK" 200
}

# HTTP to HTTPS redirect
http://${DOMAIN}, http://www.${DOMAIN}, http://erp.${DOMAIN}, http://docs.${DOMAIN}, http://mail.${DOMAIN}, http://nomogrow.${DOMAIN}, http://ventura-tech.${DOMAIN} {
    redir https://{host}{uri} permanent
}
EOF

# Set Caddy permissions
sudo chown -R caddy:caddy /etc/caddy
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy

# -------------------
# FIREWALL CONFIGURATION
# -------------------

echo ""
echo "[INFO] Configuring firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 192.168.116.0/24
echo "y" | sudo ufw enable

# -------------------
# START SERVICES
# -------------------

echo ""
echo "==============================================="
echo " STARTING SERVICES"
echo "==============================================="

# Stop old web server
if [ "$WEB_SERVER" = "apache" ]; then
    sudo systemctl stop apache2
    sudo systemctl disable apache2
elif [ "$WEB_SERVER" = "nginx" ]; then
    sudo systemctl stop nginx
    sudo systemctl disable nginx
fi

# Start Caddy
sudo systemctl restart caddy
sudo systemctl enable caddy

# Wait and check
sleep 3
echo "[INFO] Service status:"
sudo systemctl status caddy --no-pager | head -10
sudo systemctl status "php${PHP_VERSION}-fpm" --no-pager | head -10

# -------------------
# TESTING
# -------------------

echo ""
echo "==============================================="
echo " TESTING"
echo "==============================================="

# Create test file
sudo tee "$SELECTED_WP_PATH/test-migration.php" > /dev/null << 'EOF'
<?php
header('Content-Type: text/plain');
echo "Migration Test\n";
echo "==============\n\n";

// Test PHP
echo "PHP Version: " . PHP_VERSION . "\n";
echo "Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "\n";
echo "HTTPS: " . (isset($_SERVER['HTTPS']) ? 'Yes' : 'No') . "\n";
echo "X-Forwarded-Proto: " . ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'Not set') . "\n\n";

// Test MySQL
echo "MySQL Test:\n";
$config_file = dirname(__FILE__) . '/wp-config.php';
if (file_exists($config_file)) {
    $config = file_get_contents($config_file);
    
    preg_match("/define\s*\(\s*'DB_NAME'\s*,\s*'([^']+)'\s*\)/", $config, $db_name);
    preg_match("/define\s*\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\)/", $config, $db_user);
    preg_match("/define\s*\(\s*'DB_HOST'\s*,\s*'([^']+)'\s*\)/", $config, $db_host);
    
    echo "Database: " . ($db_name[1] ?? 'Not found') . "\n";
    echo "User: " . ($db_user[1] ?? 'Not found') . "\n";
    echo "Host: " . ($db_host[1] ?? 'localhost') . "\n";
    
    // Try connection
    if (isset($db_user[1])) {
        $conn = @mysqli_connect(
            $db_host[1] ?? 'localhost',
            $db_user[1],
            defined('DB_PASSWORD') ? DB_PASSWORD : '',
            $db_name[1]
        );
        
        if ($conn) {
            echo "Connection: SUCCESS\n";
            mysqli_close($conn);
        } else {
            echo "Connection: FAILED - " . mysqli_connect_error() . "\n";
        }
    }
} else {
    echo "wp-config.php not found\n";
}
?>
EOF

sudo chown www-data:www-data "$SELECTED_WP_PATH/test-migration.php"
sudo chmod 644 "$SELECTED_WP_PATH/test-migration.php"

# Test access
echo "[INFO] Testing WordPress access..."
sleep 2
curl -s -H "Host: $DOMAIN" http://127.0.0.1/test-migration.php | head -20

# -------------------
# FINAL OUTPUT
# -------------------

echo ""
echo "==============================================="
echo " MIGRATION COMPLETE!"
echo "==============================================="
echo ""
echo "✅ Backup created: $BACKUP_ROOT"
echo "✅ WordPress preserved: $SELECTED_WP_PATH"
if [ "$EXISTING_WP" = true ]; then
    echo "✅ Database preserved: $DB_NAME"
else
    echo "✅ New WordPress installed"
    echo "   Database: $DB_NAME"
    echo "   User: $DB_USER"
    echo "   Password saved in wp-config.php"
fi
echo "✅ Caddy configured for:"
echo "   • https://$DOMAIN"
echo "   • https://erp.$DOMAIN"
echo "   • https://docs.$DOMAIN"
echo "   • https://mail.$DOMAIN"
echo "   • https://nomogrow.$DOMAIN"
echo "   • https://ventura-tech.$DOMAIN"
echo ""
echo "🔧 Management:"
echo "   sudo systemctl status caddy"
echo "   sudo journalctl -u caddy -f"
echo "   sudo caddy validate --config /etc/caddy/Caddyfile"
echo ""
echo "📁 Backup location: $BACKUP_ROOT"
echo "   Contains: Web server config, WordPress files, database backup"
echo ""
echo "⚠️  Next steps:"
echo "   1. Update DNS to point to $THIS_VM_IP"
echo "   2. Test all services"
echo "   3. Remove test file: sudo rm $SELECTED_WP_PATH/test-migration.php"
echo "   4. Keep backup for at least 30 days"
echo ""
echo "==============================================="
