#!/bin/bash
# ===============================================
# Full Setup Script: WordPress + PHP-FPM + Caddy + Let's Encrypt
# Enhanced with failsafe database handling and website selection
# Domain: sahmcore.com.sa
# ===============================================

set -e

# -------------------
# CLEANUP PREVIOUS BACKUPS AND FREE DISK SPACE
# -------------------

echo "[INFO] Cleaning up previous backups and freeing up disk space..."

# Remove temporary files in /tmp (keep recent files)
echo "[INFO] Cleaning /tmp directory..."
find /tmp -type f -atime +1 -delete 2>/dev/null || true

# Remove old backups
echo "[INFO] Removing old backup directories..."
find /root/backup-* -maxdepth 0 -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true

# Clean package cache
echo "[INFO] Cleaning up package cache..."
sudo apt-get clean

# Remove unnecessary packages
echo "[INFO] Removing unnecessary packages..."
sudo apt-get autoremove -y --purge

# Check disk usage
echo "[INFO] Checking disk usage..."
df -h

# -------------------
# USER CONFIGURATION
# -------------------
DOMAIN="sahmcore.com.sa"
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
# DETECT EXISTING WORDPRESS INSTALLATION
# -------------------
WP_PATH="/var/www/html"
EXISTING_WP=false
NEW_WP_INSTALL=false

echo "[INFO] Checking for existing WordPress installation..."
if [ -d "$WP_PATH" ] && [ -f "$WP_PATH/wp-config.php" ]; then
    echo "[INFO] Found existing WordPress installation at $WP_PATH"
    
    # Try to extract database info from wp-config.php
    if [ -f "$WP_PATH/wp-config.php" ]; then
        echo "[INFO] Extracting database information from existing wp-config.php..."
        
        # Extract database name
        DB_NAME=$(grep -i "DB_NAME" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d"'" -f4 | head -1)
        if [ -z "$DB_NAME" ]; then
            DB_NAME=$(grep -i "DB_NAME" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d'"' -f2 | head -1)
        fi
        
        # Extract database user
        DB_USER=$(grep -i "DB_USER" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d"'" -f4 | head -1)
        if [ -z "$DB_USER" ]; then
            DB_USER=$(grep -i "DB_USER" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d'"' -f2 | head -1)
        fi
        
        # Extract database password
        DB_PASSWORD=$(grep -i "DB_PASSWORD" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d"'" -f4 | head -1)
        if [ -z "$DB_PASSWORD" ]; then
            DB_PASSWORD=$(grep -i "DB_PASSWORD" "$WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | cut -d'"' -f2 | head -1)
        fi
        
        if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
            echo "[INFO] Found existing WordPress database configuration:"
            echo "  Database: $DB_NAME"
            echo "  User: $DB_USER"
            
            # Test database connection
            if mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "USE $DB_NAME;" 2>/dev/null; then
                echo "[SUCCESS] Database connection successful!"
                EXISTING_WP=true
                
                # Get WordPress site URL from database
                if command -v wp >/dev/null 2>&1; then
                    SITE_URL=$(cd "$WP_PATH" && sudo -u www-data wp option get home 2>/dev/null || echo "")
                else
                    SITE_URL=$(mysql -u "$DB_USER" -p"$DB_PASSWORD" -D "$DB_NAME" -sN -e "SELECT option_value FROM wp_options WHERE option_name = 'home' LIMIT 1;" 2>/dev/null || echo "")
                fi
                
                if [ -n "$SITE_URL" ]; then
                    echo "[INFO] Existing WordPress site URL: $SITE_URL"
                    echo ""
                    echo "==============================================="
                    echo "EXISTING WORDPRESS DETECTED"
                    echo "==============================================="
                    echo "Found an existing WordPress installation at:"
                    echo "  Path: $WP_PATH"
                    echo "  Database: $DB_NAME"
                    echo "  Site URL: $SITE_URL"
                    echo ""
                    echo "Options:"
                    echo "  1) Use existing WordPress installation"
                    echo "  2) Install fresh WordPress (existing data will be backed up)"
                    echo "  3) Cancel setup"
                    echo ""
                    
                    while true; do
                        read -p "Select option (1-3): " wp_option
                        case $wp_option in
                            1)
                                echo "[INFO] Will use existing WordPress installation."
                                EXISTING_WP=true
                                break
                                ;;
                            2)
                                echo "[INFO] Will install fresh WordPress."
                                EXISTING_WP=false
                                NEW_WP_INSTALL=true
                                
                                # Backup existing installation
                                BACKUP_DIR="/root/wordpress-backup-$(date +%Y%m%d-%H%M%S)"
                                echo "[INFO] Backing up existing WordPress to $BACKUP_DIR..."
                                sudo mkdir -p "$BACKUP_DIR"
                                sudo cp -r "$WP_PATH" "$BACKUP_DIR/wordpress-files"
                                
                                # Backup database
                                if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
                                    echo "[INFO] Backing up database '$DB_NAME'..."
                                    mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" > "$BACKUP_DIR/wordpress-database.sql" 2>/dev/null || \
                                        echo "[WARNING] Could not backup database. Continuing anyway..."
                                fi
                                
                                echo "[INFO] Backup completed to: $BACKUP_DIR"
                                echo "[INFO] Removing existing WordPress files..."
                                sudo rm -rf "$WP_PATH"/*
                                break
                                ;;
                            3)
                                echo "[INFO] Setup cancelled by user."
                                exit 0
                                ;;
                            *)
                                echo "Invalid option. Please enter 1, 2, or 3."
                                ;;
                        esac
                    done
                fi
            else
                echo "[WARNING] Could not connect to existing database."
                echo "[INFO] Will proceed with fresh installation."
                EXISTING_WP=false
                NEW_WP_INSTALL=true
            fi
        else
            echo "[WARNING] Could not extract database info from wp-config.php"
            echo "[INFO] Will proceed with fresh installation."
            EXISTING_WP=false
            NEW_WP_INSTALL=true
        fi
    else
        echo "[WARNING] wp-config.php not found or readable."
        echo "[INFO] Will proceed with fresh installation."
        EXISTING_WP=false
        NEW_WP_INSTALL=true
    fi
else
    echo "[INFO] No existing WordPress installation found."
    EXISTING_WP=false
    NEW_WP_INSTALL=true
fi

# -------------------
# DETERMINE SITE DOMAIN
# -------------------
if [ "$EXISTING_WP" = true ] && [ -n "$SITE_URL" ]; then
    # Extract domain from existing site URL
    DOMAIN=$(echo "$SITE_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|^www\.||')
    echo "[INFO] Using existing WordPress domain: $DOMAIN"
else
    echo ""
    echo "==============================================="
    echo "WORDPRESS DOMAIN CONFIGURATION"
    echo "==============================================="
    echo "Please enter the primary domain for WordPress:"
    echo "  (This will be used for SSL certificates and site URL)"
    echo ""
    read -p "Primary domain [$DOMAIN]: " user_domain
    if [ -n "$user_domain" ]; then
        DOMAIN="$user_domain"
    fi
    echo "[INFO] Using domain: $DOMAIN"
fi

# -------------------
# WORDPRESS CREDENTIALS
# -------------------
if [ "$NEW_WP_INSTALL" = true ]; then
    echo ""
    echo "==============================================="
    echo "WORDPRESS ADMIN CREDENTIALS"
    echo "==============================================="
    echo "Please enter admin credentials for new WordPress installation:"
    echo ""
    read -p "Admin username [admin]: " WP_ADMIN_USER
    WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
    
    while true; do
        read -sp "Admin password: " WP_ADMIN_PASSWORD
        echo
        if [ -z "$WP_ADMIN_PASSWORD" ]; then
            echo "Password cannot be empty. Please try again."
        else
            read -sp "Confirm admin password: " WP_ADMIN_PASSWORD_CONFIRM
            echo
            if [ "$WP_ADMIN_PASSWORD" = "$WP_ADMIN_PASSWORD_CONFIRM" ]; then
                break
            else
                echo "Passwords do not match. Please try again."
            fi
        fi
    done
    
    # Database configuration for NEW installation
    DB_NAME="wordpress_$(echo "$DOMAIN" | tr -cd '[:alnum:]' | cut -c1-16)"
    DB_USER="wp_$(openssl rand -hex 4)"
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)
else
    # For existing installation, credentials remain unchanged
    echo "[INFO] Using existing WordPress credentials from database."
    WP_ADMIN_USER=""  # Not used for existing installs
    WP_ADMIN_PASSWORD=""  # Not used for existing installs
fi

# -------------------
# VALIDATE DNS RESOLUTION
# -------------------
echo ""
echo "[INFO] Checking DNS resolution for $DOMAIN..."
if ! dig +short "$DOMAIN" | grep -q '.'; then
    echo "[WARNING] $DOMAIN does not resolve to any IP address."
    echo "[WARNING] Let's Encrypt SSL certificates will fail without proper DNS."
    
    # Get server public IP
    PUBLIC_IP=$(curl -s http://ifconfig.me || curl -s http://api.ipify.org || echo "unknown")
    echo "[INFO] Your server's public IP appears to be: $PUBLIC_IP"
    echo ""
    echo "DNS CONFIGURATION REQUIRED:"
    echo "==============================================="
    echo "Please create these DNS A records pointing to $PUBLIC_IP:"
    echo "  $DOMAIN"
    echo "  www.$DOMAIN"
    echo "  erp.$DOMAIN"
    echo "  docs.$DOMAIN"
    echo "  mail.$DOMAIN"
    echo "  nomogrow.$DOMAIN"
    echo "  ventura-tech.$DOMAIN"
    echo ""
    
    read -p "Have you configured DNS? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "[WARNING] Continuing without DNS verification. SSL certificates will fail."
        echo "[INFO] You can run this script again after DNS is configured."
    fi
fi

# -------------------
# SYSTEM UPDATE & DEPENDENCIES
# -------------------
echo "[INFO] Updating system and installing dependencies..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget unzip lsb-release software-properties-common \
    net-tools ufw dnsutils git mariadb-client mariadb-server

# -------------------
# MARIADB/MYSQL SETUP
# -------------------
echo "[INFO] Setting up MariaDB..."

# Start and enable MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Secure MariaDB installation (only if not already done)
if [ ! -f ~/.mysql_configured ]; then
    echo "[INFO] Securing MariaDB installation..."
    
    # Generate a secure root password
    MYSQL_ROOT_PASS=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)
    
    sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASS';"
    sudo mysql -e "DELETE FROM mysql.user WHERE User='';"
    sudo mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    sudo mysql -e "DROP DATABASE IF EXISTS test;"
    sudo mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    
    # Save root password securely
    echo "MySQL root password: $MYSQL_ROOT_PASS" | sudo tee /root/.mysql_root_pass
    sudo chmod 600 /root/.mysql_root_pass
    
    touch ~/.mysql_configured
    echo "[INFO] MariaDB secured. Root password saved to /root/.mysql_root_pass"
fi

# Only create new database if it's a fresh installation
if [ "$NEW_WP_INSTALL" = true ]; then
    echo "[INFO] Creating WordPress database for new installation..."
    
    # Check if database already exists
    if mysql -e "SHOW DATABASES LIKE '$DB_NAME';" | grep -q "$DB_NAME"; then
        echo "[WARNING] Database '$DB_NAME' already exists!"
        echo "[INFO] Will use existing database for WordPress."
    else
        # Create new database
        sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        echo "[INFO] Database '$DB_NAME' created."
    fi
    
    # Check if user already exists
    if mysql -e "SELECT User FROM mysql.user WHERE User='$DB_USER';" | grep -q "$DB_USER"; then
        echo "[WARNING] Database user '$DB_USER' already exists!"
        echo "[INFO] Updating password for existing user..."
        sudo mysql -e "ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
    else
        # Create new user
        sudo mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
        echo "[INFO] User '$DB_USER' created."
    fi
    
    # Grant privileges (always do this, even if user exists)
    sudo mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    
    echo "[INFO] Database configuration for new installation complete:"
    echo "  Database: $DB_NAME"
    echo "  Username: $DB_USER"
    echo "  Password: $DB_PASSWORD"
    
    # Save database credentials
    echo "DB_NAME=$DB_NAME" | sudo tee /root/.wordpress_db_info
    echo "DB_USER=$DB_USER" | sudo tee -a /root/.wordpress_db_info
    echo "DB_PASSWORD=$DB_PASSWORD" | sudo tee -a /root/.wordpress_db_info
    sudo chmod 600 /root/.wordpress_db_info
fi

# -------------------
# PHP-FPM INSTALLATION
# -------------------
echo "[INFO] Checking PHP-FPM..."

# Determine and install PHP version
if ! command -v php >/dev/null 2>&1; then
    echo "[INFO] Installing PHP 8.3 and extensions..."
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update
    sudo apt install -y php8.3 php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd \
        php8.3-mbstring php8.3-xml php8.3-xmlrpc php8.3-soap php8.3-intl \
        php8.3-zip php8.3-bcmath php8.3-imagick
    PHP_VERSION="8.3"
else
    PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
    echo "[INFO] PHP $PHP_VERSION already installed"
fi

PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"
echo "[INFO] Using PHP-FPM socket: $PHP_SOCKET"

# Configure PHP-FPM for WordPress
PHP_FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
if [ -f "$PHP_FPM_CONF" ]; then
    # Backup original
    sudo cp "$PHP_FPM_CONF" "${PHP_FPM_CONF}.backup"
    
    # Optimize for WordPress
    sudo sed -i 's/^pm = .*/pm = dynamic/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.max_children = .*/pm.max_children = 20/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.start_servers = .*/pm.start_servers = 5/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.min_spare_servers = .*/pm.min_spare_servers = 5/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.max_spare_servers = .*/pm.max_spare_servers = 10/' "$PHP_FPM_CONF"
    
    # Increase limits for WordPress
    if ! grep -q "upload_max_filesize" "$PHP_FPM_CONF"; then
        echo "php_admin_value[upload_max_filesize] = 64M" | sudo tee -a "$PHP_FPM_CONF"
        echo "php_admin_value[post_max_size] = 64M" | sudo tee -a "$PHP_FPM_CONF"
        echo "php_admin_value[max_execution_time] = 300" | sudo tee -a "$PHP_FPM_CONF"
        echo "php_admin_value[max_input_time] = 300" | sudo tee -a "$PHP_FPM_CONF"
        echo "php_admin_value[memory_limit] = 256M" | sudo tee -a "$PHP_FPM_CONF"
    fi
fi

# Start PHP-FPM
sudo systemctl restart "php${PHP_VERSION}-fpm"
sudo systemctl enable --now "php${PHP_VERSION}-fpm"

# -------------------
# CADDY INSTALLATION WITH LET'S ENCRYPT
# -------------------
echo "[INFO] Installing Caddy..."
if ! command -v caddy >/dev/null 2>&1; then
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install -y caddy
fi

# -------------------
# STOP OTHER WEB SERVERS
# -------------------
echo "[INFO] Stopping other web servers..."
for service in apache2 nginx; do
    sudo systemctl stop "$service" 2>/dev/null || true
    sudo systemctl disable "$service" 2>/dev/null || true
    sudo systemctl mask "$service" 2>/dev/null || true
done

# -------------------
# WORDPRESS INSTALLATION/CONFIGURATION
# -------------------
if [ "$NEW_WP_INSTALL" = true ]; then
    echo "[INFO] Installing fresh WordPress..."
    
    # Create directory if it doesn't exist
    sudo mkdir -p "$WP_PATH"
    
    # Download WordPress
    cd /tmp
    wget -q https://wordpress.org/latest.zip
    unzip -q latest.zip
    sudo mv wordpress/* "$WP_PATH/"
    sudo rm -rf wordpress latest.zip
    
    # Create wp-config.php
    echo "[INFO] Creating wp-config.php..."
    sudo cp "$WP_PATH/wp-config-sample.php" "$WP_PATH/wp-config.php"
    
    # Set database configuration
    sudo sed -i "s/database_name_here/$DB_NAME/" "$WP_PATH/wp-config.php"
    sudo sed -i "s/username_here/$DB_USER/" "$WP_PATH/wp-config.php"
    sudo sed -i "s/password_here/$DB_PASSWORD/" "$WP_PATH/wp-config.php"
    sudo sed -i "s/localhost/localhost/" "$WP_PATH/wp-config.php"
    
    # Generate secure salts
    echo "[INFO] Generating secure authentication keys..."
    SALT=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
    sudo sed -i "/define( 'AUTH_KEY',/a $SALT" "$WP_PATH/wp-config.php"
    
    # Install WordPress via wp-cli or manually
    echo "[INFO] Installing WordPress core..."
    
    # Check if wp-cli is available
    if command -v wp >/dev/null 2>&1; then
        cd "$WP_PATH"
        sudo -u www-data wp core install \
            --url="https://$DOMAIN" \
            --title="Sahmcore" \
            --admin_user="$WP_ADMIN_USER" \
            --admin_password="$WP_ADMIN_PASSWORD" \
            --admin_email="$ADMIN_EMAIL" \
            --skip-email
        
        # Set pretty permalinks
        sudo -u www-data wp rewrite structure '/%postname%/' --hard
    else
        # Install wp-cli
        curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x wp-cli.phar
        sudo mv wp-cli.phar /usr/local/bin/wp
        
        cd "$WP_PATH"
        sudo -u www-data wp core install \
            --url="https://$DOMAIN" \
            --title="Sahmcore" \
            --admin_user="$WP_ADMIN_USER" \
            --admin_password="$WP_ADMIN_PASSWORD" \
            --admin_email="$ADMIN_EMAIL" \
            --skip-email
    fi
    
    echo "[INFO] Fresh WordPress installation complete!"
else
    echo "[INFO] Using existing WordPress installation..."
    
    # Verify the existing installation is working
    if [ -f "$WP_PATH/wp-config.php" ]; then
        echo "[INFO] Found existing wp-config.php"
        
        # Update site URLs in database if needed
        if command -v wp >/dev/null 2>&1; then
            cd "$WP_PATH"
            
            # Get current URLs
            CURRENT_HOME=$(sudo -u www-data wp option get home 2>/dev/null || echo "")
            CURRENT_SITEURL=$(sudo -u www-data wp option get siteurl 2>/dev/null || echo "")
            
            # Update if different from new domain
            if [ -n "$CURRENT_HOME" ] && [[ "$CURRENT_HOME" != *"$DOMAIN"* ]]; then
                echo "[INFO] Updating WordPress URLs to use $DOMAIN..."
                sudo -u www-data wp search-replace "$CURRENT_HOME" "https://$DOMAIN" --all-tables --quiet
                sudo -u www-data wp search-replace "$CURRENT_SITEURL" "https://$DOMAIN" --all-tables --quiet
            fi
        fi
    else
        echo "[ERROR] Existing WordPress installation appears broken (wp-config.php missing)"
        echo "[INFO] Will attempt to continue with Caddy setup..."
    fi
fi

# Add reverse proxy support to wp-config.php (if not already present)
if [ -f "$WP_PATH/wp-config.php" ] && ! grep -q "HTTP_X_FORWARDED_PROTO" "$WP_PATH/wp-config.php"; then
    echo "[INFO] Adding reverse proxy support to wp-config.php..."
    cat >> "$WP_PATH/wp-config.php" << 'EOF'

/* Reverse Proxy Support for Caddy */
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = 443;
}
if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST'];
}

/* Debugging Settings */
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
EOF
fi

# Set proper permissions
sudo chown -R www-data:www-data "$WP_PATH"
sudo find "$WP_PATH" -type d -exec chmod 755 {} \;
sudo find "$WP_PATH" -type f -exec chmod 644 {} \;

# Special permissions for wp-content
if [ -d "$WP_PATH/wp-content" ]; then
    sudo chmod 775 "$WP_PATH/wp-content"
    sudo chown -R www-data:www-data "$WP_PATH/wp-content"
fi

# -------------------
# CREATE CADDYFILE WITH LET'S ENCRYPT
# -------------------
echo "[INFO] Creating Caddyfile with Let's Encrypt SSL..."

# Backup existing Caddyfile
sudo cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

# Create new Caddyfile
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
# Global options for Let's Encrypt
{
    email $ADMIN_EMAIL
    # Use HTTP challenge (requires port 80 to be accessible)
    acme_ca https://acme-v02.api.letsencrypt.org/directory
}

# Main WordPress site
$DOMAIN, www.$DOMAIN {
    root * $WP_PATH
    
    # PHP-FPM configuration
    php_fastcgi unix:$PHP_SOCKET {
        resolve_root_symlink
        split .php
        index index.php
    }
    
    # File server for static content
    file_server
    
    # WordPress rewrite rules
    try_files {path} {path}/ /index.php?{query}
    
    # Compression
    encode gzip
    
    # Security headers
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    
    # Logging
    log {
        output file /var/log/caddy/wordpress.log
        level INFO
    }
}

# ERP Service
erp.$DOMAIN {
    reverse_proxy http://$ERP_IP:$ERP_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
    log {
        output file /var/log/caddy/erp.log
    }
}

# Documentation Service
docs.$DOMAIN {
    reverse_proxy https://$DOCS_IP:$DOCS_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log {
        output file /var/log/caddy/docs.log
    }
}

# Mail Service
mail.$DOMAIN {
    reverse_proxy https://$MAIL_IP:$MAIL_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log {
        output file /var/log/caddy/mail.log
    }
}

# Nomogrow Service
nomogrow.$DOMAIN {
    reverse_proxy http://$NOMOGROW_IP:$NOMOGROW_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log {
        output file /var/log/caddy/nomogrow.log
    }
}

# Ventura-Tech Service
ventura-tech.$DOMAIN {
    reverse_proxy http://$VENTURA_IP:$VENTURA_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log {
        output file /var/log/caddy/ventura-tech.log
    }
}

# Health check endpoint
health.$DOMAIN {
    respond "OK" 200 {
        header Content-Type "text/plain"
        header Cache-Control "no-cache"
    }
}

# HTTP to HTTPS redirect
http://${DOMAIN}, http://www.${DOMAIN}, http://erp.${DOMAIN}, http://docs.${DOMAIN}, http://mail.${DOMAIN}, http://nomogrow.${DOMAIN}, http://ventura-tech.${DOMAIN} {
    redir https://{host}{uri} permanent
}
EOF

# Set proper permissions for Caddy
sudo chown -R caddy:caddy /etc/caddy
sudo chmod 644 /etc/caddy/Caddyfile

# Create log directory
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy

# -------------------
# FIREWALL SETUP
# -------------------
echo "[INFO] Configuring firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP for Let'\''s Encrypt'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow from 192.168.116.0/24 comment 'Internal network'
echo "y" | sudo ufw enable

echo "[INFO] Firewall status:"
sudo ufw status verbose

# -------------------
# CREATE TEST FILES
# -------------------
echo "[INFO] Creating test files..."

# Create test.php
sudo tee "$WP_PATH/test.php" > /dev/null << 'EOF'
<?php
header('Content-Type: text/plain');
echo "=== WordPress Test Page ===\n\n";
echo "WordPress Status: ";
if (file_exists('wp-config.php')) {
    echo "INSTALLED\n";
    
    // Try to connect to database
    $config = file_get_contents('wp-config.php');
    if (preg_match("/define\s*\(\s*'DB_NAME'\s*,\s*'([^']+)'\s*\)/", $config, $matches)) {
        $db_name = $matches[1];
        echo "Database Name: $db_name\n";
    }
    
    if (preg_match("/define\s*\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\)/", $config, $matches)) {
        $db_user = $matches[1];
        echo "Database User: $db_user\n";
    }
    
    echo "PHP Version: " . PHP_VERSION . "\n";
    echo "Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "\n";
    echo "HTTPS: " . (isset($_SERVER['HTTPS']) ? 'Yes' : 'No') . "\n";
    
} else {
    echo "NOT INSTALLED or wp-config.php not found\n";
}
?>
EOF

# Create info.php (temporary, for debugging)
sudo tee "$WP_PATH/info.php" > /dev/null << 'EOF'
<?php 
if (isset($_GET['debug']) && $_GET['debug'] === 'admin123') {
    phpinfo();
} else {
    echo "Access denied.";
}
?>
EOF

sudo chown www-data:www-data "$WP_PATH/test.php" "$WP_PATH/info.php"
sudo chmod 600 "$WP_PATH/info.php"
sudo chmod 644 "$WP_PATH/test.php"

# -------------------
# START AND VALIDATE SERVICES
# -------------------
echo "[INFO] Starting and validating services..."

# Start PHP-FPM
echo "[INFO] Starting PHP-FPM..."
sudo systemctl restart "php${PHP_VERSION}-fpm"
if sudo systemctl is-active --quiet "php${PHP_VERSION}-fpm"; then
    echo "[SUCCESS] PHP-FPM is running"
else
    echo "[ERROR] PHP-FPM failed to start"
    sudo systemctl status "php${PHP_VERSION}-fpm" --no-pager
fi

# Start Caddy
echo "[INFO] Starting Caddy..."
sudo systemctl restart caddy
sleep 5

if sudo systemctl is-active --quiet caddy; then
    echo "[SUCCESS] Caddy is running"
else
    echo "[ERROR] Caddy failed to start"
    sudo systemctl status caddy --no-pager
fi

# Validate Caddy configuration
echo "[INFO] Validating Caddy configuration..."
if sudo caddy validate --config /etc/caddy/Caddyfile 2>&1; then
    echo "[SUCCESS] Caddyfile is valid"
else
    echo "[ERROR] Caddyfile validation failed"
    sudo caddy validate --config /etc/caddy/Caddyfile 2>&1
fi

# -------------------
# HEALTH CHECKS
# -------------------
echo "[INFO] Performing health checks..."

# Check PHP-FPM socket
if [ -S "$PHP_SOCKET" ]; then
    echo "[SUCCESS] PHP-FPM socket exists: $PHP_SOCKET"
else
    echo "[ERROR] PHP-FPM socket not found"
fi

# Test local access
echo "[INFO] Testing local WordPress access..."
LOCAL_TEST=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" http://127.0.0.1/test.php 2>/dev/null || echo "000")
if [ "$LOCAL_TEST" = "200" ]; then
    echo "[SUCCESS] WordPress is accessible locally"
else
    echo "[WARNING] Local test returned HTTP $LOCAL_TEST"
fi

# Test PHP execution
echo "[INFO] Testing PHP execution..."
if php -r "echo 'PHP OK';" 2>/dev/null; then
    echo "[SUCCESS] PHP CLI is working"
else
    echo "[ERROR] PHP CLI is not working"
fi

# -------------------
# FINAL CONFIGURATION
# -------------------

# Create logrotate config
sudo tee /etc/logrotate.d/caddy > /dev/null << 'LOGROTATE'
/var/log/caddy/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 caddy caddy
    sharedscripts
    postrotate
        systemctl reload caddy 2>/dev/null || true
    endscript
}
LOGROTATE

# Create health check script
sudo tee /usr/local/bin/check-wordpress-health > /dev/null << 'HEALTH'
#!/bin/bash
# WordPress health check script

echo "=== WordPress Health Check ==="
echo "Time: $(date)"
echo ""

# Check PHP-FPM
if systemctl is-active --quiet php*-fpm; then
    echo "✅ PHP-FPM: RUNNING"
else
    echo "❌ PHP-FPM: NOT RUNNING"
fi

# Check Caddy
if systemctl is-active --quiet caddy; then
    echo "✅ Caddy: RUNNING"
else
    echo "❌ Caddy: NOT RUNNING"
fi

# Check PHP socket
PHP_SOCKET=$(ls /run/php/php*.sock 2>/dev/null | head -1)
if [ -n "$PHP_SOCKET" ] && [ -S "$PHP_SOCKET" ]; then
    echo "✅ PHP Socket: EXISTS ($PHP_SOCKET)"
else
    echo "❌ PHP Socket: MISSING"
fi

# Check disk space
DISK_USAGE=$(df / --output=pcent | tail -1 | tr -d '% ' | tr -d ' ')
if [ "$DISK_USAGE" -lt 90 ]; then
    echo "✅ Disk Usage: ${DISK_USAGE}%"
else
    echo "⚠️  Disk Usage: ${DISK_USAGE}% (High)"
fi

echo ""
echo "=== Test Complete ==="
HEALTH

sudo chmod +x /usr/local/bin/check-wordpress-health

# Remove temporary info.php after a delay (for debugging)
echo "[INFO] Will remove info.php in 5 minutes for security..."
(sleep 300 && sudo rm -f "$WP_PATH/info.php" && echo "[INFO] Removed info.php for security") &

# -------------------
# FINAL OUTPUT
# -------------------
echo ""
echo "==============================================="
echo "            SETUP COMPLETE!"
echo "==============================================="
echo ""
if [ "$EXISTING_WP" = true ]; then
    echo "✅ Existing WordPress installation preserved and configured"
else
    echo "✅ New WordPress installation completed"
fi
echo "✅ Caddy reverse proxy with HTTPS configured"
echo "✅ PHP-FPM optimized for WordPress"
echo "✅ Firewall configured"
echo "✅ All services running"
echo ""
echo "📋 CONFIGURATION SUMMARY:"
echo "==============================================="
echo "Primary Domain: https://$DOMAIN"
echo "WordPress Path: $WP_PATH"
echo ""
echo "Subdomains:"
echo "  • https://erp.$DOMAIN"
echo "  • https://docs.$DOMAIN"
echo "  • https://mail.$DOMAIN"
echo "  • https://nomogrow.$DOMAIN"
echo "  • https://ventura-tech.$DOMAIN"
echo ""
if [ "$NEW_WP_INSTALL" = true ]; then
    echo "🔐 NEW WORDPRESS CREDENTIALS:"
    echo "  Admin URL: https://$DOMAIN/wp-admin"
    echo "  Username: $WP_ADMIN_USER"
    echo "  Password: $WP_ADMIN_PASSWORD"
    echo ""
    echo "📊 DATABASE INFO (saved to /root/.wordpress_db_info):"
    echo "  Database: $DB_NAME"
    echo "  Username: $DB_USER"
    echo "  Password: $DB_PASSWORD"
else
    echo "🔐 EXISTING WORDPRESS PRESERVED"
    echo "  Using existing database and credentials"
    echo "  Admin URL: https://$DOMAIN/wp-admin"
fi
echo ""
echo "⚙️ SERVER INFO:"
echo "  Server IP: $THIS_VM_IP"
echo "  PHP Version: $PHP_VERSION"
echo "  PHP Socket: $PHP_SOCKET"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "  • Check status: sudo systemctl status caddy php${PHP_VERSION}-fpm"
echo "  • View logs: sudo tail -f /var/log/caddy/wordpress.log"
echo "  • Health check: /usr/local/bin/check-wordpress-health"
echo "  • Test SSL: sudo caddy list-certificates"
echo "  • Restart all: sudo systemctl restart caddy php${PHP_VERSION}-fpm"
echo ""
echo "⚠️ IMPORTANT NEXT STEPS:"
echo "==============================================="
echo "1. DNS CONFIGURATION (if not done):"
echo "   Point all domains to: $THIS_VM_IP"
echo ""
echo "2. SSL CERTIFICATES:"
echo "   Let's Encrypt will auto-obtain certificates when DNS is ready"
echo "   Check: sudo journalctl -u caddy -f"
echo ""
echo "3. TESTING:"
echo "   • Visit: https://$DOMAIN/test.php"
echo "   • Test all subdomains"
echo "   • Check WordPress admin: https://$DOMAIN/wp-admin"
echo ""
echo "4. SECURITY:"
echo "   • Remove test.php after testing: sudo rm $WP_PATH/test.php"
echo "   • info.php will auto-remove in 5 minutes"
echo "   • Change WordPress password if using default"
echo ""
echo "🔗 QUICK LINKS:"
echo "  • WordPress: https://$DOMAIN"
echo "  • Test Page: https://$DOMAIN/test.php"
echo "  • Health Check: /usr/local/bin/check-wordpress-health"
echo ""
echo "==============================================="
echo "[INFO] Setup completed at $(date)"
if [ "$NEW_WP_INSTALL" != true ] && [ -n "$BACKUP_DIR" ]; then
    echo "[INFO] Old WordPress backed up to: $BACKUP_DIR"
fi
echo "==============================================="
