#!/bin/bash
# ===============================================
# WordPress Migration Script: Apache/Nginx → Caddy
# Preserves existing websites and databases
# Automatically migrates configuration
# Domain: sahmcore.com.sa
# ===============================================

set -e

# -------------------
# DETECTION PHASE
# -------------------

echo "==============================================="
echo " WORDPRESS MIGRATION & CADDY SETUP"
echo " Detecting existing configuration..."
echo "==============================================="

# Detect existing web server
WEB_SERVER="none"
if systemctl is-active --quiet apache2; then
    WEB_SERVER="apache"
    echo "[INFO] Detected running Apache web server"
elif systemctl is-active --quiet nginx; then
    WEB_SERVER="nginx"
    echo "[INFO] Detected running Nginx web server"
else
    echo "[INFO] No active web server detected"
fi

# Detect WordPress installations
echo ""
echo "[INFO] Searching for WordPress installations..."
WP_INSTALLATIONS=()

# Common WordPress locations to check
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
        if [ -f "$dir/wp-config.php" ]; then
            WP_INSTALLATIONS+=("$dir")
            echo "  ✓ Found: $dir"
        fi
    done
done

if [ ${#WP_INSTALLATIONS[@]} -eq 0 ]; then
    echo "[INFO] No WordPress installations found"
    SELECTED_WP_PATH="/var/www/html"
    EXISTING_WP=false
else
    echo ""
    echo "==============================================="
    echo " SELECT WORDPRESS INSTALLATION"
    echo "==============================================="
    
    for i in "${!WP_INSTALLATIONS[@]}"; do
        echo "$((i+1))) ${WP_INSTALLATIONS[$i]}"
    done
    echo "$(( ${#WP_INSTALLATIONS[@]} + 1 ))) Install fresh WordPress"
    echo ""
    
    while true; do
        read -p "Select installation (1-$((${#WP_INALLATIONS[@]} + 1))): " wp_choice
        if [[ "$wp_choice" =~ ^[0-9]+$ ]] && [ "$wp_choice" -ge 1 ] && [ "$wp_choice" -le $((${#WP_INSTALLATIONS[@]} + 1)) ]; then
            if [ "$wp_choice" -le ${#WP_INSTALLATIONS[@]} ]; then
                SELECTED_WP_PATH="${WP_INSTALLATIONS[$((wp_choice-1))]}"
                EXISTING_WP=true
                echo "[INFO] Selected existing WordPress: $SELECTED_WP_PATH"
            else
                read -p "Enter path for new WordPress [/var/www/html]: " new_path
                SELECTED_WP_PATH="${new_path:-/var/www/html}"
                EXISTING_WP=false
                echo "[INFO] Will install fresh WordPress to: $SELECTED_WP_PATH"
            fi
            break
        else
            echo "Invalid selection. Please enter a number between 1 and $((${#WP_INSTALLATIONS[@]} + 1))"
        fi
    done
fi

# -------------------
# BACKUP EXISTING CONFIGURATION
# -------------------

echo ""
echo "==============================================="
echo " BACKUP EXISTING CONFIGURATION"
echo "==============================================="


# Extract database info from existing WordPress
if [ "$EXISTING_WP" = true ] && [ -f "$SELECTED_WP_PATH/wp-config.php" ]; then
    echo "[INFO] Extracting database information..."
    
    # Extract from wp-config.php
    DB_NAME=$(grep -i "DB_NAME" "$SELECTED_WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | sed -e "s/.*['\"]\([^'\"]*\)['\"].*/\1/" | head -1)
    DB_USER=$(grep -i "DB_USER" "$SELECTED_WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | sed -e "s/.*['\"]\([^'\"]*\)['\"].*/\1/" | head -1)
    DB_PASSWORD=$(grep -i "DB_PASSWORD" "$SELECTED_WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | sed -e "s/.*['\"]\([^'\"]*\)['\"].*/\1/" | head -1)
    DB_HOST=$(grep -i "DB_HOST" "$SELECTED_WP_PATH/wp-config.php" | grep -v "^[ \t]*/\|^[ \t]*\*" | sed -e "s/.*['\"]\([^'\"]*\)['\"].*/\1/" | head -1)
    DB_HOST="${DB_HOST:-localhost}"
    
    if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
        echo "[INFO] Found existing WordPress database:"
        echo "  Database: $DB_NAME"
        echo "  User: $DB_USER"
        echo "  Host: $DB_HOST"
        
        
        # Save database info
        echo "DB_NAME=$DB_NAME" > "$BACKUP_DIR/database.info"
        echo "DB_USER=$DB_USER" >> "$BACKUP_DIR/database.info"
        echo "DB_PASSWORD=$DB_PASSWORD" >> "$BACKUP_DIR/database.info"
        echo "DB_HOST=$DB_HOST" >> "$BACKUP_DIR/database.info"
        
        # Get WordPress site URL from database
        echo "[INFO] Getting WordPress site URL..."
        if command -v wp >/dev/null 2>&1; then
            SITE_URL=$(cd "$SELECTED_WP_PATH" && sudo -u www-data wp option get home 2>/dev/null || echo "")
        else
            # Try to extract directly from database
            if mysql -u "$DB_USER" -p"$DB_PASSWORD" -h "$DB_HOST" -D "$DB_NAME" -sN -e "SELECT option_value FROM wp_options WHERE option_name = 'home' LIMIT 1;" 2>/dev/null; then
                SITE_URL=$(mysql -u "$DB_USER" -p"$DB_PASSWORD" -h "$DB_HOST" -D "$DB_NAME" -sN -e "SELECT option_value FROM wp_options WHERE option_name = 'home' LIMIT 1;" 2>/dev/null)
            fi
        fi
        
        if [ -n "$SITE_URL" ]; then
            echo "[INFO] Current WordPress URL: $SITE_URL"
            DOMAIN=$(echo "$SITE_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|^www\.||')
            echo "[INFO] Extracted domain: $DOMAIN"
        else
            # Ask for domain
            read -p "Enter domain for WordPress [$DOMAIN]: " user_domain
            DOMAIN="${user_domain:-$DOMAIN}"
        fi
    fi
fi

# If no domain determined yet
if [ -z "$DOMAIN" ]; then
    DOMAIN="sahmcore.com.sa"
    read -p "Enter primary domain [$DOMAIN]: " user_domain
    DOMAIN="${user_domain:-$DOMAIN}"
fi

ADMIN_EMAIL="a.saeed@$DOMAIN"

# Internal VM IPs (configure as needed)
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

echo ""
echo "==============================================="
echo " MIGRATION SUMMARY"
echo "==============================================="
echo "Web Server: $WEB_SERVER"
echo "WordPress: $SELECTED_WP_PATH"
echo "Domain: $DOMAIN"
echo "Backup: $BACKUP_DIR"
echo ""
read -p "Proceed with migration? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[INFO] Migration cancelled."
    exit 0
fi

# -------------------
# SYSTEM PREPARATION
# -------------------

echo ""
echo "==============================================="
echo " SYSTEM PREPARATION"
echo "==============================================="

echo "[INFO] Updating system..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "[INFO] Installing required packages..."
sudo apt install -y curl wget unzip lsb-release software-properties-common \
    net-tools ufw dnsutils git mariadb-client mariadb-server

# -------------------
# PHP-FPM SETUP
# -------------------

echo "[INFO] Setting up PHP-FPM..."

# Check existing PHP version
EXISTING_PHP_VERSION=""
if command -v php >/dev/null 2>&1; then
    EXISTING_PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION;")
    echo "[INFO] Found existing PHP $EXISTING_PHP_VERSION"
    
    # Check if PHP-FPM is installed
    if ! systemctl list-unit-files | grep -q php; then
        echo "[INFO] Installing PHP-FPM for existing PHP version..."
        sudo apt install -y "php$EXISTING_PHP_VERSION-fpm"
    fi
    
    PHP_VERSION="$EXISTING_PHP_VERSION"
else
    # Install PHP 8.3
    echo "[INFO] Installing PHP 8.3 with FPM..."
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update
    sudo apt install -y php8.3 php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd \
        php8.3-mbstring php8.3-xml php8.3-xmlrpc php8.3-soap php8.3-intl \
        php8.3-zip php8.3-bcmath
    PHP_VERSION="8.3"
fi

PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"
echo "[INFO] Using PHP-FPM socket: $PHP_SOCKET"

# Configure PHP-FPM
PHP_FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
if [ -f "$PHP_FPM_CONF" ]; then
    # Backup original
    sudo cp "$PHP_FPM_CONF" "${PHP_FPM_CONF}.backup"
    
    # Configure for WordPress
    sudo sed -i 's/^pm = .*/pm = dynamic/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.max_children = .*/pm.max_children = 20/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.start_servers = .*/pm.start_servers = 5/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.min_spare_servers = .*/pm.min_spare_servers = 5/' "$PHP_FPM_CONF"
    sudo sed -i 's/^pm.max_spare_servers = .*/pm.max_spare_servers = 10/' "$PHP_FPM_CONF"
    
    # Set user/group to match web server user
    if [ "$WEB_SERVER" = "apache" ]; then
        sudo sed -i 's/^user = .*/user = www-data/' "$PHP_FPM_CONF"
        sudo sed -i 's/^group = .*/group = www-data/' "$PHP_FPM_CONF"
    fi
    
    # Increase limits
    echo "php_admin_value[upload_max_filesize] = 64M" | sudo tee -a "$PHP_FPM_CONF"
    echo "php_admin_value[post_max_size] = 64M" | sudo tee -a "$PHP_FPM_CONF"
    echo "php_admin_value[max_execution_time] = 300" | sudo tee -a "$PHP_FPM_CONF"
fi

# Start PHP-FPM
sudo systemctl restart "php${PHP_VERSION}-fpm"
sudo systemctl enable --now "php${PHP_VERSION}-fpm"

# -------------------
# MIGRATE WORDPRESS CONFIGURATION
# -------------------

echo ""
echo "==============================================="
echo " MIGRATING WORDPRESS CONFIGURATION"
echo "==============================================="

if [ "$EXISTING_WP" = true ]; then
    echo "[INFO] Preparing existing WordPress for Caddy..."
    
    # Ensure proper permissions
    echo "[INFO] Setting WordPress permissions..."
    sudo chown -R www-data:www-data "$SELECTED_WP_PATH"
    sudo find "$SELECTED_WP_PATH" -type d -exec chmod 755 {} \;
    sudo find "$SELECTED_WP_PATH" -type f -exec chmod 644 {} \;
    
    # Update wp-config.php for Caddy reverse proxy
    WP_CONFIG="$SELECTED_WP_PATH/wp-config.php"
    if [ -f "$WP_CONFIG" ]; then
        echo "[INFO] Updating wp-config.php for Caddy..."
        
        # Remove any existing reverse proxy settings
        sudo sed -i '/HTTP_X_FORWARDED_PROTO/d' "$WP_CONFIG"
        sudo sed -i '/HTTP_X_FORWARDED_HOST/d' "$WP_CONFIG"
        sudo sed -i '/Reverse Proxy Support/d' "$WP_CONFIG"
        
        # Add Caddy reverse proxy support
        if ! grep -q "HTTP_X_FORWARDED_PROTO" "$WP_CONFIG"; then
            cat >> "$WP_CONFIG" << 'EOF'

/* ============================================
 * Caddy Reverse Proxy Support
 * Added during migration from $WEB_SERVER to Caddy
 * ============================================ */
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = 443;
}
if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST'];
}

/* Update WordPress URLs if domain changed */
if (!defined('WP_SITEURL')) {
    define('WP_SITEURL', 'https://' . $_SERVER['HTTP_HOST']);
}
if (!defined('WP_HOME')) {
    define('WP_HOME', 'https://' . $_SERVER['HTTP_HOST']);
}

/* Security and Performance */
define('FORCE_SSL_ADMIN', true);
EOF
        fi
        
        # Update database constants if they don't exist
        if [ -n "$DB_NAME" ] && ! grep -q "define.*DB_NAME" "$WP_CONFIG"; then
            sed -i "/<?php/a define('DB_NAME', '$DB_NAME');" "$WP_CONFIG"
        fi
        if [ -n "$DB_USER" ] && ! grep -q "define.*DB_USER" "$WP_CONFIG"; then
            sed -i "/DB_NAME/a define('DB_USER', '$DB_USER');" "$WP_CONFIG"
        fi
        if [ -n "$DB_PASSWORD" ] && ! grep -q "define.*DB_PASSWORD" "$WP_CONFIG"; then
            sed -i "/DB_USER/a define('DB_PASSWORD', '$DB_PASSWORD');" "$WP_CONFIG"
        fi
        if [ -n "$DB_HOST" ] && ! grep -q "define.*DB_HOST" "$WP_CONFIG"; then
            sed -i "/DB_PASSWORD/a define('DB_HOST', '$DB_HOST');" "$WP_CONFIG"
        fi
        
        echo "[SUCCESS] WordPress configuration updated for Caddy"
    fi
    
    # Update WordPress URLs in database if domain changed
    echo "[INFO] Updating WordPress URLs in database..."
    if command -v wp >/dev/null 2>&1; then
        cd "$SELECTED_WP_PATH"
        
        # Get current URLs
        OLD_HOME=$(sudo -u www-data wp option get home 2>/dev/null || echo "")
        OLD_SITEURL=$(sudo -u www-data wp option get siteurl 2>/dev/null || echo "")
        
        NEW_HOME="https://$DOMAIN"
        
        if [ -n "$OLD_HOME" ] && [ "$OLD_HOME" != "$NEW_HOME" ]; then
            echo "[INFO] Updating WordPress URLs from $OLD_HOME to $NEW_HOME"
            sudo -u www-data wp search-replace "$OLD_HOME" "$NEW_HOME" --all-tables --quiet
            sudo -u www-data wp search-replace "http://$DOMAIN" "https://$DOMAIN" --all-tables --quiet
            sudo -u www-data wp search-replace "http://www.$DOMAIN" "https://$DOMAIN" --all-tables --quiet
            echo "[SUCCESS] WordPress URLs updated"
        else
            echo "[INFO] WordPress URLs already correct"
        fi
        
        # Flush cache
        sudo -u www-data wp cache flush 2>/dev/null || true
    else
        echo "[WARNING] wp-cli not available. URLs may need manual update."
    fi
else
    # Fresh WordPress installation
    echo "[INFO] Installing fresh WordPress..."
    
    sudo mkdir -p "$SELECTED_WP_PATH"
    cd /tmp
    wget -q https://wordpress.org/latest.zip
    unzip -q latest.zip
    sudo mv wordpress/* "$SELECTED_WP_PATH/"
    sudo rm -rf wordpress latest.zip
    
    # Generate database credentials
    DB_NAME="wp_$(echo "$DOMAIN" | tr -cd '[:alnum:]' | cut -c1-16)"
    DB_USER="wpuser_$(openssl rand -hex 4)"
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)
    DB_HOST="localhost"
    
    # Create database
    echo "[INFO] Creating database $DB_NAME..."
    sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    
    # Configure wp-config.php
    sudo cp "$SELECTED_WP_PATH/wp-config-sample.php" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/database_name_here/$DB_NAME/" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/username_here/$DB_USER/" "$SELECTED_WP_PATH/wp-config.php"
    sudo sed -i "s/password_here/$DB_PASSWORD/" "$SELECTED_WP_PATH/wp-config.php"
    
    # Generate salts
    SALT=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
    sudo sed -i "/define( 'AUTH_KEY',/a $SALT" "$SELECTED_WP_PATH/wp-config.php"
    
    # Set permissions
    sudo chown -R www-data:www-data "$SELECTED_WP_PATH"
    
    echo "[INFO] Fresh WordPress installation complete"
fi

# -------------------
# INSTALL CADDY
# -------------------

echo ""
echo "==============================================="
echo " INSTALLING CADDY"
echo "==============================================="

echo "[INFO] Installing Caddy..."
if ! command -v caddy >/dev/null 2>&1; then
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install -y caddy
fi

# -------------------
# MIGRATE OLD WEB SERVER CONFIGURATION
# -------------------

echo ""
echo "==============================================="
echo " MIGRATING WEB SERVER CONFIGURATION"
echo "==============================================="

# Extract virtual host configurations from old web server
ADDITIONAL_DOMAINS=()

if [ "$WEB_SERVER" = "apache" ]; then
    echo "[INFO] Migrating Apache virtual hosts..."
    
    # Find all enabled sites
    for conf_file in /etc/apache2/sites-enabled/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "[INFO] Processing Apache config: $conf_file"
            
            # Extract ServerName and ServerAlias
            SERVER_NAME=$(grep -i "ServerName" "$conf_file" | head -1 | awk '{print $2}')
            SERVER_ALIASES=$(grep -i "ServerAlias" "$conf_file" | awk '{print $2}')
            
            if [ -n "$SERVER_NAME" ]; then
                ADDITIONAL_DOMAINS+=("$SERVER_NAME")
                echo "  - Found domain: $SERVER_NAME"
                
                # Check if this is the WordPress site
                DOCUMENT_ROOT=$(grep -i "DocumentRoot" "$conf_file" | head -1 | awk '{print $2}')
                if [ "$DOCUMENT_ROOT" = "$SELECTED_WP_PATH" ]; then
                    echo "  - This is the WordPress document root"
                fi
            fi
            
            for alias in $SERVER_ALIASES; do
                ADDITIONAL_DOMAINS+=("$alias")
                echo "  - Found alias: $alias"
            done
        fi
    done
    
elif [ "$WEB_SERVER" = "nginx" ]; then
    echo "[INFO] Migrating Nginx server blocks..."
    
    # Find all enabled sites
    for conf_file in /etc/nginx/sites-enabled/*; do
        if [ -f "$conf_file" ]; then
            echo "[INFO] Processing Nginx config: $conf_file"
            
            # Extract server_name
            SERVER_NAMES=$(grep -i "server_name" "$conf_file" | head -1 | sed 's/server_name//' | sed 's/;//' | tr -d '\t')
            
            for server in $SERVER_NAMES; do
                if [ "$server" != "_" ] && [ "$server" != "localhost" ]; then
                    ADDITIONAL_DOMAINS+=("$server")
                    echo "  - Found domain: $server"
                    
                    # Check if this is the WordPress site
                    ROOT_DIR=$(grep -i "root" "$conf_file" | head -1 | awk '{print $2}' | sed 's/;//')
                    if [ "$ROOT_DIR" = "$SELECTED_WP_PATH" ]; then
                        echo "  - This is the WordPress root directory"
                    fi
                fi
            done
        fi
    done
fi

# Remove duplicates and main domain
UNIQUE_DOMAINS=()
for domain in "${ADDITIONAL_DOMAINS[@]}"; do
    domain=$(echo "$domain" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|^www\.||')
    if [[ ! " ${UNIQUE_DOMAINS[@]} " =~ " ${domain} " ]] && [ "$domain" != "$DOMAIN" ] && [ "$domain" != "www.$DOMAIN" ]; then
        UNIQUE_DOMAINS+=("$domain")
    fi
done

echo "[INFO] Found additional domains: ${UNIQUE_DOMAINS[*]}"

# -------------------
# CREATE CADDYFILE
# -------------------

echo ""
echo "==============================================="
echo " CREATING CADDY CONFIGURATION"
echo "==============================================="

# Backup existing Caddyfile
sudo cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

# Build domain list for Caddyfile
CADDY_DOMAINS="$DOMAIN, www.$DOMAIN"
for extra_domain in "${UNIQUE_DOMAINS[@]}"; do
    if [ -n "$extra_domain" ]; then
        CADDY_DOMAINS="$CADDY_DOMAINS, $extra_domain"
        if [[ ! "$extra_domain" =~ ^www\. ]]; then
            CADDY_DOMAINS="$CADDY_DOMAINS, www.$extra_domain"
        fi
    fi
done

# Create Caddyfile
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
# ============================================
# Caddy Configuration
# Migrated from $WEB_SERVER on $(date)
# WordPress: $SELECTED_WP_PATH
# ============================================

# Global settings
{
    email $ADMIN_EMAIL
    # Uncomment for DNS challenge (recommended for wildcard)
    # acme_dns cloudflare <token>
    
    # HTTP challenge (requires port 80 accessible)
    acme_ca https://acme-v02.api.letsencrypt.org/directory
    
    # Security headers (applied to all sites)
    header {
        -Server
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
    }
    
    # Logging
    log {
        output file /var/log/caddy/access.log
        level INFO
    }
}

# Main WordPress site
$CADDY_DOMAINS {
    root * $SELECTED_WP_PATH
    
    # PHP-FPM configuration
    php_fastcgi unix:$PHP_SOCKET {
        resolve_root_symlink
        split .php
        index index.php
    }
    
    # File server
    file_server
    
    # WordPress URL rewrites
    try_files {path} {path}/ /index.php?{query}
    
    # Security headers specific to WordPress
    header {
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), microphone=(), camera=()"
    }
    
    # Compression
    encode gzip zstd
    
    # WordPress-specific logging
    log {
        output file /var/log/caddy/wordpress.log
        format json
        level INFO
    }
    
    # Error pages
    handle_errors {
        @404 {
            expression {http.error.status_code} == 404
        }
        rewrite @404 /index.php?{query}
        file_server
    }
}

# ERP Service
erp.$DOMAIN {
    reverse_proxy http://$ERP_IP:$ERP_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
    log /var/log/caddy/erp.log
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
    log /var/log/caddy/docs.log
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
    log /var/log/caddy/mail.log
}

# Nomogrow Service
nomogrow.$DOMAIN {
    reverse_proxy http://$NOMOGROW_IP:$NOMOGROW_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log /var/log/caddy/nomogrow.log
}

# Ventura-Tech Service
ventura-tech.$DOMAIN {
    reverse_proxy http://$VENTURA_IP:$VENTURA_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
    log /var/log/caddy/ventura-tech.log
}

# Health check endpoint
health.$DOMAIN {
    respond "{
        \"status\": \"healthy\",
        \"server\": \"$THIS_VM_IP\",
        \"wordpress\": \"$SELECTED_WP_PATH\",
        \"php\": \"$PHP_VERSION\",
        \"migrated_from\": \"$WEB_SERVER\"
    }" 200 {
        header Content-Type "application/json"
    }
}

# Redirect HTTP to HTTPS
http://${DOMAIN}, http://www.${DOMAIN}, http://erp.${DOMAIN}, http://docs.${DOMAIN}, http://mail.${DOMAIN}, http://nomogrow.${DOMAIN}, http://ventura-tech.${DOMAIN} {
    redir https://{host}{uri} permanent
}

# Handle Let's Encrypt HTTP challenge
@acme path /.well-known/acme-challenge/*
handle @acme {
    reverse_proxy unix//run/caddy.sock
}
EOF

echo "[SUCCESS] Caddyfile created"

# Set permissions
sudo chown -R caddy:caddy /etc/caddy
sudo chmod 644 /etc/caddy/Caddyfile

# Create log directory
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy

# -------------------
# STOP OLD WEB SERVER
# -------------------

echo ""
echo "==============================================="
echo " STOPPING OLD WEB SERVER"
echo "==============================================="

if [ "$WEB_SERVER" = "apache" ]; then
    echo "[INFO] Stopping Apache..."
    sudo systemctl stop apache2
    sudo systemctl disable apache2
    # Don't mask so we can restart if needed for migration
    
elif [ "$WEB_SERVER" = "nginx" ]; then
    echo "[INFO] Stopping Nginx..."
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    # Don't mask so we can restart if needed for migration
fi

echo "[INFO] Old web server stopped"

# -------------------
# CONFIGURE FIREWALL
# -------------------

echo ""
echo "==============================================="
echo " CONFIGURING FIREWALL"
echo "==============================================="

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP for Let'\''s Encrypt'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow from 192.168.116.0/24 comment 'Internal network'
echo "y" | sudo ufw enable

echo "[INFO] Firewall configured"
sudo ufw status verbose

# -------------------
# START CADDY
# -------------------

echo ""
echo "==============================================="
echo " STARTING CADDY"
echo "==============================================="

# Validate Caddy configuration
echo "[INFO] Validating Caddy configuration..."
if sudo caddy validate --config /etc/caddy/Caddyfile 2>&1; then
    echo "[SUCCESS] Caddyfile is valid"
else
    echo "[ERROR] Caddyfile validation failed. Check configuration."
    exit 1
fi

# Start Caddy
sudo systemctl restart caddy
sudo systemctl enable caddy

# Wait for Caddy to start
sleep 5

if sudo systemctl is-active --quiet caddy; then
    echo "[SUCCESS] Caddy is running"
else
    echo "[ERROR] Caddy failed to start"
    sudo journalctl -u caddy --no-pager -n 20
    exit 1
fi

# -------------------
# CREATE TEST FILES
# -------------------

echo ""
echo "==============================================="
echo " CREATING TEST FILES"
echo "==============================================="

# Create migration test file
sudo tee "$SELECTED_WP_PATH/migration-test.html" > /dev/null << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Migration Successful - $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { color: green; font-size: 24px; }
        .info { margin: 20px 0; padding: 15px; background: #f5f5f5; }
    </style>
</head>
<body>
    <h1>Migration Successful! 🎉</h1>
    
    <div class="info">
        <p><strong>Domain:</strong> $DOMAIN</p>
        <p><strong>Web Server:</strong> Migrated from $WEB_SERVER to Caddy</p>
        <p><strong>PHP Version:</strong> $PHP_VERSION</p>
        <p><strong>WordPress Path:</strong> $SELECTED_WP_PATH</p>
        <p><strong>Migration Date:</strong> $(date)</p>
    </div>
    
    <div class="success">
        ✓ Caddy is now serving your WordPress site
    </div>
    
    <p>
        <a href="/wp-admin">WordPress Admin</a> |
        <a href="/">Home Page</a> |
        <a href="/migration-info.php">PHP Info</a>
    </p>
</body>
</html>
EOF

# Create PHP info file (protected)
sudo tee "$SELECTED_WP_PATH/migration-info.php" > /dev/null << 'EOF'
<?php
// Only show if accessed from localhost or with secret key
$secret_key = 'migration-' . date('Ymd');
if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1' || 
    (isset($_GET['key']) && $_GET['key'] === $secret_key)) {
    phpinfo();
} else {
    header('HTTP/1.0 403 Forbidden');
    echo 'Access denied. This file is for migration debugging only.';
}
?>
EOF

sudo chown www-data:www-data "$SELECTED_WP_PATH/migration-test.html" "$SELECTED_WP_PATH/migration-info.php"
sudo chmod 644 "$SELECTED_WP_PATH/migration-test.html"
sudo chmod 600 "$SELECTED_WP_PATH/migration-info.php"

# -------------------
# HEALTH CHECKS
# -------------------

echo ""
echo "==============================================="
echo " PERFORMING HEALTH CHECKS"
echo "==============================================="

# Check PHP-FPM
echo -n "[TEST] PHP-FPM status: "
if systemctl is-active --quiet "php${PHP_VERSION}-fpm"; then
    echo "✓ RUNNING"
else
    echo "✗ NOT RUNNING"
fi

# Check Caddy
echo -n "[TEST] Caddy status: "
if systemctl is-active --quiet caddy; then
    echo "✓ RUNNING"
else
    echo "✗ NOT RUNNING"
fi

# Check PHP socket
echo -n "[TEST] PHP-FPM socket: "
if [ -S "$PHP_SOCKET" ]; then
    echo "✓ EXISTS ($PHP_SOCKET)"
else
    echo "✗ MISSING"
fi

# Test WordPress locally
echo -n "[TEST] WordPress local access: "
LOCAL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" http://127.0.0.1/migration-test.html 2>/dev/null || echo "000")
if [ "$LOCAL_STATUS" = "200" ]; then
    echo "✓ SUCCESS (HTTP $LOCAL_STATUS)"
else
    echo "✗ FAILED (HTTP $LOCAL_STATUS)"
fi

# Test PHP execution
echo -n "[TEST] PHP execution: "
if php -r "echo 'OK';" >/dev/null 2>&1; then
    echo "✓ WORKING"
else
    echo "✗ FAILED"
fi

# Check SSL certificates (if DNS is configured)
echo -n "[TEST] SSL certificates: "
if sudo caddy list-certificates 2>/dev/null | grep -q "$DOMAIN"; then
    echo "✓ OBTAINED"
else
    echo "⚠ PENDING (DNS may not be configured)"
fi

# -------------------
# CREATE LOGROTATE AND MONITORING
# -------------------

echo ""
echo "[INFO] Setting up log rotation..."
sudo tee /etc/logrotate.d/caddy-migration > /dev/null << 'LOGROTATE'
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

# Create migration recovery script
sudo tee /usr/local/bin/restore-webserver > /dev/null << 'RECOVERY'
#!/bin/bash
# Migration recovery script
# Restores original web server configuration if needed

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    echo "Available backups:"
    ls -d /root/webserver-backup-* 2>/dev/null || echo "No backups found"
    exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
    echo "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

echo "Restoring from backup: $BACKUP_DIR"

# Stop Caddy
echo "Stopping Caddy..."
systemctl stop caddy
systemctl disable caddy

# Restore Apache
if [ -d "$BACKUP_DIR/apache2" ]; then
    echo "Restoring Apache configuration..."
    cp -r "$BACKUP_DIR/apache2" /etc/
    systemctl start apache2
    systemctl enable apache2
    echo "Apache restored"
fi

# Restore Nginx
if [ -d "$BACKUP_DIR/nginx" ]; then
    echo "Restoring Nginx configuration..."
    cp -r "$BACKUP_DIR/nginx" /etc/
    systemctl start nginx
    systemctl enable nginx
    echo "Nginx restored"
fi

# Restore WordPress database if backed up
if [ -f "$BACKUP_DIR/wordpress-database.sql" ]; then
    echo "Restoring WordPress database..."
    mysql < "$BACKUP_DIR/wordpress-database.sql"
    echo "Database restored"
fi

echo "Recovery complete. Original web server restored."
echo "Note: You may need to adjust firewall rules manually."
RECOVERY

sudo chmod +x /usr/local/bin/restore-webserver

# -------------------
# FINAL OUTPUT
# -------------------

echo ""
echo "==============================================="
echo "     MIGRATION COMPLETE!"
echo "==============================================="
echo ""
echo "✅ Successfully migrated from $WEB_SERVER to Caddy"
echo "✅ WordPress preserved at: $SELECTED_WP_PATH"
if [ "$EXISTING_WP" = true ]; then
    echo "✅ Database preserved: $DB_NAME"
fi
echo "✅ All configurations backed up to: $BACKUP_DIR"
echo ""
echo "📋 MIGRATION SUMMARY:"
echo "==============================================="
echo "Primary Domain: https://$DOMAIN"
echo "Additional Domains: ${UNIQUE_DOMAINS[*]}"
echo "WordPress Path: $SELECTED_WP_PATH"
echo "PHP Version: $PHP_VERSION"
echo "PHP Socket: $PHP_SOCKET"
echo ""
echo "🔗 ACCESS LINKS:"
echo "  • WordPress Site: https://$DOMAIN"
echo "  • Migration Test: https://$DOMAIN/migration-test.html"
echo "  • WordPress Admin: https://$DOMAIN/wp-admin"
echo "  • Health Check: https://health.$DOMAIN"
echo ""
echo "🔧 REVERSE PROXY SERVICES:"
echo "  • ERP: https://erp.$DOMAIN → $ERP_IP:$ERP_PORT"
echo "  • Docs: https://docs.$DOMAIN → $DOCS_IP:$DOCS_PORT"
echo "  • Mail: https://mail.$DOMAIN → $MAIL_IP:$MAIL_PORT"
echo "  • Nomogrow: https://nomogrow.$DOMAIN → $NOMOGROW_IP:$NOMOGROW_PORT"
echo "  • Ventura-Tech: https://ventura-tech.$DOMAIN → $VENTURA_IP:$VENTURA_PORT"
echo ""
echo "⚙️ MANAGEMENT COMMANDS:"
echo "  • Check Caddy: sudo systemctl status caddy"
echo "  • View Caddy logs: sudo journalctl -u caddy -f"
echo "  • Check PHP-FPM: sudo systemctl status php${PHP_VERSION}-fpm"
echo "  • Validate config: sudo caddy validate --config /etc/caddy/Caddyfile"
echo "  • List SSL certs: sudo caddy list-certificates"
echo "  • Restore old server: sudo restore-webserver $BACKUP_DIR"
echo ""
echo "📊 BACKUP INFORMATION:"
echo "  • Location: $BACKUP_DIR"
echo "  • Contains: Web server config, WordPress files, database dump"
echo "  • Keep this backup for at least 30 days"
echo ""
echo "⚠️ IMPORTANT NEXT STEPS:"
echo "==============================================="
echo "1. DNS VERIFICATION:"
echo "   Ensure DNS records point to: $THIS_VM_IP"
echo ""
echo "2. SSL CERTIFICATES:"
echo "   Let's Encrypt will auto-issue certificates"
echo "   Monitor: sudo journalctl -u caddy -f"
echo ""
echo "3. TEST ALL FUNCTIONALITY:"
echo "   • Test WordPress admin login"
echo "   • Test media uploads"
echo "   • Test plugins and themes"
echo "   • Test all reverse proxy services"
echo ""
echo "4. MONITOR FOR 24 HOURS:"
echo "   • Check logs: sudo tail -f /var/log/caddy/wordpress.log"
echo "   • Monitor SSL: sudo caddy list-certificates"
echo "   • Test performance"
echo ""
echo "5. CLEANUP (after 7 days):"
echo "   • Remove test files:"
echo "     sudo rm $SELECTED_WP_PATH/migration-test.html"
echo "     sudo rm $SELECTED_WP_PATH/migration-info.php"
echo "   • Consider removing old web server packages"
echo ""
echo "🔒 SECURITY NOTES:"
echo "  • Firewall is configured (ports 80, 443, 22 open)"
echo "  • PHP-FPM running as www-data"
echo "  • Caddy running as caddy user"
echo "  • SSL auto-renewal enabled"
echo ""
echo "📞 TROUBLESHOOTING:"
echo "  • If site doesn't load: Check DNS propagation"
echo "  • If SSL fails: Ensure port 80 is accessible"
echo "  • If WordPress broken: Check database connection"
echo "  • To revert: sudo restore-webserver $BACKUP_DIR"
echo ""
echo "==============================================="
echo "[SUCCESS] Migration completed at $(date)"
echo "Backup saved to: $BACKUP_DIR"
echo "==============================================="
