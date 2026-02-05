#!/bin/bash
# ===============================================
# Migration Script: WordPress + PHP-FPM + Caddy
# Migrates WordPress from backup zip to Caddy with Let's Encrypt SSL
# ===============================================

set -e

# -------------------
# USER CONFIGURATION
# -------------------
DOMAIN="sahmcore.com.sa"
ADMIN_EMAIL="a.saeed@$DOMAIN"
WP_PATH="/var/www/html"          # The original WordPress path
BACKUP_DIR="/home/sahm"          # Backup location
ZIP_FILE="sahmcore.com.sa.zip"   # Website backup zip
DB_DUMP="3478617_wpress0f72a664.sql"  # Database backup
PHP_VERSION="8.3"
PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"
WP_CONFIG="$WP_PATH/wp-config.php"

# -------------------
# SYSTEM UPDATE & DEPENDENCIES
# -------------------
echo "[INFO] Updating system and installing dependencies..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget unzip lsb-release software-properties-common net-tools ufw dnsutils git mariadb-client mariadb-server

# -------------------
# PHP-FPM INSTALLATION
# -------------------
echo "[INFO] Checking PHP-FPM..."
if ! command -v php >/dev/null 2>&1; then
    echo "[INFO] Installing PHP-FPM..."
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update
    sudo apt install -y php8.3 php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-xmlrpc php8.3-soap php8.3-intl php8.3-zip
fi

echo "[INFO] Using PHP-FPM socket: $PHP_SOCKET"

# -------------------
# CADDY INSTALLATION
# -------------------
echo "[INFO] Installing Caddy..."
if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install -y caddy
fi

# -------------------
# STOP OTHER WEB SERVERS (Apache / Nginx)
# -------------------
echo "[INFO] Stopping Apache and Nginx to avoid conflicts..."
sudo systemctl stop apache2 nginx 2>/dev/null || true
sudo systemctl disable apache2 nginx 2>/dev/null || true
sudo systemctl mask apache2 nginx  # Ensure Apache and Nginx do not restart

# -------------------
# RESTORE WEBSITE FILES
# -------------------
echo "[INFO] Restoring website from backup..."

# Ensure the website directory exists
if [ ! -d "$WP_PATH" ]; then
    sudo mkdir -p $WP_PATH
fi

# Unzip the website backup to the target directory
sudo unzip -o $BACKUP_DIR/$ZIP_FILE -d $WP_PATH

# Ensure correct permissions for the WordPress files
sudo chown -R www-data:www-data $WP_PATH
sudo find $WP_PATH -type d -exec chmod 755 {} \;
sudo find $WP_PATH -type f -exec chmod 644 {} \;

# -------------------
# RESTORE DATABASE CREDENTIALS FROM wp-config.php
# -------------------
echo "[INFO] Extracting database credentials from wp-config.php..."
DB_NAME="3478617_wpress0f72a664"
DB_USER="3478617_wpress0f72a664"
DB_PASSWORD="I9hqHCqkg5IGhUKZQYqpvjbMx5peIBgh"
DB_HOST="localhost"  # Assuming the DB is on the same machine

echo "[INFO] Using the following database credentials:"
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo "Database Password: (hidden)"

# -------------------
# RESTORE DATABASE
# -------------------
echo "[INFO] Restoring database..."

# Set MYSQL_PWD to avoid interactive password prompt
export MYSQL_PWD=$DB_PASSWORD

# If necessary, create the database (ensure the database exists in MySQL)
sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"

# Import the database dump
sudo mysql -u root $DB_NAME < $BACKUP_DIR/$DB_DUMP

# -------------------
# VERIFY wp-config.php
# -------------------
echo "[INFO] Verifying wp-config.php..."
if [ ! -f "$WP_CONFIG" ]; then
    echo "[ERROR] wp-config.php is missing!"
    exit 1
fi

# Ensure wp-config.php points to the correct database
sed -i "s/database_name_here/$DB_NAME/" $WP_CONFIG
sed -i "s/username_here/$DB_USER/" $WP_CONFIG
sed -i "s/password_here/$DB_PASSWORD/" $WP_CONFIG
sed -i "s/localhost/$DB_HOST/" $WP_CONFIG

# Update site URL if necessary
sed -i "s|define('WP_HOME', 'http://localhost');|define('WP_HOME', 'https://$DOMAIN');|" $WP_CONFIG
sed -i "s|define('WP_SITEURL', 'http://localhost');|define('WP_SITEURL', 'https://$DOMAIN');|" $WP_CONFIG

# -------------------
# CREATE CADDYFILE
# -------------------
echo "[INFO] Creating Caddyfile..."
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
# WordPress site $DOMAIN, www.$DOMAIN
$DOMAIN, www.$DOMAIN {
    root * $WP_PATH
    php_fastcgi unix:$PHP_SOCKET
    file_server
    encode gzip zstd
    log {
        output file /var/log/caddy/wordpress.log
    }
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
    # Automatically get SSL certificates from Let's Encrypt
    tls $ADMIN_EMAIL
}

# ERP
erp.$DOMAIN {
    reverse_proxy http://$THIS_VM_IP:8069
    log {
        output file /var/log/caddy/erp.log
    }
}

# Documentation
docs.$DOMAIN {
    reverse_proxy https://$THIS_VM_IP:9443
    log {
        output file /var/log/caddy/docs.log
    }
}

# Mail
mail.$DOMAIN {
    reverse_proxy https://$THIS_VM_IP:444
    log {
        output file /var/log/caddy/mail.log
    }
}

# Nomogrow
nomogrow.$DOMAIN {
    reverse_proxy http://$THIS_VM_IP:8082
    log {
        output file /var/log/caddy/nomogrow.log
    }
}

# Ventura-Tech
ventura-tech.$DOMAIN {
    reverse_proxy http://$THIS_VM_IP:8080
    log {
        output file /var/log/caddy/ventura-tech.log
    }
}

# HTTP redirect to HTTPS (for debugging)
http://$DOMAIN, http://www.$DOMAIN, http://erp.$DOMAIN, http://docs.$DOMAIN, http://mail.$DOMAIN, http://nomogrow.$DOMAIN, http://ventura-tech.$DOMAIN {
    redir https://{host}{uri} permanent
}
EOF

# -------------------
# FIREWALL SETUP
# -------------------
echo "[INFO] Configuring firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp    # Allow HTTP for debugging
sudo ufw allow 443/tcp   # Allow HTTPS for Let's Encrypt
sudo ufw enable

# -------------------
# START SERVICES
# -------------------
echo "[INFO] Starting PHP-FPM and Caddy..."
sudo systemctl daemon-reload
sudo systemctl enable --now php${PHP_VERSION}-fpm
sudo systemctl enable --now caddy

# -------------------
# DIAGNOSTIC SCRIPT
# -------------------
echo "[INFO] Starting diagnostic check..."

# Check for Apache and Nginx conflicts
echo "[INFO] Checking if Apache or Nginx are running..."
if systemctl is-active --quiet apache2; then
    echo "[ERROR] Apache is running. Stopping and disabling..."
    sudo systemctl stop apache2
    sudo systemctl disable apache2
    sudo systemctl mask apache2
else
    echo "[INFO] Apache is not running."
fi
if systemctl is-active --quiet nginx; then
    echo "[ERROR] Nginx is running. Stopping and disabling..."
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    sudo systemctl mask nginx
else
    echo "[INFO] Nginx is not running."
fi

# Check if PHP-FPM is running
echo "[INFO] Checking if PHP-FPM is running..."
if systemctl is-active --quiet php${PHP_VERSION}-fpm; then
    echo "[INFO] PHP-FPM is running."
else
    echo "[ERROR] PHP-FPM is not running. Please check the installation."
    exit 1
fi

# -------------------
# FINAL STATUS
# -------------------
echo "[INFO] Migration script completed successfully!"
echo "Your WordPress site should be accessible at https://$DOMAIN now."
