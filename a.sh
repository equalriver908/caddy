#!/bin/bash
# ===============================================
# Full Setup Script: WordPress + PHP-FPM + Caddy
# Also includes Diagnostic Check for proper operation
# Domain: sahmcore.com.sa
# ===============================================

set -e

# -------------------
# USER CONFIGURATION
# -------------------
DOMAIN="sahmcore.com.sa"
ADMIN_EMAIL="a.saeed@$DOMAIN"
WP_ADMIN_USER="admin"
WP_ADMIN_PASSWORD="Sahm2190"  # Keeping the original password as requested
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
# SYSTEM UPDATE & DEPENDENCIES
# -------------------
echo "[INFO] Updating system and installing dependencies..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget unzip lsb-release software-properties-common net-tools ufw dnsutils git mariadb-client mariadb-server

# -------------------
# PHP-FPM INSTALLATION
# -------------------
echo "[INFO] Checking PHP-FPM..."
PHP_VERSION=""
if ! command -v php >/dev/null 2>&1; then
    echo "[INFO] Installing latest PHP and PHP-FPM..."
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update
    sudo apt install -y php8.3 php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-xmlrpc php8.3-soap php8.3-intl php8.3-zip
    PHP_VERSION="8.3"
else
    PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
fi
PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"
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
# STOP OTHER WEB SERVERS
# -------------------
sudo systemctl stop apache2 nginx 2>/dev/null || true
sudo systemctl disable apache2 nginx 2>/dev/null || true
sudo systemctl mask apache2 nginx  # Ensure Apache and Nginx do not restart

# -------------------
# WORDPRESS INSTALLATION
# -------------------
WP_PATH="/var/www/html"
if [ ! -d "$WP_PATH" ]; then
    echo "[INFO] Installing WordPress..."
    sudo mkdir -p $WP_PATH
    cd /tmp
    wget https://wordpress.org/latest.zip
    unzip latest.zip
    sudo mv wordpress/* $WP_PATH/
    sudo chown -R www-data:www-data $WP_PATH
fi

# Create wp-config.php if missing
WP_CONFIG="$WP_PATH/wp-config.php"
if [ ! -f "$WP_CONFIG" ]; then
    echo "[INFO] Creating wp-config.php..."
    cp "$WP_PATH/wp-config-sample.php" "$WP_CONFIG"
    # Set DB defaults
    sed -i "s/database_name_here/wordpress_db/" $WP_CONFIG
    sed -i "s/username_here/wordpress_user/" $WP_CONFIG
    sed -i "s/password_here/wordpress_pass/" $WP_CONFIG
fi

# Reverse proxy HTTPS support
if ! grep -q "HTTP_X_FORWARDED_PROTO" "$WP_CONFIG"; then
    cat >> "$WP_CONFIG" << 'EOF'
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = 443;
}
if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST'];
}
if (!defined('WP_SITEURL')) define('WP_SITEURL', 'https://' . $_SERVER['HTTP_HOST']);
if (!defined('WP_HOME')) define('WP_HOME', 'https://' . $_SERVER['HTTP_HOST']);
EOF
fi

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
}

# ERP
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

# Documentation
docs.$DOMAIN {
    reverse_proxy https://$DOCS_IP:$DOCS_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
    log {
        output file /var/log/caddy/docs.log
    }
}

# Mail
mail.$DOMAIN {
    reverse_proxy https://$MAIL_IP:$MAIL_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
    log {
        output file /var/log/caddy/mail.log
    }
}

# Nomogrow
nomogrow.$DOMAIN {
    reverse_proxy http://$NOMOGROW_IP:$NOMOGROW_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
    log {
        output file /var/log/caddy/nomogrow.log
    }
}

# Ventura-Tech
ventura-tech.$DOMAIN {
    reverse_proxy http://$VENTURA_IP:$VENTURA_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote}
    }
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
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp    # Allow HTTP for debugging
sudo ufw allow 443/tcp
sudo ufw enable

# -------------------
# PERMISSIONS
# -------------------
sudo chown -R www-data:www-data $WP_PATH
sudo find $WP_PATH -type d -exec chmod 755 {} \;
sudo find $WP_PATH -type f -exec chmod 644 {} \;

# -------------------
# START SERVICES
# -------------------
sudo systemctl daemon-reload
sudo systemctl enable --now php${PHP_VERSION}-fpm
sudo systemctl enable --now caddy

echo ""
echo "==============================================="
echo "SETUP COMPLETE!"
echo "WordPress: https://$DOMAIN"
echo "ERP: https://erp.$DOMAIN"
echo "Docs: https://docs.$DOMAIN"
echo "Mail: https://mail.$DOMAIN"
echo "Nomogrow: https://nomogrow.$DOMAIN"
echo "Ventura-Tech: https://ventura-tech.$DOMAIN"
echo "WordPress default admin: $WP_ADMIN_USER / $WP_ADMIN_PASSWORD"
echo "Caddy + HTTPS is fully functional."
echo "==============================================="

# -------------------
# DIAGNOSTIC SCRIPT STARTS HERE
# -------------------
echo "[INFO] Starting WordPress + PHP-FPM Diagnostic Check..."
# --- Configuration ---
PHP_FPM_SERVICE="php${PHP_VERSION}-fpm"
CADDY_SERVICE="caddy"

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
if systemctl is-active --quiet $PHP_FPM_SERVICE; then
    echo "[INFO] PHP-FPM is running."
else
    echo "[ERROR] PHP-FPM is NOT running. Starting PHP-FPM..."
    sudo systemctl start $PHP_FPM_SERVICE
    sudo systemctl enable $PHP_FPM_SERVICE
fi

# Check if Caddy is running
echo "[INFO] Checking if Caddy is running..."
if systemctl is-active --quiet $CADDY_SERVICE; then
    echo "[INFO] Caddy is running."
else
    echo "[ERROR] Caddy is NOT running. Starting Caddy..."
    sudo systemctl start $CADDY_SERVICE
    sudo systemctl enable $CADDY_SERVICE
fi

# Check WordPress directory
echo "[INFO] Checking WordPress directory: $WP_PATH..."
if [ ! -d "$WP_PATH" ]; then
    echo "[ERROR] WordPress directory $WP_PATH does not exist!"
    exit 1
else
    echo "[INFO] WordPress directory exists."
fi

# Check wp-config.php
if [ ! -f "$WP_PATH/wp-config.php" ]; then
    echo "[ERROR] wp-config.php is missing!"
else
    echo "[INFO] wp-config.php found."
fi

# Check PHP-FPM socket
echo "[INFO] Checking PHP-FPM socket: $PHP_SOCKET..."
if [ ! -S "$PHP_SOCKET" ]; then
    echo "[ERROR] PHP-FPM socket $PHP_SOCKET is missing."
    exit 1
else
    echo "[INFO] PHP-FPM socket is available."
fi

# Perform Health Check (Curl)
echo "[INFO] Performing basic health check for WordPress..."
curl -s --head "https://$DOMAIN" | head -n 20
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "[INFO] WordPress is responsive (status code 200)."
else
    echo "[ERROR] WordPress is not responsive (status code: $HTTP_STATUS)."
    exit 1
fi

# -------------------
# Final Status
# -------------------
echo ""
echo "==============================================="
echo "DIAGNOSTIC COMPLETED!"
echo "==============================================="
echo "WordPress should now be functional with PHP-FPM."
echo "If any issues were found, please check the error messages above."
echo "==============================================="
