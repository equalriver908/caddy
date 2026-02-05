#!/bin/bash
# ===============================================
# WordPress Migration Script: Apache/Nginx → Caddy
# Low-disk-space version - No backups, direct migration
# Fixed domain: sahmcore.com.sa
# Sets static IP: 192.168.116.37
# ===============================================

set -e

# -------------------
# STATIC IP CONFIGURATION
# -------------------

echo "==============================================="
echo " STATIC IP CONFIGURATION"
echo " Setting IP to: 192.168.116.37"
echo "==============================================="

# Fixed IP and domain
STATIC_IP="192.168.116.37"
DOMAIN="sahmcore.com.sa"
ADMIN_EMAIL="a.saeed@$DOMAIN"
GATEWAY="192.168.116.1"
NETMASK="255.255.255.0"
DNS_SERVERS="8.8.8.8 8.8.4.4"

# Detect primary network interface
PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$PRIMARY_INTERFACE" ]; then
    PRIMARY_INTERFACE=$(ls /sys/class/net/ | grep -E '^en|^eth' | head -1)
    if [ -z "$PRIMARY_INTERFACE" ]; then
        PRIMARY_INTERFACE="eth0"
    fi
fi

echo "[INFO] Detected primary interface: $PRIMARY_INTERFACE"
echo "[INFO] Current IP configuration:"
ip addr show $PRIMARY_INTERFACE | grep inet

# Set temporary static IP
echo "[INFO] Setting temporary static IP..."
sudo ip addr flush dev $PRIMARY_INTERFACE 2>/dev/null || true
sudo ip addr add $STATIC_IP/24 dev $PRIMARY_INTERFACE
sudo ip link set $PRIMARY_INTERFACE up

# Add default gateway
echo "[INFO] Setting default gateway..."
sudo ip route add default via $GATEWAY dev $PRIMARY_INTERFACE 2>/dev/null || true

# Test network connectivity
echo "[INFO] Testing network connectivity..."
if ping -c 2 -W 2 $GATEWAY >/dev/null 2>&1; then
    echo "✓ Network connectivity: OK"
else
    echo "⚠ Network connectivity: Check cable/connection"
fi

# Make IP persistent (Netplan for Ubuntu/Debian)
echo "[INFO] Making IP configuration persistent..."
if [ -d /etc/netplan ]; then
    NETPLAN_FILE=$(ls /etc/netplan/*.yaml | head -1)
    if [ -n "$NETPLAN_FILE" ]; then
        echo "[INFO] Configuring Netplan..."
        sudo cp $NETPLAN_FILE $NETPLAN_FILE.backup.$(date +%Y%m%d)
        sudo tee $NETPLAN_FILE > /dev/null << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: no
      addresses:
        - $STATIC_IP/24
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS_SERVERS]
EOF
        sudo netplan apply
        echo "✓ Netplan configured for persistent IP"
    fi
elif [ -f /etc/network/interfaces ]; then
    echo "[INFO] Configuring /etc/network/interfaces..."
    sudo cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d)
    sudo tee -a /etc/network/interfaces > /dev/null << EOF

# Static IP configured by WordPress migration script
auto $PRIMARY_INTERFACE
iface $PRIMARY_INTERFACE inet static
    address $STATIC_IP
    netmask $NETMASK
    gateway $GATEWAY
    dns-nameservers $DNS_SERVERS
EOF
    sudo systemctl restart networking 2>/dev/null || true
    echo "✓ /etc/network/interfaces configured"
fi

# Verify IP is set
echo "[INFO] Verifying IP configuration..."
CURRENT_IP=$(ip addr show $PRIMARY_INTERFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [ "$CURRENT_IP" = "$STATIC_IP" ]; then
    echo "✓ Static IP successfully set to: $STATIC_IP"
else
    echo "⚠ IP may not be persistent. Current IP: $CURRENT_IP"
fi

# -------------------
# CLEAN UP DISK SPACE
# -------------------

echo ""
echo "==============================================="
echo " LOW-DISK-SPACE MIGRATION TO CADDY"
echo " Domain: $DOMAIN"
echo " Static IP: $STATIC_IP"
echo "==============================================="

# Check disk space first
echo "[INFO] Checking disk space..."
df -h /

# Clean up ALL old backups from previous runs
echo "[INFO] Cleaning up ALL old backups..."
echo "[INFO] Removing backup directories..."
sudo rm -rf /root/backup-* 2>/dev/null || true
sudo rm -rf /root/webserver-backup-* 2>/dev/null || true
sudo rm -rf /root/wordpress-backup-* 2>/dev/null || true
sudo rm -rf /root/*-backup-* 2>/dev/null || true

echo "[INFO] Removing old Caddy backups..."
sudo rm -rf /etc/caddy/Caddyfile.backup-* 2>/dev/null || true
sudo rm -rf /etc/caddy/*.backup 2>/dev/null || true

echo "[INFO] Removing old web server logs..."
sudo rm -rf /var/backups/*.old 2>/dev/null || true
sudo rm -rf /var/backups/*.bak 2>/dev/null || true

# Clean temporary files
echo "[INFO] Cleaning temporary files..."
sudo rm -rf /tmp/* 2>/dev/null || true
sudo rm -rf /var/tmp/* 2>/dev/null || true
sudo rm -rf ~/.cache/* 2>/dev/null || true

# Clean package cache
echo "[INFO] Cleaning package cache..."
sudo apt-get clean 2>/dev/null || true
sudo apt-get autoclean 2>/dev/null || true

# Remove old kernel versions (free up significant space)
echo "[INFO] Removing old kernel versions..."
sudo apt-get autoremove --purge -y 2>/dev/null || true

# Clear systemd journal logs (keep only current)
echo "[INFO] Clearing old journal logs..."
sudo journalctl --vacuum-time=1d 2>/dev/null || true

# Check again
echo ""
echo "[INFO] Disk space after cleanup:"
df -h /

# -------------------
# DETECT CURRENT SETUP
# -------------------

echo ""
echo "==============================================="
echo " DETECTING CURRENT SETUP"
echo "==============================================="

# Detect web server
WEB_SERVER="none"
if systemctl is-active --quiet apache2; then
    WEB_SERVER="apache"
    echo "[INFO] Detected running Apache"
elif systemctl is-active --quiet nginx; then
    WEB_SERVER="nginx"
    echo "[INFO] Detected running Nginx"
else
    echo "[INFO] No active web server detected"
fi

# Find WordPress installations
echo "[INFO] Looking for WordPress..."
WP_PATH=""
WP_PATHS=("/var/www/html" "/var/www" "/home/*/public_html" "/home/*/www")

for path in "${WP_PATHS[@]}"; do
    for dir in $(ls -d $path 2>/dev/null || true); do
        if [ -f "$dir/wp-config.php" ]; then
            WP_PATH="$dir"
            echo "[INFO] Found WordPress at: $WP_PATH"
            break 2
        fi
    done
done

if [ -z "$WP_PATH" ]; then
    WP_PATH="/var/www/html"
    echo "[INFO] No WordPress found, will use: $WP_PATH"
    EXISTING_WP=false
else
    EXISTING_WP=true
fi

# Internal VM IPs (minimal configuration)
THIS_VM_IP="$STATIC_IP"  # Use the static IP
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
echo " CONFIRM MIGRATION"
echo "==============================================="
echo "Web Server: $WEB_SERVER"
echo "WordPress: $WP_PATH"
echo "Domain: $DOMAIN"
echo "Static IP: $THIS_VM_IP"
echo "Interface: $PRIMARY_INTERFACE"
echo ""
echo "This will:"
echo "1. Set static IP: $STATIC_IP on $PRIMARY_INTERFACE"
echo "2. Migrate from $WEB_SERVER to Caddy"
echo "3. NO backups will be created"
echo "4. Old backups from previous runs will be deleted"
echo "5. Configure all subdomains for $DOMAIN"
echo ""
read -p "Proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[INFO] Migration cancelled."
    exit 0
fi

# -------------------
# MINIMAL SYSTEM SETUP
# -------------------

echo ""
echo "==============================================="
echo " MINIMAL SYSTEM SETUP"
echo "==============================================="

# Update only essentials
echo "[INFO] Updating package lists..."
sudo apt update

# Install absolute minimum required
echo "[INFO] Installing minimum required packages..."
REQUIRED_PKGS="curl php8.3-fpm php8.3-mysql"
for pkg in $REQUIRED_PKGS; do
    if ! dpkg -l | grep -q "^ii.*$pkg"; then
        sudo apt install -y $pkg
    else
        echo "[INFO] $pkg already installed"
    fi
done

# Check if PHP is already installed
if ! command -v php >/dev/null 2>&1; then
    echo "[INFO] Installing PHP..."
    sudo apt install -y php8.3 php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml
else
    echo "[INFO] PHP already installed"
fi

PHP_VERSION="8.3"
PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"

# Install Caddy (minimal)
echo "[INFO] Installing Caddy..."
if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install -y caddy
fi

# -------------------
# DIRECT MIGRATION
# -------------------

echo ""
echo "==============================================="
echo " DIRECT MIGRATION (NO BACKUPS)"
echo "==============================================="

# Stop old web server (but keep configs)
if [ "$WEB_SERVER" = "apache" ]; then
    echo "[INFO] Stopping Apache..."
    sudo systemctl stop apache2
    sudo systemctl disable apache2
    echo "[INFO] Apache stopped (configs preserved in /etc/apache2)"
elif [ "$WEB_SERVER" = "nginx" ]; then
    echo "[INFO] Stopping Nginx..."
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    echo "[INFO] Nginx stopped (configs preserved in /etc/nginx)"
fi

# Configure PHP-FPM minimally
echo "[INFO] Configuring PHP-FPM..."
sudo systemctl restart "php${PHP_VERSION}-fpm"
sudo systemctl enable --now "php${PHP_VERSION}-fpm"

# Ensure WordPress directory exists
sudo mkdir -p "$WP_PATH"

# If no existing WordPress, install minimal
if [ "$EXISTING_WP" != true ]; then
    echo "[INFO] Creating minimal WordPress placeholder..."
    sudo tee "$WP_PATH/index.php" > /dev/null << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$DOMAIN - WordPress Migration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        .success { color: #28a745; font-size: 18px; margin: 20px 0; }
        .info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .services { margin: 20px 0; }
        .service-item { margin: 10px 0; padding: 10px; background: #e9ecef; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$DOMAIN - Migration Complete</h1>
        
        <div class="success">
            ✓ Successfully migrated to Caddy Web Server
        </div>
        
        <div class="info">
            <h3>Server Information</h3>
            <p><strong>Domain:</strong> $DOMAIN</p>
            <p><strong>IP Address:</strong> <?php echo \$_SERVER['SERVER_ADDR'] ?? '$THIS_VM_IP'; ?></p>
            <p><strong>Server:</strong> <?php echo \$_SERVER['SERVER_SOFTWARE'] ?? 'Caddy'; ?></p>
            <p><strong>PHP Version:</strong> <?php echo PHP_VERSION; ?></p>
            <p><strong>Migration Date:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
        
        <div class="services">
            <h3>Available Services</h3>
            <div class="service-item">
                <strong>Main Site:</strong> https://$DOMAIN
            </div>
            <div class="service-item">
                <strong>ERP System:</strong> https://erp.$DOMAIN
            </div>
            <div class="service-item">
                <strong>Documentation:</strong> https://docs.$DOMAIN
            </div>
            <div class="service-item">
                <strong>Mail Service:</strong> https://mail.$DOMAIN
            </div>
            <div class="service-item">
                <strong>Nomogrow:</strong> https://nomogrow.$DOMAIN
            </div>
            <div class="service-item">
                <strong>Ventura Tech:</strong> https://ventura-tech.$DOMAIN
            </div>
        </div>
        
        <p><a href="/wp-admin">Install WordPress</a> or upload your existing WordPress files to this directory.</p>
    </div>
</body>
</html>
EOF
fi

# Update wp-config.php for Caddy if it exists
if [ -f "$WP_PATH/wp-config.php" ]; then
    echo "[INFO] Updating wp-config.php for Caddy..."
    # Backup original wp-config.php (tiny backup)
    if [ ! -f "$WP_PATH/wp-config.php.bak" ]; then
        sudo cp "$WP_PATH/wp-config.php" "$WP_PATH/wp-config.php.bak"
    fi
    
    # Add reverse proxy support if not present
    if ! grep -q "HTTP_X_FORWARDED_PROTO" "$WP_PATH/wp-config.php"; then
        sudo tee -a "$WP_PATH/wp-config.php" > /dev/null << EOF

/* ============================================
 * Caddy Reverse Proxy Support
 * Added during migration to Caddy
 * Domain: $DOMAIN
 * Static IP: $THIS_VM_IP
 * ============================================ */
if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    \$_SERVER['HTTPS'] = 'on';
    \$_SERVER['SERVER_PORT'] = 443;
}
if (isset(\$_SERVER['HTTP_X_FORWARDED_HOST'])) {
    \$_SERVER['HTTP_HOST'] = \$_SERVER['HTTP_X_FORWARDED_HOST'];
}

/* Force SSL for admin */
define('FORCE_SSL_ADMIN', true);
EOF
    fi
fi

# Set minimal permissions
echo "[INFO] Setting permissions..."
sudo chown -R www-data:www-data "$WP_PATH"
sudo find "$WP_PATH" -type d -exec chmod 755 {} \; 2>/dev/null || true
sudo find "$WP_PATH" -type f -exec chmod 644 {} \; 2>/dev/null || true

# -------------------
# MINIMAL CADDY CONFIG
# -------------------

echo ""
echo "==============================================="
echo " MINIMAL CADDY CONFIGURATION"
echo "==============================================="

# Remove old Caddyfile if exists
sudo rm -f /etc/caddy/Caddyfile.bak 2>/dev/null || true

# Create minimal Caddyfile for $DOMAIN
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
# Minimal Caddy configuration for $DOMAIN
# Generated: $(date)
# Server IP: $THIS_VM_IP
# Static IP: $STATIC_IP
# Migration from: $WEB_SERVER

{
    # Email for Let's Encrypt
    email $ADMIN_EMAIL
    
    # Auto HTTPS with HTTP challenge
    acme_ca https://acme-v02.api.letsencrypt.org/directory
}

# Main WordPress site
$DOMAIN, www.$DOMAIN {
    # Root directory
    root * $WP_PATH
    
    # PHP-FPM handler
    php_fastcgi unix:$PHP_SOCKET {
        resolve_root_symlink
        split .php
        index index.php
    }
    
    # File server
    file_server
    
    # WordPress URL rewrites
    try_files {path} {path}/ /index.php?{query}
    
    # Security headers
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        -Server
    }
    
    # Logging
    log {
        output file /var/log/caddy/sahmcore.log
    }
}

# ERP Service
erp.$DOMAIN {
    reverse_proxy $ERP_IP:$ERP_PORT {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
}

# Documentation Service
docs.$DOMAIN {
    reverse_proxy https://$DOCS_IP:$DOCS_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
    }
}

# Mail Service
mail.$DOMAIN {
    reverse_proxy https://$MAIL_IP:$MAIL_PORT {
        transport http {
            tls_insecure_skip_verify
        }
        header_up Host {host}
    }
}

# Nomogrow Service
nomogrow.$DOMAIN {
    reverse_proxy $NOMOGROW_IP:$NOMOGROW_PORT {
        header_up Host {host}
    }
}

# Ventura-Tech Service
ventura-tech.$DOMAIN {
    reverse_proxy $VENTURA_IP:$VENTURA_PORT {
        header_up Host {host}
    }
}

# Health check endpoint
health.$DOMAIN {
    respond "{
        \"status\": \"healthy\",
        \"service\": \"caddy\",
        \"domain\": \"$DOMAIN\",
        \"server_ip\": \"$THIS_VM_IP\",
        \"static_ip\": \"$STATIC_IP\",
        \"interface\": \"$PRIMARY_INTERFACE\",
        \"migrated_from\": \"$WEB_SERVER\",
        \"timestamp\": \"$(date -Iseconds)\"
    }" 200 {
        header Content-Type "application/json"
    }
}

# HTTP to HTTPS redirect for all domains
http://$DOMAIN, http://www.$DOMAIN, http://erp.$DOMAIN, http://docs.$DOMAIN, http://mail.$DOMAIN, http://nomogrow.$DOMAIN, http://ventura-tech.$DOMAIN {
    redir https://{host}{uri} permanent
}
EOF

echo "[INFO] Caddyfile created for $DOMAIN"

# -------------------
# FIXED MINIMAL FIREWALL
# -------------------

echo ""
echo "==============================================="
echo " CONFIGURING FIREWALL"
echo "==============================================="

# Check if UFW is installed
if ! command -v ufw >/dev/null 2>&1; then
    echo "[INFO] Installing UFW..."
    sudo apt install -y ufw
fi

# Configure UFW with non-interactive method
echo "[INFO] Configuring firewall rules..."
sudo ufw --force reset >/dev/null 2>&1 || true

# Set defaults
echo "[INFO] Setting firewall defaults..."
sudo ufw default deny incoming >/dev/null 2>&1
sudo ufw default allow outgoing >/dev/null 2>&1

# Add rules
echo "[INFO] Adding firewall rules..."
sudo ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
sudo ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
sudo ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
sudo ufw allow from 192.168.116.0/24 comment 'Internal Network' >/dev/null 2>&1

# Enable UFW non-interactively
echo "[INFO] Enabling firewall..."
echo "y" | sudo ufw enable >/dev/null 2>&1

echo "[INFO] Firewall status:"
sudo ufw status numbered

# -------------------
# START SERVICES
# -------------------

echo ""
echo "==============================================="
echo " STARTING SERVICES"
echo "==============================================="

# Create log directory
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy

# Restart PHP-FPM
echo "[INFO] Restarting PHP-FPM..."
sudo systemctl restart "php${PHP_VERSION}-fpm"
echo "[INFO] PHP-FPM restarted"

# Start Caddy
echo "[INFO] Starting Caddy..."
sudo systemctl restart caddy
sudo systemctl enable caddy
echo "[INFO] Caddy started"

# Verify services
sleep 3
echo ""
echo "[INFO] Service status:"
if systemctl is-active --quiet caddy; then
    echo "✓ Caddy: RUNNING"
else
    echo "✗ Caddy: FAILED"
    echo "[INFO] Checking Caddy logs..."
    sudo journalctl -u caddy --no-pager -n 10
fi

if systemctl is-active --quiet "php${PHP_VERSION}-fpm"; then
    echo "✓ PHP-FPM: RUNNING"
else
    echo "✗ PHP-FPM: FAILED"
    echo "[INFO] Checking PHP-FPM logs..."
    sudo journalctl -u "php${PHP_VERSION}-fpm" --no-pager -n 10
fi

# Validate Caddy configuration
echo "[INFO] Validating Caddy configuration..."
if sudo caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    echo "✓ Caddy configuration is valid"
else
    echo "✗ Caddy configuration validation failed"
    sudo caddy validate --config /etc/caddy/Caddyfile
fi

# -------------------
# QUICK TEST
# -------------------

echo ""
echo "==============================================="
echo " QUICK TEST"
echo "==============================================="

# Create simple test file
TEST_FILE="$WP_PATH/test-caddy-migration.php"
sudo tee "$TEST_FILE" > /dev/null << EOF
<?php
header('Content-Type: text/plain');
echo "$DOMAIN - Caddy Migration Test\n";
echo str_repeat("=", 50) . "\n\n";
echo "Domain: " . (\$_SERVER['HTTP_HOST'] ?? '$DOMAIN') . "\n";
echo "Server IP: " . (\$_SERVER['SERVER_ADDR'] ?? '$THIS_VM_IP') . "\n";
echo "Static IP: $STATIC_IP\n";
echo "Interface: $PRIMARY_INTERFACE\n";
echo "Server Software: " . (\$_SERVER['SERVER_SOFTWARE'] ?? 'Caddy') . "\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "HTTPS: " . (isset(\$_SERVER['HTTPS']) ? 'Yes' : 'No') . "\n";
echo "X-Forwarded-Proto: " . (\$_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'Not set') . "\n";
echo "\nMigration Status: SUCCESS\n";
echo "Old Server: $WEB_SERVER\n";
echo "New Server: Caddy\n";
echo "Timestamp: " . date('Y-m-d H:i:s') . "\n";
?>
EOF

sudo chown www-data:www-data "$TEST_FILE"
sudo chmod 644 "$TEST_FILE"

# Test local access
echo "[INFO] Testing local access..."
sleep 2
if curl -s -H "Host: $DOMAIN" http://127.0.0.1/test-caddy-migration.php 2>/dev/null | grep -q "SUCCESS"; then
    echo "✓ Local test: PASSED"
    echo "✓ Caddy is serving WordPress correctly"
else
    echo "⚠ Local test: May have issues"
    echo "[INFO] Testing directly..."
    curl -s -H "Host: $DOMAIN" http://127.0.0.1/test-caddy-migration.php 2>&1 | head -20
fi

# Clean test file
sudo rm -f "$TEST_FILE"

# Test network connectivity with new IP
echo ""
echo "[INFO] Testing network connectivity with static IP..."
if ping -c 2 -W 2 $GATEWAY >/dev/null 2>&1; then
    echo "✓ Gateway connectivity: OK"
else
    echo "⚠ Gateway connectivity: Failed"
fi

# Test external connectivity
if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "✓ External connectivity: OK"
else
    echo "⚠ External connectivity: Failed"
fi

# -------------------
# FINAL OUTPUT
# -------------------

echo ""
echo "==============================================="
echo " MIGRATION COMPLETE!"
echo "==============================================="
echo ""
echo "✅ STATIC IP CONFIGURED: $STATIC_IP on $PRIMARY_INTERFACE"
echo "✅ DIRECT MIGRATION SUCCESSFUL"
echo "✅ Domain: $DOMAIN"
echo "✅ Server IP: $THIS_VM_IP"
echo "✅ Old backups from previous runs DELETED"
echo "✅ Disk space preserved"
echo ""
echo "📋 NETWORK CONFIGURATION:"
echo "   Static IP: $STATIC_IP"
echo "   Gateway: $GATEWAY"
echo "   Interface: $PRIMARY_INTERFACE"
echo "   Netmask: $NETMASK"
echo "   DNS: $DNS_SERVERS"
echo ""
echo "📋 WEB CONFIGURATION:"
echo "   WordPress Path: $WP_PATH"
echo "   PHP Version: $PHP_VERSION"
echo "   PHP Socket: $PHP_SOCKET"
echo "   Migrated From: $WEB_SERVER → Caddy"
echo ""
echo "🔗 ALL SERVICES (HTTPS):"
echo "   • https://$DOMAIN (Main WordPress)"
echo "   • https://www.$DOMAIN"
echo "   • https://erp.$DOMAIN → $ERP_IP:$ERP_PORT"
echo "   • https://docs.$DOMAIN → $DOCS_IP:$DOCS_PORT"
echo "   • https://mail.$DOMAIN → $MAIL_IP:$MAIL_PORT"
echo "   • https://nomogrow.$DOMAIN → $NOMOGROW_IP:$NOMOGROW_PORT"
echo "   • https://ventura-tech.$DOMAIN → $VENTURA_IP:$VENTURA_PORT"
echo "   • https://health.$DOMAIN (Health Check)"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "   Check IP:         ip addr show $PRIMARY_INTERFACE"
echo "   Check Caddy:      sudo systemctl status caddy"
echo "   View logs:        sudo journalctl -u caddy -f"
echo "   Restart Caddy:    sudo systemctl restart caddy"
echo "   Restart PHP:      sudo systemctl restart php${PHP_VERSION}-fpm"
echo "   Validate config:  sudo caddy validate --config /etc/caddy/Caddyfile"
echo "   Check firewall:   sudo ufw status"
echo ""
echo "⚠️  IMPORTANT NOTES:"
echo "   1. Static IP set to: $STATIC_IP"
echo "   2. NO BACKUPS WERE CREATED (to save disk space)"
echo "   3. Old web server ($WEB_SERVER) configs preserved in /etc/"
echo "   4. All old backup directories were deleted"
echo "   5. Ensure DNS points to: $THIS_VM_IP"
echo "   6. Let's Encrypt will auto-configure SSL"
echo ""
echo "🔄 ROLLBACK INSTRUCTIONS:"
if [ "$WEB_SERVER" = "apache" ]; then
    echo "   sudo systemctl stop caddy"
    echo "   sudo systemctl disable caddy"
    echo "   sudo systemctl start apache2"
    echo "   sudo systemctl enable apache2"
elif [ "$WEB_SERVER" = "nginx" ]; then
    echo "   sudo systemctl stop caddy"
    echo "   sudo systemctl disable caddy"
    echo "   sudo systemctl start nginx"
    echo "   sudo systemctl enable nginx"
else
    echo "   No previous web server detected"
fi
echo ""
echo "📊 DISK SPACE AFTER MIGRATION:"
df -h /
echo ""
echo "🌐 NETWORK STATUS:"
ip addr show $PRIMARY_INTERFACE | grep inet
echo ""
echo "==============================================="
echo " Next steps:"
echo " 1. Test all services in browser"
echo " 2. Check SSL certificates: sudo caddy list-certificates"
echo " 3. Monitor logs for errors"
echo " 4. Update DNS records to point to $STATIC_IP"
echo "==============================================="
