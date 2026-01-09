#!/bin/bash
#
# pyIRCX SSL/TLS Certificate Setup Helper
# Automates certificate generation and configuration
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONFIG_FILE="${1:-/etc/pyircx/pyircx_config.json}"
DOMAIN=""
EMAIL=""
CONFIGURE_WEBCHAT_SSL=0
PYIRCX_WAS_RUNNING=0
CERT_FILE=""
KEY_FILE=""

# Function to configure HTTPS for webchat
configure_webchat_https() {
    local cert_file="$1"
    local key_file="$2"
    local domain="$3"

    echo ""
    echo -e "${BLUE}Configuring HTTPS for WebChat...${NC}"

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
    else
        OS_ID="unknown"
    fi

    # Install mod_ssl for Apache if needed
    if [ -d /etc/httpd ]; then
        # RHEL/Fedora/CentOS
        if ! rpm -q mod_ssl &>/dev/null; then
            echo -e "${YELLOW}Installing mod_ssl...${NC}"
            dnf install -y mod_ssl 2>/dev/null || yum install -y mod_ssl
        fi
        APACHE_SSL_CONF="/etc/httpd/conf.d/ssl-webchat.conf"
        APACHE_SERVICE="httpd"
    elif [ -d /etc/apache2 ]; then
        # Debian/Ubuntu
        if ! a2query -m ssl &>/dev/null; then
            echo -e "${YELLOW}Enabling mod_ssl...${NC}"
            a2enmod ssl
        fi
        APACHE_SSL_CONF="/etc/apache2/sites-available/ssl-webchat.conf"
        APACHE_SERVICE="apache2"
    else
        echo -e "${YELLOW}⚠ Apache not found, skipping HTTPS configuration${NC}"
        return 1
    fi

    # Create Apache SSL config
    echo -e "${YELLOW}Creating Apache SSL configuration...${NC}"
    cat > "$APACHE_SSL_CONF" <<SSLCONF
# pyIRCX WebChat HTTPS Configuration
<VirtualHost *:443>
    ServerName ${domain}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile ${cert_file}
    SSLCertificateKeyFile ${key_file}

    # Modern SSL configuration
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off

    # WebSocket proxy for secure WebSocket (wss://)
    ProxyPreserveHost On
    ProxyRequests Off

    # Proxy WebSocket connections to the gateway
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/ws$ ws://127.0.0.1:8765/ [P,L]

    ProxyPass /ws ws://127.0.0.1:8765/
    ProxyPassReverse /ws ws://127.0.0.1:8765/

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    ErrorLog logs/webchat-ssl-error.log
    CustomLog logs/webchat-ssl-access.log combined
</VirtualHost>
SSLCONF

    # Enable required Apache modules
    if [ -d /etc/httpd ]; then
        # Check and enable modules for RHEL/Fedora
        if ! httpd -M 2>/dev/null | grep -q proxy_wstunnel; then
            echo "LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so" >> /etc/httpd/conf.modules.d/00-proxy.conf 2>/dev/null || true
        fi
    elif [ -d /etc/apache2 ]; then
        # Enable modules for Debian/Ubuntu
        a2enmod proxy proxy_wstunnel rewrite 2>/dev/null || true
        a2ensite ssl-webchat 2>/dev/null || true
    fi

    # Configure SELinux to allow Apache to connect to backend WebSocket server
    if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
        echo -e "${YELLOW}Configuring SELinux for WebSocket proxy...${NC}"
        setsebool -P httpd_can_network_connect 1 2>/dev/null || true
        echo -e "${GREEN}✓ SELinux configured${NC}"
    fi

    # Update webchat HTML to use secure WebSocket when on HTTPS
    WEBCHAT_HTML="/opt/pyircx/webchat/index.html"
    if [ -f "$WEBCHAT_HTML" ]; then
        # Update WebSocket URL to auto-detect protocol
        if grep -q "ws://\${window.location.hostname}:8765" "$WEBCHAT_HTML"; then
            sed -i "s|ws://\${window.location.hostname}:8765|window.location.protocol === 'https:' ? 'wss://' + window.location.host + '/ws' : 'ws://' + window.location.hostname + ':8765'|g" "$WEBCHAT_HTML"
            echo -e "${GREEN}✓ WebChat updated to use secure WebSocket${NC}"
        fi
    fi

    # Restart Apache
    echo -e "${YELLOW}Restarting Apache...${NC}"
    systemctl restart "$APACHE_SERVICE"

    if systemctl is-active --quiet "$APACHE_SERVICE"; then
        echo -e "${GREEN}✓ Apache HTTPS configured successfully${NC}"
    else
        echo -e "${RED}Failed to restart Apache${NC}"
        echo "Check logs: journalctl -u $APACHE_SERVICE -n 50"
        return 1
    fi

    return 0
}

echo ""
echo "========================================"
echo "pyIRCX SSL/TLS Setup Helper"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0"
    exit 1
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
    exit 1
fi

# Display options
echo "Select SSL/TLS certificate option:"
echo ""
echo "  1) Let's Encrypt (recommended for production)"
echo "     - Free, trusted by all browsers/clients"
echo "     - Requires domain name and port 80 access"
echo "     - Auto-renewal included"
echo ""
echo "  2) Self-signed certificate (testing/internal use)"
echo "     - Generated immediately"
echo "     - NOT trusted by browsers (certificate warning)"
echo "     - Good for testing or internal networks"
echo ""
echo "  3) Use existing certificate"
echo "     - You already have certificate files"
echo "     - Just configure pyIRCX to use them"
echo ""
read -p "Choose option [1/2/3]: " -n 1 -r
echo
echo

case $REPLY in
    1)
        # Let's Encrypt
        echo -e "${BLUE}Let's Encrypt Certificate Setup${NC}"
        echo ""

        # Get domain name
        read -p "Enter your domain name (e.g., irc.example.com): " DOMAIN
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}Error: Domain name required${NC}"
            exit 1
        fi

        # Get email
        read -p "Enter your email address (for renewal notifications): " EMAIL
        if [ -z "$EMAIL" ]; then
            echo -e "${RED}Error: Email address required${NC}"
            exit 1
        fi

        # Check if certbot is installed
        if ! command -v certbot &> /dev/null; then
            echo -e "${YELLOW}Installing certbot...${NC}"

            # Detect OS for package installation
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                OS_ID=$ID
            else
                OS_ID="unknown"
            fi

            case "$OS_ID" in
                ubuntu|debian|linuxmint|pop|elementary|zorin|kali|parrot|raspbian)
                    apt update && apt install -y certbot
                    ;;
                fedora)
                    dnf install -y certbot
                    ;;
                centos|rhel|rocky|almalinux|oracle|scientific)
                    dnf install -y certbot || yum install -y certbot
                    ;;
                arch|manjaro|endeavouros|garuda|artix)
                    pacman -Sy --noconfirm certbot
                    ;;
                opensuse*|sles|tumbleweed)
                    zypper install -y certbot
                    ;;
                gentoo|funtoo)
                    emerge --ask=n app-crypt/certbot
                    ;;
                void)
                    xbps-install -Sy certbot
                    ;;
                alpine)
                    apk add --no-cache certbot
                    ;;
                *)
                    # Generic fallback
                    if command -v apt &> /dev/null; then
                        apt update && apt install -y certbot
                    elif command -v dnf &> /dev/null; then
                        dnf install -y certbot
                    elif command -v yum &> /dev/null; then
                        yum install -y certbot
                    elif command -v pacman &> /dev/null; then
                        pacman -Sy --noconfirm certbot
                    elif command -v zypper &> /dev/null; then
                        zypper install -y certbot
                    elif command -v apk &> /dev/null; then
                        apk add --no-cache certbot
                    elif command -v emerge &> /dev/null; then
                        emerge --ask=n app-crypt/certbot
                    else
                        echo -e "${RED}Could not install certbot automatically${NC}"
                        echo "Please install certbot manually and run this script again"
                        echo "Visit: https://certbot.eff.org/instructions"
                        exit 1
                    fi
                    ;;
            esac
        fi

        echo -e "${YELLOW}Obtaining certificate from Let's Encrypt...${NC}"
        echo "This requires port 80 to be open and the domain to point to this server"
        echo ""

        # Stop pyircx temporarily if running
        PYIRCX_WAS_RUNNING=0
        if systemctl is-active --quiet pyircx; then
            PYIRCX_WAS_RUNNING=1
            echo "Stopping pyircx temporarily..."
            systemctl stop pyircx
        fi

        # Get certificate
        if certbot certonly --standalone -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive; then
            echo -e "${GREEN}✓ Certificate obtained successfully!${NC}"

            CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

            # Ensure pyircx user can read certificates
            if id pyircx &>/dev/null; then
                # Create ssl-cert group if it doesn't exist (Debian/Ubuntu have it, others don't)
                if ! getent group ssl-cert &>/dev/null; then
                    groupadd ssl-cert
                    echo -e "${GREEN}Created ssl-cert group${NC}"
                fi
                usermod -a -G ssl-cert pyircx
                # Set group ownership and permissions on Let's Encrypt directories
                chgrp -R ssl-cert /etc/letsencrypt/live/$DOMAIN /etc/letsencrypt/archive/$DOMAIN
                chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
                chmod 750 /etc/letsencrypt/live/$DOMAIN /etc/letsencrypt/archive/$DOMAIN
                echo -e "${GREEN}Certificate permissions configured for pyircx user${NC}"
            fi

            # Set up auto-renewal
            if [ ! -f /etc/systemd/system/pyircx-certbot-renew.service ]; then
                cat > /etc/systemd/system/pyircx-certbot-renew.service <<EOF
[Unit]
Description=Renew Let's Encrypt certificates and reload pyIRCX
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet
ExecStartPost=/usr/bin/systemctl reload pyircx.service

[Install]
WantedBy=multi-user.target
EOF

                cat > /etc/systemd/system/pyircx-certbot-renew.timer <<EOF
[Unit]
Description=Daily renewal of Let's Encrypt certificates

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

                systemctl daemon-reload
                systemctl enable pyircx-certbot-renew.timer
                systemctl start pyircx-certbot-renew.timer

                echo -e "${GREEN}✓ Auto-renewal configured${NC}"
            fi

        else
            echo -e "${RED}Failed to obtain certificate${NC}"
            echo "Common issues:"
            echo "  - Port 80 is blocked by firewall"
            echo "  - Domain doesn't point to this server"
            echo "  - Another web server is using port 80"
            exit 1
        fi
        ;;

    2)
        # Self-signed certificate
        echo -e "${BLUE}Self-Signed Certificate Setup${NC}"
        echo ""

        read -p "Enter domain/hostname (e.g., irc.local): " DOMAIN
        DOMAIN=${DOMAIN:-irc.local}

        CERT_DIR="/etc/pyircx/ssl"
        mkdir -p "$CERT_DIR"

        CERT_FILE="$CERT_DIR/cert.pem"
        KEY_FILE="$CERT_DIR/key.pem"

        echo -e "${YELLOW}Generating self-signed certificate...${NC}"

        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 365 \
            -subj "/C=US/ST=State/L=City/O=pyIRCX/CN=$DOMAIN" \
            2>/dev/null

        chmod 600 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        chown pyircx:pyircx "$KEY_FILE" "$CERT_FILE" 2>/dev/null || true

        echo -e "${GREEN}✓ Self-signed certificate created${NC}"
        echo -e "${YELLOW}⚠ Warning: Clients will see certificate warnings${NC}"
        echo "  This is normal for self-signed certificates"
        ;;

    3)
        # Existing certificate
        echo -e "${BLUE}Use Existing Certificate${NC}"
        echo ""

        read -p "Enter path to certificate file: " CERT_FILE
        read -p "Enter path to private key file: " KEY_FILE

        if [ ! -f "$CERT_FILE" ]; then
            echo -e "${RED}Error: Certificate file not found: $CERT_FILE${NC}"
            exit 1
        fi

        if [ ! -f "$KEY_FILE" ]; then
            echo -e "${RED}Error: Key file not found: $KEY_FILE${NC}"
            exit 1
        fi

        echo -e "${GREEN}✓ Certificate files verified${NC}"
        ;;

    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

# Ask about webchat HTTPS
echo ""
read -p "Configure HTTPS for WebChat? [y/N]: " -n 1 -r WEBCHAT_REPLY
echo
if [[ $WEBCHAT_REPLY =~ ^[Yy]$ ]]; then
    CONFIGURE_WEBCHAT_SSL=1
fi

# Update configuration
echo ""
echo -e "${YELLOW}Updating pyIRCX configuration...${NC}"

# Backup config
cp "$CONFIG_FILE" "$CONFIG_FILE.backup"

# Update config using Python JSON manipulation
python3 - <<EOF
import json
import sys

config_file = "$CONFIG_FILE"

try:
    with open(config_file, 'r') as f:
        config = json.load(f)

    # Ensure ssl section exists
    if 'ssl' not in config:
        config['ssl'] = {}

    # Update SSL settings
    config['ssl']['enabled'] = True
    config['ssl']['cert_file'] = "$CERT_FILE"
    config['ssl']['key_file'] = "$KEY_FILE"
    config['ssl']['port'] = 6697
    config['ssl']['min_version'] = "TLSv1.2"

    # Write back
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)

    print("Configuration updated successfully")
except Exception as e:
    print(f"Error updating config: {e}", file=sys.stderr)
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Configuration updated${NC}"
else
    echo -e "${RED}Failed to update configuration${NC}"
    echo "Restoring backup..."
    mv "$CONFIG_FILE.backup" "$CONFIG_FILE"
    exit 1
fi

# Restart pyircx
echo ""
if [ $PYIRCX_WAS_RUNNING -eq 1 ] || systemctl is-enabled --quiet pyircx 2>/dev/null; then
    echo -e "${YELLOW}Restarting pyIRCX...${NC}"
    systemctl restart pyircx
    sleep 2

    if systemctl is-active --quiet pyircx; then
        echo -e "${GREEN}✓ pyIRCX restarted successfully${NC}"
    else
        echo -e "${RED}Failed to start pyIRCX${NC}"
        echo "Check logs: journalctl -u pyircx -n 50"
        exit 1
    fi
fi

# Configure webchat HTTPS if requested
if [ $CONFIGURE_WEBCHAT_SSL -eq 1 ]; then
    configure_webchat_https "$CERT_FILE" "$KEY_FILE" "$DOMAIN"
fi

# Summary
echo ""
echo "========================================"
echo -e "${GREEN}SSL/TLS Setup Complete!${NC}"
echo "========================================"
echo ""
echo "Certificate: $CERT_FILE"
echo "Private Key: $KEY_FILE"
echo ""
echo "SSL Port: 6697 (default)"
echo "Plain Port: 6667 (still active)"
echo ""
echo "Testing your SSL connection:"
echo "  openssl s_client -connect localhost:6697"
echo ""

if [ "$REPLY" == "1" ]; then
    echo "Certificate auto-renewal: ENABLED"
    echo "  Status: systemctl status pyircx-certbot-renew.timer"
    echo ""
fi

if [ $CONFIGURE_WEBCHAT_SSL -eq 1 ]; then
    echo "WebChat HTTPS: ENABLED"
    echo "  URL: https://$DOMAIN/chat.html"
    echo ""
fi

echo "Firewall configuration:"
echo "  firewall-cmd --add-port=6697/tcp --permanent  # IRC SSL port"
if [ $CONFIGURE_WEBCHAT_SSL -eq 1 ]; then
    echo "  firewall-cmd --add-port=443/tcp --permanent   # HTTPS port"
fi
echo "  firewall-cmd --reload"
echo ""

echo -e "${GREEN}Done!${NC}"
