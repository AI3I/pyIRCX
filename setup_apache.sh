#!/bin/bash
#
# pyIRCX Apache/httpd Setup Script
#
# Automatically configures Apache/httpd for WebChat and WebAdmin
# Supports all distributions from install.sh
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WEBCHAT_DIR="/var/www/html/webchat"
WEBADMIN_DIR="/var/www/html/webadmin"
PYIRCX_DIR="/opt/pyircx"

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS="unknown"
    fi
    echo "$OS"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Try: sudo $0"
        exit 1
    fi
}

# Detect Apache service name
detect_apache_service() {
    if systemctl list-unit-files | grep -q "^httpd.service"; then
        echo "httpd"
    elif systemctl list-unit-files | grep -q "^apache2.service"; then
        echo "apache2"
    else
        # Try to guess based on OS
        local os=$(detect_os)
        case "$os" in
            ubuntu|debian|linuxmint|pop|elementary|zorin|kali|parrot|raspbian|opensuse*|sles|tumbleweed)
                echo "apache2"
                ;;
            *)
                echo "httpd"
                ;;
        esac
    fi
}

# Detect Apache config directory
detect_apache_config_dir() {
    local service=$(detect_apache_service)
    if [ "$service" = "apache2" ]; then
        echo "/etc/apache2"
    else
        echo "/etc/httpd"
    fi
}

# Install Apache and PHP
install_apache_php() {
    local os=$(detect_os)
    echo -e "${YELLOW}Installing Apache and PHP for $os...${NC}"

    case "$os" in
        # Debian/Ubuntu family
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|parrot|raspbian)
            apt-get update
            apt-get install -y apache2 php libapache2-mod-php php-fpm php-json php-mbstring php-cli

            # Enable required modules
            a2enmod rewrite
            a2enmod proxy
            a2enmod proxy_http
            a2enmod proxy_wstunnel
            a2enmod headers
            a2enmod ssl

            systemctl enable apache2
            ;;

        # RHEL/CentOS/Fedora family
        fedora)
            dnf install -y httpd php php-fpm php-json php-mbstring mod_ssl
            systemctl enable httpd
            systemctl enable php-fpm
            ;;

        centos|rhel|rocky|almalinux|oracle|scientific)
            # Detect package manager (yum vs dnf)
            if command -v dnf &> /dev/null; then
                dnf install -y httpd php php-fpm php-json php-mbstring mod_ssl
            else
                yum install -y httpd php php-fpm php-json php-mbstring mod_ssl
            fi
            systemctl enable httpd
            systemctl enable php-fpm
            ;;

        # Arch Linux family
        arch|manjaro|endeavouros|garuda|artix)
            pacman -Sy --noconfirm apache php php-fpm php-apache

            # Enable PHP module in httpd.conf
            if ! grep -q "LoadModule php_module" /etc/httpd/conf/httpd.conf; then
                echo "LoadModule php_module modules/libphp.so" >> /etc/httpd/conf/httpd.conf
                echo "AddHandler php-script .php" >> /etc/httpd/conf/httpd.conf
                echo "Include conf/extra/php_module.conf" >> /etc/httpd/conf/httpd.conf
            fi

            systemctl enable httpd
            systemctl enable php-fpm
            ;;

        # openSUSE family
        opensuse*|sles|tumbleweed)
            zypper install -y apache2 apache2-mod_php8 php8 php8-fpm php8-json php8-mbstring apache2-mod_ssl

            # Enable required modules
            a2enmod rewrite
            a2enmod proxy
            a2enmod proxy_http
            a2enmod proxy_wstunnel
            a2enmod headers
            a2enmod ssl
            a2enmod php8

            systemctl enable apache2
            ;;

        # Gentoo/Funtoo
        gentoo|funtoo)
            emerge --ask=n www-servers/apache www-apache/mod_php dev-lang/php

            # Enable modules in make.conf
            if ! grep -q "APACHE2_MODULES.*proxy" /etc/portage/make.conf 2>/dev/null; then
                echo 'APACHE2_MODULES="${APACHE2_MODULES} proxy proxy_http proxy_wstunnel rewrite headers ssl"' >> /etc/portage/make.conf
            fi

            rc-update add apache2 default
            ;;

        # Void Linux
        void)
            xbps-install -Sy apache php php-fpm php-apache
            ln -s /etc/sv/apache /var/service/
            ln -s /etc/sv/php-fpm /var/service/
            ;;

        # Alpine Linux
        alpine)
            apk add --no-cache apache2 apache2-ssl php-apache2 php-fpm php-json php-mbstring

            # Enable required modules
            sed -i 's/#LoadModule rewrite_module/LoadModule rewrite_module/' /etc/apache2/httpd.conf
            sed -i 's/#LoadModule proxy_module/LoadModule proxy_module/' /etc/apache2/httpd.conf
            sed -i 's/#LoadModule proxy_http_module/LoadModule proxy_http_module/' /etc/apache2/httpd.conf
            sed -i 's/#LoadModule ssl_module/LoadModule ssl_module/' /etc/apache2/httpd.conf

            rc-update add apache2 default
            ;;

        # Solus
        solus)
            eopkg install -y apache php php-fpm
            systemctl enable httpd
            systemctl enable php-fpm
            ;;

        # NixOS
        nixos)
            echo -e "${YELLOW}NixOS detected. Please add Apache and PHP to your configuration.nix${NC}"
            echo ""
            echo "Example configuration:"
            echo "  services.httpd = {"
            echo "    enable = true;"
            echo "    enablePHP = true;"
            echo "    extraModules = [ \"proxy\" \"proxy_http\" \"proxy_wstunnel\" \"rewrite\" \"headers\" ];"
            echo "  };"
            echo ""
            echo "After updating configuration.nix, run: sudo nixos-rebuild switch"
            exit 0
            ;;

        # Clear Linux
        clear-linux-os)
            swupd bundle-add web-server-basic php-basic
            systemctl enable httpd
            ;;

        # Mageia
        mageia)
            urpmi apache apache-mod_php php-cli php-json php-mbstring
            systemctl enable httpd
            ;;

        # Slackware
        slackware)
            echo -e "${YELLOW}Slackware detected. Apache is typically pre-installed.${NC}"

            # Check if httpd is available
            if ! command -v httpd &> /dev/null; then
                echo -e "${RED}Apache (httpd) not found. Please install it manually.${NC}"
                exit 1
            fi

            # Enable at boot
            chmod +x /etc/rc.d/rc.httpd
            ;;

        *)
            echo -e "${YELLOW}Unknown OS ($os), attempting generic installation...${NC}"

            # Try to detect package manager
            if command -v apt-get &> /dev/null; then
                apt-get update && apt-get install -y apache2 php libapache2-mod-php php-fpm php-json php-mbstring
            elif command -v dnf &> /dev/null; then
                dnf install -y httpd php php-fpm php-json php-mbstring mod_ssl
            elif command -v yum &> /dev/null; then
                yum install -y httpd php php-fpm php-json php-mbstring mod_ssl
            elif command -v pacman &> /dev/null; then
                pacman -Sy --noconfirm apache php php-fpm
            elif command -v zypper &> /dev/null; then
                zypper install -y apache2 php php-fpm php-json php-mbstring
            else
                echo -e "${RED}No supported package manager found.${NC}"
                echo -e "${YELLOW}Please install Apache and PHP manually.${NC}"
                exit 1
            fi
            ;;
    esac

    echo -e "${GREEN}Apache and PHP installed${NC}"
}

# Configure Apache for WebChat
configure_webchat() {
    local config_dir=$(detect_apache_config_dir)
    local service=$(detect_apache_service)

    echo -e "${YELLOW}Configuring Apache for WebChat...${NC}"

    # Create config snippet
    local conf_file=""
    if [ "$service" = "apache2" ]; then
        # Debian/Ubuntu style
        conf_file="$config_dir/sites-available/pyircx-webchat.conf"
    else
        # RHEL/Fedora style
        conf_file="$config_dir/conf.d/pyircx-webchat.conf"
    fi

    cat > "$conf_file" << 'EOF'
# pyIRCX WebChat Configuration
# WebSocket proxy for WebChat browser client

<IfModule mod_proxy.c>
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyAddHeaders On

    # Pass real client IP to backend (for WEBIRC)
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"

    # WebSocket upgrade handling
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/ws$ ws://127.0.0.1:8765/ [P,L]

    # Proxy configuration for /ws path
    <Location /ws>
        ProxyPass ws://127.0.0.1:8765/
        ProxyPassReverse ws://127.0.0.1:8765/
    </Location>
</IfModule>

# WebChat static files
<Directory /var/www/html/webchat>
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF

    # Enable site on Debian/Ubuntu
    if [ "$service" = "apache2" ] && command -v a2ensite &> /dev/null; then
        a2ensite pyircx-webchat.conf
    fi

    echo -e "${GREEN}WebChat configuration created${NC}"
}

# Configure Apache for WebAdmin
configure_webadmin() {
    local config_dir=$(detect_apache_config_dir)
    local service=$(detect_apache_service)

    echo -e "${YELLOW}Configuring Apache for WebAdmin...${NC}"

    # Create config snippet
    local conf_file=""
    if [ "$service" = "apache2" ]; then
        conf_file="$config_dir/sites-available/pyircx-webadmin.conf"
    else
        conf_file="$config_dir/conf.d/pyircx-webadmin.conf"
    fi

    cat > "$conf_file" << 'EOF'
# pyIRCX WebAdmin Configuration
# Web Administration Panel

<Directory /var/www/html/webadmin>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted

    # PHP configuration
    <IfModule mod_php.c>
        php_flag display_errors Off
        php_flag log_errors On
        php_value error_log /var/log/pyircx-webadmin-error.log
    </IfModule>
</Directory>
EOF

    # Enable site on Debian/Ubuntu
    if [ "$service" = "apache2" ] && command -v a2ensite &> /dev/null; then
        a2ensite pyircx-webadmin.conf
    fi

    echo -e "${GREEN}WebAdmin configuration created${NC}"
}

# Configure firewall
configure_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"

    # firewalld (RHEL/Fedora/CentOS)
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        echo "Configuring firewalld..."
        firewall-cmd --permanent --add-service=http 2>/dev/null || true
        firewall-cmd --permanent --add-service=https 2>/dev/null || true
        firewall-cmd --permanent --add-port=8765/tcp 2>/dev/null || true  # WebSocket
        firewall-cmd --reload 2>/dev/null || true
        echo -e "${GREEN}✓ firewalld configured${NC}"

    # ufw (Ubuntu/Debian)
    elif command -v ufw &> /dev/null; then
        echo "Configuring ufw..."
        ufw allow 'Apache Full' 2>/dev/null || ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw allow 8765/tcp 2>/dev/null || true  # WebSocket
        echo -e "${GREEN}✓ ufw configured${NC}"

    # iptables (generic)
    elif command -v iptables &> /dev/null; then
        echo "Configuring iptables..."
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 8765 -j ACCEPT 2>/dev/null || true

        # Try to save rules (method varies by distro)
        if command -v iptables-save &> /dev/null && [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        elif command -v service &> /dev/null; then
            service iptables save 2>/dev/null || true
        fi
        echo -e "${GREEN}✓ iptables configured${NC}"

    else
        echo -e "${YELLOW}No firewall detected, skipping firewall configuration${NC}"
    fi
}

# Add web server user to pyircx group
configure_permissions() {
    echo -e "${YELLOW}Configuring permissions...${NC}"

    # Detect web server user
    WEB_USER=""
    if id apache &>/dev/null; then
        WEB_USER="apache"
    elif id www-data &>/dev/null; then
        WEB_USER="www-data"
    elif id http &>/dev/null; then
        WEB_USER="http"
    elif id wwwrun &>/dev/null; then
        WEB_USER="wwwrun"  # openSUSE
    fi

    if [ -n "$WEB_USER" ]; then
        echo "Detected web server user: $WEB_USER"

        # Add to pyircx group for database access
        if getent group pyircx &>/dev/null; then
            usermod -a -G pyircx "$WEB_USER" 2>/dev/null || true
            echo -e "${GREEN}✓ $WEB_USER added to pyircx group${NC}"
        fi

        # Add to systemd-journal group for log access
        if getent group systemd-journal &>/dev/null; then
            usermod -a -G systemd-journal "$WEB_USER" 2>/dev/null || true
            echo -e "${GREEN}✓ $WEB_USER added to systemd-journal group${NC}"
        fi

        # Set ownership of web directories
        if [ -d "$WEBADMIN_DIR" ]; then
            chown -R "$WEB_USER:$WEB_USER" "$WEBADMIN_DIR"
            echo -e "${GREEN}✓ WebAdmin ownership set${NC}"
        fi

        if [ -d "$WEBCHAT_DIR" ]; then
            chown -R "$WEB_USER:$WEB_USER" "$WEBCHAT_DIR"
            echo -e "${GREEN}✓ WebChat ownership set${NC}"
        fi
    else
        echo -e "${YELLOW}Could not detect web server user${NC}"
    fi
}

# Configure SELinux (RHEL/Fedora/CentOS)
configure_selinux() {
    if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
        echo -e "${YELLOW}SELinux detected, configuring...${NC}"

        # Get script directory to find SELinux policies
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        # Install SELinux policy modules if available
        if [ -d "$SCRIPT_DIR/selinux" ]; then
            echo -e "${YELLOW}Installing SELinux policy modules...${NC}"

            cd "$SCRIPT_DIR/selinux"

            # Compile and install httpd-systemd policy (for service control)
            if [ -f pyircx-httpd-systemd.te ]; then
                if command -v checkmodule &> /dev/null && command -v semodule_package &> /dev/null; then
                    checkmodule -M -m -o pyircx-httpd-systemd.mod pyircx-httpd-systemd.te 2>/dev/null
                    semodule_package -o pyircx-httpd-systemd.pp -m pyircx-httpd-systemd.mod 2>/dev/null
                    semodule -i pyircx-httpd-systemd.pp 2>/dev/null || true
                    echo -e "${GREEN}✓ httpd-systemd policy installed${NC}"
                    # Clean up compiled files
                    rm -f pyircx-httpd-systemd.mod pyircx-httpd-systemd.pp 2>/dev/null || true
                fi
            fi

            # Compile and install httpd-journal policy (for log access)
            if [ -f pyircx-httpd-journal-v3.te ]; then
                if command -v checkmodule &> /dev/null && command -v semodule_package &> /dev/null; then
                    checkmodule -M -m -o pyircx-httpd-journal-v3.mod pyircx-httpd-journal-v3.te 2>/dev/null
                    semodule_package -o pyircx-httpd-journal-v3.pp -m pyircx-httpd-journal-v3.mod 2>/dev/null
                    semodule -i pyircx-httpd-journal-v3.pp 2>/dev/null || true
                    echo -e "${GREEN}✓ httpd-journal policy installed${NC}"
                    # Clean up compiled files
                    rm -f pyircx-httpd-journal-v3.mod pyircx-httpd-journal-v3.pp 2>/dev/null || true
                fi
            fi

            cd - > /dev/null
        fi

        # Configure SELinux file contexts
        if command -v semanage &> /dev/null && command -v restorecon &> /dev/null; then
            echo -e "${YELLOW}Configuring SELinux file contexts...${NC}"

            # /opt/pyircx - Main installation (read-write for web admin API)
            semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?" 2>/dev/null || true

            # /etc/pyircx - Configuration directory (read-write for web admin config editor)
            semanage fcontext -a -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?" 2>/dev/null || true

            # /etc/pyircx/webchat.conf - SystemD environment file (needs etc_t for systemd)
            semanage fcontext -a -t etc_t "/etc/pyircx/webchat\.conf" 2>/dev/null || true

            # /var/www/html/webadmin - Web admin panel (read-write for API operations)
            semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?" 2>/dev/null || true

            # /var/www/html/webchat - WebChat frontend (read-only static content)
            semanage fcontext -a -t httpd_sys_content_t "/var/www/html/webchat(/.*)?" 2>/dev/null || true

            # Apply all contexts
            restorecon -Rv /opt/pyircx 2>/dev/null || true
            restorecon -Rv /etc/pyircx 2>/dev/null || true
            [ -d "$WEBADMIN_DIR" ] && restorecon -Rv "$WEBADMIN_DIR" 2>/dev/null || true
            [ -d "$WEBCHAT_DIR" ] && restorecon -Rv "$WEBCHAT_DIR" 2>/dev/null || true

            echo -e "${GREEN}✓ SELinux file contexts configured${NC}"
        else
            echo -e "${YELLOW}SELinux tools not found, skipping context configuration${NC}"
        fi

        echo -e "${GREEN}SELinux configuration complete${NC}"
    fi
}

# Install Polkit authorization rules
install_polkit() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ ! -d "$SCRIPT_DIR/polkit" ]; then
        echo -e "${YELLOW}Polkit rules not found, skipping${NC}"
        return 0
    fi

    echo -e "${YELLOW}Installing Polkit authorization rules...${NC}"

    # Detect web server user
    WEB_USER=""
    if id apache &>/dev/null; then
        WEB_USER="apache"
    elif id www-data &>/dev/null; then
        WEB_USER="www-data"
    elif id http &>/dev/null; then
        WEB_USER="http"
    elif id wwwrun &>/dev/null; then
        WEB_USER="wwwrun"
    fi

    if [ -z "$WEB_USER" ]; then
        echo -e "${YELLOW}Could not detect web server user, skipping polkit setup${NC}"
        return 0
    fi

    echo "Detected web server user: $WEB_USER"

    # Create polkit rules directory if it doesn't exist
    mkdir -p /etc/polkit-1/rules.d/

    # Copy and customize polkit rules for the detected web user
    if [ -f "$SCRIPT_DIR/polkit/10-pyircx-admin.rules" ]; then
        # Replace "apache" with detected web user
        sed "s/subject\.user == \"apache\"/subject.user == \"$WEB_USER\"/g" \
            "$SCRIPT_DIR/polkit/10-pyircx-admin.rules" > /etc/polkit-1/rules.d/10-pyircx-admin.rules

        chown root:root /etc/polkit-1/rules.d/10-pyircx-admin.rules
        chmod 644 /etc/polkit-1/rules.d/10-pyircx-admin.rules

        # Reload polkit
        systemctl reload polkit 2>/dev/null || true

        echo -e "${GREEN}✓ Polkit rules installed for $WEB_USER${NC}"
    else
        echo -e "${YELLOW}Polkit rules file not found${NC}"
    fi
}

# Restart services
restart_services() {
    local service=$(detect_apache_service)

    echo -e "${YELLOW}Restarting services...${NC}"

    # Restart PHP-FPM if it exists
    if systemctl list-unit-files | grep -q php-fpm.service; then
        systemctl restart php-fpm 2>/dev/null || true
        echo -e "${GREEN}✓ PHP-FPM restarted${NC}"
    fi

    # Restart Apache
    if command -v systemctl &> /dev/null; then
        systemctl restart "$service"
        echo -e "${GREEN}✓ $service restarted${NC}"
    elif command -v service &> /dev/null; then
        service "$service" restart
        echo -e "${GREEN}✓ $service restarted${NC}"
    elif command -v rc-service &> /dev/null; then
        rc-service "$service" restart
        echo -e "${GREEN}✓ $service restarted${NC}"
    else
        echo -e "${YELLOW}Could not restart $service automatically${NC}"
        echo "Please restart Apache manually"
    fi
}

# Test Apache configuration
test_config() {
    local service=$(detect_apache_service)

    echo -e "${YELLOW}Testing Apache configuration...${NC}"

    if command -v apachectl &> /dev/null; then
        if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
            echo -e "${GREEN}✓ Apache configuration is valid${NC}"
            return 0
        else
            echo -e "${RED}✗ Apache configuration has errors${NC}"
            apachectl configtest
            return 1
        fi
    elif command -v "$service" &> /dev/null; then
        if "$service" -t 2>&1 | grep -q "Syntax OK"; then
            echo -e "${GREEN}✓ Apache configuration is valid${NC}"
            return 0
        else
            echo -e "${RED}✗ Apache configuration has errors${NC}"
            "$service" -t
            return 1
        fi
    else
        echo -e "${YELLOW}Could not test Apache configuration${NC}"
        return 0
    fi
}

# Print status
print_status() {
    local service=$(detect_apache_service)

    echo ""
    echo "========================================"
    echo -e "${GREEN}Apache Setup Complete!${NC}"
    echo "========================================"
    echo ""
    echo "Service: $service"
    echo "Config:  $(detect_apache_config_dir)"
    echo ""
    echo "WebChat:  http://localhost/webchat/"
    echo "WebAdmin: http://localhost/webadmin/"
    echo ""
    echo "Commands:"
    echo "  systemctl status $service    - Check status"
    echo "  systemctl restart $service   - Restart Apache"
    echo "  systemctl reload $service    - Reload config"
    echo ""

    if [ -f "$(detect_apache_config_dir)/../ssl-webchat.conf.example" ] || [ -f "./apache/ssl-webchat.conf.example" ]; then
        echo "For HTTPS/WSS setup, see: apache/ssl-webchat.conf.example"
        echo ""
    fi
}

# Main function
main() {
    echo ""
    echo "========================================"
    echo "  pyIRCX Apache/httpd Setup"
    echo "========================================"
    echo ""

    check_root

    local os=$(detect_os)
    echo "Detected OS: $os"
    echo "Apache service: $(detect_apache_service)"
    echo ""

    # Installation steps
    install_apache_php
    configure_webchat
    configure_webadmin
    configure_permissions
    configure_selinux
    install_polkit
    configure_firewall

    # Test and restart
    if test_config; then
        restart_services
        print_status
    else
        echo ""
        echo -e "${RED}Apache configuration test failed. Please fix errors before restarting.${NC}"
        exit 1
    fi
}

# Run main function
main
