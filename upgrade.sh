#!/bin/bash
#
# pyIRCX Upgrade Script
#
# Upgrades an existing installation to the latest version
# Version 2.0.0
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/pyircx"
CONFIG_DIR="/etc/pyircx"
WEB_ADMIN_DIR="/var/www/html/webadmin"
SERVICE_USER="pyircx"
SERVICE_GROUP="pyircx"

echo ""
echo "========================================"
echo "  pyIRCX Upgrade Script v2.0.0"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0"
    exit 1
fi

# Check if pyIRCX is installed
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${RED}Error: pyIRCX does not appear to be installed${NC}"
    echo "Installation directory not found: $INSTALL_DIR"
    echo ""
    echo "Please run ./install.sh first"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}Detecting current installation...${NC}"
echo ""

# Detect what needs upgrading
NEEDS_LINKING_PY=0
NEEDS_API_PY=0
NEEDS_SYSTEMD_UPDATE=0
NEEDS_WEB_ADMIN=0
NEEDS_SELINUX=0
NEEDS_POLKIT=0
NEEDS_APACHE_SETUP=0
NEEDS_WEBCHAT_UPDATE=0
WEBCHAT_SERVICE_WAS_RUNNING=0
SERVICE_WAS_RUNNING=0

# Check if service is running
if systemctl is-active --quiet pyircx 2>/dev/null; then
    SERVICE_WAS_RUNNING=1
    echo -e "${YELLOW}Service is currently running${NC}"
fi

# Check version consistency
echo ""
echo -e "${BLUE}Checking version consistency...${NC}"
if [ -f "$INSTALL_DIR/pyircx.py" ]; then
    INSTALLED_VERSION=$(grep "__version__" "$INSTALL_DIR/pyircx.py" | head -1 | cut -d'"' -f2)
    echo -e "${GREEN}Currently installed version: $INSTALLED_VERSION${NC}"

    if [ -f "$SCRIPT_DIR/pyircx.py" ]; then
        NEW_VERSION=$(grep "__version__" "$SCRIPT_DIR/pyircx.py" | head -1 | cut -d'"' -f2)
        echo -e "${GREEN}Upgrade package version: $NEW_VERSION${NC}"

        # Check if webadmin and webchat versions match in upgrade package
        VERSION_ISSUES=0

        if [ -f "$SCRIPT_DIR/webadmin/index.php" ]; then
            WEBADMIN_VER=$(grep -o "pyIRCX v[0-9]\+\.[0-9]\+\.[0-9]\+" "$SCRIPT_DIR/webadmin/index.php" | head -1 | sed 's/pyIRCX v//')
            if [ "$NEW_VERSION" != "$WEBADMIN_VER" ]; then
                echo -e "${YELLOW}⚠ Upgrade package webadmin version mismatch: $WEBADMIN_VER${NC}"
                VERSION_ISSUES=1
            fi
        fi

        if [ -f "$SCRIPT_DIR/webchat/index.html" ]; then
            WEBCHAT_VER=$(grep -o "v[0-9]\+\.[0-9]\+\.[0-9]\+</span>" "$SCRIPT_DIR/webchat/index.html" | head -1 | sed 's/v\(.*\)<\/span>/\1/')
            if [ "$NEW_VERSION" != "$WEBCHAT_VER" ]; then
                echo -e "${YELLOW}⚠ Upgrade package webchat version mismatch: $WEBCHAT_VER${NC}"
                VERSION_ISSUES=1
            fi
        fi

        if [ $VERSION_ISSUES -eq 1 ]; then
            echo -e "${YELLOW}Warning: Version inconsistencies detected in upgrade package${NC}"
            read -p "Continue with upgrade anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
fi
echo ""

# Check for linking.py
if [ ! -f "$INSTALL_DIR/linking.py" ]; then
    echo -e "${YELLOW}✗ Missing linking.py module${NC}"
    NEEDS_LINKING_PY=1
else
    echo -e "${GREEN}✓ linking.py module present${NC}"
fi

# Check for api.py in new location
if [ ! -f "$INSTALL_DIR/api.py" ]; then
    echo -e "${YELLOW}✗ api.py needs to be moved to /opt/pyircx${NC}"
    NEEDS_API_PY=1
else
    echo -e "${GREEN}✓ api.py in correct location${NC}"
fi

# Check for Web Admin Panel
if [ ! -d "$WEB_ADMIN_DIR" ]; then
    echo -e "${YELLOW}✗ Web Administration Panel not installed${NC}"
    NEEDS_WEB_ADMIN=1
else
    echo -e "${GREEN}✓ Web Administration Panel installed${NC}"
fi

# Check for SELinux policies
if command -v semodule &> /dev/null; then
    if semodule -l | grep -q "pyircx-httpd-journal-v3"; then
        echo -e "${GREEN}✓ SELinux policies installed${NC}"
    else
        echo -e "${YELLOW}✗ SELinux policies not installed${NC}"
        NEEDS_SELINUX=1
    fi
fi

# Check for Polkit rules
if [ ! -f /etc/polkit-1/rules.d/10-pyircx-admin.rules ]; then
    echo -e "${YELLOW}✗ Polkit rules not installed${NC}"
    NEEDS_POLKIT=1
else
    echo -e "${GREEN}✓ Polkit rules installed${NC}"
fi

# Check if apache user is in systemd-journal group
if id apache &>/dev/null; then
    if groups apache | grep -q systemd-journal; then
        echo -e "${GREEN}✓ Apache user configured for journal access${NC}"
    else
        echo -e "${YELLOW}✗ Apache user needs systemd-journal group${NC}"
        NEEDS_APACHE_SETUP=1
    fi
fi

# Check systemd service file
if [ -f /etc/systemd/system/pyircx.service ]; then
    SERVICE_MODIFIED=$(stat -c %Y /etc/systemd/system/pyircx.service)
    if [ -f "$SCRIPT_DIR/pyircx.service" ]; then
        SCRIPT_MODIFIED=$(stat -c %Y "$SCRIPT_DIR/pyircx.service")
        if [ $SCRIPT_MODIFIED -gt $SERVICE_MODIFIED ]; then
            echo -e "${YELLOW}✗ Systemd service file outdated${NC}"
            NEEDS_SYSTEMD_UPDATE=1
        else
            echo -e "${GREEN}✓ Systemd service up to date${NC}"
        fi
    fi
else
    echo -e "${YELLOW}✗ Systemd service file missing${NC}"
    NEEDS_SYSTEMD_UPDATE=1
fi

# Check WebChat installation
if [ -d "$INSTALL_DIR/webchat" ]; then
    if [ -f "$SCRIPT_DIR/webchat/gateway.py" ]; then
        echo -e "${YELLOW}✗ WebChat may need updating${NC}"
        NEEDS_WEBCHAT_UPDATE=1
    else
        echo -e "${GREEN}✓ WebChat installed${NC}"
    fi
    # Check if webchat service is running
    if systemctl is-active --quiet pyircx-webchat 2>/dev/null; then
        WEBCHAT_SERVICE_WAS_RUNNING=1
    fi
fi

# Calculate total updates needed
TOTAL_UPDATES=$((NEEDS_LINKING_PY + NEEDS_API_PY + NEEDS_SYSTEMD_UPDATE + NEEDS_WEB_ADMIN + NEEDS_SELINUX + NEEDS_POLKIT + NEEDS_APACHE_SETUP + NEEDS_WEBCHAT_UPDATE))

echo ""
if [ $TOTAL_UPDATES -eq 0 ]; then
    echo -e "${GREEN}✓ Installation appears to be up to date!${NC}"
    echo ""
    read -p "Perform full upgrade anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "No changes made."
        exit 0
    fi
fi

echo "========================================"
echo -e "${BLUE}Starting upgrade process...${NC}"
echo "========================================"
echo ""

# Stop service if running
if [ $SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${YELLOW}Stopping pyircx service...${NC}"
    systemctl stop pyircx
    echo -e "${GREEN}✓ Service stopped${NC}"
fi

# Stop webchat service if running
if [ $WEBCHAT_SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${YELLOW}Stopping webchat service...${NC}"
    systemctl stop pyircx-webchat
    echo -e "${GREEN}✓ WebChat service stopped${NC}"
fi

# Backup current installation
echo ""
echo -e "${BLUE}Creating backup...${NC}"
BACKUP_DIR="/tmp/pyircx_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR/opt" "$BACKUP_DIR/etc"
cp -r "$INSTALL_DIR" "$BACKUP_DIR/opt/" 2>/dev/null || true
cp -r "$CONFIG_DIR" "$BACKUP_DIR/etc/" 2>/dev/null || true
cp /etc/systemd/system/pyircx.service "$BACKUP_DIR/" 2>/dev/null || true
if [ -d /usr/share/cockpit/pyircx ]; then
    mkdir -p "$BACKUP_DIR/cockpit"
    cp -r /usr/share/cockpit/pyircx "$BACKUP_DIR/cockpit/" 2>/dev/null || true
fi
echo -e "${GREEN}✓ Backup created at: $BACKUP_DIR${NC}"

# Update files
echo ""
echo -e "${BLUE}Updating core files...${NC}"

# Copy main scripts
cp "$SCRIPT_DIR/pyircx.py" "$INSTALL_DIR/"
echo -e "${GREEN}✓ Updated pyircx.py${NC}"

if [ -f "$SCRIPT_DIR/linking.py" ]; then
    cp "$SCRIPT_DIR/linking.py" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Updated linking.py${NC}"
fi

# Copy API helper modules
if [ -f "$SCRIPT_DIR/db_pool.py" ]; then
    cp "$SCRIPT_DIR/db_pool.py" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Updated db_pool.py${NC}"
fi

if [ -f "$SCRIPT_DIR/api_helpers.py" ]; then
    cp "$SCRIPT_DIR/api_helpers.py" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Updated api_helpers.py${NC}"
fi

# Copy or move api.py to /opt/pyircx
if [ $NEEDS_API_PY -eq 1 ]; then
    if [ -f "$SCRIPT_DIR/api.py" ]; then
        cp "$SCRIPT_DIR/api.py" "$INSTALL_DIR/"
        echo -e "${GREEN}✓ Installed api.py to /opt/pyircx${NC}"
    elif [ -f /usr/share/cockpit/pyircx/api.py ]; then
        cp /usr/share/cockpit/pyircx/api.py "$INSTALL_DIR/"
        echo -e "${GREEN}✓ Moved api.py to /opt/pyircx${NC}"
    fi
fi

# Update or preserve config
if [ ! -f "$CONFIG_DIR/pyircx_config.json" ]; then
    if [ -f "$SCRIPT_DIR/pyircx_config.json" ]; then
        cp "$SCRIPT_DIR/pyircx_config.json" "$CONFIG_DIR/"
        echo -e "${GREEN}✓ Created config from template${NC}"
    else
        echo -e "${YELLOW}Generating default config...${NC}"
        python3 "$SCRIPT_DIR/generate_default_config.py" "$INSTALL_DIR/pyircx.py" "$CONFIG_DIR/pyircx_config.json"
        echo -e "${GREEN}✓ Generated default config${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Preserving existing config${NC}"
fi

# Ensure config symlink exists
ln -sf "$CONFIG_DIR/pyircx_config.json" "$INSTALL_DIR/pyircx_config.json" 2>/dev/null || true

# Update systemd service
if [ $NEEDS_SYSTEMD_UPDATE -eq 1 ] || [ -f "$SCRIPT_DIR/pyircx.service" ]; then
    echo ""
    echo -e "${BLUE}Updating systemd service...${NC}"
    cp "$SCRIPT_DIR/pyircx.service" /etc/systemd/system/
    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service updated${NC}"
fi

# Install or Update Web Admin Panel
if [ $NEEDS_WEB_ADMIN -eq 1 ] || [ -d "$WEB_ADMIN_DIR" ]; then
    echo ""
    if [ $NEEDS_WEB_ADMIN -eq 1 ]; then
        echo -e "${BLUE}Installing Web Administration Panel...${NC}"
    else
        echo -e "${BLUE}Updating Web Administration Panel...${NC}"
    fi

    if [ ! -d "$SCRIPT_DIR/webadmin" ]; then
        echo -e "${RED}✗ webadmin directory not found${NC}"
        echo -e "${YELLOW}⚠ Skipping web admin installation${NC}"
    else
        # Check for Apache/httpd
        if ! command -v httpd &> /dev/null && ! command -v apache2 &> /dev/null; then
            echo -e "${RED}✗ Apache web server not found${NC}"
            echo -e "${YELLOW}⚠ Install Apache first: dnf install httpd php php-fpm${NC}"
        else
            # Create web admin directory
            mkdir -p "$WEB_ADMIN_DIR"

            # Copy files
            cp "$SCRIPT_DIR/webadmin"/*.php "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/webadmin"/*.js "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/webadmin"/*.css "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/webadmin"/.htaccess "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/webadmin"/*.md "$WEB_ADMIN_DIR/" 2>/dev/null || true

            # Set permissions
            # Detect web server user
            if id apache &>/dev/null; then
                chown -R apache:apache "$WEB_ADMIN_DIR"
            elif id www-data &>/dev/null; then
                chown -R www-data:www-data "$WEB_ADMIN_DIR"
            elif id http &>/dev/null; then
                chown -R http:http "$WEB_ADMIN_DIR"
            fi
            chmod 644 "$WEB_ADMIN_DIR"/*.php "$WEB_ADMIN_DIR"/*.js "$WEB_ADMIN_DIR"/*.css 2>/dev/null || true

            if [ $NEEDS_WEB_ADMIN -eq 1 ]; then
                echo -e "${GREEN}✓ Web Administration Panel installed${NC}"
            else
                echo -e "${GREEN}✓ Web Administration Panel updated${NC}"
            fi
            echo -e "${YELLOW}  Access at: http://localhost/webadmin/${NC}"
        fi
    fi
fi

# Install SELinux Policies
if [ $NEEDS_SELINUX -eq 1 ] && command -v semodule &> /dev/null; then
    echo ""
    echo -e "${BLUE}Installing SELinux policies...${NC}"

    if [ -d "$SCRIPT_DIR/selinux" ]; then
        cd "$SCRIPT_DIR/selinux"

        # Compile and install httpd-systemd policy
        if [ -f pyircx-httpd-systemd.te ]; then
            checkmodule -M -m -o pyircx-httpd-systemd.mod pyircx-httpd-systemd.te
            semodule_package -o pyircx-httpd-systemd.pp -m pyircx-httpd-systemd.mod
            semodule -i pyircx-httpd-systemd.pp
            echo -e "${GREEN}✓ Installed pyircx-httpd-systemd policy${NC}"
        fi

        # Compile and install httpd-journal policy
        if [ -f pyircx-httpd-journal-v3.te ]; then
            checkmodule -M -m -o pyircx-httpd-journal-v3.mod pyircx-httpd-journal-v3.te
            semodule_package -o pyircx-httpd-journal-v3.pp -m pyircx-httpd-journal-v3.mod
            semodule -i pyircx-httpd-journal-v3.pp
            echo -e "${GREEN}✓ Installed pyircx-httpd-journal-v3 policy${NC}"
        fi

        # Install httpd-reload policy (allows webadmin to reload pyircx service)
        if [ -f pyircx-httpd-reload.pp ]; then
            semodule -i pyircx-httpd-reload.pp
            echo -e "${GREEN}✓ Installed pyircx-httpd-reload policy${NC}"
        fi

        cd - > /dev/null
    else
        echo -e "${YELLOW}⚠ SELinux policies not found, skipping${NC}"
    fi
fi

# Configure SELinux file contexts (comprehensive configuration)
if command -v semanage &> /dev/null && command -v restorecon &> /dev/null; then
    echo ""
    echo -e "${BLUE}Configuring SELinux file contexts...${NC}"

    # /opt/pyircx - Main installation (read-write for web admin API)
    semanage fcontext -d -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?" 2>/dev/null || true

    # /etc/pyircx - Configuration directory (read-write for web admin config editor)
    #               EXCEPT webchat.conf which needs etc_t for systemd EnvironmentFile
    semanage fcontext -d -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?" 2>/dev/null || true

    # /etc/pyircx/webchat.conf - SystemD EnvironmentFile (MUST be etc_t, NOT httpd_sys_rw_content_t)
    # This overrides the previous rule specifically for webchat.conf
    semanage fcontext -d -t etc_t "/etc/pyircx/webchat\.conf" 2>/dev/null || true
    semanage fcontext -a -t etc_t "/etc/pyircx/webchat\.conf" 2>/dev/null || true

    # /var/www/html/webadmin - Web admin panel (read-write for API operations)
    semanage fcontext -d -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?" 2>/dev/null || true

    # /var/www/html/webchat - WebChat frontend (read-only static content)
    semanage fcontext -d -t httpd_sys_content_t "/var/www/html/webchat(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_content_t "/var/www/html/webchat(/.*)?" 2>/dev/null || true

    # Apply all contexts
    restorecon -Rv /opt/pyircx 2>/dev/null || true
    restorecon -Rv /etc/pyircx 2>/dev/null || true
    [ -d "/var/www/html/webadmin" ] && restorecon -Rv /var/www/html/webadmin 2>/dev/null || true
    [ -d "/var/www/html/webchat" ] && restorecon -Rv /var/www/html/webchat 2>/dev/null || true

    # CRITICAL: Explicitly fix webchat.conf after global restorecon
    if [ -f "/etc/pyircx/webchat.conf" ]; then
        chcon -t etc_t "/etc/pyircx/webchat.conf" 2>/dev/null || true
        echo -e "${GREEN}✓ SELinux context fixed for webchat.conf (etc_t)${NC}"
    fi

    echo -e "${GREEN}✓ SELinux file contexts configured${NC}"
fi

# Install Polkit Rules
if [ $NEEDS_POLKIT -eq 1 ]; then
    echo ""
    echo -e "${BLUE}Installing Polkit rules...${NC}"

    if [ -f "$SCRIPT_DIR/polkit/10-pyircx-admin.rules" ]; then
        cp "$SCRIPT_DIR/polkit/10-pyircx-admin.rules" /etc/polkit-1/rules.d/
        chown root:root /etc/polkit-1/rules.d/10-pyircx-admin.rules
        chmod 644 /etc/polkit-1/rules.d/10-pyircx-admin.rules
        echo -e "${GREEN}✓ Polkit rules installed${NC}"

        # Reload polkit
        systemctl reload polkit 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠ Polkit rules not found, skipping${NC}"
    fi
fi

# Setup Apache User
if [ $NEEDS_APACHE_SETUP -eq 1 ]; then
    echo ""
    echo -e "${BLUE}Configuring Apache user...${NC}"

    if id apache &>/dev/null; then
        usermod -a -G systemd-journal apache
        echo -e "${GREEN}✓ Added apache to systemd-journal group${NC}"

        # Add apache to pyircx group for database write access
        if getent group pyircx &>/dev/null; then
            usermod -a -G pyircx apache
            echo -e "${GREEN}✓ Added apache to pyircx group${NC}"

            # Ensure /opt/pyircx directory has group write permissions for SQLite
            chmod 775 /opt/pyircx
            echo -e "${GREEN}✓ Set group write permissions on /opt/pyircx${NC}"

            # Ensure /etc/pyircx directory has group write permissions for web admin
            chmod 775 /etc/pyircx
            echo -e "${GREEN}✓ Set group write permissions on /etc/pyircx${NC}"

            # Ensure config file is group writable for web admin MOTD editor
            chmod 660 /etc/pyircx/pyircx_config.json 2>/dev/null || true
            echo -e "${GREEN}✓ Set group write permissions on config file${NC}"

            # Ensure admin commands queue exists and is group writable
            touch /opt/pyircx/admin_commands.queue 2>/dev/null || true
            chmod 660 /opt/pyircx/admin_commands.queue 2>/dev/null || true
            echo -e "${GREEN}✓ Created admin commands queue${NC}"
        fi

        # Restart PHP-FPM and Apache
        if systemctl is-active --quiet php-fpm 2>/dev/null; then
            systemctl restart php-fpm
            echo -e "${GREEN}✓ Restarted PHP-FPM${NC}"
        fi

        if systemctl is-active --quiet httpd 2>/dev/null; then
            systemctl restart httpd
            echo -e "${GREEN}✓ Restarted Apache${NC}"
        fi
    fi
fi

# Update WebChat installation
if [ $NEEDS_WEBCHAT_UPDATE -eq 1 ] && [ -d "$SCRIPT_DIR/webchat" ]; then
    echo ""
    echo -e "${BLUE}Updating WebChat...${NC}"

    # Ensure webchat backend directory exists
    if [ ! -d "$INSTALL_DIR/webchat" ]; then
        echo -e "${YELLOW}Creating webchat backend directory...${NC}"
        mkdir -p "$INSTALL_DIR/webchat"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/webchat"
        echo -e "${GREEN}✓ WebChat backend directory created${NC}"
    fi

    # Update backend (gateway)
    if [ -d "$INSTALL_DIR/webchat" ]; then
        cp "$SCRIPT_DIR/webchat/gateway.py" "$INSTALL_DIR/webchat/"
        chmod 755 "$INSTALL_DIR/webchat/gateway.py"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/webchat/gateway.py"
        echo -e "${GREEN}✓ WebChat gateway updated${NC}"
    fi

    # Update frontend (HTML)
    if [ -d "/var/www/html/webchat" ]; then
        cp "$SCRIPT_DIR/webchat/index.html" /var/www/html/webchat/
        cp "$SCRIPT_DIR/webchat/config.js" /var/www/html/webchat/
        cp "$SCRIPT_DIR/webchat/favicon.svg" /var/www/html/webchat/ 2>/dev/null || true
        chmod 644 /var/www/html/webchat/index.html
        chmod 644 /var/www/html/webchat/config.js
        echo -e "${GREEN}✓ WebChat frontend updated${NC}"
    fi

    # Update webchat service file
    if [ -f "$SCRIPT_DIR/pyircx-webchat.service" ]; then
        cp "$SCRIPT_DIR/pyircx-webchat.service" /etc/systemd/system/
        systemctl daemon-reload
        echo -e "${GREEN}✓ WebChat service updated${NC}"
    fi
fi

# Update certbot renewal service if present
if [ -f "$SCRIPT_DIR/pyircx-certbot-renew.service" ]; then
    echo ""
    echo -e "${BLUE}Updating certbot renewal service...${NC}"
    cp "$SCRIPT_DIR/pyircx-certbot-renew.service" /etc/systemd/system/
    cp "$SCRIPT_DIR/pyircx-certbot-renew.timer" /etc/systemd/system/
    systemctl daemon-reload
    echo -e "${GREEN}✓ Certbot renewal service updated${NC}"
fi

# Fix permissions
echo ""
echo -e "${BLUE}Fixing permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
chmod 775 "$INSTALL_DIR"  # Group needs write for SQLite journal files
chmod 775 "$CONFIG_DIR"  # Group needs write for web admin config edits
chmod 750 "$INSTALL_DIR/transcripts" 2>/dev/null || true
chmod 660 "$INSTALL_DIR/pyircx.db" 2>/dev/null || true
chmod 660 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true  # Config group writable (for web admin)
touch "$INSTALL_DIR/admin_commands.queue" 2>/dev/null || true  # Create admin command queue
chmod 660 "$INSTALL_DIR/admin_commands.queue" 2>/dev/null || true  # Queue group-writable (needed for webadmin)
chmod 755 "$INSTALL_DIR/pyircx.py"
chmod 755 "$INSTALL_DIR/api.py" 2>/dev/null || true
chmod 755 "$INSTALL_DIR/linking.py" 2>/dev/null || true

# Add web server user to pyircx group for database access
# Detect web server user (apache, www-data, or http)
WEB_USER=""
if id apache &>/dev/null; then
    WEB_USER="apache"
elif id www-data &>/dev/null; then
    WEB_USER="www-data"
elif id http &>/dev/null; then
    WEB_USER="http"
fi

if [ -n "$WEB_USER" ]; then
    echo -e "${YELLOW}Adding $WEB_USER to $SERVICE_GROUP group for database access...${NC}"
    usermod -a -G "$SERVICE_GROUP" "$WEB_USER"
    echo -e "${GREEN}✓ Web server user added to group${NC}"

    # Restart PHP-FPM to apply group membership
    if systemctl is-active --quiet php-fpm 2>/dev/null; then
        echo -e "${YELLOW}Restarting PHP-FPM to apply group membership...${NC}"
        systemctl restart php-fpm
        echo -e "${GREEN}✓ PHP-FPM restarted${NC}"
    fi
fi

echo -e "${GREEN}✓ Permissions fixed${NC}"

# Restart service if it was running
echo ""
if [ $SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${BLUE}Restarting pyircx service...${NC}"
    systemctl start pyircx
    sleep 2

    if systemctl is-active --quiet pyircx; then
        echo -e "${GREEN}✓ Service restarted successfully${NC}"
        # Fix database permissions after service creates/accesses it
        sleep 1
        chmod 660 "$INSTALL_DIR/pyircx.db" 2>/dev/null || true
        chmod 775 "$INSTALL_DIR" 2>/dev/null || true
    else
        echo -e "${RED}✗ Service failed to start${NC}"
        echo "Check logs: journalctl -u pyircx -n 50"
    fi
else
    echo -e "${YELLOW}Service was not running, not starting${NC}"
    echo "Start with: systemctl start pyircx"
fi

# Restart webchat service if it was running
if [ $WEBCHAT_SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${BLUE}Restarting webchat service...${NC}"
    systemctl start pyircx-webchat
    if systemctl is-active --quiet pyircx-webchat; then
        echo -e "${GREEN}✓ WebChat service restarted${NC}"
    else
        echo -e "${RED}✗ WebChat service failed to start${NC}"
    fi
fi

# Summary
echo ""
echo "========================================"
echo -e "${GREEN}Upgrade Complete!${NC}"
echo "========================================"
echo ""
echo "Backup location: $BACKUP_DIR"
echo "Installation: $INSTALL_DIR"
echo "Configuration: $CONFIG_DIR"
echo ""

if [ $NEEDS_WEB_ADMIN -eq 1 ]; then
    echo "Web Administration Panel"
    echo "  Access at: http://your-server/webadmin/"
    echo "  Login with: ADMIN level staff account"
    echo ""
    echo "  Set staff password:"
    echo "    python3 $INSTALL_DIR/api.py change-staff-password <username> <password>"
    echo ""
fi

echo "Commands:"
echo "  systemctl status pyircx   - Check status"
echo "  systemctl start pyircx    - Start server"
echo "  systemctl restart pyircx  - Restart server"
echo "  journalctl -u pyircx -f   - View logs"
echo ""
echo -e "${YELLOW}⚠ Security Reminder:${NC}"
echo "  SSL authentication is currently DISABLED for easier initial setup."
echo "  After configuring SSL, enable it in /etc/pyircx/pyircx_config.json:"
echo "    \"auth_require_ssl\": true"
echo "  Run: sudo ./setup_ssl.sh to configure SSL/TLS"
echo ""
echo -e "${GREEN}pyIRCX v2.0.0 - Upgrade complete!${NC}"
