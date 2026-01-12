#!/bin/bash
#
# pyIRCX Upgrade Script
#
# Intelligently upgrades an existing installation to the latest version
# Version 1.1.0 - Migrates from Cockpit to Web Admin Panel
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
WEB_ADMIN_DIR="/var/www/html/pyircx-admin"
SERVICE_USER="pyircx"
SERVICE_GROUP="pyircx"

echo ""
echo "========================================"
echo "  pyIRCX Upgrade Script v1.1.0"
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
NEEDS_DB_MIGRATION=0
NEEDS_SELINUX=0
NEEDS_POLKIT=0
NEEDS_APACHE_SETUP=0
NEEDS_COCKPIT_REMOVAL=0
NEEDS_WEBCHAT_UPDATE=0
WEBCHAT_SERVICE_WAS_RUNNING=0
SERVICE_WAS_RUNNING=0

# Check if service is running
if systemctl is-active --quiet pyircx 2>/dev/null; then
    SERVICE_WAS_RUNNING=1
    echo -e "${YELLOW}Service is currently running${NC}"
fi

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

# Check for Cockpit installation (needs removal in v1.1.0)
if [ -d /usr/share/cockpit/pyircx ] || [ -d ~/.local/share/cockpit/pyircx ]; then
    echo -e "${YELLOW}✗ Cockpit module detected (will be removed in v1.1.0)${NC}"
    NEEDS_COCKPIT_REMOVAL=1
fi

# Check for Web Admin Panel
if [ ! -d "$WEB_ADMIN_DIR" ]; then
    echo -e "${YELLOW}✗ Web Administration Panel not installed${NC}"
    NEEDS_WEB_ADMIN=1
else
    echo -e "${GREEN}✓ Web Administration Panel installed${NC}"
fi

# Check database schema for v1.1.0 columns
if [ -f "$INSTALL_DIR/pyircx.db" ]; then
    # Ensure sqlite3 is available
    if ! command -v sqlite3 &>/dev/null; then
        echo -e "${YELLOW}✗ sqlite3 not installed (needed for database migration)${NC}"
        NEEDS_DB_MIGRATION=1
    else
        HAS_EMAIL_COL=$(sqlite3 "$INSTALL_DIR/pyircx.db" "PRAGMA table_info(users);" 2>/dev/null | grep -c "|email|")
        HAS_TIMEOUT_COL=$(sqlite3 "$INSTALL_DIR/pyircx.db" "PRAGMA table_info(server_access);" 2>/dev/null | grep -c "|timeout|")

        # Ensure we got valid integers (grep -c should never fail, but handle empty/error cases)
        HAS_EMAIL_COL=${HAS_EMAIL_COL:-0}
        HAS_TIMEOUT_COL=${HAS_TIMEOUT_COL:-0}

        if [ "$HAS_EMAIL_COL" -eq 0 ] || [ "$HAS_TIMEOUT_COL" -eq 0 ]; then
            echo -e "${YELLOW}✗ Database needs migration to v1.1.0 schema${NC}"
            NEEDS_DB_MIGRATION=1
        else
            echo -e "${GREEN}✓ Database schema up to date${NC}"
        fi
    fi
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
TOTAL_UPDATES=$((NEEDS_LINKING_PY + NEEDS_API_PY + NEEDS_SYSTEMD_UPDATE + NEEDS_WEB_ADMIN + NEEDS_DB_MIGRATION + NEEDS_SELINUX + NEEDS_POLKIT + NEEDS_APACHE_SETUP + NEEDS_COCKPIT_REMOVAL + NEEDS_WEBCHAT_UPDATE))

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

# Copy or move api.py to /opt/pyircx
if [ $NEEDS_API_PY -eq 1 ]; then
    if [ -f "$SCRIPT_DIR/api.py" ]; then
        cp "$SCRIPT_DIR/api.py" "$INSTALL_DIR/"
        echo -e "${GREEN}✓ Installed api.py to /opt/pyircx${NC}"
    elif [ -f /usr/share/cockpit/pyircx/api.py ]; then
        cp /usr/share/cockpit/pyircx/api.py "$INSTALL_DIR/"
        echo -e "${GREEN}✓ Moved api.py from Cockpit to /opt/pyircx${NC}"
    fi
fi

# Update or preserve config
if [ -f "$SCRIPT_DIR/pyircx_config.json" ]; then
    if [ ! -f "$CONFIG_DIR/pyircx_config.json" ]; then
        cp "$SCRIPT_DIR/pyircx_config.json" "$CONFIG_DIR/"
        echo -e "${GREEN}✓ Created config${NC}"
    else
        echo -e "${YELLOW}⚠ Preserving existing config${NC}"
    fi
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

# Database Migration
if [ $NEEDS_DB_MIGRATION -eq 1 ]; then
    echo ""
    echo -e "${BLUE}Running database migration...${NC}"

    # Install sqlite if not present
    if ! command -v sqlite3 &>/dev/null; then
        echo -e "${YELLOW}Installing sqlite for database migration...${NC}"
        if command -v dnf &> /dev/null; then
            dnf install -y sqlite >/dev/null 2>&1
        elif command -v apt-get &> /dev/null; then
            apt-get install -y sqlite3 >/dev/null 2>&1
        elif command -v yum &> /dev/null; then
            yum install -y sqlite >/dev/null 2>&1
        elif command -v pacman &> /dev/null; then
            pacman -S --noconfirm sqlite >/dev/null 2>&1
        fi

        if command -v sqlite3 &>/dev/null; then
            echo -e "${GREEN}✓ sqlite installed${NC}"
        else
            echo -e "${RED}✗ Failed to install sqlite${NC}"
            echo -e "${YELLOW}⚠ Please install sqlite manually and re-run upgrade${NC}"
        fi
    fi

    if [ -f "$SCRIPT_DIR/migrate_1.0_to_1.1.sh" ]; then
        bash "$SCRIPT_DIR/migrate_1.0_to_1.1.sh"
        echo -e "${GREEN}✓ Database migrated to v1.1.0 schema${NC}"
    else
        echo -e "${RED}✗ Migration script not found: migrate_1.0_to_1.1.sh${NC}"
        echo -e "${YELLOW}⚠ You may need to run migration manually${NC}"
    fi
fi

# Install Web Admin Panel
if [ $NEEDS_WEB_ADMIN -eq 1 ]; then
    echo ""
    echo -e "${BLUE}Installing Web Administration Panel...${NC}"

    if [ ! -d "$SCRIPT_DIR/web-admin" ]; then
        echo -e "${RED}✗ web-admin directory not found${NC}"
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
            cp "$SCRIPT_DIR/web-admin"/*.php "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/web-admin"/*.js "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/web-admin"/*.css "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/web-admin"/.htaccess "$WEB_ADMIN_DIR/" 2>/dev/null || true
            cp "$SCRIPT_DIR/web-admin"/*.md "$WEB_ADMIN_DIR/" 2>/dev/null || true

            # Set permissions
            chown -R apache:apache "$WEB_ADMIN_DIR"
            chmod 644 "$WEB_ADMIN_DIR"/*.php "$WEB_ADMIN_DIR"/*.js "$WEB_ADMIN_DIR"/*.css 2>/dev/null || true

            echo -e "${GREEN}✓ Web Administration Panel installed${NC}"
            echo -e "${YELLOW}  Access at: http://localhost/pyircx-admin/${NC}"
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

        cd - > /dev/null
    else
        echo -e "${YELLOW}⚠ SELinux policies not found, skipping${NC}"
    fi
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

        # Restart PHP-FPM
        if systemctl is-active --quiet php-fpm 2>/dev/null; then
            systemctl restart php-fpm
            echo -e "${GREEN}✓ Restarted PHP-FPM${NC}"
        fi
    fi
fi

# Remove Cockpit Module
if [ $NEEDS_COCKPIT_REMOVAL -eq 1 ]; then
    echo ""
    echo -e "${BLUE}Removing Cockpit module...${NC}"

    # Remove system-wide installation
    if [ -d /usr/share/cockpit/pyircx ]; then
        rm -rf /usr/share/cockpit/pyircx
        echo -e "${GREEN}✓ Removed system-wide Cockpit module${NC}"
    fi

    # Remove user installation
    if [ -d ~/.local/share/cockpit/pyircx ]; then
        rm -rf ~/.local/share/cockpit/pyircx
        echo -e "${GREEN}✓ Removed user Cockpit module${NC}"
    fi

    # Remove Cockpit admin token (no longer needed)
    if [ -f /etc/pyircx/cockpit_admin_token ]; then
        rm -f /etc/pyircx/cockpit_admin_token
        echo -e "${GREEN}✓ Removed obsolete Cockpit token${NC}"
    fi

    echo -e "${YELLOW}  Note: Cockpit has been replaced with Web Admin Panel${NC}"
fi

# Update WebChat installation
if [ $NEEDS_WEBCHAT_UPDATE -eq 1 ] && [ -d "$SCRIPT_DIR/webchat" ]; then
    echo ""
    echo -e "${BLUE}Updating WebChat...${NC}"

    if [ -d "$INSTALL_DIR/webchat" ]; then
        cp "$SCRIPT_DIR/webchat/gateway.py" "$INSTALL_DIR/webchat/"
        cp "$SCRIPT_DIR/webchat/index.html" "$INSTALL_DIR/webchat/"
        echo -e "${GREEN}✓ WebChat files updated${NC}"
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
chmod 755 "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR/transcripts" 2>/dev/null || true
chmod 664 "$INSTALL_DIR/pyircx.db" 2>/dev/null || true
chmod 755 "$INSTALL_DIR/pyircx.py"
chmod 755 "$INSTALL_DIR/api.py" 2>/dev/null || true
chmod 755 "$INSTALL_DIR/linking.py" 2>/dev/null || true
chmod 644 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true
echo -e "${GREEN}✓ Permissions fixed${NC}"

# Restart service if it was running
echo ""
if [ $SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${BLUE}Restarting pyircx service...${NC}"
    systemctl start pyircx
    sleep 2

    if systemctl is-active --quiet pyircx; then
        echo -e "${GREEN}✓ Service restarted successfully${NC}"
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
    echo "🎉 NEW in v1.1.0: Web Administration Panel"
    echo "  Access at: http://your-server/pyircx-admin/"
    echo "  Login with: ADMIN level staff account"
    echo ""
    echo "  Set staff password:"
    echo "    python3 $INSTALL_DIR/api.py change-staff-password <username> <password>"
    echo ""
fi

if [ $NEEDS_COCKPIT_REMOVAL -eq 1 ]; then
    echo "📋 Cockpit module has been replaced"
    echo "  Old: Cockpit at :9090"
    echo "  New: Web Admin at /pyircx-admin/"
    echo ""
fi

echo "Commands:"
echo "  systemctl status pyircx   - Check status"
echo "  systemctl start pyircx    - Start server"
echo "  systemctl restart pyircx  - Restart server"
echo "  journalctl -u pyircx -f   - View logs"
echo ""
echo -e "${GREEN}pyIRCX v1.1.0 - All done!${NC}"
