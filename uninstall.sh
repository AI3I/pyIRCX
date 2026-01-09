#!/bin/bash
#
# pyIRCX Uninstallation Script
#
# Safely removes pyIRCX and all associated files
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default installation paths
INSTALL_DIR="/opt/pyircx"
CONFIG_DIR="/etc/pyircx"
SERVICE_USER="pyircx"
SERVICE_GROUP="pyircx"

echo ""
echo "========================================"
echo "  pyIRCX Uninstallation"
echo "========================================"
echo ""
echo -e "${YELLOW}This will remove pyIRCX from your system.${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0"
    exit 1
fi

# Confirm uninstallation
echo -e "${RED}WARNING: This will remove pyIRCX and optionally delete your data.${NC}"
echo ""
read -p "Are you sure you want to continue? [y/N] " -n 1 -r
echo
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

# Stop and disable service
echo -e "${BLUE}Stopping pyIRCX service...${NC}"
if systemctl is-active --quiet pyircx 2>/dev/null; then
    systemctl stop pyircx
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo "Service not running"
fi

if systemctl is-enabled --quiet pyircx 2>/dev/null; then
    systemctl disable pyircx
    echo -e "${GREEN}✓ Service disabled${NC}"
else
    echo "Service not enabled"
fi


# Stop and disable webchat service
echo ""
echo -e "${BLUE}Stopping WebChat service...${NC}"
if systemctl is-active --quiet pyircx-webchat 2>/dev/null; then
    systemctl stop pyircx-webchat
    echo -e "${GREEN}✓ WebChat service stopped${NC}"
else
    echo "WebChat service not running"
fi

if systemctl is-enabled --quiet pyircx-webchat 2>/dev/null; then
    systemctl disable pyircx-webchat
    echo -e "${GREEN}✓ WebChat service disabled${NC}"
else
    echo "WebChat service not enabled"
fi

# Remove systemd service files
echo ""
echo -e "${BLUE}Removing systemd service files...${NC}"
if [ -f /etc/systemd/system/pyircx.service ]; then
    rm -f /etc/systemd/system/pyircx.service
    echo -e "${GREEN}✓ Removed pyircx.service${NC}"
fi


# Remove webchat service file
if [ -f /etc/systemd/system/pyircx-webchat.service ]; then
    rm -f /etc/systemd/system/pyircx-webchat.service
    echo -e "${GREEN}✓ Removed pyircx-webchat.service${NC}"
fi

# Remove certbot auto-renewal (if exists)
if [ -f /etc/systemd/system/pyircx-certbot-renew.service ]; then
    systemctl disable pyircx-certbot-renew.timer 2>/dev/null || true
    systemctl stop pyircx-certbot-renew.timer 2>/dev/null || true
    rm -f /etc/systemd/system/pyircx-certbot-renew.service
    rm -f /etc/systemd/system/pyircx-certbot-renew.timer
    echo -e "${GREEN}✓ Removed certbot auto-renewal${NC}"
fi

systemctl daemon-reload
echo -e "${GREEN}✓ Systemd reloaded${NC}"

# Remove installation directory
echo ""
echo -e "${YELLOW}Installation directory: $INSTALL_DIR${NC}"
if [ -d "$INSTALL_DIR" ]; then
    echo "This directory contains:"
    ls -lh "$INSTALL_DIR" 2>/dev/null | tail -n +2 || echo "  (empty or inaccessible)"
    echo ""
    read -p "Remove installation directory? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}✓ Installation directory removed${NC}"
    else
        echo "Keeping installation directory"
    fi
else
    echo "Installation directory not found"
fi

# Remove configuration directory (with database backup option)
echo ""
echo -e "${YELLOW}Configuration directory: $CONFIG_DIR${NC}"
if [ -d "$CONFIG_DIR" ]; then
    echo "This directory contains:"
    ls -lh "$CONFIG_DIR" 2>/dev/null | tail -n +2 || echo "  (empty or inaccessible)"

    # Check for database
    if [ -f "$INSTALL_DIR/pyircx.db" ]; then
        echo ""
        echo -e "${YELLOW}Database found: $INSTALL_DIR/pyircx.db${NC}"
        echo "This contains user accounts, channels, and messages."
        echo ""
        read -p "Backup database before removing? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            BACKUP_PATH="$HOME/pyircx_db_backup_$(date +%Y%m%d_%H%M%S).db"
            cp "$INSTALL_DIR/pyircx.db" "$BACKUP_PATH"
            echo -e "${GREEN}✓ Database backed up to: $BACKUP_PATH${NC}"
        fi
    fi

    echo ""
    read -p "Remove configuration directory? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}✓ Configuration directory removed${NC}"
    else
        echo "Keeping configuration directory"
    fi
else
    echo "Configuration directory not found"
fi

# Remove Cockpit module
echo ""
echo -e "${BLUE}Checking for Cockpit module...${NC}"
COCKPIT_REMOVED=0

# Check system-wide installation
if [ -d /usr/share/cockpit/pyircx ]; then
    read -p "Remove Cockpit web admin module (system-wide)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf /usr/share/cockpit/pyircx
        echo -e "${GREEN}✓ Cockpit module removed (system-wide)${NC}"
        COCKPIT_REMOVED=1
    fi
fi

# Check user installation (old location)
if [ -d ~/.local/share/cockpit/pyircx ]; then
    read -p "Remove Cockpit web admin module (user directory)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf ~/.local/share/cockpit/pyircx
        echo -e "${GREEN}✓ Cockpit module removed (user directory)${NC}"
        COCKPIT_REMOVED=1
    fi
fi

if [ $COCKPIT_REMOVED -eq 0 ]; then
    echo "Cockpit module not found"
fi

# Remove service user
echo ""
echo -e "${BLUE}Checking for service user...${NC}"
if id "$SERVICE_USER" &>/dev/null; then
    read -p "Remove user '$SERVICE_USER'? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        echo -e "${GREEN}✓ User removed${NC}"
    else
        echo "Keeping user '$SERVICE_USER'"
    fi
else
    echo "Service user not found"
fi

# Ask about Let's Encrypt certificates
echo ""
echo -e "${BLUE}Checking for Let's Encrypt certificates...${NC}"
if [ -d /etc/letsencrypt/live ] && ls /etc/letsencrypt/live/*/fullchain.pem 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}Let's Encrypt certificates found${NC}"
    echo "These may be used by other services."
    echo ""
    read -p "Remove Let's Encrypt certificates? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Are you ABSOLUTELY SURE? This may affect other services! [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf /etc/letsencrypt
            echo -e "${GREEN}✓ Let's Encrypt certificates removed${NC}"
        else
            echo "Keeping certificates"
        fi
    else
        echo "Keeping certificates"
    fi
fi

# Ask about self-signed certificates
if [ -d "$CONFIG_DIR/ssl" ] && [ -f "$CONFIG_DIR/ssl/cert.pem" ]; then
    echo ""
    echo -e "${BLUE}Self-signed SSL certificates found${NC}"
    read -p "Remove self-signed certificates? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR/ssl"
        echo -e "${GREEN}✓ Self-signed certificates removed${NC}"
    fi
fi

# Ask about Python packages
echo ""
echo -e "${BLUE}Python packages${NC}"
echo "The following Python packages were installed for pyIRCX:"
echo "  - aiosqlite"
echo "  - bcrypt"
echo "  - pyotp"
echo "  - cryptography"
echo ""
echo -e "${YELLOW}Note: These packages may be used by other applications.${NC}"
read -p "Remove Python packages? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip3 uninstall -y aiosqlite bcrypt pyotp cryptography 2>/dev/null || true
    echo -e "${GREEN}✓ Python packages removed${NC}"
else
    echo "Keeping Python packages"
fi

# Final summary
echo ""
echo "========================================"
echo -e "${GREEN}Uninstallation Complete${NC}"
echo "========================================"
echo ""
echo "pyIRCX has been removed from your system."
echo ""
echo "The following may still remain:"
if [ -d "$INSTALL_DIR" ]; then
    echo "  - Installation directory: $INSTALL_DIR"
fi
if [ -d "$CONFIG_DIR" ]; then
    echo "  - Configuration directory: $CONFIG_DIR"
fi
if id "$SERVICE_USER" &>/dev/null; then
    echo "  - Service user: $SERVICE_USER"
fi
if [ -d /etc/letsencrypt/live ]; then
    echo "  - SSL certificates: /etc/letsencrypt/"
fi
echo ""
echo "These can be manually removed if desired."
echo ""
echo "Thank you for trying pyIRCX!"
echo ""
echo "Feedback and bug reports: https://github.com/AI3I/pyIRCX/issues"
echo ""
