#!/bin/bash
#
# pyIRCX Upgrade Script
#
# Intelligently upgrades an existing installation to the latest version
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
SERVICE_USER="pyircx"
SERVICE_GROUP="pyircx"

echo ""
echo "========================================"
echo "  pyIRCX Upgrade Script"
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
NEEDS_SYSTEMD_UPDATE=0
NEEDS_COCKPIT_UPDATE=0
NEEDS_PERMISSION_FIX=0
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

# Check systemd service file
if [ -f /etc/systemd/system/pyircx.service ]; then
    if grep -q "ProtectSystem=strict" /etc/systemd/system/pyircx.service; then
        echo -e "${YELLOW}✗ Systemd service using old restrictive settings${NC}"
        NEEDS_SYSTEMD_UPDATE=1
    else
        echo -e "${GREEN}✓ Systemd service up to date${NC}"
    fi
else
    echo -e "${YELLOW}✗ Systemd service file missing${NC}"
    NEEDS_SYSTEMD_UPDATE=1
fi

# Check Cockpit installation location
if [ -d ~/.local/share/cockpit/pyircx ]; then
    echo -e "${YELLOW}✗ Cockpit installed in old user location${NC}"
    NEEDS_COCKPIT_UPDATE=1
elif [ -d /usr/share/cockpit/pyircx ]; then
    echo -e "${GREEN}✓ Cockpit installed system-wide${NC}"
fi

# Check file permissions
if [ -f "$INSTALL_DIR/pyircx.py" ]; then
    if [ ! -x "$INSTALL_DIR/pyircx.py" ]; then
        echo -e "${YELLOW}✗ Main script not executable${NC}"
        NEEDS_PERMISSION_FIX=1
    fi
fi

# Calculate total updates needed
TOTAL_UPDATES=$((NEEDS_LINKING_PY + NEEDS_SYSTEMD_UPDATE + NEEDS_COCKPIT_UPDATE + NEEDS_PERMISSION_FIX))

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

# Backup current installation
echo ""
echo -e "${BLUE}Creating backup...${NC}"
BACKUP_DIR="/tmp/pyircx_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r "$INSTALL_DIR" "$BACKUP_DIR/opt/" 2>/dev/null || true
cp -r "$CONFIG_DIR" "$BACKUP_DIR/etc/" 2>/dev/null || true
cp /etc/systemd/system/pyircx.service "$BACKUP_DIR/" 2>/dev/null || true
echo -e "${GREEN}✓ Backup created at: $BACKUP_DIR${NC}"

# Update files
echo ""
echo -e "${BLUE}Updating files...${NC}"

# Copy main scripts
cp "$SCRIPT_DIR/pyircx.py" "$INSTALL_DIR/"
echo -e "${GREEN}✓ Updated pyircx.py${NC}"

if [ $NEEDS_LINKING_PY -eq 1 ] || [ -f "$SCRIPT_DIR/linking.py" ]; then
    cp "$SCRIPT_DIR/linking.py" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Updated linking.py${NC}"
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

# Update Cockpit installation
if [ $NEEDS_COCKPIT_UPDATE -eq 1 ] || [ -d "$SCRIPT_DIR/cockpit/pyircx" ]; then
    echo ""
    echo -e "${BLUE}Updating Cockpit module...${NC}"

    # Remove old user installation
    if [ -d ~/.local/share/cockpit/pyircx ]; then
        echo -e "${YELLOW}Removing old user installation...${NC}"
        rm -rf ~/.local/share/cockpit/pyircx
    fi

    # Install system-wide
    mkdir -p /usr/share/cockpit
    cp -r "$SCRIPT_DIR/cockpit/pyircx" /usr/share/cockpit/
    chmod +x /usr/share/cockpit/pyircx/api.py

    # Restart Cockpit if running
    if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
        systemctl restart cockpit.socket
        echo -e "${GREEN}✓ Cockpit module updated and reloaded${NC}"
    else
        echo -e "${GREEN}✓ Cockpit module updated${NC}"
    fi
fi

# Fix permissions
echo ""
echo -e "${BLUE}Fixing permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
chmod 750 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/pyircx.py"
chmod 755 "$INSTALL_DIR/linking.py" 2>/dev/null || true
chmod 640 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true
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
echo "Commands:"
echo "  systemctl status pyircx   - Check status"
echo "  systemctl start pyircx    - Start server"
echo "  systemctl restart pyircx  - Restart server"
echo "  journalctl -u pyircx -f   - View logs"
echo ""

if [ $NEEDS_COCKPIT_UPDATE -eq 1 ]; then
    echo "Cockpit updated - refresh your browser to see changes"
    echo "  https://localhost:9090"
    echo ""
fi

echo -e "${GREEN}All done!${NC}"
echo ""
