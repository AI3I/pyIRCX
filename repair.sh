#!/bin/bash
#
# pyIRCX Repair Script
#
# Validates and repairs an existing installation
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
echo "  pyIRCX Repair & Validation Script"
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

ISSUES_FOUND=0
FIXES_APPLIED=0

echo -e "${BLUE}Running validation checks...${NC}"
echo ""

# Check 1: Required files exist
echo "=== Checking Required Files ==="
REQUIRED_FILES=(
    "$INSTALL_DIR/pyircx.py"
    "$INSTALL_DIR/linking.py"
    "$CONFIG_DIR/pyircx_config.json"
    "/etc/systemd/system/pyircx.service"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $file"
    else
        echo -e "${RED}✗${NC} $file ${YELLOW}(MISSING)${NC}"
        ((ISSUES_FOUND++))
    fi
done
echo ""

# Check 2: Service user exists
echo "=== Checking Service User ==="
if id "$SERVICE_USER" &>/dev/null; then
    echo -e "${GREEN}✓${NC} User '$SERVICE_USER' exists"
else
    echo -e "${RED}✗${NC} User '$SERVICE_USER' does not exist ${YELLOW}(ISSUE)${NC}"
    ((ISSUES_FOUND++))
fi
echo ""

# Check 3: File permissions
echo "=== Checking File Permissions ==="
PERM_ISSUES=0

# Check pyircx.py is executable
if [ -f "$INSTALL_DIR/pyircx.py" ]; then
    if [ -x "$INSTALL_DIR/pyircx.py" ]; then
        echo -e "${GREEN}✓${NC} pyircx.py is executable"
    else
        echo -e "${YELLOW}⚠${NC} pyircx.py is not executable ${YELLOW}(FIXABLE)${NC}"
        ((PERM_ISSUES++))
    fi
fi

# Check ownership
if [ -d "$INSTALL_DIR" ]; then
    OWNER=$(stat -c '%U' "$INSTALL_DIR")
    if [ "$OWNER" == "$SERVICE_USER" ]; then
        echo -e "${GREEN}✓${NC} Install directory owned by $SERVICE_USER"
    else
        echo -e "${YELLOW}⚠${NC} Install directory owned by $OWNER (should be $SERVICE_USER) ${YELLOW}(FIXABLE)${NC}"
        ((PERM_ISSUES++))
    fi
fi

if [ -d "$CONFIG_DIR" ]; then
    OWNER=$(stat -c '%U' "$CONFIG_DIR")
    if [ "$OWNER" == "$SERVICE_USER" ]; then
        echo -e "${GREEN}✓${NC} Config directory owned by $SERVICE_USER"
    else
        echo -e "${YELLOW}⚠${NC} Config directory owned by $OWNER (should be $SERVICE_USER) ${YELLOW}(FIXABLE)${NC}"
        ((PERM_ISSUES++))
    fi
fi

if [ $PERM_ISSUES -gt 0 ]; then
    ((ISSUES_FOUND++))
fi
echo ""

# Check 4: Systemd service
echo "=== Checking Systemd Service ==="
if systemctl list-unit-files | grep -q pyircx.service; then
    echo -e "${GREEN}✓${NC} Service is installed"

    if systemctl is-enabled --quiet pyircx 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Service is enabled"
    else
        echo -e "${YELLOW}⚠${NC} Service is not enabled ${YELLOW}(FIXABLE)${NC}"
        ((ISSUES_FOUND++))
    fi

    if systemctl is-active --quiet pyircx 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Service is running"
    else
        echo -e "${YELLOW}⚠${NC} Service is not running ${YELLOW}(INFO)${NC}"
    fi
else
    echo -e "${RED}✗${NC} Service is not installed ${YELLOW}(ISSUE)${NC}"
    ((ISSUES_FOUND++))
fi
echo ""

# Check 5: Database
echo "=== Checking Database ==="
if [ -f "$INSTALL_DIR/pyircx.db" ]; then
    echo -e "${GREEN}✓${NC} Database exists"
    DB_SIZE=$(du -h "$INSTALL_DIR/pyircx.db" | cut -f1)
    echo "  Size: $DB_SIZE"
else
    echo -e "${YELLOW}⚠${NC} Database does not exist yet ${YELLOW}(Normal if never started)${NC}"
fi
echo ""

# Check 6: Cockpit module
echo "=== Checking Cockpit Module ==="
if [ -d /usr/share/cockpit/pyircx ]; then
    echo -e "${GREEN}✓${NC} Cockpit module installed (system-wide)"
    if [ -x /usr/share/cockpit/pyircx/api.py ]; then
        echo -e "${GREEN}✓${NC} Cockpit API is executable"
    else
        echo -e "${YELLOW}⚠${NC} Cockpit API is not executable ${YELLOW}(FIXABLE)${NC}"
        ((ISSUES_FOUND++))
    fi
elif [ -d ~/.local/share/cockpit/pyircx ]; then
    echo -e "${YELLOW}⚠${NC} Cockpit module in old user location ${YELLOW}(Should be system-wide)${NC}"
    ((ISSUES_FOUND++))
else
    echo -e "${BLUE}ℹ${NC} Cockpit module not installed ${BLUE}(Optional)${NC}"
fi
echo ""

# Check 7: Config symlink
echo "=== Checking Configuration Symlink ==="
if [ -L "$INSTALL_DIR/pyircx_config.json" ]; then
    TARGET=$(readlink -f "$INSTALL_DIR/pyircx_config.json")
    if [ "$TARGET" == "$CONFIG_DIR/pyircx_config.json" ]; then
        echo -e "${GREEN}✓${NC} Config symlink is correct"
    else
        echo -e "${YELLOW}⚠${NC} Config symlink points to wrong location ${YELLOW}(FIXABLE)${NC}"
        ((ISSUES_FOUND++))
    fi
elif [ -f "$INSTALL_DIR/pyircx_config.json" ]; then
    echo -e "${YELLOW}⚠${NC} Config is a regular file (should be symlink) ${YELLOW}(FIXABLE)${NC}"
    ((ISSUES_FOUND++))
else
    echo -e "${RED}✗${NC} Config symlink missing ${YELLOW}(FIXABLE)${NC}"
    ((ISSUES_FOUND++))
fi
echo ""

# Check 8: Python dependencies
echo "=== Checking Python Dependencies ==="
MISSING_DEPS=0
for dep in aiosqlite bcrypt pyotp cryptography; do
    if python3 -c "import $dep" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $dep"
    else
        echo -e "${RED}✗${NC} $dep ${YELLOW}(MISSING)${NC}"
        ((MISSING_DEPS++))
    fi
done

if [ $MISSING_DEPS -gt 0 ]; then
    ((ISSUES_FOUND++))
fi
echo ""

# Summary
echo "========================================"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ No issues found!${NC}"
    echo "========================================"
    echo ""
    echo "Installation appears to be healthy."
    exit 0
else
    echo -e "${YELLOW}⚠ Found $ISSUES_FOUND issue(s)${NC}"
    echo "========================================"
    echo ""
fi

# Offer to fix issues
read -p "Attempt to repair these issues? [Y/n] " -n 1 -r
echo
echo

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${BLUE}Starting repair...${NC}"
    echo ""

    # Fix missing service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        echo -e "${YELLOW}Creating service user...${NC}"
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        echo -e "${GREEN}✓ Service user created${NC}"
        ((FIXES_APPLIED++))
    fi

    # Fix permissions
    if [ $PERM_ISSUES -gt 0 ]; then
        echo -e "${YELLOW}Fixing permissions...${NC}"
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" 2>/dev/null || true
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR" 2>/dev/null || true
        chmod 755 "$INSTALL_DIR" 2>/dev/null || true  # Allow Cockpit access
        chmod 750 "$INSTALL_DIR/transcripts" 2>/dev/null || true  # Keep transcripts private
        chmod 644 "$INSTALL_DIR/pyircx.db" 2>/dev/null || true  # Database readable
        chmod 755 "$INSTALL_DIR/pyircx.py" 2>/dev/null || true
        chmod 755 "$INSTALL_DIR/linking.py" 2>/dev/null || true
        chmod 644 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true  # Config readable for Cockpit
        echo -e "${GREEN}✓ Permissions fixed${NC}"
        ((FIXES_APPLIED++))
    fi

    # Fix config symlink
    if [ ! -L "$INSTALL_DIR/pyircx_config.json" ] || [ "$(readlink -f "$INSTALL_DIR/pyircx_config.json")" != "$CONFIG_DIR/pyircx_config.json" ]; then
        echo -e "${YELLOW}Fixing config symlink...${NC}"
        rm -f "$INSTALL_DIR/pyircx_config.json"
        ln -sf "$CONFIG_DIR/pyircx_config.json" "$INSTALL_DIR/pyircx_config.json"
        echo -e "${GREEN}✓ Config symlink fixed${NC}"
        ((FIXES_APPLIED++))
    fi

    # Fix Cockpit permissions
    if [ -f /usr/share/cockpit/pyircx/api.py ] && [ ! -x /usr/share/cockpit/pyircx/api.py ]; then
        echo -e "${YELLOW}Fixing Cockpit API permissions...${NC}"
        chmod +x /usr/share/cockpit/pyircx/api.py
        echo -e "${GREEN}✓ Cockpit API permissions fixed${NC}"
        ((FIXES_APPLIED++))
    fi

    # Enable service if not enabled
    if systemctl list-unit-files | grep -q pyircx.service; then
        if ! systemctl is-enabled --quiet pyircx 2>/dev/null; then
            echo -e "${YELLOW}Enabling service...${NC}"
            systemctl enable pyircx
            echo -e "${GREEN}✓ Service enabled${NC}"
            ((FIXES_APPLIED++))
        fi
    fi

    # Reload systemd
    echo -e "${YELLOW}Reloading systemd...${NC}"
    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd reloaded${NC}"

    # Install missing Python dependencies
    if [ $MISSING_DEPS -gt 0 ]; then
        echo -e "${YELLOW}Installing missing Python dependencies...${NC}"
        pip3 install --upgrade aiosqlite bcrypt pyotp cryptography
        echo -e "${GREEN}✓ Python dependencies installed${NC}"
        ((FIXES_APPLIED++))
    fi

    echo ""
    echo "========================================"
    echo -e "${GREEN}Repair Complete!${NC}"
    echo "========================================"
    echo ""
    echo "Fixed $FIXES_APPLIED issue(s)"
    echo ""
    echo "Recommendations:"
    echo "  1. Restart the service: systemctl restart pyircx"
    echo "  2. Check status: systemctl status pyircx"
    echo "  3. View logs: journalctl -u pyircx -f"
    echo ""
else
    echo "No repairs performed."
fi

echo ""
