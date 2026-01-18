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

# Check 0: Version consistency
echo "=== Checking Version Consistency ==="
if [ -f "$INSTALL_DIR/pyircx.py" ]; then
    PYIRCX_VERSION=$(grep "__version__" "$INSTALL_DIR/pyircx.py" | head -1 | cut -d'"' -f2)
    echo -e "${GREEN}pyircx.py version: $PYIRCX_VERSION${NC}"

    # Check webadmin/index.php
    if [ -f "/var/www/html/webadmin/index.php" ]; then
        WEBADMIN_VER=$(grep -o "pyIRCX v[0-9]\+\.[0-9]\+\.[0-9]\+" /var/www/html/webadmin/index.php | head -1 | sed 's/pyIRCX v//')
        if [ "$PYIRCX_VERSION" != "$WEBADMIN_VER" ]; then
            echo -e "${YELLOW}⚠${NC} webadmin/index.php version mismatch: $WEBADMIN_VER (expected $PYIRCX_VERSION)"
            ((ISSUES_FOUND++))
        else
            echo -e "${GREEN}✓${NC} webadmin/index.php version matches"
        fi
    fi

    # Check webchat/index.html
    WEBCHAT_LOCATIONS=(
        "/var/www/html/webchat/index.html"
        "/usr/share/nginx/html/webchat/index.html"
    )
    for location in "${WEBCHAT_LOCATIONS[@]}"; do
        if [ -f "$location" ]; then
            WEBCHAT_VER=$(grep -o "v[0-9]\+\.[0-9]\+\.[0-9]\+</span>" "$location" | head -1 | sed 's/v\(.*\)<\/span>/\1/')
            if [ "$PYIRCX_VERSION" != "$WEBCHAT_VER" ]; then
                echo -e "${YELLOW}⚠${NC} webchat/index.html version mismatch: $WEBCHAT_VER (expected $PYIRCX_VERSION)"
                ((ISSUES_FOUND++))
            else
                echo -e "${GREEN}✓${NC} webchat/index.html version matches"
            fi
            break
        fi
    done
else
    echo -e "${RED}✗${NC} pyircx.py not found, cannot check version"
    ((ISSUES_FOUND++))
fi
echo ""

# Check 1: Required files exist
echo "=== Checking Required Files ==="
REQUIRED_FILES=(
    "$INSTALL_DIR/pyircx.py"
    "$INSTALL_DIR/api.py"
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

# Check 6: Web Admin Panel
echo "=== Checking Web Admin Panel ==="
WEB_ADMIN_DIR="/var/www/html/webadmin"
if [ -d "$WEB_ADMIN_DIR" ]; then
    echo -e "${GREEN}✓${NC} Web Admin directory exists"

    # Check required files
    REQUIRED_WEB_FILES=("index.php" "login.php" "api.php" "admin.js" "style.css")
    WEB_ISSUES=0
    for file in "${REQUIRED_WEB_FILES[@]}"; do
        if [ -f "$WEB_ADMIN_DIR/$file" ]; then
            echo -e "${GREEN}✓${NC} $file"
        else
            echo -e "${RED}✗${NC} $file missing"
            ((WEB_ISSUES++))
        fi
    done

    # Check ownership
    OWNER=$(stat -c '%U' "$WEB_ADMIN_DIR" 2>/dev/null || echo "unknown")
    if [ "$OWNER" == "apache" ]; then
        echo -e "${GREEN}✓${NC} Web admin owned by apache"
    else
        echo -e "${YELLOW}⚠${NC} Web admin owned by $OWNER (should be apache) ${YELLOW}(FIXABLE)${NC}"
        ((WEB_ISSUES++))
    fi

    # Check apache in systemd-journal group
    if groups apache 2>/dev/null | grep -q systemd-journal; then
        echo -e "${GREEN}✓${NC} apache user in systemd-journal group"
    else
        echo -e "${YELLOW}⚠${NC} apache not in systemd-journal group ${YELLOW}(FIXABLE)${NC}"
        ((WEB_ISSUES++))
    fi

    # Check polkit rules
    if [ -f /etc/polkit-1/rules.d/10-pyircx-admin.rules ]; then
        echo -e "${GREEN}✓${NC} Polkit rules installed"
    else
        echo -e "${YELLOW}⚠${NC} Polkit rules missing ${YELLOW}(FIXABLE)${NC}"
        ((WEB_ISSUES++))
    fi

    # Check SELinux policies (if SELinux is enabled)
    if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
        if semodule -l 2>/dev/null | grep -q pyircx-httpd-systemd; then
            echo -e "${GREEN}✓${NC} SELinux httpd-systemd policy installed"
        else
            echo -e "${YELLOW}⚠${NC} SELinux httpd-systemd policy missing ${YELLOW}(FIXABLE)${NC}"
            ((WEB_ISSUES++))
        fi

        if semodule -l 2>/dev/null | grep -q pyircx-httpd-journal; then
            echo -e "${GREEN}✓${NC} SELinux httpd-journal policy installed"
        else
            echo -e "${YELLOW}⚠${NC} SELinux httpd-journal policy missing ${YELLOW}(FIXABLE)${NC}"
            ((WEB_ISSUES++))
        fi
    fi

    if [ $WEB_ISSUES -gt 0 ]; then
        ((ISSUES_FOUND++))
    fi
else
    echo -e "${BLUE}ℹ${NC} Web Admin Panel not installed ${BLUE}(Optional)${NC}"
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

# Check 9: WebChat (optional)
echo "=== Checking WebChat (Optional) ==="
WEBCHAT_ISSUES=0
if [ -d "$INSTALL_DIR/webchat" ]; then
    echo -e "${GREEN}✓${NC} WebChat directory exists"

    # Check gateway.py
    if [ -f "$INSTALL_DIR/webchat/gateway.py" ]; then
        echo -e "${GREEN}✓${NC} gateway.py exists"
        if [ -x "$INSTALL_DIR/webchat/gateway.py" ]; then
            echo -e "${GREEN}✓${NC} gateway.py is executable"
        else
            echo -e "${YELLOW}⚠${NC} gateway.py is not executable ${YELLOW}(FIXABLE)${NC}"
            ((WEBCHAT_ISSUES++))
        fi
    else
        echo -e "${RED}✗${NC} gateway.py missing ${YELLOW}(ISSUE)${NC}"
        ((WEBCHAT_ISSUES++))
    fi

    # Check index.html
    if [ -f "$INSTALL_DIR/webchat/index.html" ]; then
        echo -e "${GREEN}✓${NC} index.html exists"
    else
        echo -e "${RED}✗${NC} index.html missing ${YELLOW}(ISSUE)${NC}"
        ((WEBCHAT_ISSUES++))
    fi

    # Check config.js
    if [ -f "/var/www/html/webchat/config.js" ]; then
        echo -e "${GREEN}✓${NC} config.js exists"
    else
        echo -e "${YELLOW}⚠${NC} config.js missing ${YELLOW}(FIXABLE)${NC}"
        ((WEBCHAT_ISSUES++))
    fi

    # Check webchat config
    if [ -f "$CONFIG_DIR/webchat.conf" ]; then
        echo -e "${GREEN}✓${NC} webchat.conf exists"
    else
        echo -e "${YELLOW}⚠${NC} webchat.conf missing ${YELLOW}(FIXABLE)${NC}"
        ((WEBCHAT_ISSUES++))
    fi

    # Check websockets module
    if python3 -c "import websockets" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} websockets module installed"
    else
        echo -e "${RED}✗${NC} websockets module missing ${YELLOW}(FIXABLE)${NC}"
        ((WEBCHAT_ISSUES++))
    fi

    # Check service
    if systemctl list-unit-files | grep -q pyircx-webchat.service; then
        echo -e "${GREEN}✓${NC} WebChat service installed"
        if systemctl is-enabled --quiet pyircx-webchat 2>/dev/null; then
            echo -e "${GREEN}✓${NC} WebChat service is enabled"
        else
            echo -e "${YELLOW}⚠${NC} WebChat service is not enabled ${YELLOW}(FIXABLE)${NC}"
            ((WEBCHAT_ISSUES++))
        fi
        if systemctl is-active --quiet pyircx-webchat 2>/dev/null; then
            echo -e "${GREEN}✓${NC} WebChat service is running"
        else
            echo -e "${YELLOW}⚠${NC} WebChat service is not running ${YELLOW}(INFO)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠${NC} WebChat service not installed"
    fi

    if [ $WEBCHAT_ISSUES -gt 0 ]; then
        ((ISSUES_FOUND++))
    fi
else
    echo -e "${BLUE}ℹ${NC} WebChat not installed ${BLUE}(Optional)${NC}"
fi
echo ""

# Check 10: API file permissions
echo "=== Checking API File ==="
if [ -f "$INSTALL_DIR/api.py" ]; then
    echo -e "${GREEN}✓${NC} API file exists"

    # Check executable
    if [ -x "$INSTALL_DIR/api.py" ]; then
        echo -e "${GREEN}✓${NC} API is executable"
    else
        echo -e "${YELLOW}⚠${NC} API is not executable ${YELLOW}(FIXABLE)${NC}"
        ((ISSUES_FOUND++))
    fi

    # Check ownership
    OWNER=$(stat -c '%U' "$INSTALL_DIR/api.py")
    if [ "$OWNER" == "$SERVICE_USER" ]; then
        echo -e "${GREEN}✓${NC} API owned by $SERVICE_USER"
    else
        echo -e "${YELLOW}⚠${NC} API owned by $OWNER (should be $SERVICE_USER) ${YELLOW}(FIXABLE)${NC}"
        ((ISSUES_FOUND++))
    fi
else
    echo -e "${YELLOW}⚠${NC} API file missing"
    ((ISSUES_FOUND++))
fi
echo ""

# Check 11: SSL/Certbot (optional)
echo "=== SSL Configuration ==="

# Check if SSL is enabled in config
if grep -q '"enabled": true' "$CONFIG_DIR/pyircx_config.json" 2>/dev/null | head -1 | grep -q ssl; then
    SSL_ENABLED=1
else
    SSL_ENABLED=0
fi

# Check certbot timer
if [ -f /etc/systemd/system/pyircx-certbot-renew.timer ]; then
    echo -e "${GREEN}✓${NC} Certbot renewal timer installed"
    if systemctl is-enabled --quiet pyircx-certbot-renew.timer 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Certbot timer enabled"
    else
        echo -e "${YELLOW}⚠${NC} Certbot timer not enabled ${YELLOW}(FIXABLE)${NC}"
        ISSUES=$((ISSUES + 1))
        FIXABLE=$((FIXABLE + 1))
    fi
fi

# Check ssl-cert group
if getent group ssl-cert &>/dev/null; then
    if groups "$SERVICE_USER" 2>/dev/null | grep -q ssl-cert; then
        echo -e "${GREEN}✓${NC} User in ssl-cert group"
    else
        echo -e "${YELLOW}⚠${NC} User not in ssl-cert group ${YELLOW}(FIXABLE)${NC}"
        ISSUES=$((ISSUES + 1))
        FIXABLE=$((FIXABLE + 1))
    fi
fi

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
        chmod 775 "$INSTALL_DIR" 2>/dev/null || true  # Group needs write for SQLite journal files
        chmod 775 "$CONFIG_DIR" 2>/dev/null || true  # Group needs write for web admin config edits
        chmod 750 "$INSTALL_DIR/transcripts" 2>/dev/null || true  # Keep transcripts private
        chmod 660 "$INSTALL_DIR/pyircx.db" 2>/dev/null || true  # Database group writable
        chmod 600 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true  # Config owner-only (sensitive data)
        chmod 755 "$INSTALL_DIR/pyircx.py" 2>/dev/null || true
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

        # Fix SELinux contexts if enabled (comprehensive configuration)
        if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
            if command -v semanage &> /dev/null && command -v restorecon &> /dev/null; then
                echo -e "${YELLOW}Fixing SELinux contexts...${NC}"

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

                echo -e "${GREEN}✓ SELinux contexts fixed${NC}"
            fi
        fi

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

    # Fix API permissions
    if [ -f "$INSTALL_DIR/api.py" ]; then
        if [ ! -x "$INSTALL_DIR/api.py" ]; then
            echo -e "${YELLOW}Fixing API permissions...${NC}"
            chmod 755 "$INSTALL_DIR/api.py"
            echo -e "${GREEN}✓ API permissions fixed${NC}"
            ((FIXES_APPLIED++))
        fi

        # Fix API ownership
        OWNER=$(stat -c '%U' "$INSTALL_DIR/api.py")
        if [ "$OWNER" != "$SERVICE_USER" ]; then
            echo -e "${YELLOW}Fixing API ownership...${NC}"
            chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/api.py"
            echo -e "${GREEN}✓ API ownership fixed${NC}"
            ((FIXES_APPLIED++))
        fi
    fi

    # Fix web admin ownership if installed
    if [ -d "$WEB_ADMIN_DIR" ]; then
        OWNER=$(stat -c '%U' "$WEB_ADMIN_DIR" 2>/dev/null || echo "unknown")
        if [ "$OWNER" != "apache" ]; then
            echo -e "${YELLOW}Fixing web admin ownership...${NC}"
            chown -R apache:apache "$WEB_ADMIN_DIR"
            echo -e "${GREEN}✓ Web admin ownership fixed${NC}"
            ((FIXES_APPLIED++))
        fi

        # Add apache to systemd-journal group
        if ! groups apache 2>/dev/null | grep -q systemd-journal; then
            echo -e "${YELLOW}Adding apache to systemd-journal group...${NC}"
            usermod -a -G systemd-journal apache
            echo -e "${GREEN}✓ apache added to systemd-journal group${NC}"
            ((FIXES_APPLIED++))
        fi
    fi

    # Enable service if not enabled
    if systemctl list-unit-files | grep -q pyircx.service; then
        if ! systemctl is-enabled --quiet pyircx 2>/dev/null; then
            echo -e "${YELLOW}Enabling pyircx service...${NC}"
            systemctl enable pyircx
            echo -e "${GREEN}✓ pyircx service enabled${NC}"
            ((FIXES_APPLIED++))
        fi
    fi

    # Fix WebChat issues - create directory if missing
    if [ ! -d "$INSTALL_DIR/webchat" ]; then
        echo -e "${YELLOW}Creating WebChat backend directory...${NC}"
        mkdir -p "$INSTALL_DIR/webchat"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/webchat"
        echo -e "${GREEN}✓ WebChat backend directory created${NC}"
        ((FIXES_APPLIED++))
    fi

    # Fix WebChat issues if installed
    if [ -d "$INSTALL_DIR/webchat" ]; then
        # Fix gateway.py permissions
        if [ -f "$INSTALL_DIR/webchat/gateway.py" ] && [ ! -x "$INSTALL_DIR/webchat/gateway.py" ]; then
            echo -e "${YELLOW}Fixing WebChat gateway permissions...${NC}"
            chmod 755 "$INSTALL_DIR/webchat/gateway.py"
            echo -e "${GREEN}✓ WebChat gateway permissions fixed${NC}"
            ((FIXES_APPLIED++))
        fi

        # Install websockets if missing
        if ! python3 -c "import websockets" 2>/dev/null; then
            echo -e "${YELLOW}Installing websockets module...${NC}"
            pip3 install websockets
            echo -e "${GREEN}✓ websockets module installed${NC}"
            ((FIXES_APPLIED++))
        fi

        # Create webchat.conf if missing
        if [ ! -f "$CONFIG_DIR/webchat.conf" ]; then
            echo -e "${YELLOW}Creating webchat.conf...${NC}"
            cat > "$CONFIG_DIR/webchat.conf" <<EOF
# pyIRCX WebChat Gateway Configuration
WS_PORT=8765
WS_HOST=0.0.0.0
IRC_HOST=localhost
IRC_PORT=6667
WEBIRC_PASS=changeme
EOF
            chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/webchat.conf"
            chmod 640 "$CONFIG_DIR/webchat.conf"
            echo -e "${GREEN}✓ webchat.conf created${NC}"
            ((FIXES_APPLIED++))
        fi

        # Enable webchat service if not enabled
        if systemctl list-unit-files | grep -q pyircx-webchat.service; then
            if ! systemctl is-enabled --quiet pyircx-webchat 2>/dev/null; then
                echo -e "${YELLOW}Enabling pyircx-webchat service...${NC}"
                systemctl enable pyircx-webchat
                echo -e "${GREEN}✓ pyircx-webchat service enabled${NC}"
                ((FIXES_APPLIED++))
            fi
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
