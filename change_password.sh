#!/bin/bash
#
# pyIRCX Password Management Utility
# Changes passwords for various pyIRCX components
#
# Usage:
#   ./change_password.sh staff <username>        - Change staff account password
#   ./change_password.sh webirc                  - Change WEBIRC gateway password
#   ./change_password.sh webchat                 - Change WebChat gateway password
#   ./change_password.sh webadmin <username>     - Change WebAdmin staff login password
#   ./change_password.sh all                     - Interactive password change for all components

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
INSTALL_DIR="/opt/pyircx"
CONFIG_DIR="/etc/pyircx"
API_SCRIPT="$INSTALL_DIR/api.py"
CONFIG_FILE="$CONFIG_DIR/pyircx_config.json"
WEBCHAT_CONF="$CONFIG_DIR/webchat.conf"

# Functions
show_usage() {
    echo "pyIRCX Password Management Utility"
    echo ""
    echo "Usage:"
    echo "  $0 staff <username>        - Change staff account password (admin/sysop/guide)"
    echo "  $0 webirc                  - Change WEBIRC gateway password"
    echo "  $0 webchat                 - Change WebChat gateway password"
    echo "  $0 webadmin <username>     - Change WebAdmin staff login password"
    echo "  $0 all                     - Interactive password change for all components"
    echo ""
    echo "Examples:"
    echo "  $0 staff admin"
    echo "  $0 webirc"
    echo "  $0 all"
    echo ""
}

change_staff_password() {
    local username="$1"

    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: $0 staff <username>"
        exit 1
    fi

    echo -e "${BLUE}Changing password for staff account: ${YELLOW}$username${NC}"
    echo ""

    # Check if api.py exists
    if [ ! -f "$API_SCRIPT" ]; then
        echo -e "${RED}Error: $API_SCRIPT not found${NC}"
        exit 1
    fi

    # Prompt for new password
    read -sp "Enter new password: " password
    echo ""
    read -sp "Confirm password: " password2
    echo ""

    if [ "$password" != "$password2" ]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        exit 1
    fi

    if [ ${#password} -lt 8 ]; then
        echo -e "${RED}Error: Password must be at least 8 characters${NC}"
        exit 1
    fi

    # Change password using API via stdin to avoid exposing it in argv
    python3 - "$password" <<'PY' | python3 "$API_SCRIPT" change-staff-password-stdin "$username"
import json
import sys
print(json.dumps({"password": sys.argv[1]}))
PY

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Password changed successfully for $username${NC}"
        echo ""
        echo "You can now authenticate with:"
        echo "  /QUOTE PASS $username:<newpassword>"
        echo ""
        echo -e "${YELLOW}⚠ Security Reminder:${NC}"
        echo "  Ensure SSL/TLS is configured for secure authentication."
        echo "  Enable 'auth_require_ssl' in $CONFIG_FILE after SSL setup:"
        echo "    \"auth_require_ssl\": true"
        echo ""
        echo "  Configure SSL with: sudo ./setup_ssl.sh"
    else
        echo -e "${RED}✗ Failed to change password${NC}"
        exit 1
    fi
}

change_webirc_password() {
    echo -e "${BLUE}Changing WEBIRC gateway password${NC}"
    echo ""

    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}Error: $CONFIG_FILE not found${NC}"
        exit 1
    fi

    # Prompt for new password
    read -sp "Enter new WEBIRC password: " password
    echo ""
    read -sp "Confirm password: " password2
    echo ""

    if [ "$password" != "$password2" ]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        exit 1
    fi

    if [ ${#password} -lt 12 ]; then
        echo -e "${YELLOW}Warning: WEBIRC password should be at least 12 characters for security${NC}"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Backup config
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"

    # Update config using Python to preserve JSON structure
    python3 -c "
import json
import sys

config_file = '$CONFIG_FILE'
new_password = '''$password'''

try:
    with open(config_file, 'r') as f:
        config = json.load(f)

    if 'security' not in config:
        config['security'] = {}
    if 'webirc' not in config['security']:
        config['security']['webirc'] = {}
    if 'hosts' not in config['security']['webirc']:
        config['security']['webirc']['hosts'] = {}

    # Update password for WebChat gateway (localhost)
    if '127.0.0.1' in config['security']['webirc']['hosts']:
        config['security']['webirc']['hosts']['127.0.0.1']['password'] = new_password
    if 'localhost' in config['security']['webirc']['hosts']:
        config['security']['webirc']['hosts']['localhost']['password'] = new_password

    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)

    print('Config updated successfully')
except Exception as e:
    print(f'Error updating config: {e}', file=sys.stderr)
    sys.exit(1)
"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ WEBIRC password updated in $CONFIG_FILE${NC}"
        echo -e "${YELLOW}Note: You must also update the WebChat gateway password${NC}"

        # Ask if they want to update WebChat too
        read -p "Update WebChat gateway password now? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            update_webchat_env "$password"
        fi
    else
        echo -e "${RED}✗ Failed to update WEBIRC password${NC}"
        exit 1
    fi
}

update_webchat_env() {
    local password="$1"

    if [ ! -f "$WEBCHAT_CONF" ]; then
        echo -e "${YELLOW}WebChat config not found, skipping${NC}"
        return
    fi

    # Backup config
    cp "$WEBCHAT_CONF" "$WEBCHAT_CONF.backup.$(date +%Y%m%d_%H%M%S)"

    python3 - "$WEBCHAT_CONF" "$password" <<'PY'
import configparser
import sys

config_path = sys.argv[1]
password = sys.argv[2]

cfg = configparser.ConfigParser()
cfg.read(config_path)
if not cfg.has_section('webirc'):
    cfg.add_section('webirc')
cfg.set('webirc', 'password', password)

with open(config_path, 'w', encoding='utf-8') as fh:
    cfg.write(fh)
PY

    echo -e "${GREEN}✓ WebChat config updated${NC}"
    echo -e "${YELLOW}Restart pyircx-webchat service to apply: systemctl restart pyircx-webchat${NC}"
}

change_webchat_password() {
    echo -e "${BLUE}Changing WebChat gateway password${NC}"
    echo ""

    # Prompt for new password
    read -sp "Enter new WebChat WEBIRC password: " password
    echo ""
    read -sp "Confirm password: " password2
    echo ""

    if [ "$password" != "$password2" ]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        exit 1
    fi

    update_webchat_env "$password"

    echo ""
    echo -e "${YELLOW}Note: You must also update the WEBIRC password in $CONFIG_FILE${NC}"
    echo "Run: $0 webirc"
}

change_webadmin_password() {
    local username="$1"

    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: $0 webadmin <username>"
        exit 1
    fi

    echo -e "${BLUE}Changing WebAdmin staff login password for: ${YELLOW}$username${NC}"
    echo ""

    # Prompt for new password
    read -sp "Enter new password: " password
    echo ""
    read -sp "Confirm password: " password2
    echo ""

    if [ "$password" != "$password2" ]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        exit 1
    fi

    python3 - "$password" <<'PY' | python3 "$API_SCRIPT" change-staff-password-stdin "$username"
import json
import sys
print(json.dumps({"password": sys.argv[1]}))
PY

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ WebAdmin password changed successfully${NC}"
        echo -e "${YELLOW}Note:${NC} WebAdmin authenticates against the IRC staff account database."
    else
        echo -e "${RED}✗ Failed to change WebAdmin password${NC}"
        exit 1
    fi
}

interactive_all() {
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}  pyIRCX Password Management${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    # Staff accounts
    echo -e "${YELLOW}Change staff account passwords?${NC}"
    read -p "Change admin password? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        change_staff_password "admin"
        echo ""
    fi

    read -p "Change sysop password? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        change_staff_password "sysop"
        echo ""
    fi

    read -p "Change guide password? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        change_staff_password "guide"
        echo ""
    fi

    # WEBIRC
    echo -e "${YELLOW}Change WEBIRC gateway password?${NC}"
    read -p "This affects WebChat connectivity [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        change_webirc_password
        echo ""
    fi

    echo -e "${GREEN}Password changes complete!${NC}"
}

# Main
case "${1:-}" in
    staff)
        change_staff_password "$2"
        ;;
    webirc)
        change_webirc_password
        ;;
    webchat)
        change_webchat_password
        ;;
    webadmin)
        change_webadmin_password "$2"
        ;;
    all)
        interactive_all
        ;;
    ""|--help|-h)
        show_usage
        exit 0
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac
