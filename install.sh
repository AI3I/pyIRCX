#!/bin/bash
#
# pyIRCX Installation Script
#
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch Linux, openSUSE
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default installation paths
INSTALL_DIR="/opt/pyircx"
CONFIG_DIR="/etc/pyircx"
SERVICE_USER="pyircx"
SERVICE_GROUP="pyircx"

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

# Check Python version
check_python() {
    echo -e "${YELLOW}Checking Python version...${NC}"

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            echo -e "${GREEN}Python $PYTHON_VERSION found${NC}"
            return 0
        fi
    fi

    echo -e "${RED}Error: Python 3.8+ is required${NC}"
    echo "Please install Python 3.8 or later"
    exit 1
}

# Install dependencies based on OS
install_dependencies() {
    local os=$(detect_os)
    echo -e "${YELLOW}Installing dependencies for $os...${NC}"

    case $os in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|parrot|raspbian)
            apt-get update
            apt-get install -y python3 python3-pip python3-venv
            ;;
        fedora)
            dnf install -y python3 python3-pip
            ;;
        centos|rhel|rocky|almalinux|oracle|scientific)
            if [ -f /etc/centos-release ] || [ "$VERSION_ID" -lt 8 ]; then
                yum install -y python3 python3-pip
            else
                dnf install -y python3 python3-pip
            fi
            ;;
        arch|manjaro|endeavouros|garuda|artix)
            pacman -Sy --noconfirm python python-pip
            ;;
        opensuse*|sles|tumbleweed)
            zypper install -y python3 python3-pip
            ;;
        gentoo|funtoo)
            emerge --ask=n dev-lang/python dev-python/pip
            ;;
        void)
            xbps-install -Sy python3 python3-pip
            ;;
        alpine)
            apk add --no-cache python3 py3-pip
            ;;
        solus)
            eopkg install -y python3 pip
            ;;
        nixos)
            echo -e "${YELLOW}NixOS detected. Please add python3 and pip to your configuration.nix${NC}"
            echo "Example: environment.systemPackages = with pkgs; [ python3 python3Packages.pip ];"
            ;;
        clear-linux-os)
            swupd bundle-add python3-basic
            ;;
        mageia)
            urpmi python3 python3-pip
            ;;
        slackware)
            # Slackware typically has Python pre-installed
            echo -e "${GREEN}Slackware detected. Python should be pre-installed.${NC}"
            if ! command -v pip3 &> /dev/null; then
                echo -e "${YELLOW}pip not found. Installing pip...${NC}"
                python3 -m ensurepip --default-pip || python3 <(curl -sS https://bootstrap.pypa.io/get-pip.py)
            fi
            ;;
        *)
            echo -e "${YELLOW}Unknown OS ($os), attempting generic installation...${NC}"
            # Try to detect package manager and install
            if command -v apt-get &> /dev/null; then
                apt-get update && apt-get install -y python3 python3-pip python3-venv
            elif command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip
            elif command -v yum &> /dev/null; then
                yum install -y python3 python3-pip
            elif command -v pacman &> /dev/null; then
                pacman -Sy --noconfirm python python-pip
            elif command -v zypper &> /dev/null; then
                zypper install -y python3 python3-pip
            elif command -v apk &> /dev/null; then
                apk add --no-cache python3 py3-pip
            elif command -v emerge &> /dev/null; then
                emerge --ask=n dev-lang/python dev-python/pip
            else
                echo -e "${YELLOW}No supported package manager found.${NC}"
                echo -e "${YELLOW}Please ensure Python 3.8+ and pip are installed manually.${NC}"
            fi
            ;;
    esac
}

# Install Python packages
install_python_packages() {
    echo -e "${YELLOW}Installing Python packages...${NC}"

    pip3 install --upgrade pip
    pip3 install aiosqlite bcrypt pyotp cryptography

    echo -e "${GREEN}Python packages installed${NC}"
}

# Create service user
create_user() {
    echo -e "${YELLOW}Creating service user...${NC}"

    if id "$SERVICE_USER" &>/dev/null; then
        echo "User $SERVICE_USER already exists"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        echo -e "${GREEN}User $SERVICE_USER created${NC}"
    fi

    # Add user to ssl-cert group for Let's Encrypt certificate access (Debian/Ubuntu)
    if getent group ssl-cert &>/dev/null; then
        if ! groups "$SERVICE_USER" 2>/dev/null | grep -q ssl-cert; then
            usermod -a -G ssl-cert "$SERVICE_USER"
            echo -e "${GREEN}User added to ssl-cert group${NC}"
        fi
    fi
}

# Create directories
create_directories() {
    echo -e "${YELLOW}Creating directories...${NC}"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/transcripts"
    mkdir -p "$CONFIG_DIR"

    echo -e "${GREEN}Directories created${NC}"
}

# Copy files
copy_files() {
    echo -e "${YELLOW}Copying files...${NC}"

    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy main script and modules
    cp "$SCRIPT_DIR/pyircx.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/linking.py" "$INSTALL_DIR/"

    # Copy or create config
    if [ -f "$SCRIPT_DIR/pyircx_config.json" ]; then
        if [ ! -f "$CONFIG_DIR/pyircx_config.json" ]; then
            cp "$SCRIPT_DIR/pyircx_config.json" "$CONFIG_DIR/"
        else
            echo "Config already exists, not overwriting"
        fi
    fi

    # Create symlink for config
    ln -sf "$CONFIG_DIR/pyircx_config.json" "$INSTALL_DIR/pyircx_config.json"

    echo -e "${GREEN}Files copied${NC}"
}

# Set permissions
set_permissions() {
    echo -e "${YELLOW}Setting permissions...${NC}"

    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 640 "$CONFIG_DIR/pyircx_config.json" 2>/dev/null || true
    chmod 755 "$INSTALL_DIR/pyircx.py"

    echo -e "${GREEN}Permissions set${NC}"
}

# Install Cockpit module
install_cockpit() {
    echo -e "${YELLOW}Installing Cockpit web admin panel...${NC}"

    local os=$(detect_os)

    # Install Cockpit package
    case "$os" in
        fedora|rhel|centos|rocky|almalinux|oracle|scientific)
            dnf install -y cockpit || yum install -y cockpit
            ;;
        debian|ubuntu|linuxmint|pop|elementary|zorin|kali|parrot|raspbian)
            apt-get update
            apt-get install -y cockpit
            ;;
        arch|manjaro|endeavouros|garuda)
            pacman -S --noconfirm cockpit
            ;;
        opensuse*|sles|tumbleweed)
            zypper install -y cockpit
            ;;
        gentoo|funtoo)
            echo -e "${YELLOW}Gentoo detected. Installing Cockpit from overlay...${NC}"
            emerge --ask=n app-admin/cockpit || echo -e "${YELLOW}Cockpit may require manual installation from overlay${NC}"
            ;;
        void)
            xbps-install -Sy cockpit
            ;;
        alpine)
            echo -e "${YELLOW}Alpine Linux: Cockpit may not be available in standard repos${NC}"
            echo "Consider using a lightweight alternative or building from source"
            return 1
            ;;
        *)
            echo -e "${YELLOW}Unknown OS. Attempting generic installation...${NC}"
            if command -v apt-get &> /dev/null; then
                apt-get update && apt-get install -y cockpit
            elif command -v dnf &> /dev/null; then
                dnf install -y cockpit
            elif command -v yum &> /dev/null; then
                yum install -y cockpit
            elif command -v pacman &> /dev/null; then
                pacman -S --noconfirm cockpit
            elif command -v zypper &> /dev/null; then
                zypper install -y cockpit
            else
                echo -e "${RED}Could not install Cockpit automatically.${NC}"
                echo "Please install Cockpit manually: https://cockpit-project.org/running.html"
                return 1
            fi
            ;;
    esac

    # Copy Cockpit module to system directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    mkdir -p /usr/share/cockpit
    cp -r "$SCRIPT_DIR/cockpit/pyircx" /usr/share/cockpit/
    chmod +x /usr/share/cockpit/pyircx/api.py

    # Enable and start Cockpit
    systemctl enable --now cockpit.socket

    # Restart Cockpit to load new module (if already running)
    if systemctl is-active --quiet cockpit.socket; then
        echo -e "${YELLOW}Restarting Cockpit to load pyIRCX module...${NC}"
        systemctl restart cockpit.socket
    fi

    echo -e "${GREEN}Cockpit installed successfully!${NC}"
    echo ""
    echo "Access Cockpit at: https://localhost:9090"
    echo "Look for 'pyIRCX Server' in the left menu"
    echo ""
}

# Install systemd service
install_systemd() {
    echo -e "${YELLOW}Installing systemd service...${NC}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy service file
    cp "$SCRIPT_DIR/pyircx.service" /etc/systemd/system/

    # Reload systemd
    systemctl daemon-reload

    echo -e "${GREEN}Systemd service installed${NC}"
    echo ""
    echo "To enable and start the service:"
    echo "  systemctl enable pyircx"
    echo "  systemctl start pyircx"
}

# Main installation
main() {
    echo ""
    echo "========================================"
    echo "  pyIRCX Installation Script"
    echo "========================================"
    echo ""

    check_root
    check_python

    echo ""
    read -p "Install to $INSTALL_DIR? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        read -p "Enter installation directory: " INSTALL_DIR
    fi

    install_dependencies
    install_python_packages
    create_user
    create_directories
    copy_files
    set_permissions
    install_systemd

    echo ""
    echo "========================================"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo "========================================"
    echo ""
    echo "Configuration: $CONFIG_DIR/pyircx_config.json"
    echo "Installation:  $INSTALL_DIR"
    echo "Logs:          journalctl -u pyircx"
    echo ""
    echo -e "${YELLOW}Default Admin Account:${NC}"
    echo "  Username: admin"
    echo "  Password: changeme"
    echo ""
    echo -e "${RED}*** CHANGE THE DEFAULT PASSWORD IMMEDIATELY ***${NC}"
    echo "  Connect to IRC and run: STAFF PASS admin yournewpassword"
    echo ""
    echo "To login as admin (in your IRC client):"
    echo "  /QUOTE PASS admin:changeme"
    echo "  Then connect normally - you'll have ADMIN privileges"
    echo ""
    echo "Commands:"
    echo "  systemctl start pyircx    - Start server"
    echo "  systemctl stop pyircx     - Stop server"
    echo "  systemctl restart pyircx  - Restart server"
    echo "  systemctl status pyircx   - Check status"
    echo "  systemctl enable pyircx   - Enable at boot"
    echo "  systemctl reload pyircx   - Reload config/SSL certs"
    echo ""
    echo "SSL/TLS Setup (optional):"
    echo "  1. Install certbot:  apt install certbot"
    echo "  2. Get certificate:  certbot certonly --standalone -d irc.example.com"
    echo "  3. Edit config and set ssl.enabled=true, ssl.cert_file, ssl.key_file"
    echo "  4. Restart pyircx:   systemctl restart pyircx"
    echo ""
    echo "Default ports: 6667 (plain), 6697 (SSL)"
    echo ""
    echo "========================================"
    echo -e "${YELLOW}Optional: SSL/TLS Certificate Setup${NC}"
    echo "========================================"
    echo ""
    echo "Would you like to set up SSL/TLS now?"
    echo "  - Let's Encrypt (free, automatic)"
    echo "  - Self-signed (for testing)"
    echo "  - Skip (configure manually later)"
    echo ""
    read -p "Set up SSL/TLS now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "setup_ssl.sh" ]; then
            ./setup_ssl.sh "$CONFIG_DIR/pyircx_config.json"
        else
            echo -e "${YELLOW}setup_ssl.sh not found, skipping SSL setup${NC}"
            echo "You can run it later: sudo ./setup_ssl.sh"
        fi
    else
        echo ""
        echo "SSL/TLS can be set up later with:"
        echo "  sudo ./setup_ssl.sh"
    fi
    echo ""
    echo "========================================"
    echo -e "${YELLOW}Optional: Web Admin Panel (Cockpit)${NC}"
    echo "========================================"
    echo ""
    read -p "Install Cockpit web admin panel? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_cockpit
    fi
}

# Uninstall function
uninstall() {
    echo ""
    echo "========================================"
    echo "  pyIRCX Uninstallation"
    echo "========================================"
    echo ""

    check_root

    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop pyircx 2>/dev/null || true
    systemctl disable pyircx 2>/dev/null || true

    echo -e "${YELLOW}Removing files...${NC}"
    rm -f /etc/systemd/system/pyircx.service
    systemctl daemon-reload

    read -p "Remove installation directory $INSTALL_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
    fi

    read -p "Remove configuration $CONFIG_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
    fi

    read -p "Remove user $SERVICE_USER? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi

    echo -e "${GREEN}Uninstallation complete${NC}"
}

# Parse arguments
case "${1:-}" in
    uninstall|remove)
        uninstall
        ;;
    *)
        main
        ;;
esac
