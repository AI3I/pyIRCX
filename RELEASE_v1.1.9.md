# pyIRCX v1.1.9 Release Notes

**Release Date:** January 16, 2026
**Focus:** Traditional IRC Service Compatibility & Apache/httpd Multi-Distribution Support

---

## 🔒 Security Improvements

None in this release.

---

## ✨ New Features

### Traditional IRC Service Alias Routing
- **NickServ Alias**: Routes to Registrar for nickname registration/authentication
- **ChanServ Alias**: Routes to Registrar for channel registration/management
- **MemoServ Alias**: Routes to Messenger for offline message delivery
- **Other Service Aliases**: OperServ, HelpServ, InfoServ, BotServ, HostServ, StatServ, Global, ALIS, Services
  - All provide helpful information directing users to active services
  - Maintains compatibility with traditional IRC client configurations

### Apache/httpd Multi-Distribution Setup Script
- **`setup_apache.sh`**: Comprehensive Apache/httpd configuration for all supported distributions
  - Auto-detects distribution (RHEL, Fedora, CentOS, Rocky, Alma, Amazon Linux, Debian, Ubuntu)
  - Configures Apache for both WebAdmin and WebChat
  - Handles SELinux contexts automatically on RHEL-based systems
  - Sets proper permissions (apache:pyircx group membership)
  - Installs and configures PHP and required modules
  - Tests configuration before applying
  - Provides clear success/error messages with troubleshooting steps

---

## 🐛 Bug Fixes

None in this release.

---

## ⚡ Performance Improvements

None in this release.

---

## 📋 All Changes from v1.1.7

1. **Service Alias Routing**: Added case-insensitive routing for traditional IRC service names (NickServ, ChanServ, MemoServ, etc.) to maintain compatibility with classic IRC networks
2. **Apache Setup Script**: Created comprehensive `setup_apache.sh` for automated Apache/httpd configuration across all supported Linux distributions

---

## 📁 Files Modified

### Core Server
- `pyircx.py`: Added service alias routing (lines 3503-3531)

### Installation Scripts
- `setup_apache.sh`: **NEW** - Multi-distribution Apache/httpd setup script

---

## 🔧 Upgrade Instructions

### From v1.1.7

1. **Stop the server:**
   ```bash
   sudo systemctl stop pyircx
   ```

2. **Backup your configuration:**
   ```bash
   sudo cp /etc/pyircx/pyircx_config.json /etc/pyircx/pyircx_config.json.backup
   ```

3. **Pull the latest code:**
   ```bash
   cd /opt/pyircx
   sudo git pull
   ```

4. **Restart the server:**
   ```bash
   sudo systemctl start pyircx
   sudo systemctl status pyircx
   ```

5. **Verify logs:**
   ```bash
   sudo journalctl -u pyircx -n 50
   ```

---

## ⚠️ Breaking Changes

**[None/List breaking changes]**

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,000 (main codebase)
- **Test Coverage:** [Update as needed]
- **Exception Handling:** 100% specific (no bare except clauses)

---

For questions, issues, or contributions, please visit:
https://github.com/AI3I/pyIRCX
