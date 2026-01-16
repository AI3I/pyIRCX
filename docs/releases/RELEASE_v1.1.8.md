# pyIRCX v1.1.8 Release Notes

**Release Date:** January 16, 2026
**Focus:** Comprehensive Documentation Reorganization & Apache Setup Script

---

## 🔒 Security Improvements

None in this release.

---

## ✨ New Features

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

## 📚 Documentation Improvements

### Documentation Reorganization
Complete restructure of documentation into organized subdirectories:

- **`docs/user/`** - User and admin guides
  - CONFIG.md - Configuration reference
  - MANUAL.md - Server manual
  - LINKING.md - Server linking guide
  - SELINUX.md - SELinux configuration
  - STAFF_ACCOUNT_REFERENCE.md - Staff account management

- **`docs/testing/`** - Testing documentation
  - TESTING.md - Testing guide
  - TESTHARNESS.md - Test harness documentation
  - TEST_COVERAGE_ANALYSIS.md - Coverage analysis

- **`docs/performance/`** - Performance guides
  - PERFORMANCE.md - Performance tuning
  - SECURITY_AND_PERFORMANCE_AUDIT.md - Security audit guide

- **`docs/development/`** - Development documentation
  - RELEASE_CHECKLIST.md - Release process
  - VERSION_MANAGEMENT.md - Version management guide
  - Bugfix notes and development guides

- **`docs/releases/`** - All release notes
  - RELEASE_v1.1.x.md files

### New Documentation

- **`webchat/README.md`** - Complete WebChat configuration and troubleshooting guide
  - config.js options and customization
  - Gateway service setup
  - Reverse proxy configuration (Apache/Nginx)
  - Performance tuning
  - Security configuration
  - WebSocket troubleshooting

### Documentation Updates

- **CONFIG.md** - Added server.motd and server.staff_login_message options
- **webadmin/README.md** - Added MOTD Editor feature documentation (v1.1.7)
- **README.md** - Updated all documentation links to new paths

### Benefits

- **Cleaner Repository Root**: Reduced from 20 markdown files to 4 (README, CHANGELOG, SECURITY, LICENSE)
- **Better Organization**: Documentation categorized by audience and purpose
- **Easier Navigation**: Clear directory structure for finding documentation
- **Improved Maintainability**: Logical grouping makes updates easier

---

## 🐛 Bug Fixes

None in this release.

---

## ⚡ Performance Improvements

None in this release.

---

## 📋 All Changes from v1.1.7

1. **Documentation Reorganization**: Restructured all documentation into organized subdirectories (user, testing, performance, development, releases)
2. **WebChat Documentation**: Added comprehensive webchat/README.md with configuration and troubleshooting
3. **Apache Setup Script**: Created `setup_apache.sh` for automated Apache/httpd configuration across all supported Linux distributions

---

## 📁 Files Modified

### Installation Scripts
- `setup_apache.sh`: **NEW** - Multi-distribution Apache/httpd setup script

### Documentation
- **Reorganized**: All documentation moved to `docs/` subdirectories
- **New**: `webchat/README.md` - Complete WebChat guide
- **Updated**: `CONFIG.md`, `webadmin/README.md`, `README.md`

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

**Note:** This release includes documentation reorganization. Update any bookmarks or links to documentation files to reflect the new paths in `docs/` subdirectories.

---

## ⚠️ Breaking Changes

**None** - No code changes, only documentation reorganization.

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,000 (main codebase)
- **Test Coverage:** 243 tests across 8 suites
- **Exception Handling:** 100% specific (no bare except clauses)

---

For questions, issues, or contributions, please visit:
https://github.com/AI3I/pyIRCX
