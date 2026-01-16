# pyIRCX v1.1.6 Release Notes

**Release Date:** January 16, 2026
**Focus:** Web Admin Authentication, Permissions, and CSRF Security

---

## 🔒 Security Improvements

- **CSRF Token Protection**: Implemented comprehensive CSRF token validation across all web admin API endpoints
- **Secure Session Handling**: Fixed session cookie security to work with both HTTP and HTTPS deployments
- **Stdin Password Input**: Added `test-staff-login-stdin` API command for secure password handling (prevents password exposure in process lists)
- **SELinux Context Hardening**: Extended httpd_sys_rw_content_t contexts to cover `/etc/pyircx` directory for proper web admin isolation

---

## ✨ New Features

- **HTTP/HTTPS Auto-Detection**: Web admin now automatically adapts session security based on protocol (HTTP or HTTPS)
- **Null-Safe Form Handling**: Configuration editor now handles missing form fields gracefully with safe getter/setter functions
- **Enhanced Installation Scripts**: All installation, upgrade, and repair scripts now properly configure web admin permissions

---

## 🐛 Bug Fixes

- **Fixed**: Web admin login "Invalid username or password" error on new installations
- **Fixed**: CSRF token validation failures on service control and configuration save operations
- **Fixed**: Permission denied errors when web admin tried to save configuration files
- **Fixed**: Configuration save crashes due to missing nested object properties
- **Fixed**: Session cookies not being set on HTTP-only deployments
- **Fixed**: PHP-FPM not picking up group membership changes without restart

---

## ⚡ Performance Improvements

- **Database Connection Pool**: Increased default pool_size from 5 to 10 connections for better concurrency with web admin
- **Group Permission Optimization**: Web server now uses group permissions instead of requiring world-writable files

---

## 📋 All Changes from v1.1.5

1. Added `test-staff-login-stdin()` function to api.py for secure web authentication
2. Fixed session.cookie_secure to conditionally require HTTPS only when available
3. Implemented CSRF token generation in index.php with meta tag exposure to JavaScript
4. Updated admin.js with comprehensive CSRF token handling for all API calls
5. Added null-safe form field accessors (getVal/setVal/getCheck) in admin.js
6. Updated install.sh to set proper directory permissions (775) and SELinux contexts
7. Updated repair.sh with PHP-FPM restart and SELinux context fixes
8. Updated upgrade.sh with complete permission and SELinux configuration
9. Enhanced uninstall.sh to properly remove user home directories and orphaned groups
10. Changed default database pool_size to 10 in pyircx_config.json

---

## 📁 Files Modified

### Core API
- `api.py`: Added test-staff-login-stdin command handler for web admin authentication

### Web Admin Interface
- `webadmin/login.php`: Fixed session security for HTTP/HTTPS compatibility
- `webadmin/index.php`: Added CSRF token generation and meta tag
- `webadmin/api.php`: Fixed session security configuration
- `webadmin/admin.js`: Implemented CSRF handling and null-safe form operations

### Installation & Management Scripts
- `install.sh`: Enhanced permissions (775 for directories, 664 for files) and SELinux contexts
- `repair.sh`: Added PHP-FPM restart, SELinux context restoration
- `upgrade.sh`: Complete permission and SELinux configuration updates
- `uninstall.sh`: Improved cleanup with user home directory removal

### Configuration
- `pyircx_config.json`: Updated default database.pool_size to 10

---

## 🔧 Upgrade Instructions

### From v1.1.5

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

4. **Run the repair script to fix permissions:**
   ```bash
   sudo ./repair.sh
   ```

5. **Restart the server:**
   ```bash
   sudo systemctl start pyircx
   sudo systemctl status pyircx
   ```

6. **Verify web admin access:**
   - Navigate to http://your-server/webadmin/
   - Login with your admin credentials
   - Test configuration save functionality

7. **Verify logs:**
   ```bash
   sudo journalctl -u pyircx -n 50
   ```

---

## ⚠️ Breaking Changes

**None** - This is a fully backward-compatible maintenance release.

**Note:** If you're using the web admin, you may need to clear your browser cache to pick up the updated JavaScript with CSRF token handling.

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,000 (main codebase)
- **Test Coverage:** Comprehensive integration tests included
- **Exception Handling:** 100% specific (no bare except clauses)
- **Security:** CSRF protection, SELinux contexts, secure session handling

---

## 🙏 Credits

This release includes contributions from:
- Claude Sonnet 4.5 (Web admin security hardening and permission fixes)

---

For questions, issues, or contributions, please visit:
https://github.com/AI3I/pyIRCX
