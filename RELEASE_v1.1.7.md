# pyIRCX v1.1.7 Release Notes

**Release Date:** January 16, 2026
**Release Type:** Documentation, SELinux Hardening, Configuration System

---

## Overview

Version 1.1.7 focuses on comprehensive documentation updates, SELinux security hardening across all installation scripts, and a new WebChat configuration system for easier customization.

## Key Highlights

### 🎯 WebChat Configuration System
- **NEW: config.js** - Externalized webchat settings for easy customization
- Configure default channel, WebSocket URL, performance parameters without editing HTML
- Comprehensive inline documentation of all configuration options
- Auto-integration with all installation and upgrade scripts

### 🔒 Comprehensive SELinux Hardening
- **NEW: SELINUX.md** - Complete SELinux reference documentation
- All installation scripts (install.sh, upgrade.sh, repair.sh) now comprehensively configure SELinux contexts
- Fixed webadmin context (requires httpd_sys_rw_content_t, not httpd_sys_content_t)
- Fixed webchat.conf context (requires etc_t for systemd environment files)
- Quick reference table, setup scripts, and troubleshooting guide

### 📚 Documentation Consolidation
- **Merged TESTING.md** - Consolidated TESTING_v1.1.5.md and TESTING_UPDATES.md
- **Simplified README.md** - Now references CHANGELOG.md as single source of truth
- **Comprehensive CHANGELOG.md** - Added v1.1.1 and v1.1.7 entries
- Renamed TESTHARNESS_v1.1.5.md → TESTHARNESS.md

---

## New Features

### WebChat Configuration System

**New File: `webchat/config.js`**
- Default channel configuration (changed default from #lobby to #pyIRCX)
- WebSocket URL configuration (auto-detection or manual override)
- Performance tuning parameters (WHO throttle, command delay)
- Staff emoji customization
- Sound and notification settings
- Theme preferences

**Example Configuration:**
```javascript
const WEBCHAT_CONFIG = {
    defaultChannel: '#pyIRCX',
    websocketPort: 8765,
    whoThrottleMs: 2000,
    commandDelayMs: 600,
    // ... and more
};
```

### SELinux Documentation

**New File: `SELINUX.md`**
- Complete context requirements for all pyIRCX directories
- Quick reference table showing path → context mappings
- Full setup script for one-command configuration
- Troubleshooting guide for common SELinux issues
- Verification commands

---

## Bug Fixes

### MOTD Editor - Blank Line Preservation
**Issue:** Web admin MOTD editor stripped blank lines, causing formatting issues
**Fix:** Changed `line.strip()` filtering to `line.rstrip()` to preserve empty lines
**Impact:** MOTD now displays with proper paragraph spacing in IRC clients

**Additional Fix:** pyircx.py now sends blank MOTD lines as single space to ensure proper display in all IRC clients (HexChat, etc.)

### MOTD Configuration Save Overwrite
**Issue:** Web admin "Save Configuration" button overwrote MOTD with stale cached version
**Root Cause:** saveConfigForm() cloned currentConfig from page load time instead of reloading from file
**Fix:** Modified saveConfigForm() to call get-config API before saving, preserving latest MOTD
**Additional Fix:** Added get-config command to api.py
**Additional Fix:** Added cache-busting version parameter to index.php to force browser reload
**Impact:** MOTD changes now persist when saving configuration; no more unexpected reverts

### Hardcoded Defaults Removed
**Issue:** Default MOTD was hardcoded in api.py and pyircx.py instead of config file
**Fix:** Removed hardcoded defaults, added MOTD to pyircx_config.json template
**Impact:** All defaults now in config file as intended; easier customization for new installations

### SELinux Context Issues
**Issue:** webadmin had wrong context (httpd_sys_content_t instead of httpd_sys_rw_content_t)
**Fix:** All scripts now properly set httpd_sys_rw_content_t for webadmin
**Impact:** Web admin can now save configurations without permission errors

**Issue:** webchat.conf had wrong context, preventing systemd from reading environment
**Fix:** Set etc_t context for /etc/pyircx/webchat.conf
**Impact:** WebChat gateway service now starts correctly with proper configuration

### Script References
**Issue:** config.js not referenced in installation/upgrade scripts
**Fix:** All scripts now install and update config.js
**Impact:** WebChat configuration properly deployed during install and upgrades

---

## Changes

### Documentation Reorganization

**README.md:**
- Removed duplicate version history (180+ lines)
- Now references CHANGELOG.md as single source of truth
- Added "Active Development" notice with link to CHANGELOG
- Updated version badge to 1.1.7

**CHANGELOG.md:**
- Added comprehensive v1.1.7 entry
- Added missing v1.1.1 entry (Kill/Lock buttons, MOTD/topic fixes)
- All releases now documented with consistent format

**TESTING.md:**
- Merged TESTING_v1.1.5.md and TESTING_UPDATES.md
- Comprehensive guide covering all 243 tests across 8 suites
- Test account setup instructions
- CI/CD integration examples
- Troubleshooting guide

### WebChat Defaults
- Default channel changed from #lobby to #pyIRCX
- Configuration now externalized and customizable
- Default values set via config.js on page load

---

## Documentation Updates

### Updated Files
- **CONFIG.md** - Updated pool_size default from 5 to 10
- **SECURITY.md** - Documented v1.1.6 web admin security features (CSRF, sessions)
- **webadmin/README.md** - Added v1.1.6 security features section
- **webadmin/INSTALL.md** - Added comprehensive SELinux and permissions setup
- **TESTHARNESS.md** - Renamed from TESTHARNESS_v1.1.5.md

### New Files
- **SELINUX.md** - Comprehensive SELinux reference (NEW)
- **webchat/config.js** - WebChat configuration system (NEW)

---

## Installation & Upgrade

### New Installations

```bash
# Clone repository
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX

# Run installation (as root)
sudo ./install.sh

# SELinux contexts are automatically configured
```

### Upgrading from v1.1.6

```bash
cd /path/to/pyIRCX
git pull
sudo ./upgrade.sh
```

**What Gets Updated:**
- pyircx.py → v1.1.7 (MOTD blank line fix)
- api.py (if needed)
- webchat/index.html (config.js integration)
- webchat/config.js (NEW - configuration file)
- All scripts (comprehensive SELinux configuration)
- SELinux contexts (properly set for all directories)

### Upgrading from v1.1.5 or Earlier

Follow the same upgrade process. All v1.1.6 security fixes are included.

---

## Testing

**Test Coverage:** 243 tests across 8 suites (100% passing)

Run the full test suite:
```bash
./run_tests.sh
```

See [TESTING.md](TESTING.md) for comprehensive testing guide.

---

## Configuration Changes

### No Breaking Changes
All changes are backwards compatible. Existing configurations will continue to work.

### New Configuration Options

**WebChat Gateway (`/etc/pyircx/webchat.conf`):**
- No changes (remains the same)

**WebChat Frontend (`/var/www/html/webchat/config.js`):**
- NEW file for customizing webchat behavior
- Edit to change defaults without modifying HTML

---

## Security

### SELinux Hardening
- All directories now have proper SELinux contexts
- webadmin: httpd_sys_rw_content_t (read-write for API)
- webchat: httpd_sys_content_t (read-only static content)
- webchat.conf: etc_t (systemd environment file)

### MOTD Security
- No security implications
- Formatting fix only

---

## Files Changed

**Modified:**
- pyircx.py (version bump, MOTD blank line handling, removed hardcoded defaults)
- api.py (MOTD editor fix, removed hardcoded defaults, added get-config command)
- README.md (simplified, version badge)
- CHANGELOG.md (added v1.1.7 and v1.1.1)
- CONFIG.md (pool_size documentation)
- SECURITY.md (v1.1.6 security features)
- TESTING.md (merged testing docs)
- install.sh (config.js installation, comprehensive SELinux)
- upgrade.sh (config.js updates, comprehensive SELinux, version refs)
- repair.sh (config.js checks, comprehensive SELinux)
- uninstall.sh (SELinux context removal)
- pyircx_config.json (added default MOTD template)
- webadmin/README.md (security features)
- webadmin/INSTALL.md (SELinux setup)
- webadmin/index.php (cache-busting version parameter)
- webadmin/admin.js (fixed saveConfigForm to preserve MOTD)
- webchat/index.html (config.js integration, documentation)

**Added:**
- SELINUX.md (comprehensive SELinux reference)
- webchat/config.js (configuration system)
- RELEASE_v1.1.7.md (this file)

**Renamed:**
- TESTHARNESS_v1.1.5.md → TESTHARNESS.md

**Removed:**
- TESTING_v1.1.5.md (merged into TESTING.md)
- TESTING_UPDATES.md (merged into TESTING.md)

---

## Known Issues

None.

---

## Deprecations

None.

---

## Future Enhancements

Planned for future releases:
- Web-based configuration editor for webchat/config.js
- Additional SELinux policies for enhanced security
- Performance monitoring dashboard

---

## Support

- **Documentation:** See [README.md](README.md), [CHANGELOG.md](CHANGELOG.md), [SELINUX.md](SELINUX.md)
- **Issues:** https://github.com/AI3I/pyIRCX/issues
- **Security:** See [SECURITY.md](SECURITY.md)

---

## Contributors

- pyIRCX Development Team
- Community feedback and testing

---

## License

pyIRCX is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

---

**Thank you for using pyIRCX!** 🚀
