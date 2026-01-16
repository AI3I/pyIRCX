# pyIRCX v1.1.3 Release Notes

**Release Date:** January 14, 2026
**Focus:** Security hardening and code quality improvements

This release completes the comprehensive security audit and implements all critical, high, and medium priority fixes identified in the security review.

---

## 🔒 Security Improvements

### Error Handling Specificity
- **Replaced all bare `except:` clauses** with specific exception types across the entire codebase
- Improved error handling in 17 locations across pyircx.py, webchat/gateway.py, and test files
- Better exception specificity prevents masking unexpected errors
- Examples:
  - Database migrations: `except aiosqlite.OperationalError`
  - File operations: `except (FileNotFoundError, PermissionError, IOError)`
  - Network cleanup: `except Exception` with clear comments
  - Unicode handling: `except UnicodeDecodeError`

### Server Link Password Security
- **Implemented bcrypt authentication for server-to-server links**
- Server link passwords now use bcrypt hashing instead of plaintext
- Backwards compatible: falls back to plaintext with warning for legacy configs
- Added `utils/hash_link_password.py` utility for generating bcrypt hashes
- Async password verification via `loop.run_in_executor()` to avoid blocking
- Modified `linking.py:authenticate_server()` to support both hash formats

### Configuration Security
- **Added config file permission validation** on server startup
- Warns if `/etc/pyircx/pyircx_config.json` is world-readable/writable
- Logs security warning with remediation instructions if insecure permissions detected
- Helps prevent exposure of sensitive data (database paths, link passwords, API keys)

---

## ⚡ Performance Improvements

### Database Connection Pooling
- **Increased default pool size from 5 to 10 connections**
- Added pool saturation monitoring and warnings
- Logs warning when all pool connections are in use
- Helps identify when pool size needs adjustment under load

---

## 📋 All Changes from v1.1.2

This release builds on v1.1.2 and includes:

1. ✅ Web admin directory rename (web-admin → webadmin)
2. ✅ Backpressure handling for User.send() and Channel.broadcast()
3. ✅ CSRF protection on all web admin POST requests
4. ✅ Session security hardening (httponly, secure, samesite flags)
5. ✅ Password visibility fix (stdin pipe instead of argv)
6. ✅ Username-based rate limiting for authentication
7. ✅ Broadcast rate limiting (max 10 per minute with 6-second cooldown)
8. ✅ Config file permission validation **(NEW in v1.1.3)**
9. ✅ Database pool improvements **(NEW in v1.1.3)**
10. ✅ Error handling specificity **(NEW in v1.1.3)**
11. ✅ Server link password bcrypt **(NEW in v1.1.3)**

---

## 📁 Files Modified

### Core Server
- `pyircx.py`: Version bump, error handling improvements
- `linking.py`: bcrypt authentication for server links
- `webchat/gateway.py`: Specific exception handling

### Test Suite
- `pyIRCX_test_links.py`: Exception handling improvements
- `pyIRCX_test_users.py`: Exception handling improvements
- `pyIRCX_test_staff.py`: Exception handling improvements

### New Utilities
- `utils/hash_link_password.py`: Utility for generating bcrypt hashes for server link passwords

### Removed
- `web-admin/` directory (renamed to `webadmin/` in v1.1.2)

---

## 🔧 Upgrade Instructions

### From v1.1.2
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

4. **Verify config file permissions:**
   ```bash
   sudo chmod 600 /etc/pyircx/pyircx_config.json
   sudo chown pyircx:pyircx /etc/pyircx/pyircx_config.json
   ```

5. **(Optional) Update server link passwords to bcrypt:**
   ```bash
   # Generate a bcrypt hash for your link password
   python3 /opt/pyircx/utils/hash_link_password.py

   # Update /etc/pyircx/pyircx_config.json linking.links[].password
   # with the generated hash
   ```

6. **Restart the server:**
   ```bash
   sudo systemctl start pyircx
   sudo systemctl status pyircx
   ```

7. **Verify logs for any warnings:**
   ```bash
   sudo journalctl -u pyircx -n 50
   ```

### From v1.1.1 or Earlier
Follow the upgrade instructions in RELEASE_v1.1.2.md first, then apply the steps above.

---

## ⚠️ Breaking Changes

**None.** This release is fully backwards compatible with v1.1.2.

**Note:** Server link passwords can continue to use plaintext format, but bcrypt is strongly recommended. A warning will be logged for plaintext passwords.

---

## 🔍 Security Audit Status

All items from the comprehensive security audit have been implemented:
- ✅ 2 Critical issues resolved
- ✅ 5 High priority issues resolved
- ✅ 5 Medium priority issues resolved
- ✅ 4 Low priority enhancements implemented

See `SECURITY_AND_PERFORMANCE_AUDIT.md` for full details.

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,000 (main codebase)
- **Test Coverage:** 45 command handler methods, 3 test suites
- **Exception Handling:** 100% specific (no bare except clauses)
- **Security Classes:** 7 (DNSBL, Proxy Detection, Rate Limiting, etc.)
- **Async/Await Compliance:** Full async/await with proper backpressure handling

---

## 🙏 Acknowledgments

This release represents a comprehensive security and quality improvement cycle based on thorough code review and analysis.

---

## 📝 Next Steps

**Planned for v1.2.0:**
- Modular code architecture refactoring
- Enhanced type hints coverage
- Config reload support (SIGHUP)
- Additional metrics and monitoring

---

For questions, issues, or contributions, please visit:
https://github.com/AI3I/pyIRCX
