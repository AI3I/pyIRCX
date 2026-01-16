# pyIRCX v1.1.9 Release Notes

**Release Date:** January 16, 2026
**Focus:** Traditional IRC Service Compatibility

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
  - Proper CamelCase formatting for service names (OperServ not Operserv)

---

## 🐛 Bug Fixes

None in this release.

---

## ⚡ Performance Improvements

None in this release.

---

## 📋 All Changes from v1.1.8

1. **Service Alias Routing**: Added case-insensitive routing for traditional IRC service names (NickServ, ChanServ, MemoServ, etc.) to maintain compatibility with classic IRC networks
2. **Service Name Formatting**: Fixed service name capitalization to use proper CamelCase (OperServ, HelpServ, etc.)

---

## 📁 Files Modified

### Core Server
- `pyircx.py`: Added service alias routing (lines 3503-3531)

---

## 🔧 Upgrade Instructions

### From v1.1.8

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
