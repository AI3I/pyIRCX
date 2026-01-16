# pyIRCX v1.1.4 - Critical Bug Fix Release

**Release Date:** January 14, 2026  
**Release Type:** Critical Bug Fix  
**Urgency:** HIGH - Immediate upgrade recommended

---

## ⚠️ CRITICAL FIX

### Channel Broadcast Async Bug (CATASTROPHIC)

**Severity:** CRITICAL  
**Impact:** All multi-user channel operations broken  
**Affects:** All installations using v1.1.3 or earlier with asyncio.gather

**The Bug:**
```python
# BROKEN (v1.1.3 and earlier)
tasks.append(await member.send(msg))  # Awaits immediately, appends None
```

**The Fix:**
```python
# FIXED (v1.1.4)
tasks.append(member.send(msg))  # Collects coroutines for concurrent execution
```

**What Happened:**
- When users joined channels, `Channel.broadcast()` would crash
- `asyncio.gather()` received `[None, None, ...]` instead of coroutines
- TypeError: "An asyncio.Future, a coroutine or an awaitable is required"
- Connection immediately terminated

**Affected Operations:**
- User joins channel
- User parts channel  
- Channel messages with multiple users
- Mode changes broadcast to channel
- Any channel broadcast with 2+ users

**Symptoms:**
- WebChat: "Connecting..." message disappears, connection fails
- IRC clients: Disconnect immediately after joining populated channels
- Logs: "Client error: An asyncio.Future, a coroutine or an awaitable is required"

**Resolution:**
✅ Upgrade to v1.1.4 immediately  
✅ Restart pyircx service  
✅ All channel operations now work correctly

---

## 🐛 Additional Bug Fixes

### KILL Command Format
- **Fixed:** Proper IRC NOTICE format instead of malformed message
- **Before:** `:{target_nick} KILLED` → Displayed as "GARBAGE" in clients
- **After:** `:servername NOTICE staffnick :*** User killed (reason)`
- **Impact:** Staff can now properly use KILL command from IRC clients

### QUIT Command Disconnect
- **Fixed:** Immediate disconnect for all user types
- **Before:** Users lingered on server after QUIT
- **After:** Disconnect within milliseconds
- **Implementation:** Added `user.disconnected` flag for reliable detection
- **Scope:** Registered, unregistered, CAP negotiation, webchat users

### CAP Negotiation
- **Fixed:** IRCv3 capability negotiation no longer disconnects clients
- **Before:** Disconnect check triggered during CAP (nickname "*")
- **After:** Skip disconnect check for unregistered users
- **Impact:** Modern IRC clients with CAP support now connect successfully

### WebChat IRCX Command Order
- **Fixed:** IRCX sent after registration, not before
- **Correct Order:** WEBIRC → NICK/USER → 001 welcome → IRCX → JOIN
- **Impact:** WebChat connections now complete successfully

### Database Write Access
- **Fixed:** Web admin "readonly database" errors
- **Solution:** Web server user (apache/www-data/http) added to pyircx group
- **Scripts Updated:** install.sh, upgrade.sh, repair.sh
- **Impact:** Staff management and config updates via web admin now work

---

## 📁 Directory Changes

### Web Admin
- **Old:** `/var/www/html/pyircx-admin`
- **New:** `/var/www/html/webadmin`
- **Access:** http://localhost/webadmin/

### WebChat
- **Backend:** `/opt/pyircx/webchat/` (gateway.py)
- **Frontend:** `/var/www/html/webchat/` (index.html, favicon.svg)
- **Access:** http://localhost/webchat/

---

## ⚙️ Configuration Changes

### WEBIRC Enabled by Default
- **Before:** `"webirc": { "enabled": false }`
- **After:** `"webirc": { "enabled": true }`
- **Impact:** WebChat works out-of-the-box on new installations
- **Note:** Existing installations keep their current settings

---

## 🔧 Installation & Upgrade

### Fresh Installation
```bash
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX
sudo bash install.sh
```

### Upgrade from v1.1.3 or earlier
```bash
cd pyIRCX
git pull origin main
sudo bash upgrade.sh
```

### Manual Upgrade (Production Systems)
```bash
# Backup current installation
sudo systemctl stop pyircx
sudo cp /opt/pyircx/pyircx.py /opt/pyircx/pyircx.py.backup

# Deploy v1.1.4
sudo cp pyircx.py /opt/pyircx/pyircx.py

# Restart service
sudo systemctl start pyircx

# Verify
sudo systemctl status pyircx
```

---

## ✅ Verification

### Test Channel Operations
```
1. Connect with IRC client
2. Join #test channel
3. Have second user join #test
4. Expected: Both users see join messages
5. Send messages between users
6. Expected: Messages delivered successfully
```

### Test WebChat
```
1. Open http://localhost/webchat/
2. Enter nickname and connect
3. Join #lobby
4. Expected: Connection succeeds, channel joined
5. Send a message
6. Expected: Message appears in chat
```

### Check Logs
```bash
# Should show NO errors about asyncio.Future
journalctl -u pyircx -n 50 --no-pager | grep -i error
```

---

## 📊 Impact Assessment

### Severity: CRITICAL
- **Risk Level:** HIGH for v1.1.3 users
- **Upgrade Priority:** IMMEDIATE
- **Downtime:** ~10 seconds (service restart)
- **Data Loss:** None
- **Rollback:** Safe (can revert to v1.1.3 if needed)

### Affected Versions
- ❌ v1.1.3 and earlier: BROKEN (channel broadcasts fail)
- ✅ v1.1.4: FIXED (all operations work)

### Compatibility
- ✅ Database schema: No changes
- ✅ Configuration: Compatible with v1.1.2/v1.1.3
- ✅ IRC Protocol: Full compliance restored
- ✅ Backwards compatible: No breaking changes

---

## 🔍 Root Cause Analysis

### How This Bug Was Introduced
The bug was introduced during an asyncio optimization where sequential sends were converted to concurrent sends using `asyncio.gather()`. The `await` keyword was incorrectly placed inside the loop instead of being removed entirely.

### Why It Wasn't Caught Earlier
- Single-user testing didn't trigger the bug (no broadcast needed)
- The error only manifested with multiple users in a channel
- Gateway wrapper (WebChat) isolated the error from direct IRC clients during initial testing

### Prevention
- ✅ Added comprehensive error logging with tracebacks
- ✅ Documented in TEST_COVERAGE_ANALYSIS.md
- 📝 TODO: Add multi-user channel test to test suite

---

## 📝 Documentation

### Updated Files
- CHANGELOG.md - Full change history
- README.md - Installation instructions with new paths
- webadmin/README.md - Updated access URLs
- docs/BUGFIX_*.md - Detailed bug analysis documents

### New Files
- webchat/favicon.svg - IRC-themed favicon
- RELEASE_v1.1.4.md - This document

---

## 🙏 Credits

**Bug Reporter:** User testing (multiple installations affected)  
**Root Cause Analysis:** Systematic debugging with traceback logging  
**Fix Development:** Claude Sonnet 4.5  
**Testing:** Production verification across multiple scenarios

---

## 📞 Support

**Issues:** https://github.com/AI3I/pyIRCX/issues  
**Discussions:** https://github.com/AI3I/pyIRCX/discussions  
**Security:** Report privately to project maintainers

---

## 📜 License

pyIRCX is licensed under GPL-3.0  
Copyright © 2026 pyIRCX Project

---

**Upgrade Now:** This release fixes a catastrophic bug that breaks all multi-user channel operations. Immediate upgrade is strongly recommended for all installations.
