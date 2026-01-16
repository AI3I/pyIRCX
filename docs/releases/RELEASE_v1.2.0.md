# pyIRCX v1.2.0 Release Notes

**Release Date:** January 16, 2026
**Focus:** User Experience Polish & Quality of Life Improvements
**Type:** Major quality improvement release

---

## Overview

Version 1.2.0 represents a comprehensive polish pass focusing on user experience, help system completeness, and administrative convenience. While no new features were added, over **150+ improvements** were made across error messages, help documentation, command shortcuts, and administrative tools.

This release makes pyIRCX significantly more user-friendly, professional, and easier to operate.

---

## 🎨 Highlights

### ✅ Complete Help System
- **100% command coverage** - Every command now has help documentation
- **7 new help pages** added (MOTD, MEMO, GAG/UNGAG, CREATE, CONNECT/SQUIT)
- **Comprehensive examples** for all commands
- **"Did you mean?" suggestions** for typos using fuzzy matching

### ⚡ Command Aliases
- **12 shortcut commands** for faster typing (J→JOIN, P→PART, W→WHOIS, etc.)
- **IRC standard compatible** - Common aliases from other servers
- **Zero overhead** - Simple dictionary lookup

### 💬 Enhanced Message Quality
- **~40 error messages improved** for clarity and actionability
- **Professional formatting** with consistent punctuation and grammar
- **Better guidance** - Messages now tell users what to do next

### 🛠️ Administrative Improvements
- **Enhanced STATS output** with counts, idle times, and better formatting
- **Detailed STAFF confirmations** with audit trails
- **Configurable client timeout** prevents ghost connections
- **Comprehensive webadmin tooltips** for all configuration fields
- **Reserved nicknames reference** showing active and unused service names

---

## ✨ New Features

### Command Aliases (pyircx.py:3001-3019)

Fast shortcuts for commonly-used commands:

| Alias | Full Command | Alias | Full Command |
|-------|-------------|-------|-------------|
| `/J` | `/JOIN` | `/W` | `/WHOIS` |
| `/P` | `/PART` | `/M` | `/MSG` |
| `/N` | `/NICK` | `/Q` | `/QUIT` |
| `/T` | `/TOPIC` | `/K` | `/KICK` |
| `/I` | `/INVITE` | `/L` | `/LIST` |
| `/WW` | `/WHOWAS` | `/WH` | `/WHISPER` |

**Example:**
```
Before: /JOIN #lobby
After:  /J #lobby
```

### Configurable Client Timeout (pyircx.py:2966-2973)

**Ghost Connection Prevention:**
- Prevents dead clients from staying connected indefinitely
- Configurable via `limits.client_timeout` (default: 300 seconds)
- Added field to webadmin Limits tab

**Before:** Hardcoded 300-second timeout in code
**After:** Admins can configure via web interface or config file

---

## 🐛 Bug Fixes

### MOTD Whitespace Preservation (webadmin/admin.js:2319)

**Fixed:** ASCII art MOTD content had leading/trailing spaces stripped

**Problem:**
```
Pasted:       _   _
Saved:  _   _       (leading spaces removed!)
```

**Solution:** Removed `.trim()` from MOTD save, now preserves exact formatting

**Impact:** MOTD ASCII art and formatted content displays correctly

### MOTD Auto-Load (webadmin/admin.js:2024-2027)

**Fixed:** MOTD tab didn't auto-load content when clicked

**Before:** User had to click "Reload" button manually
**After:** MOTD content loads automatically when tab is opened

### Help System Completion (pyircx.py:6669-6724)

**Fixed:** Missing help documentation for 7 commands

**Commands Added:**
1. **MOTD** - Display server Message of the Day
2. **MEMO** - Offline message system (SEND, LIST, READ, DEL)
3. **GAG/UNGAG** - Staff command to mute/unmute users
4. **CREATE** - Alias for JOIN (creates or joins channel)
5. **CONNECT** - Admin command for server linking
6. **SQUIT** - Admin command to disconnect linked servers

**Fuzzy Matching Updated:**
Now suggests these commands for typos (e.g., `/HELP MOTO` → "Did you mean: MOTD?")

---

## ⚡ Enhancements

### Message Quality Improvements (~40 messages)

**Grammar & Punctuation:**
- Fixed inconsistent punctuation across all messages
- Added trailing periods to multi-sentence messages
- Standardized use of colons for context separation
- Fixed "Permission Denied" → "Permission denied" (sentence case)

**Clarity & User-Friendliness:**
- Changed "Erroneous nickname" → "Invalid nickname" (432)
- Changed "No such nick/channel" → "No such nickname or channel" (401)
- Added guidance to "Not enough parameters" messages (461)
- Added context to "Cannot send to channel" errors (404, 840)
- Improved KNOCK messages with clearer guidance (711, 712, 716)

**Actionable Guidance:**
- Added "use NICK and USER commands" to registration error (451)
- Added "check channel modes or permissions" to channel errors (404)
- Added "See /HELP {command} for usage" to parameter errors (461)
- Enhanced MFA messages with clear instructions (865, 878)
- Improved rate limiting messages with "please wait" guidance (830-834)
- Added "contact administrator if persists" to database errors (900, 903, 905)

**Examples:**
```
Before: "432: {target} :Erroneous nickname"
After:  "432: {target} :Invalid nickname"

Before: "481: Permission Denied - You're not an IRC operator"
After:  "481: Permission denied: You're not an IRC operator"

Before: "712: {target} :Too many KNOCKs"
After:  "712: {target} :Too many knock requests. Please wait before trying again."
```

### STATS Formatting Enhancements (pyircx.py:5145-5182)

**Staff Listings (STATS a, o, g):**
- Added **count in header**: "=== Online ADMINs (3) ==="
- Added **idle time** for each staff member
- Added **"No X currently online"** for empty lists
- Enhanced **visual separators**: "===" instead of "---"
- Format: `username!user@host (idle: 5m)`

**Before:**
```
--- Online ADMINs ---
alice!alice@host
bob!bob@host
--- End ---
```

**After:**
```
=== Online ADMINs (2) ===
  alice!alice@host (idle: 2m)
  bob!bob@host (idle: 15s)
=== End of ADMINs ===
```

### STAFF Command Enhancements (pyircx.py:5729-5959)

**STAFF LIST Improvements:**
- Count in header: "=== Staff Accounts (12) ==="
- Counts per level: "ADMIN (3):", "SYSOP (5):", "GUIDE (4):"
- **[ONLINE]** status indicators for currently connected staff
- Better visual organization with blank lines between sections

**STAFF ADD/DEL/SET/PASS - Enhanced Confirmations:**

All operations now show:
- **"=== SUCCESS ==="** header
- Detailed confirmation with all fields
- **"Created/Changed/Deleted by"** tracking
- Status messages about when changes take effect

**Example (STAFF ADD):**
```
Before: Staff account 'newuser' created with level GUIDE

After:
=== SUCCESS ===
Staff account created:
  Username: newuser
  Level: GUIDE
  Created by: alice
The account will be active on next login.
```

### Webadmin Comprehensive Tooltips (webadmin/index.php)

**Complete Coverage for All Configuration Tabs:**

#### Server Tab (lines 415-462)
- Server name, database path, network info
- All fields have defaults and examples
- IPv6 address field added with tooltip

#### Limits Tab (lines 467-512)
- Maximum users, message length, nickname cooldown
- **Client timeout** field with ghost connection explanation
- All length limits with IRC standard notes

#### Security Tab (lines 537-631)
- Flood protection, throttling, authentication
- DNSBL, proxy detection with clear explanations
- Profanity filter with action descriptions

#### Services Tab (lines 638-770)
- **ServiceBot settings** with count and channel limits
- **Profanity filter** with action explanations
- **Malicious detection** thresholds with clear guidance

#### SSL/TLS Tab (lines 772-813)
- Certificate paths with Let's Encrypt examples
- TLS version comparison (1.2 vs 1.3)
- Auto-reload for certificate renewal

#### Linking Tab (lines 815-832)
- Server-to-server binding with defaults
- Port and firewall guidance
- Multi-homed server notes

#### Advanced Tab (lines 834-877)
- Transcripts, persistence, NewsFlash
- All intervals with defaults and recommendations

**Impact:** Admins can configure without consulting documentation

### Reserved Nicknames Reference (webadmin/index.php:289-357)

**Comprehensive Reference on Access Control Page:**

Shows three categories:

1. **Active Virtual Services (4):**
   - System, Registrar, Messenger, NewsFlash

2. **ServiceBot Pool (dynamic):**
   - ServiceBot, ServiceBot01-ServiceBotNN
   - Updates based on configuration

3. **Reserved IRC Services (12):**
   - NickServ, ChanServ, MemoServ, OperServ
   - BotServ, HostServ, HelpServ, InfoServ
   - StatServ, Global, ALIS, Services
   - Noted as "reserved for future features"

**Features:**
- Color-coded sections with visual organization
- **Dynamic ServiceBot count** - Shows correct range based on config
- Clear notes about access control implications
- Explains both active and unused reserved names

### Webadmin UI Improvements

**Compact Number Inputs (style.css:631-635):**
- Number fields now 150px wide (was full-width)
- Better for 4-digit values (ports, timeouts, limits)

**MOTD Editor (index.php:512-518):**
- Changed "Reload" to green "Load MOTD" button
- Moved to left of "Save MOTD"
- Auto-loads content when tab clicked

**Profanity Word List (index.php:675-679):**
- Changed from "comma-separated" to "one per line"
- Better placeholder showing correct format
- Note about /PROFANITY command for regex

---

## 📋 All Changes from v1.1.9

### Core Server (pyircx.py)

**Version Updated:**
- Line 1: Version bumped to 1.2.0

**Command Aliases:**
- Lines 3001-3019: Alias mapping in dispatch()

**Client Timeout:**
- Lines 2966-2973: Configurable timeout from config

**RESPONSES Dictionary:**
- Lines 1711-1918: ~30 messages improved for clarity

**SERVER_MESSAGES Dictionary:**
- Lines 1923-1995: ~10 messages improved

**Help System:**
- Lines 6669-6724: 7 new help commands added
- Lines 8076-8108: Fuzzy matching updated with new topics

**STATS Formatting:**
- Lines 5145-5182: Enhanced output with counts and idle times

**STAFF Commands:**
- Lines 5729-5768: Enhanced STAFF LIST with counts and [ONLINE] status
- Lines 5816-5821: Enhanced STAFF ADD confirmation
- Lines 5859-5863: Enhanced STAFF DEL confirmation
- Lines 5905-5911: Enhanced STAFF SET confirmation
- Lines 5952-5959: Enhanced STAFF PASS confirmation

### Webadmin (webadmin/)

**index.php:**
- Lines 289-357: Reserved nicknames reference added
- Lines 415-462: Server tab tooltips
- Lines 467-512: Limits tab tooltips (including client timeout)
- Lines 537-631: Security tab tooltips
- Lines 638-770: Services tab tooltips
- Lines 772-813: SSL/TLS tab tooltips
- Lines 815-832: Linking tab tooltips
- Lines 834-877: Advanced tab tooltips
- Lines 512-518: MOTD button improvements

**admin.js:**
- Lines 2024-2027: MOTD auto-load on tab click
- Lines 2077 & 2207: IPv6 address handling
- Lines 2087 & 2216: Client timeout configuration
- Lines 2317-2328: MOTD whitespace preservation (removed .trim())
- Lines 469-540: Reserved nicknames dynamic update

**style.css:**
- Lines 631-635: Compact number inputs
- Lines 643-653: Form row layout

---

## 📊 Statistics

### Message Improvements
- **Error messages:** ~30 improved
- **System messages:** ~10 improved
- **Total messages:** ~40 enhanced

### Help System
- **New help pages:** 7
- **Total commands with help:** 50+
- **Fuzzy matching topics:** 50+
- **Coverage:** 100%

### Command Shortcuts
- **Aliases added:** 12
- **Coverage:** Most common IRC commands

### Webadmin Enhancements
- **Tooltip fields:** 60+
- **Tabs covered:** 7 (all configuration tabs)
- **Reserved nicknames documented:** 18+

### Code Quality
- **Lines modified:** ~200
- **Files updated:** 3 (pyircx.py, index.php, admin.js, style.css)
- **Breaking changes:** 0
- **Configuration changes:** +2 fields (client_timeout, listen_addr_ipv6)

---

## 🔧 Upgrade Instructions

### From v1.1.9

**1. Stop the server:**
```bash
sudo systemctl stop pyircx
```

**2. Backup your configuration:**
```bash
sudo cp /opt/pyircx/pyircx_config.json /opt/pyircx/pyircx_config.json.backup
```

**3. Pull the latest code:**
```bash
cd /opt/pyircx
sudo git pull
```

**4. Optional: Update webadmin (if installed):**
```bash
sudo cp webadmin/index.php /var/www/html/webadmin/
sudo cp webadmin/admin.js /var/www/html/webadmin/
sudo cp webadmin/style.css /var/www/html/webadmin/
sudo chown -R apache:apache /var/www/html/webadmin/
sudo restorecon -Rv /var/www/html/webadmin/
```

**5. Restart the server:**
```bash
sudo systemctl start pyircx
sudo systemctl status pyircx
```

**6. Verify logs:**
```bash
sudo journalctl -u pyircx -n 50
```

### New Configuration Options

**Optional additions to pyircx_config.json:**

```json
{
  "network": {
    "listen_addr_ipv6": "::"
  },
  "limits": {
    "client_timeout": 300
  }
}
```

**Defaults:**
- `listen_addr_ipv6`: `::` (all IPv6 interfaces)
- `client_timeout`: `300` (5 minutes)

---

## ⚠️ Breaking Changes

**None** - All changes are additive or improvements to existing functionality.

- Message text changes are clarifications only
- New aliases don't conflict with existing commands
- Configuration fields have sensible defaults
- Webadmin changes are cosmetic/enhancement only

---

## 📁 Files Modified

### Core Server
- `pyircx.py` (version, aliases, timeout, help, STATS, STAFF, messages)

### Webadmin
- `webadmin/index.php` (tooltips, reserved names, MOTD buttons)
- `webadmin/admin.js` (MOTD auto-load, whitespace, timeout, IPv6, dynamic updates)
- `webadmin/style.css` (compact inputs, form rows)

### Documentation
- `README.md` (version 1.2.0, latest releases)
- `docs/releases/RELEASE_v1.2.0.md` (this file)
- `CHANGELOG.md` (comprehensive v1.2.0 entry)

---

## User-Facing Impact

### What Users Will Notice

**Better Error Messages:**
- Clearer language ("Invalid nickname" not "Erroneous")
- Helpful guidance ("See /HELP JOIN" not just "Not enough parameters")
- Professional formatting (consistent punctuation)

**Complete Help System:**
- Every command now has help
- Examples for all commands
- Typo suggestions ("Did you mean: JOIN?")

**Faster Typing:**
- Use `/J #lobby` instead of `/JOIN #lobby`
- All common commands have shortcuts
- IRC standard compatible

### What Staff/Admins Will Notice

**Better STATS Output:**
- Counts at a glance (3 ADMINs online)
- Idle times for each staff member
- Professional formatting

**Detailed Confirmations:**
- Know who made what changes (audit trail)
- Clear success messages
- Status about when changes take effect

**Easier Configuration:**
- Tooltips explain every field
- Examples show correct format
- Defaults clearly documented

### What Server Operators Will Notice

**Ghost Connection Prevention:**
- Dead clients auto-disconnect after 5 minutes (configurable)
- No more phantom users in channel lists
- Logged for monitoring

**Reserved Names Reference:**
- See all reserved nicknames at a glance
- Understand active vs. unused services
- ServiceBot count updates dynamically

---

## 🎯 Future Enhancements

While v1.2.0 focuses on polish, these areas could be explored in future releases:

### Test Coverage
- Add test cases for command aliases
- Test configurable client timeout
- Verify enhanced help system
- Test STATS/STAFF formatting
- Webadmin tooltip rendering tests

### Documentation
- Update MANUAL.md with command aliases
- Document all defaults in one place
- Create troubleshooting guide

### Additional Polish
- Enhanced error messages for IRCX-specific commands
- More ServiceBot error feedback
- API documentation for webadmin

---

## 🙏 Acknowledgments

This release represents extensive user feedback and quality-of-life improvements across the entire codebase. Special thanks to all users who reported unclear error messages, missing help documentation, and usability issues.

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,200 (main codebase)
- **Test Coverage:** 243 passing tests (needs updates for v1.2.0 features)
- **Exception Handling:** 100% specific (no bare except clauses)
- **Message Quality:** Professional, clear, actionable
- **Help Coverage:** 100% (all commands documented)
- **Configuration Documentation:** 100% (all fields have tooltips)

---

## Release Checklist

- [x] Version bumped to 1.2.0 in pyircx.py
- [x] README.md updated with v1.2.0
- [x] CHANGELOG.md updated with comprehensive notes
- [x] RELEASE_v1.2.0.md created with detailed changes
- [ ] MANUAL.md updated (command aliases, client timeout, reserved names)
- [ ] Test harnesses updated for v1.2.0 features
- [ ] Git tag created: v1.2.0
- [ ] GitHub release published

---

For questions, issues, or contributions, please visit:
https://github.com/AI3I/pyIRCX

---

**pyIRCX v1.2.0** - Polish, Quality, and User Experience
