# pyIRCX v1.1.5 - Comprehensive Release Notes

**Release Date:** January 14, 2026
**Created:** Wed Jan 14 10:02:18 PM EST 2026
**Previous Version:** v1.1.4

## Executive Summary

Version 1.1.5 represents a major usability and documentation release. This version adds comprehensive server statistics, complete help documentation, service enhancements, web chat improvements, and numerous quality-of-life features while maintaining 100% backward compatibility.

**Highlights:**
- 🎯 8 new STATS flags (p, f, m, b, n, v, enhanced k/d/l)
- 📚 Complete /HELP system covering all commands and modes
- 🤖 Enhanced service HELP commands (Registrar, ServiceBot, Messenger, NewsFlash)
- 🌐 Web chat UI/UX improvements (emoji picker, search, settings, normalized sounds)
- 🔧 Bug fixes (ServiceBot routing, emoji display, flood protection scope)
- ✅ Zero breaking changes, no migration required

---

## Table of Contents

1. [STATS System Enhancements](#1-stats-system-enhancements)
2. [Help System Implementation](#2-help-system-implementation)
3. [Service Improvements](#3-service-improvements)
4. [Web Chat Enhancements](#4-web-chat-enhancements)
5. [Bug Fixes](#5-bug-fixes)
6. [Technical Changes](#6-technical-changes)
7. [Testing Guide](#7-testing-guide)
8. [Migration & Compatibility](#8-migration--compatibility)

---

## 1. STATS System Enhancements

### 1.1 New STATS Flags

#### STATS p - Peak Usage Statistics
**Access:** All users
**Purpose:** Display peak concurrent user statistics

**Output:**
```
Peak users: 42
Peak time: 2026-01-14 19:30:15
```

**Implementation:** `pyircx.py:5233-5241`

---

#### STATS f - Flood Protection Statistics
**Access:** All users
**Purpose:** Monitor flood protection effectiveness

**Output:**
```
Total flood events: 127
Flood protection: Enabled
```

**Implementation:** `pyircx.py:5243-5247`

---

####STATS m - Message Statistics
**Access:** All users
**Purpose:** Detailed message activity analysis

**Output:**
```
Total messages: 15,432
Most active channels:
  #lobby: 8,234
  #general: 3,102
  #help: 1,543
  [... all channels listed ...]
Active channels: 15
```

**Implementation:** `pyircx.py:5253-5270`

---

#### STATS b - ServiceBot Statistics
**Access:** All users
**Purpose:** ServiceBot monitoring and activity

**Output:**
```
ServiceBots enabled: True
Active bots: 10
Violations detected:
  flood: 45
  caps: 23
  profanity: 12
  [... all types listed ...]
Actions taken:
  warn: 62
  gag: 15
  kick: 3
```

**Implementation:** `pyircx.py:5272-5308`

---

#### STATS n - Network Statistics
**Access:** All users
**Purpose:** General network information

**Output:**
```
Server: irc.local
Network: IRCX Network
Users: 42
Channels: 15
Services: 15
Server version: pyIRCX 1.1.5
Uptime: 86400 seconds
```

**Implementation:** `pyircx.py:5310-5321`

---

#### STATS v - Command Usage Statistics
**Access:** GUIDE+ (staff only)
**Purpose:** Track command usage patterns

**Output:**
```
WHO: 1,234
PRIVMSG: 987
JOIN: 456
PART: 345
MODE: 234
[... all commands listed ...]
Total commands: 5,432
```

**Implementation:** `pyircx.py:5328-5342`

---

#### STATS k - Enhanced Ban Statistics
**Access:** All users
**Purpose:** Complete ban and access control listing

**Changes:**
- Shows **all** ACCESS DENY entries (no 10-entry limit)
- Shows **all** server bans (no 10-entry limit)
- Removed "... and X more" truncation messages

**Implementation:** `pyircx.py:5058-5089`

---

#### STATS d - Enhanced Database Statistics
**Access:** All users
**Purpose:** Database health and usage metrics

**Output:**
```
Registered nicknames: 123
Registered channels: 45
NewsFlash messages: 12
Database size: 2.5 MB
```

**Implementation:** `pyircx.py:5024-5056`

---

#### STATS l - Linking Statistics
**Access:** All users
**Purpose:** Server linking status and configuration

**Output:**
```
Linking enabled: True
Bind host: 0.0.0.0
Bind port: 7001
Configured links: 0
```

**Implementation:** `pyircx.py:5091-5104`

---

### 1.2 STATS * Comprehensive Report Enhancements

**Access:** ADMIN only
**Major Improvements:**

1. **Hierarchical Indentation**
   - Main items: 2-space indentation
   - Sub-items: 4-space indentation
   - Significantly improves readability

2. **Removed All Artificial Limits**
   - Command Usage: ~~Top 10~~ → **All commands**
   - Message Statistics: ~~Top 5 channels~~ → **All channels**
   - ServiceBot Violations: ~~Top 3~~ → **All violation types**

3. **Added New Sections**
   - Peak Usage
   - Flood Protection
   - Message Statistics (with all channels)
   - ServiceBot Statistics (with all violations)

**Implementation:** `pyircx.py:4849-4969`

---

### 1.3 Real-Time Statistics Tracking

**New tracking mechanisms:**
- Individual command usage counts → `command_usage` dict
- Peak concurrent users and timestamp → `peak_users`, `peak_time`
- Flood protection events → `flood_events` counter
- Per-channel message counts → `messages_by_channel` dict
- ServiceBot violation types → `servicebot_violations` dict
- ServiceBot action types → `servicebot_actions` dict

**Implementation:**
- Stats dict initialization: `pyircx.py:2036-2047`
- Command tracking: `pyircx.py:2964-2966`
- Peak user tracking: `pyircx.py:2941-2944`
- Flood event tracking: `pyircx.py:2991`
- Message tracking: `pyircx.py:3599-3602`
- ServiceBot tracking: `pyircx.py:2240-2247`

---

## 2. Help System Implementation

### 2.1 Main /HELP Command

**Implementation:** `pyircx.py:5803-5955`

**Topics Available:**
- COMMANDS - All available commands
- CHANNEL - Channel management
- **REGISTER - Registration system** *(NEW)*
- IRCX - IRCX-specific features
- USERMODES - User mode flags
- CHANMODES - Channel mode flags
- SERVICES - Available services
- STAFF - Staff commands (staff only)

---

### 2.2 New HELP REGISTER Topic

**Usage:** `/HELP REGISTER`

**Comprehensive documentation includes:**

**Nickname Registration:**
- `REGISTER <account> <email|*> <password>` - Register nickname
- `IDENTIFY <account> <password>` - Log into registered nickname
- `UNREGISTER <account>` - Delete registration
- `MFA ENABLE` - Enable two-factor authentication
- `MFA DISABLE <code>` - Disable 2FA
- `MFA VERIFY <code>` - Complete MFA login

**Channel Registration:**
- `REGISTER <#channel> [password]` - Register channel (owner only)
- `UNREGISTER <#channel>` - Unregister channel (owner only)

**Additional Info:**
- Alternative /MSG Registrar interface
- Explains +r mode benefits

**Implementation:** `pyircx.py:5848-5861`

---

### 2.3 Complete Command Documentation

All existing help topics now include:
- **COMMANDS** - Added Registration category
- **CHANNEL** - Complete channel command syntax
- **IRCX** - All ACCESS, PROP, EVENT, WHISPER, DATA commands
- **USERMODES** - All 9 user modes documented
- **CHANMODES** - All 18 channel modes documented
- **SERVICES** - Directory of all services with command lists
- **STAFF** - All 3 KILL variants, STAFF commands, CONFIG, BROADCAST

---

## 3. Service Improvements

### 3.1 Registrar Service - New HELP Command

**Usage:** `/MSG Registrar HELP`
**Implementation:** `pyircx.py:7309-7327`

**Documentation includes:**

**Nickname Registration:**
- REGISTER <password> [email]
- IDENTIFY <password>
- DROP
- INFO [nickname]

**Channel Registration:**
- CHANNEL REGISTER <#channel>
- CHANNEL DROP <#channel>
- CHANNEL INFO <#channel>

**Account Settings:**
- SET PASSWORD <newpass>
- SET EMAIL <email>

**Two-Factor Authentication:**
- MFA ENABLE
- MFA VERIFY <code>
- MFA DISABLE <code>

---

### 3.2 ServiceBot - Fixed & Enhanced

#### Bug Fix: Case-Insensitive Routing
**Issue:** ServiceBot commands failed with lowercase nicknames
**Fixed:** `/msg servicebot01 help` now works (any case)
**Implementation:** `pyircx.py:3501-3505`

#### Enhanced HELP Command
**Usage:** `/MSG ServiceBot01 HELP` (case-insensitive)
**Implementation:** `pyircx.py:8155-8184`

**Comprehensive help includes:**
- Service description
- Monitoring features with configured actions:
  - Profanity Filter (warn/gag/kick)
  - Flood Protection (warn/gag/kick)
  - CAPS Detection (warn/gag/kick)
  - URL Spam Detection (warn/gag/kick)
  - Repeat Message Detection (warn/gag/kick)
- Action explanations
- Available commands (HELP, STATUS)
- Invitation instructions (/INVITE ServiceBot01 #channel)
- Capacity information (10 channels max)

#### Enhanced STATUS Command
**Usage:** `/MSG ServiceBot01 STATUS`
**Implementation:** `pyircx.py:8186-8208`

**Status includes:**
- Active channel count (e.g., "Active in 2/10 channels")
- List of monitored channels
- Detection status (profanity, flood)
- Global monitoring enable/disable

---

### 3.3 Other Services

**Messenger** - Existing HELP maintained
**NewsFlash** - Existing HELP maintained
**System** - Provides service directory when messaged

---

## 4. Web Chat Enhancements

### 4.1 Sound System

#### Normalized Volumes
**Issue:** Inconsistent sound volumes
**Fixed:** All sounds standardized to amplitude 0.7
**Implementation:** `webchat/index.html:380-445`

**Sounds normalized:**
- Message, join, part, notice, private message, kick, error, invite

**Benefits:**
- Consistent audio experience
- No jarring volume differences
- Professional sound presentation

---

### 4.2 Service Emoji Display

#### Fixed WHO Responses
**Issue:** ServiceBots (🤖) emoji not displaying
**Root Cause:** Server filtered virtual users from WHO
**Fixed:** Services (+s mode) now included in WHO replies
**Implementation:** `pyircx.py:3747`

#### Removed WHO Throttling
**Issue:** Delayed emoji display on JOIN
**Fixed:** Immediate WHO requests for joining users
**Implementation:** `webchat/index.html:1123`

**Results:**
- Instant robot emoji (🤖) for ServiceBots
- Instant staff emoji (⭐) for staff
- Better user experience

---

### 4.3 UI/UX Improvements

#### Enhanced User List
- Width increased: 200px → 280px
- Service user styling (purple, bold)
- Maintained staff colors (admin/sysop/guide)
- Added hover effects

#### New Buttons & Icons
- 😀 Emoji picker button
- ➕ Join / ➖ Leave
- 🔧 Modes / ⚙️ Properties
- 🔍 Search / ⚙️ Settings
- 📤 Send / 🔌 Connect

#### Settings Modal (NEW)
- 24-hour time format toggle
- Desktop notifications toggle
- Sound notifications toggle
- Ignored users management
  - View ignored list
  - Add users to ignore

#### Emoji Picker (NEW)
- Quick emoji insertion
- Category organization
- One-click insertion

#### Search Functionality (NEW)
- Search chat history
- Highlight matches
- Navigate results

#### Modes Dialog (NEW)
- View/modify channel modes
- Toggle individual modes
- Visual status indicators

---

## 5. Bug Fixes

### 5.1 ServiceBot Case-Sensitive Routing
**Issue:** `/msg servicebot01 help` didn't work
**Cause:** Case-sensitive dictionary lookup
**Fix:** Case-insensitive routing loop
**Impact:** Consistent operation regardless of case
**File:** `pyircx.py:3501-3505`

### 5.2 Service Emoji Display
**Issue:** Robot emoji missing for ServiceBots
**Causes:**
1. Server excluded virtual users from WHO
2. WHO throttling delayed response

**Fixes:**
1. Include services (+s) in WHO replies
2. Remove WHO throttle on individual joins

**Impact:** Immediate emoji display
**Files:** `pyircx.py:3747`, `webchat/index.html:1123`

### 5.3 STATS Output Truncation
**Issue:** "Top 10" limits hiding data
**Fix:** Removed all slicing and "... and X more" messages
**Impact:** Complete visibility
**Files:** `pyircx.py:4891-4931, 5062-5081, 5258-5263`

### 5.4 Flood Protection Scope
**Issue:** Rate limiting on JOIN/MODE commands
**Cause:** Flood protection on all commands
**Fix:** Scoped to message commands only (PRIVMSG, NOTICE, WHISPER, BROADCAST)
**Impact:** Normal operations not rate-limited
**File:** `pyircx.py:2981-2999`

---

## 6. Technical Changes

### 6.1 Code Statistics

**Files Modified:** 8 files
- `pyircx.py` (57 change sections)
- `webchat/index.html` (extensive UI updates)
- `CHANGELOG.md`, `README.md`, `api.py`, `upgrade.sh`
- `webadmin/admin.js`, `webadmin/index.php`

### 6.2 New Properties

**Channel Properties:**
- `voice_key` - Third-tier channel access key
- Serialization support added

**Statistics Properties:**
- `command_usage` - Per-command usage counts
- `peak_users` / `peak_time` - Peak tracking
- `flood_events` - Flood trigger counter
- `messages_by_channel` - Per-channel message counts
- `servicebot_violations` / `servicebot_actions` - ServiceBot tracking

### 6.3 Enhanced 005 Numeric

Added IRCv3-compliant parameters:
- CHANMODES (A,B,C,D format)
- MAXNICKLEN
- TOPICLEN
- MODES (max per command)
- CASEMAPPING
- STATUSMSG

### 6.4 Performance Impact

**Minimal:**
- Statistics tracking: O(1) dictionary operations
- STATS output: More data, but infrequent and admin-only
- Help system: In-memory, instant response
- ServiceBot routing: O(n) where n ≤ 10

---

## 7. Testing Guide

### 7.1 STATS System

**Test each new flag:**
```
/STATS p   # Peak usage
/STATS f   # Flood protection
/STATS m   # Message statistics
/STATS b   # ServiceBot statistics
/STATS n   # Network statistics
/STATS v   # Command usage (staff only)
/STATS k   # Ban statistics (no truncation)
/STATS d   # Database statistics
/STATS l   # Linking statistics
/STATS *   # Comprehensive (ADMIN, check indentation)
```

**Verify:**
- No "Top X" or "... and X more" messages
- All data shown completely
- Hierarchical indentation in STATS *

### 7.2 Help System

**Test all topics:**
```
/HELP
/HELP COMMANDS
/HELP CHANNEL
/HELP REGISTER   # NEW topic
/HELP IRCX
/HELP USERMODES
/HELP CHANMODES
/HELP SERVICES
/HELP STAFF      # Requires staff
```

**Verify:** Complete documentation, REGISTER topic comprehensive

### 7.3 Services

**Test service HELP:**
```
/MSG Registrar HELP
/MSG ServiceBot01 HELP      # Any case
/MSG servicebot01 help      # Should work
/MSG SERVICEBOT01 STATUS    # Should work
/MSG Messenger HELP
/MSG NewsFlash HELP
```

**Verify:** Comprehensive help, case-insensitive ServiceBot

### 7.4 Web Chat

**Test sounds:**
- Join/part/message/notice events
- Verify consistent volume

**Test emoji:**
- Invite ServiceBot: `/INVITE ServiceBot01 #channel`
- Verify 🤖 appears immediately
- Test with staff users for ⭐

**Test new features:**
- Settings modal (toggles, ignored users)
- Emoji picker
- Search functionality
- Modes dialog

### 7.5 Regression

**Verify existing functionality:**
- User registration/authentication
- Channel management
- IRCX commands (ACCESS, PROP)
- Staff commands (KILL, STAFF, CONFIG)
- ServiceBot monitoring
- Message delivery

---

## 8. Migration & Compatibility

### 8.1 Backward Compatibility

**100% Compatible**
- No database schema changes
- No configuration changes required
- Existing commands enhanced, not changed
- New features additive only

### 8.2 Upgrade Process

**Standard upgrade:**
```bash
# Backup
sudo systemctl stop pyircx

# Update
sudo cp pyircx.py /opt/pyircx/
sudo cp -r webchat/* /opt/pyircx/webchat/

# Restart
sudo systemctl start pyircx
sudo systemctl status pyircx
```

**No migration steps required**

### 8.3 Configuration

**No changes required**
- All features work with existing config
- Statistics tracking automatic
- Help system active immediately

**Optional:**
- Review ServiceBot actions in config
- Enable desktop notifications in web chat
- Customize as needed

---

## 9. Known Issues

**None identified.**

All known issues from v1.1.4 have been addressed.

---

## 10. Summary

pyIRCX v1.1.5 delivers major usability improvements:

✅ **8 new/enhanced STATS flags** - Comprehensive server monitoring
✅ **Complete /HELP system** - All 80+ commands documented
✅ **Service HELP commands** - Registrar, ServiceBot, all services
✅ **Web chat enhancements** - Emoji picker, search, settings, normalized sounds
✅ **Bug fixes** - ServiceBot routing, emoji display, flood protection
✅ **Zero breaking changes** - 100% backward compatible
✅ **No migration required** - Drop-in upgrade

**Total:** Major enhancement release with zero disruption.

---

## 11. Credits

**Development:** Claude (Anthropic)
**Testing:** jdlewis
**Platform:** pyIRCX Internet Relay Chat Server
**License:** GPL-3.0
**Repository:** https://github.com/AI3I/pyIRCX

---

**End of Release Notes - pyIRCX v1.1.5**
