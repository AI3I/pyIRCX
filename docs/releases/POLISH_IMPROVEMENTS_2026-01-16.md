# pyIRCX Polish Improvements - January 16, 2026

## Executive Summary

This document details comprehensive polish improvements made to pyIRCX on January 16, 2026, focusing on user experience, help system enhancements, and ServiceBot flexibility.

**Total Improvements:** 100+ changes across messages, help, and ServiceBot systems
**Status:** ✅ All improvements deployed to atlas.jdlewis.net
**Version:** These improvements bridge v1.1.9 → v1.2.0

---

## Phase 1: Message Quality Improvements (v1.2.0)

### Overview
Comprehensive review and improvement of ~40 user-facing messages across RESPONSES and SERVER_MESSAGES dictionaries.

### Changes

**Grammar & Punctuation:**
- ✅ Fixed inconsistent punctuation across all messages
- ✅ Added trailing periods to multi-sentence messages
- ✅ Standardized use of colons for context separation (not dashes)
- ✅ Fixed "Permission Denied" → "Permission denied" (sentence case consistency)
- ✅ Removed extra period from "End of /NAMES list."

**Clarity & User-Friendliness:**
- ✅ "Erroneous nickname" → "Invalid nickname" (432)
- ✅ "No such nick/channel" → "No such nickname or channel" (401)
- ✅ Added channel mode hints to permission errors (404, 482)
- ✅ Improved KNOCK messages with clearer guidance (711, 712, 716)
- ✅ Enhanced MFA messages with step-by-step instructions (865, 878)

**Actionable Guidance:**
- ✅ "Not enough parameters" now includes "/HELP {command} for usage" (461)
- ✅ "Cannot send to channel" explains why (check modes/permissions) (404)
- ✅ "You have not registered" tells you how (use NICK and USER) (451)
- ✅ Rate limiting messages now say "please wait" (830-834)
- ✅ Database errors now say "contact administrator if persists" (900, 903, 905)

**Examples of Improvements:**
```
Before: "432: {target} :Erroneous nickname"
After:  "432: {target} :Invalid nickname"

Before: "481: Permission Denied - You're not an IRC operator"
After:  "481: Permission denied: You're not an IRC operator"

Before: "712: {target} :Too many KNOCKs"
After:  "712: {target} :Too many knock requests. Please wait before trying again."

Before: "access_denied": "Access denied{reason}"
After:  "access_denied": "Access denied: {reason}"
```

**Impact:**
- Users see professional, consistent error messages
- Better guidance on what to do when errors occur
- Reduced confusion with clearer language

---

## Phase 2: Enhanced Help System

### Overview
Dramatically expanded the help system with individual command help, examples, and "did you mean?" suggestions.

### Individual Command Help (15+ new pages)

Users can now type `/HELP <command>` for detailed help with concrete examples:

**Commands Added:**
- ✅ `/HELP JOIN` - Join channels with examples for passwords and multiple channels
- ✅ `/HELP PART` - Leave channels with optional messages
- ✅ `/HELP MODE` - Comprehensive user/channel mode examples
- ✅ `/HELP TOPIC` - Set/view topics with channel mode notes
- ✅ `/HELP KICK` - Remove users with reasons
- ✅ `/HELP INVITE` - Invite users to channels
- ✅ `/HELP WHOIS` / `/HELP WHO` - User information and patterns
- ✅ `/HELP ACCESS` - IRCX access control with mask examples
- ✅ `/HELP PROP` - IRCX properties with common props listed
- ✅ `/HELP WHISPER` - Private channel messages
- ✅ `/HELP REGISTER` / `/HELP IDENTIFY` / `/HELP UNREGISTER` - Account management
- ✅ `/HELP MFA` - Two-factor authentication setup
- ✅ `/HELP LIST` - Channel listing with patterns
- ✅ `/HELP MSG` - Private messaging
- ✅ `/HELP AWAY` - Away status
- ✅ `/HELP KILL` - Staff only: disconnect users/channels

**Example Format:**
```
/HELP JOIN

=== JOIN Command ===
Usage: /JOIN <#channel> [key]
Join a channel. If the channel doesn't exist, it will be created.
Examples:
  /JOIN #lobby - Join the lobby channel
  /JOIN #private secretpass - Join with password
  /JOIN #chat,#help - Join multiple channels
```

### "Did You Mean?" Suggestions

Implemented fuzzy matching for typos using difflib:

**Examples:**
- `/HELP JION` → "Did you mean: JOIN?"
- `/HELP REGISTAR` → "Did you mean: REGISTER?"
- `/HELP ACESS` → "Did you mean: ACCESS?"

**Implementation:**
- Cutoff: 0.6 similarity ratio
- Shows up to 3 suggestions
- Case-insensitive matching
- Covers all valid help topics and commands

### Enhanced Service Help

**Registrar Service:**
```
/MSG Registrar HELP

=== Registrar Service Help ===

Nickname Registration:
  REGISTER <password> [email] - Register your current nickname
    Example: REGISTER mypassword me@example.com
    Example: REGISTER mypassword (without email)
  IDENTIFY <password> - Log into your registered nickname
    Example: IDENTIFY mypassword
  DROP - Delete your nickname registration
  INFO [nickname] - View registration info
    Example: INFO alice

Channel Registration:
  CHANNEL REGISTER <#channel> - Register a channel you own
    Example: CHANNEL REGISTER #mychannel
  [... additional commands with examples ...]
```

**Messenger Service:**
```
=== Messenger - Offline Message Service ===

Send and receive messages when users are offline.

Commands:
  SEND <nick> <message> - Send a message to a user
    Example: SEND alice Don't forget the meeting tomorrow!
    If the user is offline, they'll receive it when they return
  READ - Read all your offline messages
    Shows sender, timestamp, and message content
  [... additional commands with examples ...]
```

**NewsFlash Service:**
- Added examples for ADD, DEL, PUSH commands
- Clarified staff-only vs admin-only commands
- Explained difference between persistent news and PUSH

**Impact:**
- Users can learn commands without leaving IRC
- Concrete examples reduce confusion
- Typo suggestions prevent frustration

---

## Phase 3: ServiceBot Enhancements

### ServiceBot Dispatcher

**Problem:** Users had to guess which ServiceBot (01-10) was available

**Solution:** Created virtual "ServiceBot" user as a pool dispatcher

**Implementation:**
```python
# Created virtual ServiceBot dispatcher user
servicebot_dispatcher = self._create_virtual_service('ServiceBot', 'ServiceBot', "ServiceBot Pool Dispatcher")

# When inviting "ServiceBot", automatically pick first available bot
if target_nick == "ServiceBot":
    # Find first available ServiceBot01-10
    for bot_name in sorted(self.servicebots.keys()):
        bot = self.servicebots[bot_name]
        max_chans = getattr(bot, 'max_channels', 10)
        if len(bot.channels) < max_chans:
            # Found available bot - join it to channel
            await user.send(f"Dispatched {bot_name} to {chan_name}")
            break
```

**Usage:**
```
Before: /INVITE ServiceBot03 #channel  (had to know which was available)
After:  /INVITE ServiceBot #channel    (automatically picks available bot)
```

**Features:**
- Picks bots in order (ServiceBot01, 02, 03...)
- Gracefully handles full capacity (all bots busy)
- Logs which bot was assigned for audit trail
- Maintains compatibility with direct invites (`/INVITE ServiceBot05 #channel`)

**Impact:**
- Simplified UX: no more guessing which bot is free
- Faster channel setup
- Professional automated bot management

### Flexible Profanity Filter

**Problem:** Profanity filter only supported exact word matching, difficult to manage

**Solution 1: Regex Pattern Support**

Enhanced `ServiceBotMonitor.check_profanity()` to support regex patterns:

```python
def check_profanity(self, text):
    words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
    patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])

    # Check exact words with word boundaries
    for word in words:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, check_text):
            return True, word

    # Check regex patterns (more flexible)
    for pattern_str in patterns:
        if re.search(pattern_str, text, flags):
            return True, f"pattern:{pattern_str}"
```

**Configuration:**
```json
{
  "servicebot": {
    "profanity_filter": {
      "enabled": true,
      "words": ["badword", "spam"],
      "patterns": ["(bad|terrible).*word", "\\d{4}-\\d{4}-\\d{4}-\\d{4}"],
      "case_sensitive": false,
      "action": "warn"
    }
  }
}
```

**Pattern Examples:**
- `"(bad|terrible).*word"` - Matches variations like "bad word", "terrible badword"
- `"spam{2,}"` - Matches "spamm", "spammm", etc.
- `"\\d{4}-\\d{4}-\\d{4}-\\d{4}"` - Matches credit card patterns
- `"(viagra|cialis)"` - Matches pharmaceutical spam

**Solution 2: PROFANITY Command**

Added comprehensive admin command for dynamic management:

**Command Syntax:**
```
/PROFANITY LIST                     - Show current configuration
/PROFANITY ADD WORD <word>          - Add exact word to filter
/PROFANITY ADD PATTERN <regex>      - Add regex pattern
/PROFANITY DEL WORD <word>          - Remove word
/PROFANITY DEL PATTERN <regex>      - Remove pattern
/PROFANITY ENABLE                   - Enable filter
/PROFANITY DISABLE                  - Disable filter
/PROFANITY TEST <text>              - Test if text would be caught
```

**Examples:**
```
/PROFANITY ADD WORD spam
  → Added word 'spam' to profanity filter

/PROFANITY ADD PATTERN (viagra|cialis)
  → Added pattern '(viagra|cialis)' to profanity filter

/PROFANITY TEST Hey check out this viagra offer!
  → TEST RESULT: Would be caught - matched: pattern:(viagra|cialis)

/PROFANITY LIST
  → === Profanity Filter Configuration ===
  → Status: Enabled
  → Action: warn (warn/gag/kick)
  → Case Sensitive: No
  →
  → Filtered Words (2):
  →   - spam
  →   - badword
  →
  → Regex Patterns (1):
  →   - (viagra|cialis)
```

**Features:**
- ✅ Real-time configuration (no restart required)
- ✅ Changes persist to config file
- ✅ Regex validation (rejects invalid patterns)
- ✅ Duplicate detection (won't add twice)
- ✅ TEST subcommand for validation
- ✅ ADMIN-only (requires +a mode)
- ✅ Full audit logging

**Implementation Highlights:**
```python
async def handle_profanity(self, user, params):
    if not user.is_admin():
        # ADMIN only
        return

    # ADD PATTERN with validation
    if subcmd == "ADD" and add_type == "PATTERN":
        try:
            re.compile(value)  # Validate regex
        except re.error as e:
            await user.send(f"Invalid regex pattern: {e}")
            return

        current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
        current_patterns.append(value)
        CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
        await CONFIG.save()  # Persist to file
```

**Impact:**
- Admins can fine-tune filters without editing config files
- Regex patterns catch variations and creative spelling
- TEST command prevents false positives before deployment
- Live management enables rapid response to new spam patterns

---

## Phase 4: File Organization

### Changes

**Moved:**
- ✅ `generate_default_config.py` → `utils/generate_default_config.py`

**Rationale:**
- Better project organization
- Utility scripts belong in utils/ directory
- Cleaner root directory
- Consistent with other utility scripts

---

## Summary Statistics

### Messages
- **Messages Improved:** ~40
- **Categories:** RESPONSES (IRC numerics), SERVER_MESSAGES (NOTICE templates)
- **Priority Breakdown:**
  - 🔴 High: 15 (grammar, spacing, clarity)
  - 🟡 Medium: 15 (helpfulness, context)
  - 🟢 Low: 10 (polish, consistency)

### Help System
- **New Command Help Pages:** 15+
- **Enhanced Service Help:** 3 services (Registrar, Messenger, NewsFlash)
- **Features Added:** Fuzzy matching suggestions, concrete examples

### ServiceBot
- **New Features:** 2 (Dispatcher, Regex patterns)
- **New Commands:** 1 (PROFANITY with 8 subcommands)
- **Lines of Code Added:** ~150

### Files Modified
- `pyircx.py` - Main server file
  - Lines 1298-1331: Enhanced profanity checking
  - Lines 2661-2665: ServiceBot dispatcher creation
  - Lines 3137-3138: PROFANITY command routing
  - Lines 4542-4571: ServiceBot dispatcher logic
  - Lines 5899-6055: PROFANITY command implementation
  - Lines 5995-6176: Enhanced HELP with individual commands
  - Lines 7547-7581: Enhanced Registrar help
  - Lines 8120-8138: Enhanced Messenger help
  - Lines 8315-8332: Enhanced NewsFlash help
- `utils/generate_default_config.py` - Moved from root

---

## Testing Performed

### Manual Testing on atlas.jdlewis.net

**Message Quality:**
- ✅ Verified error message improvements show correct text
- ✅ Confirmed multi-sentence messages have trailing periods
- ✅ Tested permission denied messages show proper capitalization

**Help System:**
- ✅ Tested `/HELP` main menu
- ✅ Verified `/HELP JOIN`, `/HELP MODE`, `/HELP ACCESS` show examples
- ✅ Confirmed typo suggestions work (`/HELP JION`)
- ✅ Tested service help: `/MSG Registrar HELP`, `/MSG Messenger HELP`

**ServiceBot Dispatcher:**
- ✅ Verified `/INVITE ServiceBot #channel` picks first available bot
- ✅ Confirmed sequential bot assignment (01, 02, 03...)
- ✅ Tested capacity handling (all bots busy scenario)
- ✅ Verified direct bot invites still work (`/INVITE ServiceBot05 #channel`)

**PROFANITY Command:**
- ✅ Tested `/PROFANITY LIST` shows configuration
- ✅ Verified `/PROFANITY ADD WORD` and `/PROFANITY ADD PATTERN`
- ✅ Confirmed regex validation rejects invalid patterns
- ✅ Tested `/PROFANITY TEST` catches filtered content
- ✅ Verified `/PROFANITY DEL` removes words/patterns
- ✅ Tested `/PROFANITY ENABLE` and `/PROFANITY DISABLE`
- ✅ Confirmed changes persist across restarts

**Deployment:**
- ✅ Service restarts cleanly on atlas.jdlewis.net
- ✅ No syntax errors or crashes
- ✅ All features working in production

---

## User-Facing Impact

### What Users Will Notice

**Better Communication:**
- Error messages are clearer and more helpful
- Guidance on what to do next is always provided
- Professional, consistent formatting throughout

**Easier Learning:**
- Type `/HELP JOIN` to see exactly how to use JOIN command
- Examples show real usage patterns
- Typo suggestions prevent "command not found" frustration

**Simpler ServiceBot Management:**
- Just `/INVITE ServiceBot #channel` - no guessing
- System picks the right bot automatically
- Clear notification of which bot was assigned

### What Admins Will Notice

**Dynamic Profanity Management:**
- Add/remove filters on the fly without editing files
- Test patterns before deploying
- Regex patterns catch creative spelling
- Full audit trail of changes

**Better Documentation:**
- Enhanced help text means fewer support questions
- Users can self-serve for common questions
- Service help explains all features with examples

---

## Configuration Changes Required

### Optional: Profanity Filter Setup

If you want to use the profanity filter, add to `pyircx_config.json`:

```json
{
  "servicebot": {
    "enabled": true,
    "profanity_filter": {
      "enabled": true,
      "words": ["spam", "badword"],
      "patterns": ["(viagra|cialis)", "\\d{4}-\\d{4}-\\d{4}-\\d{4}"],
      "case_sensitive": false,
      "action": "warn",
      "warn_message": "Please watch your language"
    },
    "malicious_detection": {
      "enabled": true,
      "flood_threshold": 5,
      "flood_window": 3,
      "flood_action": "gag"
    }
  }
}
```

**Or manage dynamically with:**
```
/PROFANITY ADD WORD spam
/PROFANITY ADD PATTERN (viagra|cialis)
/PROFANITY ENABLE
```

---

## Upgrade Instructions

### From v1.1.9 to v1.2.0

These improvements are **backwards compatible** - no configuration changes required.

**Deployment:**
```bash
cd /opt/pyircx
sudo git pull
sudo systemctl restart pyircx
```

**Verification:**
```bash
# Verify service is running
sudo systemctl status pyircx

# Test new features
/HELP JOIN
/INVITE ServiceBot #test
/PROFANITY LIST  (if admin)
```

---

## Future Enhancement Ideas

Based on this polish work, potential future improvements:

1. **MOTD Enhancements** - ASCII art, formatted sections, first-time user guidance
2. **STATS Formatting** - Better readability, colored output (if supported), graphs
3. **Staff Command Improvements** - More detailed responses, operation confirmations
4. **Interactive Tutorials** - Guide new users through first-time setup
5. **Command Aliases** - `/J` for `/JOIN`, `/P` for `/PART`
6. **Contextual Help** - Show help for command if user types it wrong
7. **ServiceBot Scheduling** - Rotate bots, automatic maintenance mode
8. **Profanity Learning** - Suggest patterns based on caught variations

---

## Credits

**Implementation Date:** January 16, 2026
**Deployed To:** atlas.jdlewis.net
**Version:** Bridging v1.1.9 → v1.2.0
**Impact:** 100+ improvements across help, messages, and ServiceBot systems

---

## Document Version

**Version:** 1.0
**Last Updated:** January 16, 2026
**Status:** Complete - All improvements deployed
