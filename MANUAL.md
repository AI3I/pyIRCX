# pyIRCX Server Manual

**Version:** 1.0.4
**Last Updated:** 2026-01-02
**License:** GNU General Public License v3.0

---

## Table of Contents

1. [Overview](#overview)
2. [Installation & Requirements](#installation--requirements)
3. [Configuration Reference](#configuration-reference)
4. [Database Schema](#database-schema)
5. [Connection & Authentication](#connection--authentication)
6. [User Commands](#user-commands)
7. [Channel Commands](#channel-commands)
8. [Channel Modes](#channel-modes)
9. [User Modes](#user-modes)
10. [IRCX Protocol Extensions](#ircx-protocol-extensions)
11. [Services](#services)
12. [Staff System](#staff-system)
13. [Security Features](#security-features)
14. [Channel Behavior & Logic](#channel-behavior--logic)
15. [Numeric Replies Reference](#numeric-replies-reference)
16. [Technical Details](#technical-details)

---

## Overview

pyIRCX is an asynchronous IRC/IRCX server implementation written in Python. It provides:

- Full IRC protocol support (RFC 1459/2812 compatible)
- Microsoft IRCX protocol extensions
- Database-backed user and channel registration
- Three-tier staff system (ADMIN, SYSOP, GUIDE)
- Built-in services (Registrar, Messenger, NewsFlash)
- Automated channel monitoring (ServiceBots)
- DNSBL integration for connection screening
- Flood protection and rate limiting
- Channel transcripts/logging
- Two-factor authentication (TOTP)
- Offline messaging system

### Key Features

| Feature | Description |
|---------|-------------|
| Async I/O | Built on Python asyncio for high performance |
| SQLite Backend | Persistent storage for users, channels, messages |
| IRCX Support | Extended protocol with PROP, WHISPER, ACCESS |
| Staff Tiers | ADMIN > SYSOP > GUIDE permission hierarchy |
| Auto-moderation | ServiceBots monitor channels for abuse |
| 2FA Support | TOTP-based two-factor authentication |

---

## Installation & Requirements

### Dependencies

```
python >= 3.8
aiosqlite
bcrypt
pyotp
```

### Quick Start

```bash
# Install dependencies
pip install aiosqlite bcrypt pyotp

# Run the server
python3 pyircx.py

# Run with custom config
python3 pyircx.py --config /path/to/config.json

# Run on specific port
python3 pyircx.py --port 6667
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--config <path>` | Path to configuration file |
| `--port <port>` | Override listen port |
| `--debug` | Enable debug logging |

---

## Configuration Reference

Configuration is stored in `pyircx_config.json`. Below is a complete reference:

### Server Section
```json
{
  "server": {
    "name": "irc.local",
    "network": "IRCX Network",
    "staff_login_message": "Welcome to the staff team."
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | `irc.local` | Server hostname shown to clients |
| `network` | string | `IRCX Network` | Network name |
| `staff_login_message` | string | `Welcome...` | Message shown to staff on login |

### Network Section
```json
{
  "network": {
    "listen_addr": "0.0.0.0",
    "listen_addr_ipv6": "::",
    "listen_ports": [6667, 7000],
    "enable_ipv6": true,
    "resolve_hostnames": true
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `0.0.0.0` | IPv4 address to bind |
| `listen_addr_ipv6` | string | `null` | IPv6 address to bind (defaults to `::` if IPv6 enabled) |
| `listen_ports` | array | `[6667]` | Ports to listen on |
| `enable_ipv6` | bool | `true` | Enable IPv6 dual-stack support |
| `resolve_hostnames` | bool | `true` | Resolve client IP to hostname |

### Database Section
```json
{
  "database": {
    "path": "pyircx.db"
  }
}
```

### System Section
```json
{
  "system": {
    "nick": "System",
    "ident": "System",
    "staff_term": "staff and services"
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `nick` | string | `System` | System service nickname |
| `ident` | string | `System` | System service ident |
| `staff_term` | string | `staff and services` | Term used in LUSERS for operator count |

### Modes Section
```json
{
  "modes": {
    "user": "agiorxz",
    "channel": "adfikmnprstuwxy",
    "channel_defaults": "nt"
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user` | string | `agiorxz` | Available user modes (alphabetized) |
| `channel` | string | `adfikmnprstuwxy` | Available channel modes (alphabetized) |
| `channel_defaults` | string | `nt` | Modes set on new channels |

### Limits Section
```json
{
  "limits": {
    "max_users": 1000,
    "msg_length": 512,
    "nick_change_cooldown": 60,
    "max_nick_length": 30,
    "max_user_length": 30,
    "max_channel_length": 50,
    "max_channels": 500,
    "max_channels_per_user": 20
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_users` | int | `1000` | Maximum concurrent connections |
| `msg_length` | int | `512` | Maximum message length |
| `nick_change_cooldown` | int | `60` | Seconds between nick changes (0-3600) |
| `max_nick_length` | int | `30` | Maximum nickname length |
| `max_user_length` | int | `30` | Maximum username length |
| `max_channel_length` | int | `50` | Maximum channel name length |
| `max_channels` | int | `500` | Maximum channels on server |
| `max_channels_per_user` | int | `20` | Maximum channels per user |

### Transcript Section
```json
{
  "transcript": {
    "enabled": true,
    "directory": "transcripts",
    "max_lines": 10000,
    "format": "[{timestamp}] {event}"
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable transcript feature |
| `directory` | string | `transcripts` | Directory for transcript files |
| `max_lines` | int | `10000` | Maximum lines per transcript |
| `format` | string | `[{timestamp}] {event}` | Log line format |

### Services Section
```json
{
  "services": {
    "servicebot_count": 10,
    "servicebot_max_channels": 10
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `servicebot_count` | int | `10` | Number of ServiceBots to create |
| `servicebot_max_channels` | int | `10` | Max channels per ServiceBot |

### Security Section
```json
{
  "security": {
    "flood_messages": 5,
    "flood_window": 2.0,
    "connection_throttle": 100,
    "throttle_window": 60.0,
    "enable_flood_protection": true,
    "enable_connection_throttle": false,
    "dnsbl": {
      "enabled": false,
      "action": "reject",
      "timeout": 3.0,
      "cache_ttl": 3600,
      "lists": ["dnsbl.dronebl.org", "rbl.efnetrbl.org"],
      "whitelist": [],
      "reject_message": "Your IP is blacklisted."
    },
    "proxy_detection": {
      "enabled": false,
      "ports": [8080, 3128, 1080, 9050],
      "timeout": 2.0,
      "action": "warn"
    },
    "connection_scoring": {
      "enabled": false,
      "threshold": 100,
      "dnsbl_score": 50,
      "proxy_score": 30,
      "no_ident_score": 10,
      "generic_hostname_score": 5
    }
  }
}
```

### ServiceBot Section
```json
{
  "servicebot": {
    "enabled": true,
    "profanity_filter": {
      "enabled": true,
      "action": "warn",
      "words": ["badword"],
      "warn_message": "Please watch your language.",
      "case_sensitive": false
    },
    "malicious_detection": {
      "enabled": true,
      "flood_threshold": 5,
      "flood_window": 3,
      "flood_action": "gag",
      "caps_threshold": 0.7,
      "caps_min_length": 10,
      "caps_action": "warn",
      "url_spam_threshold": 3,
      "url_spam_window": 10,
      "url_spam_action": "warn",
      "repeat_threshold": 3,
      "repeat_window": 30,
      "repeat_action": "warn"
    }
  }
}
```

**ServiceBot Actions:**
- `warn` - Send warning notice to user
- `gag` - Prevent user from speaking (+z)
- `kick` - Remove from channel
- `ban` - Ban and remove from channel

### Persistence Section
```json
{
  "persistence": {
    "auto_save": true,
    "save_interval": 300
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_save` | bool | `true` | Automatically save channel data |
| `save_interval` | int | `300` | Seconds between auto-saves |

### Admin Section
```json
{
  "admin": {
    "loc1": "pyIRCX Administration",
    "loc2": "Network Operations",
    "email": "admin@irc.local"
  }
}
```

---

## Database Schema

pyIRCX uses SQLite for persistent storage. The database contains the following tables:

### users
Staff account credentials.
```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    level TEXT  -- 'ADMIN', 'SYSOP', or 'GUIDE'
);
```

### registered_nicks
Registered nickname information.
```sql
CREATE TABLE registered_nicks (
    nickname TEXT PRIMARY KEY,
    password_hash TEXT,
    email TEXT,
    registered_at INTEGER,
    last_seen INTEGER,
    mfa_secret TEXT,
    mfa_enabled INTEGER DEFAULT 0,
    backup_codes TEXT
);
```

### registered_channels
Channel ownership records.
```sql
CREATE TABLE registered_channels (
    channel TEXT PRIMARY KEY,
    owner TEXT,
    registered_at INTEGER,
    last_used INTEGER,
    FOREIGN KEY (owner) REFERENCES registered_nicks(nickname)
);
```

### reg_chans
Serialized channel state for persistence.
```sql
CREATE TABLE reg_chans (
    name TEXT PRIMARY KEY,
    data TEXT,  -- JSON blob
    registered_at INTEGER
);
```

### server_access
Server-wide access control lists.
```sql
CREATE TABLE server_access (
    id INTEGER PRIMARY KEY,
    type TEXT,      -- 'OWNER', 'HOST', 'VOICE', 'GRANT', or 'DENY'
    pattern TEXT,   -- Hostmask pattern
    set_by TEXT,
    set_at INTEGER,
    timeout INTEGER, -- Unix timestamp when entry expires (0 = permanent)
    reason TEXT
);
```

### mailbox
Offline message storage.
```sql
CREATE TABLE mailbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT,
    sender TEXT,
    message TEXT,
    sent_at INTEGER,
    read INTEGER DEFAULT 0
);
```

### newsflash
Broadcast message storage.
```sql
CREATE TABLE newsflash (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    created_by TEXT,
    created_at INTEGER,
    expires_at INTEGER
);
```

### memos
Quick memo storage.
```sql
CREATE TABLE memos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT,
    sender TEXT,
    message TEXT,
    sent_at INTEGER,
    delivered INTEGER DEFAULT 0
);
```

---

## Connection & Authentication

### Connection Flow

**Standard Flow:**
1. Client connects to server port
2. Server sends welcome banner (if DNSBL passes)
3. Client sends NICK and USER commands
4. Server validates nickname/username
5. Server sends 001-005 welcome numerics
6. Client is registered and can join channels

**With CAP/SASL (IRCv3):**
1. Client connects to server port
2. Client sends `CAP LS 302`
3. Server lists available capabilities
4. Client sends `CAP REQ :sasl multi-prefix` (etc.)
5. Server sends `CAP ACK :sasl multi-prefix`
6. Client sends `AUTHENTICATE PLAIN`, then credentials
7. Server sends 903 on success (or 904 on failure)
8. Client sends `CAP END`
9. Client sends NICK and USER commands
10. Server sends 001-005 welcome numerics
11. Client is registered with SASL-authenticated identity

### NICK
Set or change nickname.
```
NICK <nickname>
```

**Validation Rules:**
- Cannot start with a digit
- Cannot contain: `. + = # ! @ % & ^ $ ~`
- Cannot look like an IP address or hostname
- Maximum length: 30 characters (configurable)
- Cannot match existing nickname (case-insensitive)

**Nick Change Cooldown:**
- Default: 60 seconds between changes
- Range: 0-3600 seconds (3600 = effectively disabled)
- ADMINs and SYSOPs are exempt
- Only applies after initial registration

### USER
Set username and realname.
```
USER <username> <mode> <unused> :<realname>
```

**Validation Rules:**
- Same character restrictions as NICK
- Maximum length: 30 characters
- Anonymous (unauthenticated) users get `~` prefix

### PASS
Authenticate as staff during connection.
```
PASS <username>:<password>
```
- Must be sent before USER command completes
- Authenticates against `users` database table
- Grants appropriate staff mode (a/o/g) on success

### IRCX / ISIRCX
Enable IRCX protocol extensions.
```
IRCX
ISIRCX
```
- Enables extended commands (PROP, WHISPER, DATA, ACCESS, EVENT)
- Sets user mode +x
- Can be sent before or after registration

### CAP (IRCv3 Capability Negotiation)
Negotiate protocol capabilities with the server.
```
CAP LS [version]      - List available capabilities
CAP REQ :<caps>       - Request capabilities (space-separated)
CAP END               - End negotiation, proceed with registration
CAP LIST              - List currently enabled capabilities
```

**Available Capabilities:**
| Capability | Description |
|------------|-------------|
| `sasl` | SASL authentication support |
| `multi-prefix` | Show all prefix modes in NAMES/WHO |
| `away-notify` | Notify when users go away |
| `account-notify` | Notify on account changes |
| `extended-join` | Extended JOIN with account info |
| `server-time` | Message timestamps |
| `userhost-in-names` | Full hostmask in NAMES |
| `cap-notify` | Notify of capability changes |
| `message-tags` | IRCv3.2 message tags |
| `batch` | Message batching |
| `echo-message` | Echo sent messages back |

**Example:**
```
CAP LS 302
CAP REQ :sasl multi-prefix
CAP END
```

### AUTHENTICATE (SASL)
Authenticate using SASL before registration completes.
```
AUTHENTICATE <mechanism>    - Start authentication (e.g., PLAIN)
AUTHENTICATE <credentials>  - Send credentials (base64 encoded)
AUTHENTICATE *              - Abort authentication
```

**Supported Mechanisms:**
- `PLAIN` - Base64 encoded `authzid\0authcid\0password`

**SASL PLAIN Flow:**
```
Client: CAP REQ :sasl
Server: CAP ACK :sasl
Client: AUTHENTICATE PLAIN
Server: AUTHENTICATE +
Client: AUTHENTICATE AGpvaG5kb2UAc2VjcmV0cGFzcw==
Server: :server 903 nick :SASL authentication successful
Client: CAP END
```

**Notes:**
- The base64 payload format is: `\0username\0password` (authzid is typically empty)
- On success, user is identified before registration completes
- Staff members receive their modes immediately upon SASL auth
- SASL is required to be enabled via `CAP REQ :sasl` first

**SASL Numerics:**
| Numeric | Meaning |
|---------|---------|
| 900 | Logged in successfully |
| 903 | SASL authentication successful |
| 904 | SASL authentication failed |
| 905 | SASL message too long |
| 906 | SASL authentication aborted |
| 907 | Already authenticated via SASL |
| 908 | Available SASL mechanisms |

### QUIT
Disconnect from server.
```
QUIT [:<message>]
```

---

## User Commands

### Message Commands

#### PRIVMSG
Send message to user or channel.
```
PRIVMSG <target> :<message>
PRIVMSG * :<message>          -- Broadcast (ADMIN only)
```

#### NOTICE
Send notice to user or channel (no auto-reply expected).
```
NOTICE <target> :<message>
NOTICE * :<message>           -- Broadcast (ADMIN only)
```

#### WHISPER (IRCX)
Send private message within channel context.
```
WHISPER <#channel> <nick> :<message>
```
- Single recipient only (no comma-separated targets)
- 5-second rate limit
- Blocked if channel has +w mode

#### DATA (IRCX)
Send data/file transfer initiation.
```
DATA <#channel> <nick> :<data>
```

### Channel Commands

#### JOIN / CREATE
Join or create a channel.
```
JOIN <#channel> [key]
CREATE <#channel>
```

#### PART
Leave a channel.
```
PART <#channel> [:<message>]
```

#### TOPIC
View or set channel topic.
```
TOPIC <#channel>                -- View topic
TOPIC <#channel> :<new topic>   -- Set topic
```

#### KICK
Remove user from channel.
```
KICK <#channel> <nick> [:<reason>]
```
- Requires +q (owner), +o (op), or ADMIN

#### INVITE
Invite user to channel.
```
INVITE <nick> <#channel>
```
- Requires +q, +o, or ADMIN for invite-only channels

#### KNOCK
Request invite to invite-only channel.
```
KNOCK <#channel> [:<message>]
```
- 60-second cooldown per channel
- Sends notice to channel operators

#### NAMES
List channel members.
```
NAMES [#channel[,#channel2,...]]
```

#### LIST / LISTX
List channels.
```
LIST [pattern]      -- Standard format
LISTX [pattern]     -- IRCX extended format
```

#### MODE
View or set modes.
```
MODE <target>                   -- View modes
MODE <target> <+/-modes> [params]
```
See [Channel Modes](#channel-modes) and [User Modes](#user-modes).

#### TRANSCRIPT
View channel message history.
```
TRANSCRIPT <#channel> [lines]
```
- Requires channel membership
- Channel must have +y mode enabled
- Default: 50 lines, Maximum: 500 lines

### Query Commands

#### WHO
Query user information.
```
WHO <#channel>     -- List channel members
WHO <pattern>      -- Search by nick pattern (* and % wildcards)
WHO *              -- All users (ADMIN/SYSOP only)
```

**WHO Flags:**
| Flag | Meaning |
|------|---------|
| `H` | Here (not away) |
| `G` | Gone (away) |
| `i` | Invisible (staff view only) |
| `x` | IRCX mode enabled |
| `a` | ADMIN (IRCX mode) |
| `o` | SYSOP (IRCX mode) |
| `g` | GUIDE (IRCX mode) |
| `*` | IRC Operator (non-IRCX) |
| `.` | Channel owner |
| `@` | Channel host |
| `+` | Channel voice |

#### WHOIS
Query detailed user information.
```
WHOIS <nick>
```

#### WHOWAS
Query recently disconnected user.
```
WHOWAS <nick>
```

#### ISON
Check if users are online.
```
ISON <nick> [nick2] [nick3]...
```

### User Management

#### AWAY
Set or clear away status.
```
AWAY :<message>    -- Set away
AWAY               -- Clear away
```

#### WATCH
Monitor user online/offline status.
```
WATCH +<nick>      -- Add to watch list
WATCH -<nick>      -- Remove from watch list
WATCH L            -- List watched nicks
WATCH C            -- Clear watch list
```

#### SILENCE
Block messages from users.
```
SILENCE +<hostmask>    -- Add to silence list
SILENCE -<hostmask>    -- Remove from silence list
SILENCE                -- List silenced masks
```

### Information Commands

#### TIME
Get server time.
```
TIME
```

#### VERSION
Get server version.
```
VERSION
```

#### MOTD
View message of the day.
```
MOTD
```

#### LUSERS
View user statistics.
```
LUSERS
```

#### ADMIN
View server administrator info.
```
ADMIN
```

#### STATS
View server statistics.
```
STATS ?    -- Help menu
STATS *    -- All stats (ADMIN only)
STATS u    -- Uptime
STATS m    -- Commands/messages
STATS c    -- Connections
STATS t    -- Traffic/users
STATS s    -- Staff online
STATS d    -- DNSBL stats
STATS x    -- IRCX user count
STATS a    -- Access lists
STATS l    -- Online staff list
```

### Registration Commands

#### REGISTER
Register current nickname.
```
REGISTER <password> [email]
```

#### IDENTIFY
Identify to registered nickname.
```
IDENTIFY <password> [mfa_code]
```

#### UNREGISTER
Drop nickname registration.
```
UNREGISTER <password>
```

#### MFA
Manage two-factor authentication.
```
MFA SETUP           -- Begin 2FA setup
MFA CONFIRM <code>  -- Confirm 2FA setup
MFA DISABLE <code>  -- Disable 2FA
MFA CODES           -- View backup codes
```

#### CHGPASS
Change password (for staff accounts).
```
CHGPASS <oldpass> <newpass>
```

### Utility Commands

#### MEMO
Send offline message (shortcut).
```
MEMO <nick> <message>
```

#### PING
Keepalive ping.
```
PING <token>
```

---

## Channel Commands

### PROP (IRCX)
Get or set channel properties.
```
PROP <#channel>                        -- List all properties
PROP <#channel> <property>             -- Get property
PROP <#channel> <property> :<value>    -- Set property
```

**Settable Properties:**

| Property | Description | Who Can Set |
|----------|-------------|-------------|
| `TOPIC` | Channel topic | Hosts/Owners (respects +t) |
| `MEMBERKEY` | Join password (syncs with MODE +k) | Hosts/Owners |
| `HOSTKEY` | Key that grants +o on join | Owners only |
| `OWNERKEY` | Key that grants +q on join | Owners only |
| `ONJOIN` | Message sent to users when they join | Owners only |
| `ONPART` | Message sent to users when they leave | Owners only |

**Read-Only Properties:**

| Property | Description |
|----------|-------------|
| `CREATION` | Unix timestamp of channel creation |
| `ACCOUNT` | UUID (only set when channel is registered) |

**ONJOIN/ONPART Messages:**

Set a welcome or goodbye message for your channel:
```
PROP #channel ONJOIN :Welcome to #channel! Please read the rules.
PROP #channel ONPART :Thanks for visiting!
```
- Clear by setting to empty: `PROP #channel ONJOIN :`
- Messages are sent as NOTICEs from the channel to the user

### ACCESS (IRCX)
Manage channel and server access lists.

**Channel Access:**
```
ACCESS <#channel> LIST [level]              -- List access entries
ACCESS <#channel> ADD <level> <mask> [timeout] [:<reason>]
ACCESS <#channel> DELETE <level> <mask>     -- Remove entry
ACCESS <#channel> CLEAR <level>             -- Clear all entries for level
```

**Server Access (Staff only):**
```
ACCESS $ LIST [level]                       -- List server access
ACCESS * LIST [level]                       -- Same as above
ACCESS $ ADD <level> <mask> [timeout] [:<reason>]
ACCESS $ DELETE <level> <mask>
ACCESS $ CLEAR <level>
```

**Access Levels:**

| Level | Description | Effect |
|-------|-------------|--------|
| `OWNER` | Auto-owner on join | Grants +q when user joins |
| `HOST` | Auto-host on join | Grants +o when user joins |
| `VOICE` | Auto-voice on join | Grants +v when user joins |
| `GRANT` | Allowed to join | Bypasses +i (invite-only) |
| `DENY` | Banned from channel | Works like +b ban |

**Mask Format:**
- `nick` - Match by nickname only
- `nick!user@host` - Full hostmask with wildcards
- `*!*@*.example.com` - Match by host pattern
- `*!~*@*` - Match unidentified users

**Timeout:**
- Specified in minutes
- `0` or omitted = permanent
- Example: `ACCESS #channel ADD DENY baduser 60 :1 hour ban`

**Examples:**
```
ACCESS #channel LIST                         -- List all access entries
ACCESS #channel LIST DENY                    -- List only DENY entries
ACCESS #channel ADD OWNER *!*@admin.net      -- Auto-owner for admin.net
ACCESS #channel ADD HOST bob                 -- Auto-host for bob
ACCESS #channel ADD VOICE *!*@*.trusted.org  -- Auto-voice for trusted.org
ACCESS #channel ADD DENY spammer 1440 :24h ban
ACCESS #channel DELETE DENY spammer
ACCESS #channel CLEAR DENY                   -- Remove all DENY entries
```

**Permissions:**
- Channel owners (+q) can manage channel ACCESS
- ADMIN/SYSOP can manage server ACCESS ($)
- DENY entries work like bans (checked on JOIN)

### EVENT (IRCX)
Subscribe to server events.
```
EVENT ADD <type>
EVENT DEL <type>
EVENT LIST
```

**Event Types:**
- `JOIN` - Channel joins
- `PART` - Channel parts
- `MODE` - Mode changes
- `KICK` - Kicks
- `TOPIC` - Topic changes

---

## Channel Modes

### Basic Modes

| Mode | Name | Description |
|------|------|-------------|
| `n` | No External | Block messages from users not in channel |
| `t` | Topic Lock | Only hosts/owners can change topic |
| `i` | Invite Only | Requires invite or key to join |
| `m` | Moderated | Only voiced/hosts can speak |
| `p` | Private | Channel marked as private |
| `s` | Secret | Hidden from WHO/WHOIS/LIST |
| `k` | Key | Requires password (MEMBERKEY) to join |
| `l` | Limit | Maximum number of users |

### Extended Modes

| Mode | Name | Description |
|------|------|-------------|
| `a` | Admin Only | Only server admins can join |
| `d` | Clone | Enable clone mode - creates overflow channels when +l limit reached |
| `e` | Cloned | Indicates channel is a clone (set automatically, read-only) |
| `f` | Filtered | Strip mIRC formatting codes |
| `h` | Hidden | Hidden from LIST (but not WHO) |
| `r` | Registered | Channel is registered (read-only, set by server) |
| `u` | Auditorium | Hide member list from non-hosts |
| `w` | No Whispers | Block WHISPER command in channel |
| `x` | IRCX | Channel supports IRCX extensions |
| `y` | Transcript | Enable message logging/history |

### Clone Channels

When a channel has both `+d` (clone mode) and `+l` (user limit) set, it becomes a clone-enabled channel. When the channel reaches its user limit, joining users are automatically placed in clone channels.

**How it works:**
1. Set `+d` and `+l` on the original channel (e.g., `MODE #lobby +dl 50`)
2. When user 51 tries to join, `#lobby1` is created automatically
3. The clone inherits all modes, properties, topic, bans, and keys from the original
4. Clones have `+e` mode to indicate they are clones
5. If `#lobby1` fills up, `#lobby2` is created, and so on

**Behavior:**
- Users joining the original are automatically placed in the first available clone
- Mode changes on the original propagate to all clones (except +d and +e)
- Clones are automatically deleted when emptied
- Staff and bots can join specific clones directly
- Clone channels cannot spawn their own clones (no nested cloning)

### User Prefix Modes

| Mode | Prefix | Name | Description |
|------|--------|------|-------------|
| `q` | `.` | Owner | Full channel control |
| `o` | `@` | Host | Channel moderation |
| `v` | `+` | Voice | Can speak in +m channels |

### Mode Examples

```
MODE #channel +nt                  -- No external messages, topic lock
MODE #channel +i                   -- Invite only
MODE #channel +k secretkey         -- Set channel key
MODE #channel -k *                 -- Remove channel key
MODE #channel +l 50                -- Set user limit to 50
MODE #channel -l                   -- Remove user limit
MODE #channel +o nick              -- Give host
MODE #channel -o nick              -- Remove host
MODE #channel +q nick              -- Give owner
MODE #channel +v nick              -- Give voice
MODE #channel +b *!*@*.bad.host    -- Ban hostmask
MODE #channel -b *!*@*.bad.host    -- Remove ban
MODE #channel +mnt                 -- Multiple modes at once
MODE #channel +ov nick1 nick2      -- Host nick1, voice nick2
```

---

## User Modes

| Mode | Name | Description | Who Can Set |
|------|------|-------------|-------------|
| `a` | Admin | Server administrator | Server (via PASS auth) |
| `g` | Guide | Server guide/helper | Server (via PASS auth) |
| `i` | Invisible | Hidden from WHO (staff can still see) | Self |
| `o` | Sysop | Server operator | Server (via PASS auth) |
| `r` | Registered | Authenticated/identified user | Server (on IDENTIFY) |
| `x` | IRCX | IRCX protocol enabled | Self (via IRCX command) |
| `z` | Gagged | Cannot send messages | Staff only |

---

## IRCX Protocol Extensions

IRCX (Internet Relay Chat Extensions) is a Microsoft extension to the IRC protocol. pyIRCX implements the following IRCX features:

### Enabling IRCX
```
IRCX
-- or --
ISIRCX
```

### IRCX-Specific Commands

| Command | Description |
|---------|-------------|
| `PROP` | Get/set channel properties |
| `WHISPER` | Private message within channel |
| `DATA` | Data/file transfer |
| `ACCESS` | Channel access lists |
| `EVENT` | Event subscriptions |
| `LISTX` | Extended channel list |

### IRCX Numeric Replies

| Code | Description |
|------|-------------|
| 800 | IRCX welcome/confirmation |
| 801 | ACCESS list entry |
| 802 | End of ACCESS list |
| 803 | ACCESS entry added |
| 804 | IRCX enabled confirmation |
| 805 | PROP not found |
| 812 | LISTX entry |
| 813 | End of LISTX |
| 817 | PROP value |
| 818 | End of PROP list |
| 819 | PROP set confirmation |
| 820 | Event added |
| 821 | Event deleted |
| 822 | Event list entry |
| 823 | End of event list |

### IRCX Channel Keys

| Key Type | Property | MODE | Grants |
|----------|----------|------|--------|
| Member Key | MEMBERKEY | +k | Join access only |
| Host Key | HOSTKEY | - | +o on join |
| Owner Key | OWNERKEY | - | +q on join |

---

## Services

### System
The main network services bot. Resides in #System channel.
- Cannot be messaged directly
- All staff should monitor #System

### Registrar
Handles nickname and channel registration.

**Nickname Commands:**
```
/MSG Registrar REGISTER <password> [email]
/MSG Registrar IDENTIFY <password> [mfa_code]
/MSG Registrar DROP <password>
/MSG Registrar INFO [nick]
/MSG Registrar SET PASSWORD <newpass>
/MSG Registrar SET EMAIL <email>
```

**Channel Commands:**
```
/MSG Registrar CHANNEL REGISTER [#channel]
/MSG Registrar CHANNEL DROP <#channel>
/MSG Registrar CHANNEL LIST
/MSG Registrar CHANNEL INFO <#channel>
```

**MFA Commands:**
```
/MSG Registrar MFA ENABLE
/MSG Registrar MFA DISABLE <code>
/MSG Registrar MFA CODES
```

### Messenger
Handles offline messages and broadcasts.

```
/MSG Messenger SEND <nick> <message>    -- Send offline message
/MSG Messenger READ                     -- Read your messages
/MSG Messenger DELETE <id|ALL>          -- Delete messages
/MSG Messenger COUNT                    -- Count unread messages
/MSG Messenger PUSH <message>           -- Broadcast (ADMIN only)
```

### NewsFlash
News and announcement service.
- Displays rotating announcements
- Managed by ADMINs

### ServiceBots (ServiceBot01-10)
Automated channel monitors. Configurable count (default: 10).

**Features:**
- Profanity filtering
- Flood detection
- Caps abuse detection
- URL spam detection
- Repeat message detection

**Actions:**
- `warn` - Send warning notice
- `gag` - Prevent speaking (+z in channel)
- `kick` - Remove from channel
- `ban` - Ban and remove

---

## Staff System

### Staff Levels

| Level | Mode | Description |
|-------|------|-------------|
| ADMIN | `a` | Full server control. Highest authority. |
| SYSOP | `o` | Server operations. Cannot override ADMIN. |
| GUIDE | `g` | User assistance. Limited commands. |

### Staff Privileges

| Action | ADMIN | SYSOP | GUIDE |
|--------|-------|-------|-------|
| KILL user | Yes | Yes | No |
| KILL channel | Yes | Yes | No |
| KILL by pattern | Yes | Yes | No |
| GAG/UNGAG (global) | Yes | Yes | Yes |
| GAG/UNGAG (channel) | Yes | Yes | Yes* |
| ACCESS server | Yes | Yes | No |
| STATS * | Yes | No | No |
| CONFIG SHOW | Yes | No | No |
| Bypass ACCESS DENY | Yes | No | No |
| Exempt from nick cooldown | Yes | Yes | No |
| Auto +q in channels | Yes | Yes | No |
| WHO * | Yes | Yes | No |
| See invisible users | Yes | Yes | Yes |
| See user IP addresses | Yes | Yes | Yes |

*\* Channel GAG/UNGAG can also be used by channel hosts and owners.*

### Creating Staff Accounts

Staff accounts are created directly in the database:

```sql
INSERT INTO users (username, password_hash, level)
VALUES ('admin', '$2b$12$...', 'ADMIN');
```

Use bcrypt to hash passwords:
```python
import bcrypt
hash = bcrypt.hashpw(b'password', bcrypt.gensalt()).decode()
```

### Staff Commands

#### KILL
Disconnect users or destroy channels.
```
KILL <nick> [:<reason>]              -- Disconnect user
KILL <#channel> [:<reason>]          -- Destroy channel (ADMIN/SYSOP)
KILL <ip_pattern> [:<reason>]        -- Disconnect by IP pattern
KILL <*!*@hostmask> [:<reason>]      -- Disconnect by hostmask
```

**Examples:**
```
KILL baduser :Spamming
KILL #badchannel :Illegal content
KILL 192.168.1.* :Abuse
KILL *!*@*.bad.isp :Known abuser
```

**Restrictions:**
- Cannot KILL #System channel
- Pattern KILL requires ADMIN or SYSOP

#### GAG / UNGAG
Prevent/allow user from sending messages.
```
GAG <nick>              -- Global gag (sets +z, blocks all messages)
GAG <#channel> <nick>   -- Channel gag (blocks messages in that channel only)
UNGAG <nick>            -- Remove global gag
UNGAG <#channel> <nick> -- Remove channel gag
```
- Global gag: Requires staff (+o/+a/+g), sets user mode +z
- Channel gag: Requires channel host/owner, only affects that channel
- User can still read messages in both cases

#### ACCESS (Server-wide)
Manage server access lists. See also [ACCESS (IRCX)](#access-ircx) for full syntax.
```
ACCESS $ LIST [level]                       -- List entries
ACCESS $ ADD <level> <mask> [timeout] [:<reason>]
ACCESS $ DELETE <level> <mask>
ACCESS $ CLEAR <level>
```

**Server Access Levels:**
| Level | Description |
|-------|-------------|
| `GRANT` | Allow connection from matching hosts |
| `DENY` | Block connection from matching hosts |

**Access List Behavior:**
1. DENY list checked first on connection
2. If matched, connection rejected (unless ADMIN)
3. GRANT list can whitelist specific hosts
4. Only ADMINs can bypass DENY rules
5. Timeouts specified in minutes (0 = permanent)

#### CONFIG
In-band configuration management.
```
CONFIG LIST [section]          -- List config sections or section contents (SYSOP+)
CONFIG GET <section.key>       -- Get specific value (SYSOP+)
CONFIG SET <section.key> <val> -- Set value (ADMIN only)
CONFIG SAVE                    -- Save to disk (ADMIN only)
CONFIG RELOAD                  -- Reload from disk (ADMIN only)
```

**Examples:**
```
CONFIG LIST security
CONFIG GET limits.max_users
CONFIG SET limits.max_users 500
CONFIG SAVE
```

#### STAFF
In-band staff account management. Staff accounts are tied to usernames (ident), not nicknames.
```
STAFF LIST                              -- List all staff accounts (SYSOP+)
STAFF ADD <username> <password> <level> -- Add account (ADMIN only)
STAFF DEL <username>                    -- Remove account (ADMIN only)
STAFF SET <username> <level>            -- Change level (ADMIN only)
STAFF PASS <username> <newpassword>     -- Change password (ADMIN or self)
```

**Staff Levels:** `ADMIN`, `SYSOP`, `GUIDE`

**Examples:**
```
STAFF LIST
STAFF ADD newadmin secretpass123 SYSOP
STAFF SET newadmin ADMIN
STAFF PASS myusername newpassword
STAFF DEL oldstaff
```

**Notes:**
- Staff authenticate via `PASS username:password` before the `USER` command
- `STAFF PASS` allows changing your own password, or any password if ADMIN
- Cannot delete your own staff account
- Regular users use `CHGPASS` for registered nicknames

---

## Security Features

### Flood Protection

Prevents message flooding from individual users.

**Configuration:**
```json
{
  "security": {
    "flood_messages": 5,
    "flood_window": 2.0,
    "enable_flood_protection": true
  }
}
```

- Users limited to `flood_messages` per `flood_window` seconds
- Staff get higher limits but are not exempt
- Exceeding limit results in message being dropped

### Connection Throttle

Limits rapid connections from same IP.

**Configuration:**
```json
{
  "security": {
    "connection_throttle": 100,
    "throttle_window": 60.0,
    "enable_connection_throttle": false
  }
}
```

### DNSBL Integration

Checks connecting IPs against DNS blacklists.

**Configuration:**
```json
{
  "security": {
    "dnsbl": {
      "enabled": false,
      "action": "reject",
      "timeout": 3.0,
      "cache_ttl": 3600,
      "lists": [
        "dnsbl.dronebl.org",
        "rbl.efnetrbl.org",
        "bl.spamcop.net"
      ],
      "whitelist": ["192.168.0.0/16"],
      "reject_message": "Your IP is blacklisted."
    }
  }
}
```

**Actions:**
- `reject` - Refuse connection
- `warn` - Allow but notify staff
- `mark` - Set flag on user

### Proxy Detection

Scans for open proxy ports on connecting IPs.

**Configuration:**
```json
{
  "security": {
    "proxy_detection": {
      "enabled": false,
      "ports": [8080, 3128, 1080, 9050],
      "timeout": 2.0,
      "action": "warn"
    }
  }
}
```

### Connection Scoring

Assigns risk scores to connections.

**Configuration:**
```json
{
  "security": {
    "connection_scoring": {
      "enabled": false,
      "threshold": 100,
      "dnsbl_score": 50,
      "proxy_score": 30,
      "no_ident_score": 10,
      "generic_hostname_score": 5
    }
  }
}
```

### ServiceBot Auto-Moderation

Automated channel monitoring for abuse.

**Profanity Filter:**
```json
{
  "servicebot": {
    "profanity_filter": {
      "enabled": true,
      "action": "warn",
      "words": ["badword1", "badword2"],
      "warn_message": "Please watch your language.",
      "case_sensitive": false
    }
  }
}
```

**Malicious Detection:**
```json
{
  "servicebot": {
    "malicious_detection": {
      "enabled": true,
      "flood_threshold": 5,
      "flood_window": 3,
      "flood_action": "gag",
      "caps_threshold": 0.7,
      "caps_min_length": 10,
      "caps_action": "warn",
      "url_spam_threshold": 3,
      "url_spam_window": 10,
      "url_spam_action": "warn",
      "repeat_threshold": 3,
      "repeat_window": 30,
      "repeat_action": "warn"
    }
  }
}
```

### SSL/TLS Support

pyIRCX supports secure connections via SSL/TLS with automatic certificate management.

**Configuration:**
```json
{
  "ssl": {
    "enabled": true,
    "ports": [6697],
    "cert_file": "/etc/letsencrypt/live/irc.example.com/fullchain.pem",
    "key_file": "/etc/letsencrypt/live/irc.example.com/privkey.pem",
    "min_version": "TLSv1.2",
    "auto_reload": true,
    "reload_interval": 3600,
    "expiry_warn_days": [14, 7, 3, 1]
  }
}
```

**Features:**
- Dual-stack support (IPv4 and IPv6 on SSL ports)
- Automatic certificate reload when files change
- Expiry warnings in server logs
- Force reload via SIGHUP (`systemctl reload pyircx`)
- `STATS t` command to view certificate status

**Let's Encrypt Setup:**
```bash
# Obtain certificate
sudo certbot certonly --standalone -d irc.example.com

# Set up auto-renewal (usually already configured by certbot)
sudo systemctl enable certbot.timer

# pyIRCX will auto-detect certificate renewal and reload
```

**Standard Ports:**
| Port | Protocol | Description |
|------|----------|-------------|
| 6667 | Plain | Standard IRC (unencrypted) |
| 6697 | SSL/TLS | Secure IRC (encrypted) |
| 7000 | Plain | Alternative IRC port |

---

## Channel Behavior & Logic

### Channel Types

| Prefix | Type | Persistence | Visibility |
|--------|------|-------------|------------|
| `#` | Global | Registered channels persist | Normal |
| `&` | Local | Never persisted | Server-only |

### Channel Lifecycle

#### Dynamic (Unregistered) Channels
1. Created when first user joins
2. First user automatically gets +q (owner)
3. Deleted when last user leaves
4. Treated as new if someone joins same name later

#### Registered Channels
1. Created via Registrar service
2. Persist even when empty
3. Settings (modes, topic, keys) are saved
4. First user does NOT auto-get +q
5. Must use OWNERKEY to get +q

#### #System Channel
1. Always exists (created at server start)
2. Always registered
3. Contains service bots
4. Only staff can join
5. Cannot be killed

### Auto-Mode Grants on Join

| Condition | Mode Granted |
|-----------|--------------|
| ADMIN or SYSOP | +q (owner) |
| Service/Bot (virtual) | +q (owner) |
| First user in dynamic channel | +q (owner) |
| Used OWNERKEY | +q (owner) |
| Used HOSTKEY | +o (host) |
| In channel ACCESS OWNER list | +q (owner) |
| In channel ACCESS HOST list | +o (host) |
| In channel ACCESS VOICE list | +v (voice) |

### Channel Keys (IRCX)

| Key | Purpose | Grants |
|-----|---------|--------|
| MEMBERKEY | Regular join access | Nothing (just allows join) |
| HOSTKEY | Operator access | +o on join |
| OWNERKEY | Owner access | +q on join |

**Setting Keys:**
```
PROP #channel MEMBERKEY :password123
PROP #channel HOSTKEY :oppassword
PROP #channel OWNERKEY :ownerpassword
```

**Using Keys:**
```
JOIN #channel password123      -- Uses as MEMBERKEY, HOSTKEY, or OWNERKEY
```
Server checks in order: OWNERKEY → HOSTKEY → MEMBERKEY

### Case Sensitivity

- Channel names are **case-insensitive**
- `#System`, `#system`, `#SYSTEM` all refer to same channel
- Canonical name (first created) is preserved
- All lookups use case-insensitive matching

---

## Numeric Replies Reference

### Connection & Registration (001-005)

| Code | Format | Description |
|------|--------|-------------|
| 001 | `Welcome to {network} {nick}` | Welcome message |
| 002 | `Your host is {server}, running {version}` | Host info |
| 003 | `This server was created {date}` | Creation date |
| 004 | `{server} {version} {usermodes} {chanmodes}` | Server info |
| 005 | `CHANTYPES=... :are supported` | ISUPPORT tokens |

### Command Responses (200-399)

| Code | Description |
|------|-------------|
| 221 | User mode string |
| 251 | LUSERS - user count |
| 252 | LUSERS - operator count |
| 253 | LUSERS - unknown connections |
| 254 | LUSERS - channel count |
| 255 | LUSERS - client count |
| 265 | Local users |
| 266 | Global users |
| 301 | User is away |
| 303 | ISON reply |
| 305 | No longer away |
| 306 | Now away |
| 311 | WHOIS - user info |
| 312 | WHOIS - server info |
| 313 | WHOIS - operator |
| 314 | WHOWAS - user info |
| 315 | End of WHO |
| 317 | WHOIS - idle time |
| 318 | End of WHOIS |
| 319 | WHOIS - channels |
| 321 | LIST header |
| 322 | LIST entry |
| 323 | End of LIST |
| 324 | Channel modes |
| 329 | Channel creation time |
| 331 | No topic set |
| 332 | Channel topic |
| 333 | Topic set by/time |
| 341 | Invite sent |
| 352 | WHO entry |
| 353 | NAMES entry |
| 366 | End of NAMES |
| 367 | Ban list entry |
| 368 | End of ban list |
| 369 | End of WHOWAS |
| 371 | INFO line |
| 374 | End of INFO |
| 375 | MOTD start |
| 372 | MOTD line |
| 376 | End of MOTD |
| 381 | You are now an IRC {role} |
| 386 | Staff login message |
| 391 | Server time |
| 392 | Users header |
| 393 | Users entry |
| 394 | End of users |

### Error Replies (400-599)

| Code | Description |
|------|-------------|
| 401 | No such nick/channel |
| 402 | No such server |
| 403 | No such channel |
| 404 | Cannot send to channel |
| 405 | Too many channels |
| 406 | Was no such nick |
| 407 | Too many targets |
| 409 | No origin specified |
| 411 | No recipient given |
| 412 | No text to send |
| 421 | Unknown command |
| 422 | No MOTD |
| 431 | No nickname given |
| 432 | Erroneous nickname |
| 433 | Nickname in use |
| 436 | Nickname collision |
| 441 | User not in channel |
| 442 | Not on channel |
| 443 | User already on channel |
| 451 | Not registered |
| 461 | Not enough parameters |
| 462 | Already registered |
| 463 | No permission (host) |
| 464 | Password mismatch |
| 465 | Banned from server |
| 467 | Channel key already set |
| 468 | Invalid username |
| 471 | Channel is full (+l) |
| 472 | Unknown mode char |
| 473 | Invite only channel (+i) |
| 474 | Banned from channel (+b) |
| 475 | Bad channel key (+k) |
| 476 | Bad channel mask |
| 477 | Channel doesn't support modes |
| 478 | Ban list full |
| 479 | Invalid channel name |
| 481 | Permission denied |
| 482 | Not channel host |
| 483 | Can't kill server |
| 484 | Connection restricted |
| 491 | No O-lines |

---

## Technical Details

### Protocol Compliance

pyIRCX implements:
- RFC 1459 (IRC Protocol)
- RFC 2812 (IRC Client Protocol)
- Microsoft IRCX Extensions

### IPv6 Support

pyIRCX fully supports IPv6 with the following features:

| Feature | Description |
|---------|-------------|
| Dual-stack binding | Listens on both IPv4 (0.0.0.0) and IPv6 (::) by default |
| IPv6 DNSBL | Supports IPv6 blacklist checks using nibble-reversed ip6.arpa format |
| Hostname resolution | Proper reverse DNS for both IPv4 and IPv6 addresses |
| Private range detection | Recognizes IPv6 loopback (::1), link-local (fe80::/10), ULA (fc00::/7) |
| Ban/ACCESS patterns | Works with IPv6 addresses in hostmasks |

**Configuration:**
- Enable/disable: `network.enable_ipv6` (default: `true`)
- Custom IPv6 bind address: `network.listen_addr_ipv6` (default: `::`)

**Notes:**
- Most DNSBLs only support IPv4. DroneBL and some others support IPv6.
- IPv6 addresses are displayed in standard notation (e.g., `2001:db8::1`)
- Use CIDR notation in ACCESS/whitelist for IPv6 ranges (e.g., `2001:db8::/32`)

### Message Format

```
:<prefix> <command> <params> :<trailing>
```

Maximum message length: 512 bytes (configurable)

### Rate Limits

| Action | Limit | Notes |
|--------|-------|-------|
| Messages | 5 per 2 seconds | Flood protection |
| Nick changes | 1 per 60 seconds | Cooldown (staff exempt) |
| WHISPER | 1 per 5 seconds | Separate from PRIVMSG |
| KNOCK | 1 per 60 seconds | Per channel |
| WHO * | Rate limited | Staff only |

### Logging

Logs are written to:
- `pyircx.log` - Server log
- `transcripts/<#channel>.log` - Channel transcripts (if +y enabled)

Log format:
```
2025-12-31 12:00:00,000 [INFO] pyIRCX: <message>
```

### Performance

- Async I/O using Python asyncio
- Non-blocking database operations (aiosqlite)
- Efficient user/channel lookups
- Connection pooling for database

### Signal Handling

| Signal | Action |
|--------|--------|
| SIGINT | Graceful shutdown |
| SIGTERM | Graceful shutdown |
| SIGHUP | Reload configuration (planned) |

---

## Appendix: Quick Reference Card

### Essential User Commands
```
/NICK <nickname>              - Change nickname
/JOIN <#channel> [key]        - Join channel
/PART <#channel> [message]    - Leave channel
/MSG <nickname> <message>     - Private message
/MSG <#channel> <message>     - Channel message
/TOPIC <#channel> [topic]     - Set/view topic
/WHO <#channel>               - List members
/WHOIS <nickname>             - User info
/AWAY [message]               - Set/clear away
/QUIT [message]               - Disconnect
```

### Channel Host Commands
```
/MODE <#channel> +o <nickname>     - Give host
/MODE <#channel> -o <nickname>     - Remove host
/MODE <#channel> +v <nickname>     - Give voice
/MODE <#channel> +b <mask>         - Ban
/KICK <#channel> <nickname> [reason] - Kick user
/INVITE <nickname> <#channel>      - Invite user
/TOPIC <#channel> <new-topic>      - Change topic
```

### IRCX Commands
```
/IRCX                                        - Enable IRCX mode
/PROP <#channel>                             - List all properties
/PROP <#channel> ONJOIN :<message>           - Set join message
/WHISPER <#channel> <nickname> :<message>    - Channel whisper
/ACCESS <#channel> LIST [level]              - View access list
/ACCESS <#channel> ADD HOST <nickname>       - Auto-host nickname
/ACCESS <#channel> ADD DENY <mask> [timeout] - Temporary ban
/ACCESS <#channel> CLEAR DENY                - Clear all bans
```

### IRCv3 CAP/SASL
```
CAP LS [302]                        - List capabilities
CAP REQ :<capability-list>          - Request capabilities
CAP END                             - End negotiation
AUTHENTICATE PLAIN                  - Start SASL auth
AUTHENTICATE <base64-credentials>   - Send credentials
```

### Registration
```
/MSG Registrar REGISTER <password> [email]
/MSG Registrar IDENTIFY <password> [mfa-code]
/MSG Registrar CHANNEL REGISTER [#channel]
```

### Staff Commands
```
/KILL <nickname> [reason]                    - Disconnect user
/GAG <nickname>                              - Global mute (sets +z)
/GAG <#channel> <nickname>                   - Channel mute
/UNGAG <nickname>                            - Remove global mute
/UNGAG <#channel> <nickname>                 - Remove channel mute
/STATS *                                     - All statistics
/STAFF LIST                                  - List staff accounts
/STAFF ADD <username> <password> <level>     - Add staff (ADMIN)
/STAFF DEL <username>                        - Remove staff (ADMIN)
/STAFF LEVEL <username> <level>              - Change level (ADMIN)
/STAFF PASS <username> <new-password>        - Change password
/CONFIG LIST [section]                       - View config
/CONFIG SET <section.key> <value>            - Change config (ADMIN)
```

---

## Features in Version 1.0.0

### Core Protocol Support

**IRC/IRCX Protocol:**
- Full IRCX protocol support (ACCESS, PROP, WHISPER, LISTX commands)
- RFC 1459/2812 IRC compatibility
- Three-tier channel privileges (Owner `.`, Host `@`, Voice `+`)
- Channel cloning (+d mode) for automatic overflow rooms
- IRCv3 capability negotiation (CAP LS/REQ/ACK/END)

**Channel Features:**
- ACCESS control lists (OWNER, HOST, VOICE, GRANT, DENY levels)
- PROP channel properties (TOPIC, ONJOIN, ONPART, MEMBERKEY, HOSTKEY, OWNERKEY)
- Channel registration and persistence
- Mode synchronization for cloned channels
- Transcript logging (+y mode)

### Server Linking

**Distributed Networks:**
- Server-to-server linking protocol with password authentication
- State synchronization (users and channels sync across servers)
- Message routing across the network
- Netsplit handling with graceful recovery
- Nick/channel collision resolution (timestamp-based)
- CONNECT, SQUIT, LINKS admin commands

### Security & Authentication

**User Authentication:**
- SASL PLAIN authentication (pre-registration)
- Nickname registration with bcrypt password hashing
- Two-factor authentication (TOTP)
- Email verification support
- Backup codes for MFA recovery

**Network Security:**
- IPv4 and IPv6 dual-stack support
- SSL/TLS encryption (ports 6697)
- Automatic certificate monitoring and hot-reload
- DNSBL integration (IPv4 and IPv6)
- Open proxy detection
- Connection throttling and flood protection
- Failed authentication tracking with IP lockout

**Staff Management:**
- Three-tier staff hierarchy (ADMIN, SYSOP, GUIDE)
- STAFF command for in-band account management
- Staff authentication via PASS or SASL
- Configurable staff privileges
- Default admin account auto-creation

### Built-in Services

**Service Bots:**
- System - Server announcements
- Registrar - Nickname and channel registration
- Messenger - Offline messaging system
- NewsFlash - Network-wide announcements
- ServiceBot01-10 - Automated channel moderation

**ServiceBot Moderation:**
- Profanity filtering (configurable word list)
- Flood detection (message frequency limits)
- Repeat spam detection (identical messages)
- Excessive caps detection (shouting)
- URL spam detection
- Configurable actions (warn, gag, kick, ban)

### Administration

**Configuration:**
- JSON-based configuration file
- CONFIG command for in-band management (LIST/GET/SET/SAVE/RELOAD)
- Hot-reloadable configuration
- Database connection pooling

**Management Tools:**
- GAG/UNGAG commands (global and channel-level muting)
- KILL command (disconnect users or destroy channels)
- ACCESS command for server-wide bans
- STATS command with multiple report types
- Interactive installer (install.sh)
- Systemd service integration

### Advanced Features

**Channel Management:**
- ONJOIN/ONPART custom messages
- Timeout support for temporary ACCESS entries
- Ban list management with expiration
- Channel owner/host/voice auto-grants via ACCESS
- MEMBERKEY, HOSTKEY, OWNERKEY support

**Performance & Reliability:**
- Async I/O using Python asyncio
- Non-blocking bcrypt operations
- Database connection pooling
- Efficient user/channel lookups
- Graceful shutdown handling

**Logging & Monitoring:**
- Comprehensive server logging
- Per-channel transcript logs
- Connection scoring system
- SSL certificate expiry warnings
- STATS commands for monitoring

### Testing

- 54 comprehensive test cases (100% passing)
- User/IRC protocol tests (50 tests)
- Server linking tests (4 tests)
- Staff authentication tests
- Full protocol compliance verification
