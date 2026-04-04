# pyIRCX API Reference

**Version:** Current release (see [`../../version.json`](../../version.json))
**Last Updated:** 2026-01-18

This document provides comprehensive reference documentation for the pyIRCX API module (`api.py`), which provides programmatic access to server administration, user management, and configuration functions.

---

## Table of Contents

- [Overview](#overview)
- [Response Format](#response-format)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)
- [Caching](#caching)
- [Function Reference](#function-reference)
  - [Configuration](#configuration)
  - [Server Status](#server-status)
  - [IRC Server Communication](#irc-server-communication)
  - [Server Access (Bans)](#server-access-bans)
  - [NewsFlash](#newsflash)
  - [Mailbox](#mailbox)
  - [Search](#search)
  - [Staff Management](#staff-management)
  - [Nickname Registration](#nickname-registration)
  - [Channel Registration](#channel-registration)
  - [Authentication Testing](#authentication-testing)
  - [Channel Access](#channel-access)
- [Usage Examples](#usage-examples)

---

## Overview

The pyIRCX API module provides Python functions for managing the IRC server. It can be used:
- Directly from Python scripts
- Via command-line interface (`python3 api.py <command> <args>`)
- Through web administration interface (future)

**Key Features:**
- Connection pooling (10 persistent connections)
- Automatic transaction management
- Standardized error handling
- Input validation
- Rate limiting on authentication endpoints
- Caching for read-only config functions
- bcrypt password hashing

---

## Response Format

All API functions return a dictionary with a standardized format:

### Success Response
```python
{
    "success": True,
    "data": <result_data>,          # Optional: function-specific data
    "message": <success_message>     # Optional: human-readable message
}
```

### Error Response
```python
{
    "success": False,
    "error": <error_message>,        # Human-readable error description
    "error_type": <error_category>   # One of: integrity, operational, validation, timeout, connection, unknown
}
```

---

## Error Codes

### Error Types

| Error Type | Description | Common Causes |
|------------|-------------|---------------|
| `integrity` | Database integrity constraint violation | Duplicate username, foreign key violation |
| `operational` | Database operational error | Lock timeout, disk full, permissions |
| `validation` | Input validation failed | Invalid nickname, bad email, short password |
| `timeout` | Socket/connection timeout | Network issue, server not responding |
| `connection` | Connection refused | Server not running, wrong port |
| `unknown` | Unexpected error | Programming error, system issue |

### Common Error Messages

| Error Message | Cause | Solution |
|--------------|-------|----------|
| "Too many attempts - please try again in a moment" | Rate limit exceeded | Wait 1 minute, try again |
| "Please provide a nickname" | Empty nickname | Supply valid nickname |
| "Password must be at least 8 characters long" | Short password | Use 8+ character password |
| "Nickname must start with a letter and contain only..." | Invalid nickname format | Use valid IRC nickname |
| "Server access rule not found for pattern '{pattern}'" | Ban/access rule doesn't exist | Check pattern spelling |
| "Staff member '{username}' not found" | Staff account doesn't exist | Create account first |

---

## Rate Limiting

**Authentication functions are rate-limited to prevent brute force attacks.**

### Protected Functions
- `test_staff_login(username, password)` - 5 attempts/minute per username
- `test_identify(nickname, password)` - 5 attempts/minute per nickname

### Rate Limit Behavior
- Tracked per username/nickname
- Resets after 1 minute
- Raises `ValueError` with message: "Too many attempts - please try again in a moment"
- Logged as warning in server logs

### Example
```python
# First 5 attempts within 1 minute - OK
for i in range(5):
    api.test_staff_login("admin", "wrong_password")  # OK

# 6th attempt - RATE LIMITED
api.test_staff_login("admin", "wrong_password")
# ValueError: Too many attempts - please try again in a moment

# Wait 60 seconds - rate limit resets
time.sleep(60)
api.test_staff_login("admin", "password")  # OK again
```

---

## Caching

**Read-only config functions are cached to reduce disk I/O.**

### Cached Functions

| Function | Cache Duration | Purpose |
|----------|---------------|---------|
| `get_motd()` | 60 seconds | MOTD rarely changes |
| `get_server_config()` | 60 seconds | Server config rarely changes |
| `get_newsflash_settings()` | 60 seconds | Settings rarely change |
| `get_full_config()` | 30 seconds | Used for editing, shorter cache |

### Cache Behavior
- Automatic expiration after timeout
- Per-function and per-arguments caching
- Transparent to caller (no code changes needed)
- Cache hits logged as DEBUG level

---

## Function Reference

### Configuration

#### `load_config()`
**Description:** Load pyIRCX configuration from JSON file

**Parameters:** None

**Returns:**
```python
{
    "server": {...},
    "network": {...},
    "ssl": {...},
    # ... full config object
}
```

**Example:**
```python
config = api.load_config()
server_name = config['server']['name']
```

---

#### `save_config(config)`
**Description:** Save pyIRCX configuration to JSON file

**Parameters:**
- `config` (dict): Complete configuration object

**Returns:**
```python
{"success": True}
```

**Example:**
```python
config = api.load_config()
config['server']['name'] = "My IRC Server"
result = api.save_config(config)
```

---

#### `get_motd()`
**Description:** Get MOTD (Message of the Day) from configuration

**Caching:** 60 seconds

**Parameters:** None

**Returns:**
```python
{
    "motd": ["Welcome to pyIRCX!", "Enjoy your stay!", ...]
}
```

**Example:**
```python
result = api.get_motd()
for line in result['motd']:
    print(line)
```

---

#### `set_motd(motd_lines)`
**Description:** Set MOTD (Message of the Day) in configuration

**Parameters:**
- `motd_lines` (str or list): MOTD lines as JSON array or newline-separated string

**Returns:**
```python
{"success": True}
```

**Example:**
```python
# From list
api.set_motd(["Welcome!", "Have fun!"])

# From JSON string
api.set_motd('["Welcome!", "Have fun!"]')

# From newline-separated string
api.set_motd("Welcome!\nHave fun!")
```

---

#### `get_server_config()`
**Description:** Get safe server configuration (no sensitive data)

**Caching:** 60 seconds

**Parameters:** None

**Returns:**
```python
{
    "server": {
        "name": "My IRC Server",
        "network": "MyNetwork"
    },
    "port": [6667, 6668],
    "ssl_enabled": True,
    "ssl_port": [6697]
}
```

**Example:**
```python
config = api.get_server_config()
print(f"Server: {config['server']['name']}")
print(f"Ports: {config['port']}")
```

---

#### `get_full_config()`
**Description:** Get full configuration for editing

**Caching:** 30 seconds

**Parameters:** None

**Returns:**
```python
{
    # Complete configuration object
    "server": {...},
    "network": {...},
    "ssl": {...},
    "database": {...},
    # ... all config sections
}
```

**Example:**
```python
config = api.get_full_config()
# Edit configuration
config['server']['motd'] = ["New MOTD"]
api.save_config(config)
```

---

#### `set_config(config_json)`
**Description:** Set configuration from JSON string

**Parameters:**
- `config_json` (str): Complete configuration as JSON string

**Returns:**
```python
{"success": True}
```

**Example:**
```python
import json
config = api.get_full_config()
config['server']['name'] = "New Name"
api.set_config(json.dumps(config))
```

---

### Server Status

#### `get_realtime_status()`
**Description:** Get real-time connected users and active channels from status dump

**Parameters:** None

**Returns:**
```python
{
    "connected_users": [
        {"nickname": "Alice", "host": "192.168.1.1", ...},
        ...
    ],
    "active_channels": [
        {"name": "#lobby", "members": ["Alice", "Bob"], ...},
        ...
    ],
    "timestamp": 1705600000,
    "status_age": 2.5  # seconds since last update
}
```

**Errors:**
- `"Status file not found - server may not be running"` - Server not running or status file missing

**Example:**
```python
status = api.get_realtime_status()
print(f"Users online: {len(status['connected_users'])}")
print(f"Active channels: {len(status['active_channels'])}")
print(f"Status age: {status['status_age']}s")
```

---

#### `get_services_list()`
**Description:** Get list of network services and ServiceBots with their status

**Parameters:** None

**Returns:**
```python
{
    "services": [
        {
            "nickname": "System",
            "type": "Core Service",
            "description": "Network Services",
            "is_servicebot": False,
            "channels": ["#System"]
        },
        {
            "nickname": "ServiceBot01",
            "type": "ServiceBot",
            "description": "Service Bot #1 (channel monitoring and moderation)",
            "is_servicebot": True,
            "max_channels": 10,
            "channels": []
        },
        ...
    ],
    "servicebot_count": 10,
    "servicebot_enabled": True,
    "server_running": True
}
```

**Example:**
```python
result = api.get_services_list()
for service in result['services']:
    print(f"{service['nickname']}: {service['description']}")
```

---

### IRC Server Communication

#### `send_irc_kill_channel(channel_name)`
**Description:** Kill a channel by writing to admin command queue

**Parameters:**
- `channel_name` (str): Channel to kill (e.g., "#channel")

**Validation:**
- Channel name validated via `validate_channel_name()`

**Returns:**
```python
{
    "success": True,
    "message": "Channel #channel will be reset"
}
```

**Example:**
```python
result = api.send_irc_kill_channel("#lobby")
# Channel will be killed and users parted
```

---

#### `send_irc_kill_user(nickname, reason="Killed by administrator")`
**Description:** Kill a user connection by writing to admin command queue

**Parameters:**
- `nickname` (str): Nickname to kill
- `reason` (str, optional): Kill reason (default: "Killed by administrator")

**Validation:**
- Nickname validated via `validate_nickname()`
- Reason must be 1-500 characters

**Returns:**
```python
{
    "success": True,
    "message": "User BadUser will be disconnected"
}
```

**Example:**
```python
result = api.send_irc_kill_user("BadUser", "Spamming")
```

---

#### `send_irc_ban_user(nickname, reason="Banned by administrator", duration=3600)`
**Description:** Ban a user by writing to admin command queue

**Parameters:**
- `nickname` (str): Nickname to ban
- `reason` (str, optional): Ban reason (default: "Banned by administrator")
- `duration` (int, optional): Ban duration in seconds (default: 3600 = 1 hour)

**Validation:**
- Nickname validated via `validate_nickname()`
- Duration must be non-negative integer
- Reason must be 1-500 characters

**Returns:**
```python
{
    "success": True,
    "message": "User Spammer will be banned for 3600 seconds"
}
```

**Example:**
```python
# Ban for 1 hour
api.send_irc_ban_user("Spammer", "Flooding", 3600)

# Ban for 24 hours
api.send_irc_ban_user("Abuser", "Harassment", 86400)
```

---

#### `send_irc_lock_channel(channel_name, owner="System")`
**Description:** Lock a channel (register + set auth-only) by writing to admin command queue

**Parameters:**
- `channel_name` (str): Channel to lock (e.g., "#admin")
- `owner` (str, optional): Owner for the channel (default: "System")

**Validation:**
- Channel name validated via `validate_channel_name()`
- Owner must be 1-30 characters

**Returns:**
```python
{
    "success": True,
    "message": "Channel #admin will be locked and registered to System"
}
```

**Example:**
```python
api.send_irc_lock_channel("#staff", "System")
```

---

#### `set_channel_mode(channel_name, mode_string)`
**Description:** Set channel mode via admin command queue

**Parameters:**
- `channel_name` (str): Channel name (e.g., "#channel")
- `mode_string` (str): Mode string (e.g., "+nt" or "-s")

**Validation:**
- Channel name validated via `validate_channel_name()`
- Mode string must be 1-50 characters
- Mode string must match pattern: `^[+-][a-zA-Z]+$`

**Returns:**
```python
{
    "success": True,
    "message": "Mode +nt will be set on #channel"
}
```

**Example:**
```python
# Set no external messages and topic protection
api.set_channel_mode("#lobby", "+nt")

# Remove secret mode
api.set_channel_mode("#public", "-s")
```

---

#### `set_channel_topic(channel_name, topic)`
**Description:** Set channel topic via admin command queue

**Parameters:**
- `channel_name` (str): Channel name (e.g., "#channel")
- `topic` (str): New topic (empty string to clear)

**Validation:**
- Channel name validated via `validate_channel_name()`
- Topic must not exceed 500 characters

**Returns:**
```python
{
    "success": True,
    "message": "Topic will be set on #lobby"
}
```

**Example:**
```python
api.set_channel_topic("#lobby", "Welcome to the lobby!")

# Clear topic
api.set_channel_topic("#lobby", "")
```

---

### Server Access (Bans)

#### `get_server_access_list()`
**Description:** Get all server access rules (bans)

**Parameters:** None

**Returns:**
```python
[
    {
        "id": 1,
        "type": "DENY",
        "pattern": "*!*@spam.com",
        "set_by": "admin",
        "reason": "Spammer network",
        "set_at": 1705600000,
        "timeout": 0  # 0 = permanent
    },
    ...
]
```

**Example:**
```python
bans = api.get_server_access_list()
for ban in bans:
    print(f"{ban['pattern']}: {ban['reason']}")
```

---

#### `add_server_access(access_type, pattern, set_by, reason, timeout=0)`
**Description:** Add a server access rule (ban)

**Parameters:**
- `access_type` (str): One of: GRANT, DENY, OWNER, HOST, VOICE
- `pattern` (str): Hostmask pattern (e.g., "*!*@spam.com")
- `set_by` (str): Staff username who set this rule
- `reason` (str): Reason for the rule
- `timeout` (int, optional): Expiration timeout in seconds (0 = permanent)

**Validation:**
- Access type validated via `validate_access_type()`
- Pattern validated via `validate_pattern()`
- Timeout must be non-negative

**Returns:**
```python
{
    "success": True,
    "message": "Added DENY for *!*@spam.com"
}
```

**Example:**
```python
# Permanent ban
api.add_server_access("DENY", "*!*@spam.com", "admin", "Spammer network", 0)

# 24-hour ban
api.add_server_access("DENY", "baduser!*@*", "sysop", "Abusive user", 86400)
```

---

#### `remove_server_access(access_type, pattern)`
**Description:** Remove a server access rule (ban)

**Parameters:**
- `access_type` (str): One of: GRANT, DENY, OWNER, HOST, VOICE
- `pattern` (str): Hostmask pattern to remove

**Validation:**
- Access type validated via `validate_access_type()`
- Pattern validated via `validate_pattern()`

**Returns:**
```python
{
    "success": True,
    "message": "Removed DENY for *!*@spam.com"
}
```

**Errors:**
- `"Server access rule not found for pattern '{pattern}'"` - Rule doesn't exist

**Example:**
```python
api.remove_server_access("DENY", "*!*@spam.com")
```

---

### NewsFlash

#### `get_newsflash_list()`
**Description:** Get all NewsFlash messages

**Parameters:** None

**Returns:**
```python
[
    {
        "id": 1,
        "message": "Server maintenance tonight at 10 PM",
        "created_by": "admin",
        "created_at": 1705600000,
        "priority": 5
    },
    ...
]
```

**Example:**
```python
messages = api.get_newsflash_list()
for msg in messages:
    print(f"[{msg['priority']}] {msg['message']}")
```

---

#### `add_newsflash(message, created_by, priority=0)`
**Description:** Add a NewsFlash message

**Parameters:**
- `message` (str): NewsFlash message content
- `created_by` (str): Staff username who created this message
- `priority` (int, optional): Priority 0-10 (default: 0 = normal)

**Validation:**
- Message must be 1-500 characters
- Priority must be 0-10

**Returns:**
```python
{
    "success": True,
    "message": "NewsFlash added"
}
```

**Example:**
```python
api.add_newsflash("Server maintenance tonight", "admin", priority=8)
```

---

#### `delete_newsflash(msg_id)`
**Description:** Delete a NewsFlash message

**Parameters:**
- `msg_id` (int): NewsFlash message ID

**Validation:**
- ID must be positive integer

**Returns:**
```python
{
    "success": True,
    "message": "NewsFlash message deleted successfully"
}
```

**Errors:**
- `"NewsFlash message with ID {msg_id} not found"` - Message doesn't exist

**Example:**
```python
api.delete_newsflash(5)
```

---

#### `get_newsflash_settings()`
**Description:** Get NewsFlash broadcast settings

**Caching:** 60 seconds

**Parameters:** None

**Returns:**
```python
{
    "on_connect": True,          # Send on user connect
    "periodic_enabled": True,    # Send periodically
    "periodic_interval": 30      # Send every 30 minutes
}
```

**Example:**
```python
settings = api.get_newsflash_settings()
print(f"Periodic: {settings['periodic_enabled']}")
```

---

#### `set_newsflash_settings(on_connect, periodic_enabled, periodic_interval)`
**Description:** Set NewsFlash broadcast settings

**Parameters:**
- `on_connect` (bool or str): Send NewsFlash on user connect ("true" or True)
- `periodic_enabled` (bool or str): Enable periodic broadcasting ("true" or True)
- `periodic_interval` (int): Interval in minutes between broadcasts

**Returns:**
```python
{
    "success": True,
    "message": "NewsFlash settings updated successfully"
}
```

**Example:**
```python
# Enable on connect, disable periodic
api.set_newsflash_settings(True, False, 30)

# From form data (strings)
api.set_newsflash_settings("true", "true", 60)
```

---

### Mailbox

#### `get_mailbox_messages(limit=50)`
**Description:** Get recent mailbox messages

**Parameters:**
- `limit` (int, optional): Maximum number of messages to retrieve (default: 50)

**Returns:**
```python
[
    {
        "id": 1,
        "sender": "Alice",
        "recipient": "Bob",
        "message": "Hey, check out this channel!",
        "sent_at": 1705600000,
        "read": False
    },
    ...
]
```

**Example:**
```python
messages = api.get_mailbox_messages(limit=100)
for msg in messages:
    status = "READ" if msg['read'] else "UNREAD"
    print(f"[{status}] {msg['sender']} → {msg['recipient']}: {msg['message']}")
```

---

#### `send_mailbox_message(sender_nick, recipient_nick, message)`
**Description:** Send a mailbox message to a registered nickname

**Parameters:**
- `sender_nick` (str): Sender's nickname
- `recipient_nick` (str): Recipient's registered nickname
- `message` (str): Message content

**Validation:**
- Sender nickname: 1-30 characters
- Recipient validated via `validate_nickname()`
- Message: 1-500 characters
- Recipient must be registered

**Returns:**
```python
{
    "success": True,
    "message": "Message sent to Bob"
}
```

**Errors:**
- `"Recipient '{recipient_nick}' is not registered"` - Recipient doesn't exist

**Example:**
```python
api.send_mailbox_message("Alice", "Bob", "Check out #lobby!")
```

---

### Search

#### `search_registered_nicks(query)`
**Description:** Search registered nicknames

**Parameters:**
- `query` (str): Search query (matches nickname, registered_by)

**Returns:**
```python
[
    {
        "nickname": "Alice",
        "registered_at": 1705600000,
        "last_seen": 1705601000,
        "email": "alice@example.com",
        "registered_by": "admin"
    },
    ...
]
```

**Example:**
```python
results = api.search_registered_nicks("ali")
for nick in results:
    print(nick['nickname'])
```

---

#### `search_channels(query)`
**Description:** Search registered channels

**Parameters:**
- `query` (str): Search query (matches channel name, description, owner)

**Returns:**
```python
[
    {
        "channel_name": "#lobby",
        "owner": "System",
        "registered_at": 1705600000,
        "description": "Main lobby channel"
    },
    ...
]
```

**Example:**
```python
results = api.search_channels("lobby")
for channel in results:
    print(f"{channel['channel_name']}: {channel['description']}")
```

---

### Staff Management

#### `get_staff_list()`
**Description:** Get list of all staff members

**Parameters:** None

**Returns:**
```python
[
    {
        "username": "admin",
        "level": "ADMIN",
        "realname": "Administrator",
        "email": "admin@example.com",
        "created_at": 1705600000
    },
    ...
]
```

**Example:**
```python
staff = api.get_staff_list()
for member in staff:
    print(f"{member['username']} ({member['level']})")
```

---

#### `add_staff(username, password, level, realname=None, email=None, force_realname=False)`
**Description:** Add a new staff member

**Parameters:**
- `username` (str): Staff username (3-20 chars, letters/numbers/_/-)
- `password` (str): Password (8+ characters)
- `level` (str): Staff level (ADMIN, SYSOP, GUIDE, USER)
- `realname` (str, optional): Real name
- `email` (str, optional): Email address
- `force_realname` (bool, optional): Force use of this realname (default: False)

**Validation:**
- Username: 3-20 characters, letters/numbers/_/-
- Password: 8+ characters
- Level validated via `validate_staff_level()`

**Returns:**
```python
{
    "success": True,
    "message": "Staff member 'john' added as SYSOP"
}
```

**Errors:**
- `"Staff member '{username}' already exists"` - Username taken

**Example:**
```python
api.add_staff("john", "secure_password_123", "SYSOP",
              realname="John Doe", email="john@example.com")
```

---

#### `delete_staff(username)`
**Description:** Delete a staff member

**Parameters:**
- `username` (str): Staff username to delete

**Validation:**
- Username: at least 3 characters

**Returns:**
```python
{
    "success": True,
    "message": "Staff member 'john' deleted successfully"
}
```

**Errors:**
- `"Staff member '{username}' not found"` - Staff doesn't exist

**Example:**
```python
api.delete_staff("john")
```

---

#### `change_staff_password(username, new_password)`
**Description:** Change a staff member's password

**Parameters:**
- `username` (str): Staff username
- `new_password` (str): New password (8+ characters)

**Validation:**
- Username: at least 3 characters
- Password: 8+ characters

**Returns:**
```python
{
    "success": True,
    "message": "Password changed for 'john'"
}
```

**Errors:**
- `"Staff member '{username}' not found"` - Staff doesn't exist

**Example:**
```python
api.change_staff_password("john", "new_secure_password_456")
```

---

#### `change_staff_level(username, new_level)`
**Description:** Change a staff member's privilege level

**Parameters:**
- `username` (str): Staff username
- `new_level` (str): New level (ADMIN, SYSOP, GUIDE, USER)

**Validation:**
- Username: at least 3 characters
- Level validated via `validate_staff_level()`

**Returns:**
```python
{
    "success": True,
    "message": "Level changed for 'john' to ADMIN"
}
```

**Errors:**
- `"Staff member '{username}' not found"` - Staff doesn't exist

**Example:**
```python
api.change_staff_level("john", "ADMIN")
```

---

#### `update_staff_profile(username, realname=None, email=None, force_realname=None)`
**Description:** Update staff member's profile information

**Parameters:**
- `username` (str): Staff username
- `realname` (str, optional): New real name
- `email` (str, optional): New email address
- `force_realname` (bool, optional): Force use of realname

**Validation:**
- Username: at least 3 characters

**Returns:**
```python
{
    "success": True,
    "message": "Profile updated for 'john'"
}
```

**Errors:**
- `"Staff member '{username}' not found"` - Staff doesn't exist

**Example:**
```python
api.update_staff_profile("john",
                         realname="John Smith",
                         email="jsmith@example.com")
```

---

#### `get_staff_details(username)`
**Description:** Get detailed staff information including owned nicknames

**Parameters:**
- `username` (str): Staff username

**Returns:**
```python
{
    "username": "admin",
    "level": "ADMIN",
    "realname": "Administrator",
    "email": "admin@example.com",
    "created_at": 1705600000,
    "owned_nicknames": ["AdminBot", "ServiceAdmin"]
}
```

**Errors:**
- `"Staff account '{username}' not found"` - Staff doesn't exist

**Example:**
```python
details = api.get_staff_details("admin")
print(f"Level: {details['level']}")
print(f"Owns {len(details['owned_nicknames'])} nicknames")
```

---

### Nickname Registration

#### `register_nickname(nickname, password, email=None)`
**Description:** Register a new nickname

**Parameters:**
- `nickname` (str): Nickname to register (IRC nickname format)
- `password` (str): Password (8+ characters)
- `email` (str, optional): Email address

**Validation:**
- Nickname validated via `validate_nickname()`
- Password: 8+ characters
- Email: valid email format (if provided)

**Returns:**
```python
{
    "success": True,
    "message": "Nickname 'Alice' registered"
}
```

**Errors:**
- `"Nickname '{nickname}' is already registered"` - Nickname taken

**Example:**
```python
api.register_nickname("Alice", "password123", email="alice@example.com")
```

---

#### `unregister_nickname(nickname)`
**Description:** Unregister a nickname

**Parameters:**
- `nickname` (str): Nickname to unregister

**Validation:**
- Nickname validated via `validate_nickname()`
- Cannot unregister if owns channels

**Returns:**
```python
{
    "success": True,
    "message": "Nickname 'Alice' unregistered"
}
```

**Errors:**
- `"Nickname '{nickname}' is not registered"` - Not registered
- `"Cannot unregister '{nickname}': owns {count} registered channel(s)..."` - Owns channels

**Example:**
```python
api.unregister_nickname("Alice")
```

---

#### `edit_nickname(nickname, new_password=None, new_email=None)`
**Description:** Edit a registered nickname's password and/or email

**Parameters:**
- `nickname` (str): Nickname to edit
- `new_password` (str, optional): New password (8+ characters)
- `new_email` (str, optional): New email (or "*" to clear)

**Validation:**
- Nickname validated via `validate_nickname()`
- Password: 8+ characters (if provided)
- Email: valid format (if provided and not "*")
- At least one of password or email must be specified

**Returns:**
```python
{
    "success": True,
    "message": "Updated password for 'Alice'"  # or "Updated password, email for 'Alice'"
}
```

**Errors:**
- `"Nickname '{nickname}' is not registered"` - Not registered
- `"No changes specified - please provide a new password and/or email address"` - No changes

**Example:**
```python
# Change password
api.edit_nickname("Alice", new_password="new_password_456")

# Change email
api.edit_nickname("Alice", new_email="newemail@example.com")

# Clear email
api.edit_nickname("Alice", new_email="*")

# Change both
api.edit_nickname("Alice", new_password="password", new_email="email@example.com")
```

---

#### `reset_mfa(nickname)`
**Description:** Reset MFA (Multi-Factor Authentication) for a nickname

**Parameters:**
- `nickname` (str): Nickname to reset MFA for

**Validation:**
- Nickname validated via `validate_nickname()`

**Returns:**
```python
{
    "success": True,
    "message": "MFA disabled for 'Alice'"
}
```

**Errors:**
- `"Nickname '{nickname}' is not registered"` - Not registered

**Example:**
```python
api.reset_mfa("Alice")
```

---

### Channel Registration

#### `get_registered_channels()`
**Description:** Get list of all registered channels

**Parameters:** None

**Returns:**
```python
[
    {
        "channel_name": "#lobby",
        "owner": "System",
        "registered_at": 1705600000,
        "description": "Main lobby channel"
    },
    ...
]
```

**Example:**
```python
channels = api.get_registered_channels()
for channel in channels:
    print(f"{channel['channel_name']}: {channel['description']}")
```

---

#### `register_channel(channel_name, owner_nickname, description="")`
**Description:** Register a new channel

**Parameters:**
- `channel_name` (str): Channel to register (e.g., "#lobby")
- `owner_nickname` (str): Owner's registered nickname or service name
- `description` (str, optional): Channel description

**Validation:**
- Channel name validated via `validate_channel_name()`
- Owner must be registered nickname or service (System, Registrar, Messenger, NewsFlash)

**Returns:**
```python
{
    "success": True,
    "message": "Channel '#mychannel' registered to Alice"
}
```

**Errors:**
- `"Channel '{channel_name}' is already registered"` - Channel taken
- `"Owner '{owner_nickname}' not found. Please use a registered nickname or service name..."` - Owner doesn't exist

**Example:**
```python
api.register_channel("#mychannel", "Alice", description="My private channel")
```

---

#### `unregister_channel(channel_name)`
**Description:** Unregister a channel

**Parameters:**
- `channel_name` (str): Channel to unregister

**Validation:**
- Channel name validated via `validate_channel_name()`

**Returns:**
```python
{
    "success": True,
    "message": "Channel '#mychannel' unregistered"
}
```

**Errors:**
- `"Channel '{channel_name}' is not registered"` - Not registered

**Example:**
```python
api.unregister_channel("#mychannel")
```

---

#### `edit_channel(channel_name, new_owner=None, new_description=None, modes=None, topic=None, onjoin=None, onpart=None, memberkey=None, hostkey=None, ownerkey=None, userlimit=None)`
**Description:** Edit channel properties (owner, description, modes, topic, etc.)

**Parameters:**
- `channel_name` (str): Channel to edit
- `new_owner` (str, optional): New owner nickname
- `new_description` (str, optional): New description
- `modes` (str, optional): Mode string (e.g., "nt")
- `topic` (str, optional): Channel topic
- `onjoin` (str, optional): On-join message
- `onpart` (str, optional): On-part message
- `memberkey` (str, optional): Member key
- `hostkey` (str, optional): Host key
- `ownerkey` (str, optional): Owner key
- `userlimit` (int, optional): User limit

**Validation:**
- Channel name validated via `validate_channel_name()`
- At least one property must be specified

**Returns:**
```python
{
    "success": True,
    "message": "Updated owner, description for channel '#mychannel'"
}
```

**Errors:**
- `"Channel '{channel_name}' is not registered"` - Not registered
- `"No changes were made - please specify at least one property to update"` - No changes
- `"Owner nickname '{new_owner}' not found"` - Owner doesn't exist

**Example:**
```python
# Change owner and description
api.edit_channel("#mychannel",
                 new_owner="Bob",
                 new_description="Bob's channel now")

# Set modes and topic
api.edit_channel("#lobby",
                 modes="nt",
                 topic="Welcome to the lobby!")
```

---

#### `get_channel_details(channel_name)`
**Description:** Get detailed channel information

**Parameters:**
- `channel_name` (str): Channel name

**Returns:**
```python
{
    "channel_name": "#lobby",
    "owner": "System",
    "description": "Main lobby",
    "modes": "nt",
    "topic": "Welcome!",
    "registered_at": 1705600000,
    "properties": {
        "onjoin": "Welcome to #lobby!",
        "onpart": "Thanks for visiting!",
        # ... other properties
    }
}
```

**Errors:**
- `"Channel '{channel_name}' not found"` - Channel doesn't exist

**Example:**
```python
details = api.get_channel_details("#lobby")
print(f"Owner: {details['owner']}")
print(f"Topic: {details['topic']}")
```

---

### Authentication Testing

#### `test_identify(nickname, password)`
**Description:** Test if a nickname/password combination is valid

**Rate Limiting:** 5 attempts/minute per nickname

**Parameters:**
- `nickname` (str): Nickname to test
- `password` (str): Password to test

**Validation:**
- Nickname validated via `validate_nickname()`
- Password required

**Returns:**
```python
# Success (no MFA)
{
    "success": True,
    "message": "Password correct (authentication would succeed)",
    "mfa_required": False
}

# Success (MFA required)
{
    "success": True,
    "message": "Password correct (MFA required for login)",
    "mfa_required": True
}

# Failure
{
    "success": False,
    "message": "Password incorrect"
}

# Not registered
{
    "success": False,
    "message": "Nickname not registered"
}
```

**Example:**
```python
result = api.test_identify("Alice", "password123")
if result['success']:
    print(f"Password OK. MFA required: {result.get('mfa_required', False)}")
else:
    print(f"Failed: {result['message']}")
```

---

#### `test_staff_login(username, password)`
**Description:** Test if a staff username/password combination is valid

**Rate Limiting:** 5 attempts/minute per username

**Parameters:**
- `username` (str): Staff username to test
- `password` (str): Password to test

**Validation:**
- Username and password required

**Returns:**
```python
# Success
{
    "success": True,
    "message": "Password correct (Level: ADMIN)",
    "level": "ADMIN"
}

# Failure
{
    "success": False,
    "message": "Password incorrect"
}

# Not found
{
    "success": False,
    "message": "Username not found"
}
```

**Example:**
```python
result = api.test_staff_login("admin", "admin_password")
if result['success']:
    print(f"Login OK. Level: {result['level']}")
else:
    print(f"Failed: {result['message']}")
```

---

#### `test_staff_login_stdin(username)`
**Description:** Test staff login with password from stdin (more secure for web interfaces)

**Rate Limiting:** 5 attempts/minute per username (inherited from test_staff_login)

**Parameters:**
- `username` (str): Staff username to test

**Returns:** Same as `test_staff_login()`

**Example:**
```python
import sys
sys.stdin = open('/dev/stdin')  # Ensure stdin is open
result = api.test_staff_login_stdin("admin")
# Password will be read from stdin
```

---

### Channel Access

#### `get_channel_access(channel_name)`
**Description:** Get channel access lists (GRANT, DENY, OWNER, HOST, VOICE)

**Parameters:**
- `channel_name` (str): Channel name

**Returns:**
```python
{
    "GRANT": ["Alice!*@*", "Bob!*@*"],
    "DENY": ["Spammer!*@*"],
    "OWNER": ["Alice!*@*"],
    "HOST": ["Admin!*@*"],
    "VOICE": ["RegularUser!*@*"]
}
```

**Errors:**
- `"Channel '{channel_name}' is not registered. Register it first."` - Not registered

**Example:**
```python
access = api.get_channel_access("#lobby")
print(f"Owners: {access['OWNER']}")
print(f"Granted: {access['GRANT']}")
```

---

#### `set_channel_access(channel_name, access_type, entries)`
**Description:** Set channel access lists (replace entire list)

**Parameters:**
- `channel_name` (str): Channel name
- `access_type` (str): One of: GRANT, DENY, OWNER, HOST, VOICE
- `entries` (str or list): Access entries (comma-separated string or list)

**Validation:**
- Channel name validated via `validate_channel_name()`
- Access type validated via `validate_access_type()`

**Returns:**
```python
{
    "success": True,
    "message": "Updated OWNER list for '#lobby' (2 entries)"
}
```

**Errors:**
- `"Channel '{channel_name}' is not registered. Register it first."` - Not registered

**Example:**
```python
# Set owners (from list)
api.set_channel_access("#lobby", "OWNER", ["Alice!*@*", "Bob!*@*"])

# Set grants (from comma-separated string)
api.set_channel_access("#lobby", "GRANT", "User1!*@*,User2!*@*")

# Clear deny list
api.set_channel_access("#lobby", "DENY", [])
```

---

## Usage Examples

### Example 1: Create Staff Account and Channel

```python
import api

# Create new staff account
result = api.add_staff(
    username="john",
    password="secure_password_123",
    level="SYSOP",
    realname="John Doe",
    email="john@example.com"
)
print(result['message'])  # "Staff member 'john' added as SYSOP"

# Register a nickname for the staff member
result = api.register_nickname("JohnAdmin", "nick_password_456", email="john@example.com")
print(result['message'])  # "Nickname 'JohnAdmin' registered"

# Register a channel owned by the nickname
result = api.register_channel("#johnchannel", "JohnAdmin", description="John's private channel")
print(result['message'])  # "Channel '#johnchannel' registered to JohnAdmin"

# Set channel access
api.set_channel_access("#johnchannel", "OWNER", ["JohnAdmin!*@*"])
api.set_channel_access("#johnchannel", "GRANT", ["Alice!*@*", "Bob!*@*"])
```

---

### Example 2: Manage Server Bans

```python
import api

# Add a permanent ban
api.add_server_access(
    access_type="DENY",
    pattern="*!*@spam.com",
    set_by="admin",
    reason="Spammer network",
    timeout=0  # Permanent
)

# Add a 24-hour ban
api.add_server_access(
    access_type="DENY",
    pattern="baduser!*@*",
    set_by="sysop",
    reason="Abusive behavior",
    timeout=86400  # 24 hours
)

# List all bans
bans = api.get_server_access_list()
for ban in bans:
    if ban['type'] == 'DENY':
        status = "PERMANENT" if ban['timeout'] == 0 else f"{ban['timeout']}s"
        print(f"{ban['pattern']}: {ban['reason']} ({status})")

# Remove a ban
api.remove_server_access("DENY", "*!*@spam.com")
```

---

### Example 3: Manage NewsFlash Messages

```python
import api

# Add high-priority announcement
api.add_newsflash(
    message="Server maintenance tonight at 10 PM EST",
    created_by="admin",
    priority=8
)

# Add normal priority message
api.add_newsflash(
    message="New channel #games created for gaming discussions",
    created_by="sysop",
    priority=3
)

# List all messages
messages = api.get_newsflash_list()
for msg in messages:
    print(f"[Priority {msg['priority']}] {msg['message']}")

# Delete old message
api.delete_newsflash(msg_id=1)

# Configure NewsFlash settings
api.set_newsflash_settings(
    on_connect=True,          # Send on user connect
    periodic_enabled=True,    # Enable periodic broadcasting
    periodic_interval=30      # Every 30 minutes
)
```

---

### Example 4: Test Authentication (with Rate Limiting)

```python
import api
import time

# Test staff login
result = api.test_staff_login("admin", "password")
if result['success']:
    print(f"Staff login OK - Level: {result['level']}")
else:
    print(f"Staff login failed: {result['message']}")

# Test nickname identification
result = api.test_identify("Alice", "password123")
if result['success']:
    if result.get('mfa_required'):
        print("Password OK, but MFA verification required")
    else:
        print("Password OK, authentication would succeed")
else:
    print(f"Identify failed: {result['message']}")

# Rate limiting example
print("Testing rate limit...")
for i in range(6):
    try:
        result = api.test_staff_login("admin", "wrong_password")
        print(f"Attempt {i+1}: {result['message']}")
    except ValueError as e:
        print(f"Attempt {i+1}: RATE LIMITED - {e}")
        break

# Wait for rate limit to reset
print("Waiting 60 seconds for rate limit to reset...")
time.sleep(60)
result = api.test_staff_login("admin", "password")
print(f"After reset: {result['message']}")
```

---

### Example 5: Send Mailbox Messages

```python
import api

# Send a message
result = api.send_mailbox_message(
    sender_nick="Alice",
    recipient_nick="Bob",
    message="Hey Bob, check out the new #games channel!"
)
print(result['message'])  # "Message sent to Bob"

# Get all mailbox messages
messages = api.get_mailbox_messages(limit=100)

# Filter unread messages
unread = [msg for msg in messages if not msg['read']]
print(f"Unread messages: {len(unread)}")

# Display recent messages
for msg in messages[:10]:
    status = "✓" if msg['read'] else "✉"
    print(f"{status} {msg['sender']} → {msg['recipient']}: {msg['message']}")
```

---

### Example 6: Edit Channel Properties

```python
import api

# Get current channel details
details = api.get_channel_details("#lobby")
print(f"Current owner: {details['owner']}")
print(f"Current topic: {details.get('topic', 'No topic')}")

# Change owner
api.edit_channel("#lobby", new_owner="NewAdmin")

# Update multiple properties
api.edit_channel(
    channel_name="#lobby",
    new_description="Main community lobby - all welcome!",
    modes="nt",  # No external messages, topic protection
    topic="Welcome to pyIRCX! Please read the rules in the topic.",
    onjoin="Welcome to #lobby! Enjoy your stay!",
    onpart="Thanks for visiting!"
)

# Set user limit
api.edit_channel("#vip", userlimit=50)
```

---

### Example 7: Search and Manage Registrations

```python
import api

# Search for nicknames
results = api.search_registered_nicks("ali")
print(f"Found {len(results)} nicknames matching 'ali':")
for nick in results:
    print(f"  {nick['nickname']} - registered by {nick['registered_by']}")

# Search for channels
results = api.search_channels("game")
print(f"Found {len(results)} channels matching 'game':")
for channel in results:
    print(f"  {channel['channel_name']}: {channel['description']}")

# Get recent registrations
recent = api.get_recent_registrations(limit=10)
print("Recent registrations:")
for reg in recent:
    print(f"  {reg['nickname']} - {reg['days_ago']} days ago")

# Get paginated nicknames
page1 = api.get_registered_nicks_paginated(page=1, per_page=20)
print(f"Page 1: {len(page1)} nicknames")
print(f"Total: {page1[0]['total']} if page1 else 0")
```

---

## Command-Line Usage

The API can be called from the command line:

```bash
# Get MOTD
python3 api.py get-motd

# Add staff
python3 api.py add-staff john password123 SYSOP "John Doe" john@example.com

# Register nickname
python3 api.py register-nick Alice password456 alice@example.com

# Register channel
python3 api.py register-channel "#mychannel" Alice "My private channel"

# Add NewsFlash
python3 api.py add-newsflash "Server maintenance tonight" admin 8

# Test staff login
python3 api.py test-staff-login admin password

# Get server stats
python3 api.py get-server-stats
```

---

## Best Practices

### Security
1. **Always validate user input** before calling API functions
2. **Use rate-limited functions** for authentication testing
3. **Store passwords securely** - never log or display them
4. **Use HTTPS** when calling API from web interface
5. **Sanitize error messages** before displaying to users

### Performance
1. **Use cached functions** for read-only config data
2. **Limit result sets** using pagination or limits
3. **Batch operations** when possible (e.g., multiple bans)
4. **Close database connections** properly (handled by connection pool)

### Error Handling
```python
try:
    result = api.register_nickname("Alice", "password")
    if not result.get('success'):
        # Handle API-level error
        print(f"API Error: {result['error']}")
    else:
        # Success
        print(f"Success: {result['message']}")
except ValueError as e:
    # Handle validation error
    print(f"Validation Error: {e}")
except Exception as e:
    # Handle unexpected error
    print(f"Unexpected Error: {e}")
```

---

## Troubleshooting

### Common Issues

**Issue:** "Too many attempts - please try again in a moment"
**Cause:** Rate limit exceeded (5 attempts/minute)
**Solution:** Wait 60 seconds and try again

**Issue:** "Status file not found - server may not be running"
**Cause:** Server is not running or status file missing
**Solution:** Start the server with `systemctl start pyircx`

**Issue:** "Database integrity error"
**Cause:** Duplicate entry, foreign key violation
**Solution:** Check for existing entries, ensure referenced entities exist

**Issue:** "Nickname '{nickname}' is not registered"
**Cause:** Nickname doesn't exist in database
**Solution:** Register nickname first with `register_nickname()`

**Issue:** "Channel '{channel}' is not registered. Register it first."
**Cause:** Channel doesn't exist in database
**Solution:** Register channel first with `register_channel()`

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
- Documentation: docs/

---

*Last Updated: 2026-01-18*
*pyIRCX Version: see `version.json` in the project root*
