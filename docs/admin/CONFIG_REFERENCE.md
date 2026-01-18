# pyIRCX Configuration Reference

**Version:** 1.2.0
**Last Updated:** 2026-01-16

## Overview

This document provides a comprehensive reference for all pyIRCX configuration options. Configuration is stored in `pyircx_config.json` and uses JSON format.

## Configuration File Location

- **Default:** `pyircx_config.json` (same directory as pyircx.py)
- **Custom:** Use `--config` flag: `python3 pyircx.py --config /path/to/config.json`

## Configuration Structure

```json
{
    "server": { ... },
    "limits": { ... },
    "security": { ... },
    "services": { ... },
    "ssl": { ... },
    "linking": { ... },
    "modes": { ... },
    "database": { ... },
    "logs": { ... },
    "advanced": { ... }
}
```

---

## Server Section

Basic server identity and network information.

### server.name
**Type:** String
**Default:** `"irc.localhost"`
**Description:** Server hostname (FQDN recommended)

**Example:**
```json
"name": "irc.example.com"
```

**Notes:**
- Used in server messages and WHOIS responses
- Should match DNS A/AAAA record for best compatibility
- Changing requires server restart

---

### server.network
**Type:** String
**Default:** `"IRCX Network"`
**Description:** Network name displayed in welcome messages

**Example:**
```json
"network": "ExampleNet IRC Network"
```

---

### server.description
**Type:** String
**Default:** `"pyIRCX Server"`
**Description:** Server description shown in /LINKS and network lists

---

### server.admin_info
**Type:** Object
**Default:**
```json
{
    "location": "Earth",
    "organization": "pyIRCX Project",
    "email": "admin@example.com"
}
```

**Description:** Administrative contact information (shown via /ADMIN command)

---

### server.motd_file
**Type:** String
**Default:** `"motd.txt"`
**Description:** Path to Message of the Day file

**Notes:**
- Relative or absolute path
- Reloaded on /REHASH or server reload
- Whitespace preserved

---

### server.bind
**Type:** String or Array
**Default:** `"0.0.0.0"`
**Description:** IP address(es) to bind IRC server

**Examples:**
```json
"bind": "0.0.0.0"                    // All IPv4 interfaces
"bind": "::"                         // All IPv6 interfaces
"bind": ["0.0.0.0", "::"]           // Both IPv4 and IPv6
"bind": "192.168.1.10"              // Specific interface
```

---

### server.port
**Type:** Integer
**Default:** `6667`
**Description:** Main IRC port (plaintext)

**Standard ports:**
- 6667 - Traditional IRC (plaintext)
- 6697 - IRC over SSL/TLS
- 7000 - Alternative plaintext
- 9999 - Alternative SSL

---

### server.websocket_port
**Type:** Integer
**Default:** `8080`
**Description:** WebSocket port for web clients

**Notes:**
- Used by webchat interface
- Separate from main IRC port
- Supports both plaintext and SSL

---

### server.ssl_port
**Type:** Integer
**Default:** `6697`
**Description:** SSL/TLS encrypted IRC port

**Requirements:**
- SSL certificates configured (see SSL section)
- Port forwarding if behind NAT

---

## Limits Section

Connection and resource limits.

### limits.max_users
**Type:** Integer
**Default:** `1000`
**Range:** 1 - 100000

**Description:** Maximum simultaneous connected users

**Recommendations:**
- **Small server:** 100-500
- **Medium server:** 500-2000
- **Large server:** 2000+

---

### limits.max_channels
**Type:** Integer
**Default:** `500`
**Description:** Maximum number of channels that can exist

---

### limits.max_channels_per_user
**Type:** Integer
**Default:** `20`
**Description:** Maximum channels a single user can join

---

### limits.max_nick_length
**Type:** Integer
**Default:** `30`
**Range:** 9 - 50

**Description:** Maximum nickname length

**Notes:**
- IRC standard: 9 characters
- Most modern servers: 30 characters
- IRCX supports up to 50

---

### limits.max_channel_name_length
**Type:** Integer
**Default:** `50`
**Description:** Maximum channel name length

---

### limits.max_topic_length
**Type:** Integer
**Default:** `390`
**Description:** Maximum topic length

---

### limits.max_kick_reason_length
**Type:** Integer
**Default:** `255`
**Description:** Maximum kick reason length

---

### limits.max_away_length
**Type:** Integer
**Default:** `200`
**Description:** Maximum away message length

---

### limits.client_timeout
**Type:** Integer (seconds)
**Default:** `300`
**Description:** Timeout for idle clients (no data received)

**How it works:**
- Tracks time since last data received from client
- If no activity for N seconds, client is disconnected
- Prevents "ghost connections" from crashed clients

**Behavior:**
- Modern IRC clients automatically send PING every 60-120 seconds
- Timeout applies even if user is active in channel
- Connection lost message: "Client timeout (no data for Ns)"

**Recommendations:**
- **300 seconds (5 min):** Good balance (default)
- **600 seconds (10 min):** Lenient for slow connections
- **120 seconds (2 min):** Strict cleanup of dead connections
- **Don't go below 120:** May disconnect legitimate users

**Example:**
```json
"limits": {
    "client_timeout": 300
}
```

---

## Security Section

Authentication, flood protection, and access control.

### security.password
**Type:** String
**Default:** `null`
**Description:** Server password (optional)

**Notes:**
- If set, clients must provide password on connect
- Sent as: `/PASS yourpassword` before NICK/USER
- Empty string or null = no password required

---

### security.enable_flood_protection
**Type:** Boolean
**Default:** `true`
**Description:** Enable rate limiting for commands

---

### security.flood_threshold
**Type:** Integer
**Default:** `10`
**Description:** Commands allowed in time window

---

### security.flood_window
**Type:** Integer (seconds)
**Default:** `10`
**Description:** Time window for flood protection

**How it works:**
- Tracks commands per user per time window
- If user exceeds threshold, they're warned/kicked
- Resets after window expires

---

### security.enable_dnsbl
**Type:** Boolean
**Default:** `false`
**Description:** Check connecting IPs against DNS blacklists

**DNSBLs checked:**
- zen.spamhaus.org
- dnsbl.dronebl.org
- bl.spamcop.net

**Notes:**
- Adds connection latency (~1-2 seconds)
- Requires internet access
- May have false positives

---

### security.enable_ident
**Type:** Boolean
**Default:** `false`
**Description:** Perform IDENT (RFC 1413) lookups on connect

**Notes:**
- Adds connection delay if user has no ident
- Most modern networks don't use IDENT
- Username prefixed with ~ if IDENT fails

---

### security.require_registration
**Type:** Boolean
**Default:** `false`
**Description:** Require nickname registration to connect

---

### security.max_login_attempts
**Type:** Integer
**Default:** `3`
**Description:** Failed login attempts before temp ban

---

### security.login_timeout
**Type:** Integer (seconds)
**Default:** `120`
**Description:** Temp ban duration after failed logins

---

### security.auth_require_ssl
**Type:** Boolean
**Default:** `true`
**Description:** Require SSL/TLS for AUTH command

**Example:**
```json
"security": {
    "auth_require_ssl": true
}
```

**Notes:**
- When enabled, AUTH command only works on SSL/TLS connections (port 6697)
- Prevents staff credentials from being transmitted in plaintext
- Recommended for production environments
- Users will receive "AUTH command requires an SSL/TLS connection" error on non-SSL
- Set to `false` only if you need to support AUTH over non-encrypted connections

**Security Impact:**
- ✅ Enabled (default): Maximum security - credentials always encrypted
- ⚠️ Disabled: Credentials may be intercepted on non-SSL connections

---

### security.pass_require_ssl
**Type:** Boolean
**Default:** `true`
**Description:** Require SSL/TLS for PASS-based staff authentication during connection

**Example:**
```json
"security": {
    "pass_require_ssl": true
}
```

**Notes:**
- When enabled, staff accounts cannot authenticate via PASS on non-SSL connections
- Prevents staff credentials from being transmitted during initial connection
- Recommended for production environments
- Regular users can still connect without SSL (only staff PASS authentication is blocked)
- Staff can still use AUTH command post-connection (see auth_require_ssl)

**How it works:**
- During connection, server checks if user is authenticating as staff via PASS
- If staff PASS authentication AND non-SSL connection: authentication blocked
- User connects as regular user instead of staff
- Staff can then use AUTH command (which has its own SSL requirement)

**Security Impact:**
- ✅ Enabled (default): Staff credentials never sent during connection without SSL
- ⚠️ Disabled: Staff can authenticate via PASS on plaintext connections (legacy support)

**Recommendation:**
Enable both `auth_require_ssl` and `pass_require_ssl` for maximum security. This ensures staff credentials are ONLY transmitted over encrypted connections, whether during initial connection (PASS) or post-connection (AUTH).

---

## Services Section

Built-in service bot configuration.

### services.enable_registrar
**Type:** Boolean
**Default:** `true`
**Description:** Enable Registrar (NickServ/ChanServ) service

**Commands provided:**
- REGISTER, IDENTIFY, DROP, INFO
- SET EMAIL, SET PASSWORD
- GHOST, RECOVER

---

### services.enable_messenger
**Type:** Boolean
**Default:** `true`
**Description:** Enable Messenger (MemoServ) service

**Commands provided:**
- SEND, READ, DELETE, COUNT, LIST

---

### services.enable_newsflash
**Type:** Boolean
**Default:** `true`
**Description:** Enable NewsFlash announcement service

---

### services.servicebot_count
**Type:** Integer
**Default:** `10`
**Range:** 1 - 99

**Description:** Number of ServiceBot monitoring instances

**How it works:**
- Creates ServiceBot01 through ServiceBotNN
- Each bot can monitor multiple channels
- Bots auto-distribute across channels
- Higher count = better channel coverage

**Recommendations:**
- **1-5 bots:** Small servers (< 50 channels)
- **10 bots:** Medium servers (50-200 channels) - DEFAULT
- **20+ bots:** Large servers (200+ channels)

**Example:**
```json
"services": {
    "servicebot_count": 15
}
```

**Notes:**
- Reserved nicknames: ServiceBot, ServiceBot01-ServiceBotNN
- Bots provide auto-moderation if enabled
- Changing requires server restart

---

### services.enable_profanity_filter
**Type:** Boolean
**Default:** `false`
**Description:** Enable automatic profanity filtering

**Actions taken:**
- Warns user on first offense
- Kicks on repeated offenses
- Can auto-ban persistent offenders

---

### services.profanity_action
**Type:** String
**Default:** `"warn"`
**Options:** `"warn"`, `"kick"`, `"ban"`

**Description:** Action to take on profanity detection

---

### services.enable_malicious_detection
**Type:** Boolean
**Default:** `true`
**Description:** Detect and block malicious patterns

**Detects:**
- Mass mentions (@everyone spam)
- Flood/repeat messages
- Phishing links
- Malware URLs

---

### services.malicious_threshold
**Type:** Integer
**Default:** `5`
**Description:** Threshold for malicious activity detection

---

## SSL/TLS Section

Encrypted connection configuration.

### ssl.enabled
**Type:** Boolean
**Default:** `false`
**Description:** Enable SSL/TLS support

**Requirements:**
- Certificate file (ssl.cert_file)
- Private key file (ssl.key_file)
- Open SSL port (server.ssl_port)

---

### ssl.cert_file
**Type:** String
**Default:** `"server.crt"`
**Description:** Path to SSL certificate

**Supported formats:**
- PEM (most common)
- DER
- Combined cert+chain

**Example:**
```json
"cert_file": "/etc/letsencrypt/live/irc.example.com/fullchain.pem"
```

---

### ssl.key_file
**Type:** String
**Default:** `"server.key"`
**Description:** Path to SSL private key

**Example:**
```json
"key_file": "/etc/letsencrypt/live/irc.example.com/privkey.pem"
```

**Security:**
- Keep private key secure (600 permissions)
- Never commit to version control
- Rotate regularly

---

### ssl.min_tls_version
**Type:** String
**Default:** `"TLSv1.2"`
**Options:** `"TLSv1.0"`, `"TLSv1.1"`, `"TLSv1.2"`, `"TLSv1.3"`

**Description:** Minimum TLS version to accept

**Recommendations:**
- **TLSv1.2:** Good balance (default)
- **TLSv1.3:** Maximum security (may break old clients)
- **TLSv1.0/1.1:** Deprecated, avoid

---

### ssl.ciphers
**Type:** String
**Default:** `"HIGH:!aNULL:!MD5"`
**Description:** OpenSSL cipher string

**Examples:**
```json
"ciphers": "HIGH:!aNULL:!MD5"                    // Secure defaults
"ciphers": "ECDHE-RSA-AES256-GCM-SHA384:..."    // Specific ciphers
```

---

## Linking Section

Server-to-server linking (for networks).

### linking.enabled
**Type:** Boolean
**Default:** `false`
**Description:** Enable server linking capability

---

### linking.bind
**Type:** String
**Default:** `"0.0.0.0"`
**Description:** Interface to bind for incoming links

---

### linking.port
**Type:** Integer
**Default:** `7777`
**Description:** Port for server-to-server connections

---

### linking.password
**Type:** String
**Default:** `""`
**Description:** Password for server authentication

**Security:**
- Use strong, unique password
- Different from user password
- Rotate regularly

---

## Modes Section

Default user and channel modes.

### modes.user
**Type:** String
**Default:** `"agiorsxz"`
**Description:** Available user modes

**Standard IRC modes:**
- `i` - Invisible (hidden from WHO)
- `o` - IRC Operator
- `w` - Wallops (receive server notices)
- `s` - Server notices
- `r` - Registered nickname
- `x` - Hidden hostname

**IRCX modes:**
- `a` - Administrator
- `g` - Guide (helper)
- `z` - Gagged (cannot send messages)

---

### modes.channel
**Type:** String
**Default:** `"adefghijklmnprstuwxyz"`
**Description:** Available channel modes

**Standard modes:**
- `i` - Invite-only
- `m` - Moderated
- `n` - No external messages
- `p` - Private
- `s` - Secret
- `t` - Topic protection
- `k` - Key (password)
- `l` - User limit

**IRCX modes:**
- `d` - Cloned (child of another channel)
- `u` - Auditorium (only ops see users)
- `x` - Hidden (not shown in LIST)
- `z` - ServiceBot monitored

---

## Database Section

SQLite database configuration.

### database.path
**Type:** String
**Default:** `"pyircx.db"`
**Description:** Path to SQLite database file

**Tables created:**
- `registered_nicks` - Nickname registrations
- `registered_channels` - Channel registrations
- `users` - Staff accounts
- `mailbox` - Offline messages
- `newsflash` - Server announcements

---

### database.auto_backup
**Type:** Boolean
**Default:** `true`
**Description:** Automatically backup database

---

### database.backup_interval
**Type:** Integer (hours)
**Default:** `24`
**Description:** Hours between automatic backups

---

## Logs Section

Logging configuration.

### logs.level
**Type:** String
**Default:** `"INFO"`
**Options:** `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`

**Description:** Minimum log level to record

---

### logs.file
**Type:** String
**Default:** `"pyircx.log"`
**Description:** Log file path

---

### logs.max_size
**Type:** Integer (bytes)
**Default:** `10485760` (10 MB)
**Description:** Maximum log file size before rotation

---

### logs.backup_count
**Type:** Integer
**Default:** `5`
**Description:** Number of rotated log files to keep

---

## Advanced Section

Advanced features and tuning.

### advanced.enable_transcripts
**Type:** Boolean
**Default:** `false`
**Description:** Log all channel messages to files

**Notes:**
- Privacy implications - inform users
- Can generate large log files
- Useful for moderation/compliance

---

### advanced.transcript_dir
**Type:** String
**Default:** `"transcripts"`
**Description:** Directory for channel transcripts

---

### advanced.enable_persistence
**Type:** Boolean
**Default:** `true`
**Description:** Persist registered channels to database

---

### advanced.newsflash_interval
**Type:** Integer (minutes)
**Default:** `60`
**Description:** Minutes between NewsFlash announcements

---

### advanced.enable_colors
**Type:** Boolean
**Default:** `true`
**Description:** Allow IRC color codes in messages

---

### advanced.enable_ctcp
**Type:** Boolean
**Default:** `true`
**Description:** Allow CTCP (Client-To-Client Protocol)

**CTCP commands:**
- VERSION, TIME, PING, FINGER
- ACTION (/me)
- DCC (file transfer)

---

## Configuration Examples

### Minimal Config (Defaults)
```json
{
    "server": {
        "name": "irc.example.com",
        "network": "ExampleNet"
    }
}
```

### Small Community Server
```json
{
    "server": {
        "name": "irc.community.com",
        "network": "CommunityChat",
        "port": 6667,
        "ssl_port": 6697
    },
    "limits": {
        "max_users": 100,
        "max_channels": 50,
        "client_timeout": 300
    },
    "security": {
        "enable_flood_protection": true,
        "enable_dnsbl": false
    },
    "services": {
        "servicebot_count": 5,
        "enable_profanity_filter": true
    },
    "ssl": {
        "enabled": true,
        "cert_file": "/etc/letsencrypt/live/irc.community.com/fullchain.pem",
        "key_file": "/etc/letsencrypt/live/irc.community.com/privkey.pem"
    }
}
```

### Large Public Server
```json
{
    "server": {
        "name": "irc.bignet.org",
        "network": "BigNet IRC",
        "bind": ["0.0.0.0", "::"],
        "port": 6667,
        "ssl_port": 6697,
        "websocket_port": 8080
    },
    "limits": {
        "max_users": 5000,
        "max_channels": 1000,
        "max_channels_per_user": 50,
        "client_timeout": 600
    },
    "security": {
        "enable_flood_protection": true,
        "flood_threshold": 10,
        "flood_window": 10,
        "enable_dnsbl": true,
        "max_login_attempts": 5
    },
    "services": {
        "servicebot_count": 25,
        "enable_profanity_filter": true,
        "profanity_action": "kick",
        "enable_malicious_detection": true
    },
    "ssl": {
        "enabled": true,
        "cert_file": "/etc/ssl/irc.bignet.org.pem",
        "key_file": "/etc/ssl/private/irc.bignet.org.key",
        "min_tls_version": "TLSv1.2"
    },
    "linking": {
        "enabled": true,
        "port": 7777,
        "password": "strong-link-password-here"
    },
    "database": {
        "auto_backup": true,
        "backup_interval": 6
    },
    "logs": {
        "level": "INFO",
        "max_size": 52428800,
        "backup_count": 10
    }
}
```

## Configuration Validation

### Using built-in validator:
```bash
python3 pyircx.py --config myconfig.json --validate
```

### Common validation errors:

**Invalid JSON syntax:**
```
Error: Unexpected token at line 15
```
*Fix: Check for missing commas, brackets, or quotes*

**Invalid port number:**
```
Error: server.port must be between 1-65535
```

**Missing SSL files:**
```
Error: ssl.cert_file not found: /path/to/cert.pem
```

**Invalid mode strings:**
```
Error: modes.user contains invalid character: '!'
```

## Dynamic Reconfiguration

### Reloadable without restart:
- MOTD file (`server.motd_file`)
- Access lists (via /ACCESS commands)
- Profanity filter words
- Some security thresholds

### Requires restart:
- Server binding addresses/ports
- SSL certificates
- Database path
- ServiceBot count
- Linking configuration

### Reload command:
```bash
# Via IRC (ADMIN only)
/REHASH

# Via server console
/reload-config

# Via webadmin
Click "Reload Server" button
```

## Troubleshooting

### Server won't start:
1. Check JSON syntax: `python3 -m json.tool pyircx_config.json`
2. Verify file permissions
3. Check port availability: `netstat -tlnp | grep :6667`
4. Review logs: `tail -f pyircx.log`

### SSL issues:
1. Verify certificate files exist and are readable
2. Check certificate expiration: `openssl x509 -in cert.pem -noout -dates`
3. Test certificate chain: `openssl verify -CAfile chain.pem cert.pem`
4. Check permissions: `chmod 600 privkey.pem`

### Performance issues:
1. Increase `limits.max_users` if at capacity
2. Disable DNSBL if causing delays
3. Reduce `services.servicebot_count` if using too much CPU
4. Enable database backups less frequently
5. Lower log level to WARNING or ERROR

## See Also

- [User Manual](../user/MANUAL.md) - User commands and features
- [WebAdmin API](WEBADMIN_API.md) - REST API documentation
- [Installation Guide](../../INSTALL.md) - Setup instructions

## Support

For configuration help:
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
- IRC: #pyircx on irc.example.com
