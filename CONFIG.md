# pyIRCX Configuration Reference

Configuration is stored in `pyircx_config.json`. All options have sensible defaults.

## Server Settings

| Option | Default | Description |
|--------|---------|-------------|
| `server.name` | `"irc.local"` | Server hostname shown to clients |
| `server.network` | `"IRCX Network"` | Network name in 005 numeric |
| `server.version` | `"1.0.4"` | Server version string |
| `server.version_label` | `"pyIRCX"` | Version label for VERSION command |
| `server.created_date` | `"2026"` | Server creation date shown in 003 |

## Network Settings

| Option | Default | Description |
|--------|---------|-------------|
| `network.listen_addr` | `"0.0.0.0"` | IPv4 bind address for listening |
| `network.listen_addr_ipv6` | `null` | IPv6 bind address (defaults to `::` if `enable_ipv6` is true) |
| `network.listen_ports` | `[6667, 7000]` | Ports to listen on |
| `network.enable_ipv6` | `true` | Enable IPv6 dual-stack support |
| `network.resolve_hostnames` | `true` | Resolve IP to hostname on connect |

### IPv6 Support

pyIRCX fully supports IPv6 connections with the following features:

- **Dual-stack binding**: Listens on both IPv4 and IPv6 by default
- **IPv6 DNSBL**: Supports checking IPv6 addresses against DNSBLs (nibble-reversed format)
- **IPv6 hostname resolution**: Proper reverse DNS lookup and verification for IPv6
- **IPv6 private range detection**: Correctly identifies IPv6 loopback (`::1`), link-local (`fe80::/10`), and private (`fc00::/7`) addresses

To disable IPv6, set `network.enable_ipv6` to `false`. To use a specific IPv6 address instead of all interfaces, set `network.listen_addr_ipv6`.

## Database Settings

| Option | Default | Description |
|--------|---------|-------------|
| `database.path` | `"pyircx.db"` | SQLite database file path |
| `database.pool_size` | `5` | Number of pooled database connections |

## System Bot Settings

| Option | Default | Description |
|--------|---------|-------------|
| `system.nick` | `"System"` | System bot nickname |
| `system.ident` | `"System"` | System bot ident/username |
| `system.staff_term` | `"staff member(s)"` | Term used in LUSERS for staff count |

## User/Channel Modes

| Option | Default | Description |
|--------|---------|-------------|
| `modes.user` | `"agiorsxz"` | Available user modes |
| `modes.channel` | `"adefhijkmnprstuwxy"` | Available channel modes |

### Channel Mode Reference

| Mode | Description |
|------|-------------|
| `d` | Clone mode - creates overflow channels when +l limit is reached |
| `e` | Clone indicator - channel is a clone (set automatically) |
| `n` | No external messages (default on) |
| `t` | Topic restricted to hosts (default on) |
| `m` | Moderated channel |
| `i` | Invite only |
| `p` | Private channel |
| `s` | Secret channel |
| `k` | Key/password required |
| `l` | User limit |
| `w` | No whispers allowed |
| `f` | Strip formatting codes |
| `y` | Transcript mode (log channel activity) |

## Limits

| Option | Default | Description |
|--------|---------|-------------|
| `limits.max_users` | `1000` | Maximum concurrent users |
| `limits.msg_length` | `512` | Maximum message length |
| `limits.nick_change_cooldown` | `60` | Seconds between nick changes (0-3600) |
| `limits.max_nick_length` | `30` | Maximum nickname length |
| `limits.max_user_length` | `30` | Maximum username length |
| `limits.max_channel_length` | `50` | Maximum channel name length |

## Services

| Option | Default | Description |
|--------|---------|-------------|
| `services.servicebot_count` | `10` | Number of ServiceBots to create |
| `services.servicebot_max_channels` | `10` | Max channels per ServiceBot |

## Security

| Option | Default | Description |
|--------|---------|-------------|
| `security.flood_messages` | `5` | Messages allowed per window |
| `security.flood_window` | `2.0` | Flood detection window (seconds) |
| `security.connection_throttle` | `3` | Connections allowed per IP per window |
| `security.throttle_window` | `10.0` | Connection throttle window (seconds) |
| `security.enable_flood_protection` | `true` | Enable flood protection |
| `security.enable_connection_throttle` | `true` | Enable connection throttling |
| `security.cap_timeout` | `60` | Seconds before CAP negotiation times out |
| `security.auth_max_attempts` | `5` | Failed auth attempts before lockout |
| `security.auth_lockout_duration` | `300` | Lockout duration in seconds |
| `security.auth_lockout_window` | `600` | Window for counting failed attempts |

### Authentication Security

pyIRCX includes brute-force protection for authentication:

- **Rate limiting**: AUTHENTICATE commands are rate-limited (2 second cooldown)
- **Failed attempt tracking**: IPs are tracked for failed login attempts
- **Automatic lockout**: After `auth_max_attempts` failures within `auth_lockout_window`, the IP is locked out for `auth_lockout_duration` seconds
- **CAP timeout**: Clients stuck in CAP negotiation are disconnected after `cap_timeout` seconds

### DNS Blacklist (DNSBL)

DNSBL checking queries DNS-based blacklists to identify known abusive IPs.

| Option | Default | Description |
|--------|---------|-------------|
| `security.dnsbl.enabled` | `false` | Enable DNSBL checking |
| `security.dnsbl.action` | `"reject"` | Action: reject, warn, mark |
| `security.dnsbl.timeout` | `3.0` | DNS lookup timeout (seconds) |
| `security.dnsbl.cache_ttl` | `3600` | Cache results for N seconds |
| `security.dnsbl.lists` | See below | DNSBL domains to query |
| `security.dnsbl.whitelist` | `[]` | IPs/CIDRs to skip checking |
| `security.dnsbl.reject_message` | `"..."` | Message shown on rejection |

Default DNSBL lists:
- `dnsbl.dronebl.org` - DroneBL (botnets, proxies)
- `rbl.efnetrbl.org` - EFnet RBL (IRC abuse)
- `bl.spamcop.net` - SpamCop (spam sources)

Private IP ranges (127.*, 10.*, 192.168.*, 172.16-31.*) are always whitelisted.

### Proxy Detection

Lightweight check for common open proxy ports.

| Option | Default | Description |
|--------|---------|-------------|
| `security.proxy_detection.enabled` | `false` | Enable proxy detection |
| `security.proxy_detection.ports` | `[8080, 3128, 1080, 9050]` | Ports to check |
| `security.proxy_detection.timeout` | `2.0` | Port check timeout (seconds) |
| `security.proxy_detection.action` | `"warn"` | Action: reject, warn |

### Connection Scoring

Assigns risk scores to connections based on multiple factors.

| Option | Default | Description |
|--------|---------|-------------|
| `security.connection_scoring.enabled` | `false` | Enable scoring |
| `security.connection_scoring.threshold` | `100` | Reject above this score |
| `security.connection_scoring.dnsbl_score` | `50` | Points for DNSBL listing |
| `security.connection_scoring.proxy_score` | `30` | Points for open proxy |
| `security.connection_scoring.no_ident_score` | `10` | Points for no ident |
| `security.connection_scoring.generic_hostname_score` | `5` | Points for ISP hostname |

When scoring is enabled, connections exceeding the threshold are rejected.
Use this for nuanced decisions instead of hard DNSBL rejection.

## SSL/TLS Settings

| Option | Default | Description |
|--------|---------|-------------|
| `ssl.enabled` | `false` | Enable SSL/TLS support |
| `ssl.ports` | `[6697]` | Ports to listen on with SSL |
| `ssl.cert_file` | `""` | Path to certificate file (PEM format) |
| `ssl.key_file` | `""` | Path to private key file (PEM format) |
| `ssl.min_version` | `"TLSv1.2"` | Minimum TLS version (TLSv1, TLSv1.1, TLSv1.2, TLSv1.3) |
| `ssl.auto_reload` | `true` | Auto-reload certificates when files change |
| `ssl.reload_interval` | `3600` | Check for certificate changes every N seconds |
| `ssl.expiry_warn_days` | `[14, 7, 3, 1]` | Days before expiry to log warnings |

### Let's Encrypt Integration

pyIRCX works with Let's Encrypt certificates using a hybrid approach:

1. **Use certbot to obtain and renew certificates:**
   ```bash
   sudo certbot certonly --standalone -d irc.example.com
   ```

2. **Configure pyIRCX to use the certificates:**
   ```json
   {
     "ssl": {
       "enabled": true,
       "ports": [6697],
       "cert_file": "/etc/letsencrypt/live/irc.example.com/fullchain.pem",
       "key_file": "/etc/letsencrypt/live/irc.example.com/privkey.pem"
     }
   }
   ```

3. **pyIRCX handles the rest:**
   - Monitors certificate files for changes
   - Automatically reloads when certbot renews
   - Logs warnings as expiry approaches
   - Reload certificates immediately with `systemctl reload pyircx` (SIGHUP)

### Certificate Monitoring

- Certificates are checked every `reload_interval` seconds (default: 1 hour)
- If file modification time changes, certificates are reloaded
- New connections use the new certificate; existing connections keep the old one
- Expiry warnings are logged at 14, 7, 3, and 1 day(s) before expiration

### STATS t Command

Staff can view SSL status with:
```
/STATS t
```

This shows certificate path, expiry date, days remaining, and status.

## Persistence

| Option | Default | Description |
|--------|---------|-------------|
| `persistence.auto_save` | `true` | Auto-save channel state |
| `persistence.save_interval` | `300` | Save interval in seconds |

## Transcript Settings

| Option | Default | Description |
|--------|---------|-------------|
| `transcript.enabled` | `true` | Enable transcript feature |
| `transcript.directory` | `"transcripts"` | Directory for log files |
| `transcript.max_lines` | `10000` | Max lines per file before rotation |
| `transcript.format` | `"[{timestamp}] {event}"` | Log line format |

Channels with mode `+y` will log activity to `transcripts/<channelname>.log`.

## ServiceBot Settings

| Option | Default | Description |
|--------|---------|-------------|
| `servicebot.enabled` | `true` | Enable ServiceBot monitoring |

### Profanity Filter

| Option | Default | Description |
|--------|---------|-------------|
| `servicebot.profanity_filter.enabled` | `true` | Enable profanity checking |
| `servicebot.profanity_filter.action` | `"warn"` | Action: warn, gag, kick, ban |
| `servicebot.profanity_filter.words` | `[]` | List of forbidden words |
| `servicebot.profanity_filter.warn_message` | `"Please watch your language."` | Warning message |
| `servicebot.profanity_filter.case_sensitive` | `false` | Case-sensitive matching |

### Malicious Activity Detection

| Option | Default | Description |
|--------|---------|-------------|
| `servicebot.malicious_detection.enabled` | `true` | Enable detection |
| `servicebot.malicious_detection.flood_threshold` | `5` | Messages triggering flood |
| `servicebot.malicious_detection.flood_window` | `3` | Flood window (seconds) |
| `servicebot.malicious_detection.flood_action` | `"gag"` | Flood action |
| `servicebot.malicious_detection.caps_threshold` | `0.7` | Caps ratio (0.0-1.0) |
| `servicebot.malicious_detection.caps_min_length` | `10` | Min length to check caps |
| `servicebot.malicious_detection.caps_action` | `"warn"` | Caps action |
| `servicebot.malicious_detection.url_spam_threshold` | `3` | URL messages triggering spam |
| `servicebot.malicious_detection.url_spam_window` | `10` | URL spam window (seconds) |
| `servicebot.malicious_detection.url_spam_action` | `"warn"` | URL spam action |
| `servicebot.malicious_detection.repeat_threshold` | `3` | Repeated messages count |
| `servicebot.malicious_detection.repeat_window` | `30` | Repeat window (seconds) |
| `servicebot.malicious_detection.repeat_action` | `"warn"` | Repeat action |

## Admin Info

| Option | Default | Description |
|--------|---------|-------------|
| `admin.loc1` | `"Server Administration"` | Admin info line 1 |
| `admin.loc2` | `"Network Operations"` | Admin info line 2 |
| `admin.email` | `"admin@irc.local"` | Admin contact email |
| `admin.default_username` | `"admin"` | Default admin username (first run only) |
| `admin.default_password` | `"changeme"` | Default admin password (first run only) |

### Default Admin Account

On first startup (when no staff accounts exist), pyIRCX automatically creates a default ADMIN account:

- **Username:** `admin` (or value of `admin.default_username`)
- **Password:** `changeme` (or value of `admin.default_password`)

**Important:** Change the default password immediately after first login:
```
STAFF PASS admin yournewsecurepassword
```

To login as admin, use the PASS command before USER:
```
PASS admin:changeme
USER admin 0 * :Administrator
NICK YourNick
```

## Example Configuration

```json
{
    "server": {
        "name": "chat.example.com",
        "network": "ExampleNet",
        "version": "2.0.0"
    },
    "network": {
        "listen_ports": [6667, 6668, 7000],
        "resolve_hostnames": true
    },
    "limits": {
        "max_users": 500,
        "nick_change_cooldown": 30
    },
    "security": {
        "flood_messages": 10,
        "flood_window": 3.0
    },
    "admin": {
        "email": "irc@example.com"
    }
}
```

## IRCv3 Capabilities

The server supports CAP negotiation with these capabilities:
- `multi-prefix` - Show all prefix modes in NAMES/WHO
- `away-notify` - Notify clients of away status changes
- `account-notify` - Notify clients of account changes
- `extended-join` - Extended JOIN with account info
- `server-time` - Server timestamps on messages
- `userhost-in-names` - Full hostmasks in NAMES
- `cap-notify` - CAP changes notification
- `message-tags` - IRCv3 message tags
- `batch` - Message batching
- `echo-message` - Echo sent messages back

## IRCX Extensions

The server supports IRCX protocol extensions:
- Send `IRCX` or `ISIRCX` after connecting to enable IRCX mode
- IRCX mode enables: PROP command, LISTX, ACCESS, enhanced WHO flags
- Staff levels: ADMIN (mode `a`), SYSOP (mode `o`), GUIDE (mode `g`)

## Staff Commands

| Command | Access | Description |
|---------|--------|-------------|
| `KILL` | ADMIN, SYSOP | Disconnect user |
| `KILL #channel` | ADMIN, SYSOP | Destroy channel and kick all users |
| `KILL pattern` | ADMIN, SYSOP | Disconnect users matching IP/hostmask |
| `KLINE/GLINE` | ADMIN, SYSOP | Ban by pattern |
| `UNKLINE/UNGLINE` | ADMIN, SYSOP | Remove ban |
| `GAG` | ADMIN, SYSOP, GUIDE | Silence user |
| `UNGAG` | ADMIN, SYSOP, GUIDE | Remove gag |
| `STATS` | All staff | Server statistics |
| `WHO *` | ADMIN, SYSOP | List all users |
| `CONFIG LIST/GET/SET` | ADMIN (SET), SYSOP+ (view) | In-band configuration |
| `INVITE ServiceBot## #channel` | ADMIN, SYSOP | Add ServiceBot monitoring |

## User Commands

| Command | Description |
|---------|-------------|
| `REGISTER nick email pass` | Register account |
| `IDENTIFY pass` | Identify to account |
| `MFA ENABLE/DISABLE/VERIFY` | Two-factor authentication |
| `WATCH +/-nick` | Track user online/offline |
| `SILENCE +/-mask` | Server-side ignore |
| `CHGPASS oldpass newpass` | Change password |
| `MEMO SEND/LIST/READ/DEL` | Offline messaging |
| `TRANSCRIPT #channel [lines] [offset]` | View channel transcript (hosts/staff only) |

## ServiceBot Usage

ServiceBots provide automated channel moderation. To use:

1. An ADMIN or SYSOP invites a ServiceBot to a channel:
   ```
   /INVITE ServiceBot01 #channel
   ```

2. The ServiceBot monitors all messages and takes action on violations:
   - **Profanity**: Detects forbidden words
   - **Flooding**: Detects rapid message sending
   - **Caps**: Detects excessive uppercase (shouting)
   - **Repeat spam**: Detects repeated identical messages
   - **URL spam**: Detects link flooding

3. Actions are configurable per violation type:
   - `warn` - Send warning notice to user
   - `gag` - Silence user in channel
   - `kick` - Remove user from channel
   - `ban` - Ban and kick user

Staff members (ADMIN, SYSOP, GUIDE) are exempt from ServiceBot monitoring.

## Installation

### Quick Install (systemd)

```bash
sudo ./install.sh
sudo systemctl enable pyircx
sudo systemctl start pyircx
```

### Manual Installation

1. Install dependencies:
   ```bash
   pip3 install aiosqlite bcrypt pyotp
   ```

2. Copy files to desired location:
   ```bash
   cp pyircx.py /opt/pyircx/
   cp pyircx_config.json /etc/pyircx/
   ```

3. Create service user:
   ```bash
   useradd --system --no-create-home pyircx
   ```

4. Install systemd service:
   ```bash
   cp pyircx.service /etc/systemd/system/
   systemctl daemon-reload
   ```

### Uninstall

```bash
sudo ./install.sh uninstall
```

## Running the Server

### Command-Line Options

```
usage: pyircx.py [-h] [--systemd] [--config CONFIG_FILE]
                 [--log-file LOG_FILE] [--log-level {DEBUG,INFO,WARNING,ERROR}]
                 [--version]

Options:
  --systemd             Run in systemd mode (log to stdout for journald)
  --config, -c FILE     Path to configuration file
  --log-file FILE       Path to log file (ignored with --systemd)
  --log-level LEVEL     Logging level: DEBUG, INFO, WARNING, ERROR
  --version, -v         Show version
```

### Standalone Mode

```bash
python3 pyircx.py
python3 pyircx.py --log-level DEBUG
python3 pyircx.py --config /etc/pyircx/config.json
```

### Systemd Mode

```bash
# Start/Stop/Restart
systemctl start pyircx
systemctl stop pyircx
systemctl restart pyircx

# Check status
systemctl status pyircx

# View logs
journalctl -u pyircx
journalctl -u pyircx -f          # Follow logs
journalctl -u pyircx --since today

# Reload configuration (sends SIGHUP)
systemctl reload pyircx

# Enable at boot
systemctl enable pyircx
```

## Signal Handling

| Signal | Action |
|--------|--------|
| SIGTERM | Graceful shutdown (saves state, disconnects clients) |
| SIGINT | Graceful shutdown (same as SIGTERM) |
| SIGHUP | Reload configuration file |

## Logging

### Standalone Mode
- Logs to stdout and `pyircx.log` (rotating, 10MB max, 5 backups)

### Systemd Mode
- Logs to stdout (captured by journald)
- Use `journalctl -u pyircx` to view logs

### Log Levels
- `DEBUG` - Verbose debugging information
- `INFO` - Normal operation messages (default)
- `WARNING` - Warning conditions
- `ERROR` - Error conditions
