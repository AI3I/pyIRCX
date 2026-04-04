# pyIRCX WebChat

Browser-based IRC/IRCX client with WebSocket gateway.

## Overview

The WebChat system consists of two components:

1. **Frontend** (`/var/www/html/webchat/index.html`) - Browser-based IRC client
2. **Gateway** (`/opt/pyircx/webchat/gateway.py`) - WebSocket-to-IRC bridge

## Deployment Options

### Local Deployment (Default)
WebChat runs on the same server as the IRC server. This README covers local deployment.

### Remote Deployment (Recommended for Production)
WebChat runs on a separate web server from the IRC server for better scalability and security.

**See: [REMOTE_DEPLOYMENT.md](REMOTE_DEPLOYMENT.md)** for complete guide on deploying WebChat on a separate server.

## Configuration

WebChat is configured via `config.js` for easy customization without editing HTML.

### Configuration File

**Location:** `/var/www/html/webchat/config.js`

**Example:**
```javascript
const WEBCHAT_CONFIG = {
    // WebSocket connection
    websocketUrl: null,              // null = auto-detect based on protocol
    websocketPort: 8765,             // Port for ws:// connections
    websocketPath: '/ws',            // Path for wss:// connections (via reverse proxy)

    // Default connection settings
    defaultChannel: '#pyIRCX',       // Channel to join on connect
    defaultNick: '',                 // Pre-filled nickname (empty = user enters)

    // Performance tuning
    whoThrottleMs: 2000,             // Minimum time between WHO requests (ms)
    commandDelayMs: 600,             // Delay after JOIN before sending commands (ms)

    // Staff emoji display
    staffEmoji: {
        'SERVICE': '🤖',
        'ADMIN': '👑',
        'SYSOP': '🏅',
        'GUIDE': '🔰'
    },

    // UI preferences
    enableSounds: true,              // Enable notification sounds
    enableNotifications: false,      // Browser desktop notifications
    theme: 'default'                 // UI theme
};
```

### Configuration Options

#### WebSocket Connection

| Option | Default | Description |
|--------|---------|-------------|
| `websocketUrl` | `null` | Full WebSocket URL (null = auto-detect) |
| `websocketPort` | `8765` | Port for direct WebSocket (ws://) connections |
| `websocketPath` | `'/ws'` | Path for proxied WebSocket (wss://) connections |

**Auto-Detection:**
- HTTP sites: `ws://hostname:8765`
- HTTPS sites: `wss://hostname/ws` (requires reverse proxy)

**Manual Override:**
```javascript
websocketUrl: 'wss://chat.example.com:9000/websocket'
```

#### Connection Settings

| Option | Default | Description |
|--------|---------|-------------|
| `defaultChannel` | `'#pyIRCX'` | Channel joined automatically on connect |
| `defaultNick` | `''` | Pre-filled nickname (empty for manual entry) |

#### Performance Settings

| Option | Default | Description |
|--------|---------|-------------|
| `whoThrottleMs` | `2000` | Minimum time between WHO requests (prevents flooding) |
| `commandDelayMs` | `600` | Delay after JOIN before WHO/commands (waits for IRCX detection) |

**Performance Notes:**
- `whoThrottleMs` prevents excessive WHO requests when switching channels frequently
- `commandDelayMs` ensures IRCX capabilities are negotiated before sending extended commands
- Lower values improve responsiveness but increase server load

#### UI Customization

| Option | Default | Description |
|--------|---------|-------------|
| `staffEmoji` | `{...}` | Emoji displayed for staff members by level |
| `enableSounds` | `true` | Play notification sounds for messages/events |
| `enableNotifications` | `false` | Show browser desktop notifications |
| `theme` | `'default'` | UI theme/color scheme |

**Staff Emoji Customization:**
```javascript
staffEmoji: {
    'SERVICE': '🔧',    // Service bots
    'ADMIN': '⭐',      // Network administrators
    'SYSOP': '🛡️',     // Server operators
    'GUIDE': '💡'       // User helpers
}
```

## Installation

### Automatic Installation

The installation scripts automatically install and configure WebChat:

```bash
sudo ./install.sh    # New installation
sudo ./upgrade.sh    # Upgrade existing installation
```

### Manual Installation

If installing manually:

1. **Copy files:**
   ```bash
   cp webchat/index.html /var/www/html/webchat/
   cp webchat/config.js /var/www/html/webchat/
   cp webchat/favicon.svg /var/www/html/webchat/
   cp webchat/gateway.py /opt/pyircx/webchat/
   ```

2. **Set permissions:**
   ```bash
   chmod 644 /var/www/html/webchat/*.html
   chmod 644 /var/www/html/webchat/config.js
   chmod 755 /opt/pyircx/webchat/gateway.py
   ```

3. **Configure SELinux:**
   ```bash
   semanage fcontext -a -t httpd_sys_content_t "/var/www/html/webchat(/.*)?"
   restorecon -Rv /var/www/html/webchat
   ```

4. **Start gateway service:**
   ```bash
   systemctl enable pyircx-webchat.service
   systemctl start pyircx-webchat.service
   ```

## Gateway Service

The WebSocket gateway (`pyircx-webchat.service`) bridges browser WebSocket connections to the IRC server.

### Configuration

**File:** `/etc/pyircx/webchat.conf`

```ini
[websocket]
host = 0.0.0.0
port = 8765

[irc]
host = localhost
port = 6667

[webirc]
password = changeme
gateway = pyircx-webchat
trusted_proxies = 127.0.0.1/32, ::1/128
```

### Service Management

```bash
# Status
systemctl status pyircx-webchat

# Logs
journalctl -u pyircx-webchat -f

# Restart
systemctl restart pyircx-webchat
```

### Reverse Proxy Setup (HTTPS)

For HTTPS sites, configure Apache/nginx to proxy WebSocket connections:

**Apache:**
```apache
# In your VirtualHost
ProxyPass /ws ws://localhost:8765/
ProxyPassReverse /ws ws://localhost:8765/
```

**nginx:**
```nginx
location /ws {
    proxy_pass http://localhost:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
}
```

## Customization

### Changing Default Channel

Edit `/var/www/html/webchat/config.js`:
```javascript
defaultChannel: '#YourChannel'
```

### Custom Branding

The webchat interface can be customized by editing `index.html`:
- Logo/title in the header
- CSS styles
- Welcome message
- Footer links

### Performance Tuning

For high-traffic sites, adjust:
```javascript
whoThrottleMs: 3000,    // Increase for busy servers
commandDelayMs: 800     // Increase if IRCX detection is slow
```

## Troubleshooting

### WebChat shows "Connecting..." forever

**Check gateway service:**
```bash
systemctl status pyircx-webchat
journalctl -u pyircx-webchat -n 50
```

**Check firewall:**
```bash
firewall-cmd --list-ports
# Should show: 8765/tcp
```

**Test WebSocket:**
```bash
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
     http://localhost:8765/
```

### "403 Forbidden" error

**Check SELinux context:**
```bash
ls -ldZ /var/www/html/webchat
# Should show: httpd_sys_content_t
```

**Fix context:**
```bash
restorecon -Rv /var/www/html/webchat
```

### Gateway won't start

**Check configuration:**
```bash
cat /etc/pyircx/webchat.conf
ls -lZ /etc/pyircx/webchat.conf
# Should show: etc_t context
```

**Fix context:**
```bash
semanage fcontext -a -t etc_t "/etc/pyircx/webchat\.conf"
restorecon -v /etc/pyircx/webchat.conf
```

### Changes to config.js not showing

**Browser cache:** Force refresh with `Ctrl+Shift+R` (or `Cmd+Shift+R` on Mac)

## Security

### WEBIRC Password

The gateway uses WEBIRC to preserve client IP addresses. Change the default password:

1. **Update server config** (`/etc/pyircx/pyircx_config.json`):
   ```json
   {
     "security": {
       "webirc": {
         "enabled": true,
         "hosts": {
           "pyircx-webchat": {
             "password": "your-secure-password",
             "allowed_ips": ["127.0.0.1", "::1"]
           }
         }
       }
     }
   }
   ```

2. **Update gateway config** (`/etc/pyircx/webchat.conf`):
   ```ini
   [webirc]
   password = your-secure-password
   ```

3. **Restart services:**
   ```bash
   systemctl restart pyircx pyircx-webchat
   ```

### Content Security Policy

For production deployments, add CSP headers to restrict WebSocket connections:
```apache
Header set Content-Security-Policy "connect-src 'self' ws://yourdomain.com:8765 wss://yourdomain.com;"
```

## See Also

- [SELINUX.md](../docs/user/SELINUX.md) - SELinux configuration
- [CONFIG.md](../docs/user/CONFIG.md) - Server configuration
- [MANUAL.md](../docs/user/MANUAL.md) - User commands
