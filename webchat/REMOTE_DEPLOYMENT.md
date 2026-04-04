# Remote WebChat Deployment

Deploy WebChat on a separate web server from your IRC server for scalability, security, and performance.

## Architecture Overview

```
┌─────────────────────────┐
│   IRC Server            │
│   (irc.example.com)     │
│                         │
│   Port 6667 (IRC)       │ ← IRC traffic only
│   Port 6697 (IRC+SSL)   │
└─────────────────────────┘
           ↑
           │ TCP Connection
           │
┌──────────┴──────────────┐
│   Web Server            │
│   (web.example.com)     │
│                         │
│   - WebChat Frontend    │ ← Static HTML/JS/CSS
│   - gateway.py          │ ← WebSocket bridge
│   - Apache/nginx        │ ← Web server + SSL
│                         │
│   Port 80 (HTTP)        │
│   Port 443 (HTTPS)      │
│   Port 8765 (WS)        │
└─────────────────────────┘
```

## Benefits

✅ **Scalability** - Web server can scale independently
✅ **Security** - IRC server doesn't need to expose HTTP/HTTPS
✅ **Performance** - Separate resources for web traffic
✅ **CDN Ready** - Static files can use CDN
✅ **Load Balancing** - Multiple web servers to one IRC server
✅ **SSL Offloading** - SSL termination on web server

## Requirements

### On IRC Server (irc.example.com)
- pyIRCX running on port 6667 and/or 6697
- Firewall allowing inbound from web server IP
- **No web server needed**
- **No webadmin needed** (stays local-only)

### On Web Server (web.example.com)
- Apache or nginx
- Python 3.8+ with websockets library
- Network connectivity to IRC server
- SSL certificate (Let's Encrypt recommended)

## Installation Steps

### Step 1: Configure IRC Server

**Allow web server IP in firewall:**
```bash
# Replace 10.0.1.100 with your web server IP
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.1.100" port port="6667" protocol="tcp" accept'
firewall-cmd --reload
```

**Optional: Configure WEBIRC for real client IPs**

Edit `/etc/pyircx/pyircx_config.json`:
```json
{
  "security": {
    "webirc": {
      "enabled": true,
      "hosts": {
        "webchat-gateway": {
          "password": "secure-random-password-here",
          "allowed_ips": ["10.0.1.100"]
        }
      }
    }
  }
}
```

Restart IRC server:
```bash
systemctl restart pyircx
```

---

### Step 2: Install WebChat on Web Server

**Install dependencies:**
```bash
# Fedora/RHEL/Rocky
dnf install -y python3 python3-pip apache httpd mod_ssl

# Debian/Ubuntu
apt install -y python3 python3-pip apache2

# Install Python WebSocket library
pip3 install websockets
```

**Create directories:**
```bash
mkdir -p /var/www/html/webchat
mkdir -p /opt/pyircx/webchat
```

**Copy WebChat files:**

From the pyIRCX git repository on your local machine:
```bash
# Copy to web server (adjust paths as needed)
scp webchat/index.html root@web.example.com:/var/www/html/webchat/
scp webchat/config.js root@web.example.com:/var/www/html/webchat/
scp webchat/favicon.svg root@web.example.com:/var/www/html/webchat/
scp webchat/gateway.py root@web.example.com:/opt/pyircx/webchat/
```

---

### Step 3: Configure Gateway

**Create configuration file:**
```bash
mkdir -p /etc/pyircx
cat > /etc/pyircx/webchat.conf << 'EOF'
[websocket]
host = 0.0.0.0
port = 8765

[irc]
host = irc.example.com
port = 6667

[webirc]
password = secure-random-password-here
gateway = pyircx-webchat
trusted_proxies = 127.0.0.1/32, ::1/128
EOF

chmod 600 /etc/pyircx/webchat.conf
```

**Key settings:**
- `[websocket] host` - Bind address (0.0.0.0 for all interfaces)
- `[websocket] port` - WebSocket port (8765 default, or use 443 for WSS behind proxy)
- `[irc] host` - **Your IRC server hostname or IP** (NOT localhost!)
- `[irc] port` - IRC server port (6667 plain, 6697 SSL)
- `[webirc] password` - Must match password in IRC server config

---

### Step 4: Configure WebChat Frontend

Edit `/var/www/html/webchat/config.js`:

**For HTTPS with reverse proxy (recommended):**
```javascript
const WEBCHAT_CONFIG = {
    websocketUrl: null,              // Auto-detect: wss://web.example.com/ws
    websocketPort: 8765,
    websocketPath: '/ws',
    defaultChannel: '#pyIRCX',
    defaultNick: '',
    // ... other settings ...
};
```

**For HTTP direct WebSocket (testing only):**
```javascript
const WEBCHAT_CONFIG = {
    websocketUrl: 'ws://web.example.com:8765',  // Explicit URL
    // ... other settings ...
};
```

---

### Step 5: Create Systemd Service

**Create service file:**
```bash
cat > /etc/systemd/system/pyircx-webchat.service << 'EOF'
[Unit]
Description=pyIRCX WebChat Gateway
After=network.target

[Service]
Type=simple
User=pyircx
Group=pyircx
ExecStart=/usr/bin/python3 /opt/pyircx/webchat/gateway.py --config /etc/pyircx/webchat.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

**Create user:**
```bash
useradd -r -s /sbin/nologin pyircx
```

**Set permissions:**
```bash
chown -R apache:apache /var/www/html/webchat
chmod 755 /opt/pyircx/webchat/gateway.py
```

**Enable and start:**
```bash
systemctl daemon-reload
systemctl enable pyircx-webchat
systemctl start pyircx-webchat
systemctl status pyircx-webchat
```

---

### Step 6: Configure Apache (HTTPS + WebSocket Proxy)

**Install mod_ssl and enable modules:**
```bash
# Fedora/RHEL/Rocky
dnf install -y mod_ssl
systemctl enable httpd

# Debian/Ubuntu
a2enmod ssl proxy proxy_http proxy_wstunnel
```

**Create SSL virtual host:**
```bash
cat > /etc/httpd/conf.d/webchat-ssl.conf << 'EOF'
<VirtualHost *:443>
    ServerName web.example.com
    DocumentRoot /var/www/html/webchat

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/web.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/web.example.com/privkey.pem

    # WebSocket proxy
    ProxyPass /ws ws://localhost:8765/
    ProxyPassReverse /ws ws://localhost:8765/

    <Directory /var/www/html/webchat>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # Security headers
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName web.example.com
    Redirect permanent / https://web.example.com/
</VirtualHost>
EOF
```

**Get Let's Encrypt certificate:**
```bash
dnf install -y certbot
certbot certonly --standalone -d web.example.com
```

**Restart Apache:**
```bash
systemctl restart httpd
```

---

### Step 7: Configure Firewall (Web Server)

```bash
# Allow HTTP/HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Optional: Allow direct WebSocket (if not using reverse proxy)
firewall-cmd --permanent --add-port=8765/tcp

firewall-cmd --reload
```

---

## Testing

### Test Gateway Connection to IRC

```bash
# From web server, test IRC connectivity
telnet irc.example.com 6667

# Should connect and you can type:
# NICK testbot
# USER test test test :Test
```

### Test WebSocket Gateway

```bash
# Check gateway is running
systemctl status pyircx-webchat
journalctl -u pyircx-webchat -n 50

# Test WebSocket locally
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
     http://localhost:8765/
```

### Test WebChat in Browser

1. Open https://web.example.com/
2. Enter nickname and connect
3. Check browser developer console for errors
4. Should see "Connected to IRC" message

---

## Troubleshooting

### WebChat shows "Connecting..." forever

**Check gateway logs:**
```bash
journalctl -u pyircx-webchat -f
```

**Common issues:**
- IRC_HOST is wrong (still set to localhost?)
- Firewall blocking web server → IRC server
- IRC server not running
- Wrong IRC_PORT

### Gateway can't connect to IRC server

**Test from web server:**
```bash
telnet irc.example.com 6667
```

**If fails:**
- Check IRC server firewall
- Verify IRC server is running: `systemctl status pyircx`
- Check IRC server is listening: `ss -tlnp | grep 6667`

### SSL/WebSocket proxy not working

**Check Apache modules:**
```bash
# Fedora/RHEL
httpd -M | grep proxy
# Should show: proxy_module, proxy_http_module, proxy_wstunnel_module

# Debian/Ubuntu
apache2ctl -M | grep proxy
```

**Enable if missing:**
```bash
a2enmod proxy proxy_http proxy_wstunnel
systemctl restart apache2
```

### WEBIRC not working (wrong IPs shown)

**Check web server IP in IRC logs:**
```bash
# On IRC server
journalctl -u pyircx | grep WEBIRC
```

**Verify:**
- `[webirc] password` matches in both configs
- Web server IP is in allowed_ips list
- IRC server security.webirc.enabled is true

---

## Scaling & Load Balancing

### Multiple Web Servers

You can deploy multiple web servers pointing to the same IRC server:

```
              ┌─────────────────┐
              │   IRC Server    │
              │  (irc.example)  │
              └────────┬────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
   ┌───▼────┐     ┌───▼────┐     ┌───▼────┐
   │ Web 1  │     │ Web 2  │     │ Web 3  │
   │ US-East│     │ US-West│     │ Europe │
   └────────┘     └────────┘     └────────┘
```

**Each web server:**
- Runs its own gateway.py
- Has same IRC_HOST pointing to IRC server
- Can have different domain names

**Load balancer:**
```nginx
upstream webchat {
    server web1.example.com:443;
    server web2.example.com:443;
    server web3.example.com:443;
}

server {
    listen 443 ssl;
    server_name chat.example.com;

    location / {
        proxy_pass https://webchat;
    }
}
```

### CDN for Static Files

Since WebChat frontend is static HTML/JS:
```
CloudFlare CDN → /webchat/*.html, *.js, *.css
Direct → /ws (WebSocket, can't be cached)
```

---

## Security Best Practices

### 1. Restrict IRC Server Access

Only allow web server IPs to connect:
```bash
# On IRC server
firewall-cmd --permanent --remove-service=irc
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.1.100" port port="6667" protocol="tcp" accept'
```

### 2. Use Strong WEBIRC Password

Generate random password:
```bash
openssl rand -base64 32
```

### 3. Enable Rate Limiting

**On web server (Apache):**
```apache
<IfModule mod_ratelimit>
    <Location /ws>
        SetOutputFilter RATE_LIMIT
        SetEnv rate-limit 512
    </Location>
</IfModule>
```

### 4. Monitor Gateway

Set up monitoring for gateway process:
```bash
# Check if running
systemctl is-active pyircx-webchat

# Alert if down
```

---

## Maintenance

### Update WebChat Files

```bash
# On web server
cd /var/www/html/webchat
cp index.html index.html.backup
# Copy new version
systemctl restart httpd
```

### Update Gateway

```bash
# On web server
systemctl stop pyircx-webchat
cp gateway.py /opt/pyircx/webchat/
systemctl start pyircx-webchat
```

### Change IRC Server

Edit `/etc/pyircx/webchat.conf`:
```bash
IRC_HOST=new-irc.example.com
```

Restart gateway:
```bash
systemctl restart pyircx-webchat
```

---

## See Also

- [README.md](README.md) - Local WebChat deployment
- [../docs/user/SELINUX.md](../docs/user/SELINUX.md) - SELinux configuration
- [../apache/](../apache/) - Apache configuration examples
