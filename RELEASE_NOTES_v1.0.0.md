# pyIRCX v1.0.0 - Production Release

**A production-ready Python implementation of the IRCX protocol with distributed server linking**

---

## What's New in v1.0.0

### Server-to-Server Linking

pyIRCX now supports **distributed chat networks** with server-to-server linking, enabling you to build multi-server IRC networks similar to traditional networks (EFnet, DALnet, Freenode).

**Key Features:**

- **Server linking protocol** with password authentication
- **State synchronization** - users and channels sync across servers
- **Message routing** - seamless communication across the network
- **Netsplit handling** - graceful recovery from server disconnections
- **Admin commands** - CONNECT, SQUIT, LINKS for network management
- **Collision detection** - timestamp-based nick collision resolution

**Example Network Topology:**

```
         hub.example.com (Central Hub)
                 |
    +------------+------------+
    |            |            |
  leaf1      leaf2        leaf3
(US-East)  (US-West)    (Europe)
```

This makes pyIRCX suitable for large-scale deployments across multiple data centers or geographic regions.

---

## Features

### IRCX Protocol Extensions

Full implementation of Microsoft's IRCX specification:

- **Three-tier channel privileges**: Owner (.), Host (@), Voice (+)
- **ACCESS command**: Granular access control lists
- **PROP command**: Channel properties
- **WHISPER command**: Private messages within channels
- **LISTX command**: Extended channel listing
- **KNOCK command**: Request invitation to invite-only channels
- **CREATE command**: Create channels with initial modes
- **ISIRCX command**: Protocol capability detection

### Channel Cloning (Overflow Rooms)

Automatic channel cloning just like MSN Chat:

```
#Lobby (50 users, +dl 50)  →  #Lobby1 (50 users)  →  #Lobby2 (37 users)
```

When a channel reaches its user limit, new joiners automatically get placed in numbered overflow channels.

### Security & Authentication

- **SASL PLAIN authentication** with IRCv3 capability negotiation
- **Nickname registration** with email verification
- **Two-factor authentication** support
- **DNSBL checking** (Spamhaus, DroneBL, etc.)
- **Open proxy detection**
- **Connection throttling** and flood protection
- **TLS 1.2/1.3** with automatic certificate management
- **IP masking** (+x user mode)

### ServiceBot System

Built-in service bots for moderation:

- **System** - Server announcements
- **Registrar** - Nickname registration
- **Messenger** - Offline messaging
- **NewsFlash** - Network-wide announcements
- **ServiceBot1-10** - Configurable monitoring bots

### Staff Management

Three-tier staff hierarchy:

| Level | Mode | Capabilities |
|-------|------|--------------|
| **ADMIN** | +a | Full server control, CONFIG access, can link servers |
| **SYSOP** | +o | Server operator, can KILL/KLINE, can link servers |
| **GUIDE** | +g | Channel moderation assistance |

### Modern Infrastructure

- **Pure Python 3.8+** with asyncio for high concurrency
- **SQLite database** with connection pooling
- **Dual-stack IPv4/IPv6** support
- **Systemd integration** for production deployments
- **Hot-reloadable configuration**
- **Comprehensive logging**
- **Web admin panel** via Cockpit integration (optional)

---

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX

# Install dependencies
pip install aiosqlite bcrypt pyotp cryptography

# Run the server
python3 pyircx.py
```

### Automated Installation

```bash
# Run the installer (supports most Linux distributions)
sudo ./install.sh
```

The installer now supports:
- Debian/Ubuntu and derivatives (Linux Mint, Pop!_OS, Elementary, etc.)
- RHEL/CentOS/Fedora/Rocky/AlmaLinux
- Arch Linux and derivatives (Manjaro, EndeavourOS, Garuda)
- openSUSE/SLES
- Gentoo/Funtoo
- Void Linux
- Alpine Linux
- Solus
- And many more!

### SSL/TLS Setup

```bash
# Automated SSL certificate setup
sudo ./setup_ssl.sh
```

Choose from:
- **Let's Encrypt** - Free, trusted certificates with auto-renewal
- **Self-signed** - For testing/internal use
- **Existing certificate** - Use your own certificate files

---

## Quick Configuration

Edit `pyircx_config.json`:

```json
{
  "server": {
    "name": "irc.example.com",
    "network": "MyNetwork"
  },
  "network": {
    "listen_ports": [6667, 7000]
  },
  "ssl": {
    "enabled": true,
    "port": 6697
  }
}
```

### Server Linking Configuration

To create a multi-server network:

```json
{
  "linking": {
    "enabled": true,
    "bind_host": "0.0.0.0",
    "bind_port": 7001,
    "links": [
      {
        "name": "leaf.example.com",
        "host": "leaf.example.com",
        "port": 7001,
        "password": "secure-link-password",
        "autoconnect": false
      }
    ]
  }
}
```

Link servers as an admin:

```
/STAFF LOGIN <username> <password>
/CONNECT <servername>
/LINKS
```

See [LINKING.md](LINKING.md) for complete documentation.

---

## Testing

pyIRCX includes comprehensive test suites:

```bash
# Automated test runner
./run_tests.sh
```

**Test Coverage:**
- ✅ **50 User/IRC Tests** - All IRC/IRCX protocol features
- ✅ **4 Linking Tests** - Server linking functionality
- **Total: 54 tests, 100% passing**

---

## Deployment

### Systemd Service

```bash
# Enable and start
sudo systemctl enable pyircx
sudo systemctl start pyircx

# View logs
sudo journalctl -u pyircx -f
```

### Docker

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install aiosqlite bcrypt pyotp cryptography
CMD ["python3", "pyircx.py"]
```

### Web Admin Panel (Optional)

```bash
# Install Cockpit module
sudo ./install.sh
# Select "Yes" when prompted for Cockpit

# Access at https://yourserver:9090
```

---

## Why pyIRCX?

### The Only Open-Source IRCX Server with Server Linking

| Feature | pyIRCX | OfficeIRC | UnrealIRCd |
|---------|:------:|:---------:|:----------:|
| Full IRCX Protocol | ✅ | ✅ | ❌ |
| Server-to-Server Linking | ✅ | ❌ | ✅ |
| Distributed Networks | ✅ | ❌ | ✅ |
| Channel Clone Mode | ✅ | ✅ | ❌ |
| Built-in NickServ/ChanServ | ✅ | ✅ | ❌* |
| Open Source | ✅ | ❌ | ✅ |
| No Licensing Fees | ✅ | ❌ | ✅ |

*UnrealIRCd requires Anope or Atheme services*

---

## Documentation

- **[README.md](README.md)** - Full documentation
- **[LINKING.md](LINKING.md)** - Server linking guide
- **[CONFIG.md](CONFIG.md)** - Configuration reference
- **[MANUAL.md](MANUAL.md)** - User and operator commands
- **[TEST_RESULTS.md](TEST_RESULTS.md)** - Test suite results

---

## Use Cases

✅ **Small Communities** (10-100 users) - Single server deployment
✅ **Medium Networks** (100-1,000 users) - 2-3 linked servers
✅ **Large Networks** (1,000+ users) - Multi-server distributed network
✅ **Enterprise Deployments** - Secure internal chat with staff hierarchy
✅ **Retro Projects** - Authentic IRCX for Microsoft Comic Chat and vintage clients

---

## Breaking Changes

This is the first production release - no breaking changes from previous versions.

---

## Upgrade Notes

If upgrading from a pre-1.0 version:

1. Backup your database: `cp pyircx.db pyircx.db.backup`
2. Update configuration file if needed
3. The database will auto-migrate on startup
4. Review new linking configuration options

---

## Known Issues

None at this time. Report issues at: https://github.com/AI3I/pyIRCX/issues

---

## Contributors

Thanks to all contributors who helped make this release possible!

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Links

- **GitHub Repository**: https://github.com/AI3I/pyIRCX
- **Documentation**: See repository docs
- **Issues**: https://github.com/AI3I/pyIRCX/issues
- **Discussions**: https://github.com/AI3I/pyIRCX/discussions

---

⭐ **Star this project on GitHub if you find it useful!** ⭐

---

**pyIRCX 1.0.0** - Bringing back the chat rooms of yesterday, with the technology of today.
