# pyIRCX

**A production-ready Python implementation of the IRCX protocol — the modern IRCX server for distributed chat networks**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.0-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/tests-243%20passing-brightgreen.svg)](#testing)

---

## What is pyIRCX?

pyIRCX is a **production-ready IRCX chat server** built on Python's asyncio framework. It faithfully recreates — and significantly enhances — the functionality of **Microsoft Exchange Chat Service** (MECS 5.5 and 6.0), the technology that powered legendary chat networks like:

- **MSN Chat** (irc.msn.com) — Microsoft's flagship chat service, serving millions daily from 1996-2006
- **TalkCity** (chat.talkcity.com) — One of the largest chat communities of the late 90s, pioneering web-based chat
- **Enterprise Exchange Chat** — Corporate deployments before Slack and Teams existed

If you remember the days of **Microsoft Comic Chat**, chat rooms with real nickserv-style registration, channel properties, and the unique IRCX extensions — pyIRCX brings all of that back with modern security, scalability, and reliability.

> **Comic Chat Compatible!** pyIRCX works with Microsoft Comic Chat (V2.5), the iconic IRC client that displayed conversations as comic strips. Run it natively or in a VM - pyIRCX speaks the same IRCX protocol.

> **Active Development:** pyIRCX is under active development with frequent updates, enhancements, and bug fixes. New features, security improvements, and performance optimizations are released regularly. See [CHANGELOG.md](CHANGELOG.md) for detailed release notes and version history.

**Current Version:** 1.3.0-dev (seamless cross-server operations)

**Latest Releases:**
- **v1.3.0-dev** (January 17, 2026) - 🎉 **Seamless Cross-Server Operations**: Complete Phase 2 implementation with network-wide TOPIC, KICK, MODE, INVITE, NICK, AWAY, WHISPER, KNOCK propagation. Channel modes, ban lists, and access controls synchronize across all linked servers. All 12 Phase 2 tests passing! Network behaves as unified system. See [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md)
- **v1.3.0-dev** (January 16, 2026) - 🎉 **Centralized Services with Trunk/Branch Topology**: Distributed network architecture with centralized services and staff authentication. Trunk servers host services (Registrar, Messenger, etc.), branch servers route requests to trunk. Phase 1 complete (4/4 tests passing)! See [TRUNK_BRANCH_PROGRESS.md](TRUNK_BRANCH_PROGRESS.md) and [SERVICES_TRUNK_IMPLEMENTATION.md](SERVICES_TRUNK_IMPLEMENTATION.md)
- **v1.2.0** (January 16, 2026) - User experience polish: Enhanced help system, command aliases, improved message quality, STATS/STAFF formatting, configurable client timeout, comprehensive webadmin tooltips
- **v1.1.9** (January 16, 2026) - Traditional IRC service aliases (NickServ/ChanServ/MemoServ)
- **v1.1.8** (January 16, 2026) - Comprehensive documentation reorganization, Apache/httpd multi-distro setup
- **v1.1.7** (January 16, 2026) - WebChat configuration system, SELinux hardening, MOTD editor fixes

For complete version history, see [CHANGELOG.md](CHANGELOG.md)

---

## Use Cases

### Distributed Chat Networks
Build multi-server IRC networks spanning geographic regions:
- Link servers in different cities/countries for low latency
- Scale horizontally by adding more servers
- Provide redundancy with multiple hubs
- Manage the network with standard IRC server commands

### Community Chat Networks
Build your own chat community with MSN Chat-style features including channel cloning for busy rooms, nickname registration, channel ownership, and automated moderation tools.

### Retro Computing & Preservation
pyIRCX provides protocol-correct IRCX for historical accuracy and works with period-accurate clients:
- **Microsoft Comic Chat** (cchat.exe) - The comic strip chat client
- **Microsoft Chat 2.5** - The standard IRCX client
- **mIRC with IRCX scripts** - Extended functionality
- **Any RFC 1459/2812 client** - Full backwards compatibility

### Enterprise & Team Communication
Self-hosted team chat with corporate-grade features:
- Staff hierarchy (ADMIN/SYSOP/GUIDE)
- Channel access control (ACCESS lists)
- Audit logging (transcripts)
- No external dependencies or subscriptions
- Multi-server deployment for large organizations

### Gaming Communities
Dedicated chat infrastructure for game servers, guilds, and gaming communities:
- ServiceBot automated moderation
- Flood protection and spam filtering
- Channel properties for rules/info
- Distributed network for global player base

### Education & Research
Study the IRCX protocol, teach network programming, or research distributed chat system architecture with a well-documented, readable Python implementation.

---

## Why pyIRCX?

### The Only Open-Source IRCX Server with Server Linking

pyIRCX offers feature parity with commercial IRCX servers like [OfficeIRC](https://www.officeirc.com/), but as **open-source software** you can deploy anywhere. While OfficeIRC supports both IRCX and server linking, it's commercial/closed-source. UnrealIRCd and other major IRC servers support linking but lack IRCX protocol extensions.

**pyIRCX is the only open-source server combining full IRCX protocol support with server-to-server linking capabilities.**

*See detailed feature comparison below.*

---

## Features

### 🌐 Server Linking & Distributed Networks (NEW!)

Build IRC networks that scale with **trunk-and-branch topology** and **seamless cross-server operations**:

#### Network Architecture
- **Centralized Services** — Trunk servers host services (Registrar, Messenger, ServiceBots)
- **Branch Routing** — Branch servers automatically route service requests to trunk
- **Staff Authentication** — Centralized staff credentials on trunk with branch routing
- **Server-to-Server Protocol** — Custom IRCX-aware linking protocol with role validation
- **Authentication** — Password-protected server links with bcrypt support
- **State Burst** — Full user/channel synchronization on link, including service users
- **Role Validation** — Enforces flat topology (trunk↔branch only, prevents multi-tier)
- **Netsplit Handling** — Automatic cleanup and recovery
- **Collision Detection** — Timestamp-based nick collision resolution

#### Seamless Cross-Server Operations (Phase 2) 🎉
Network-wide command propagation makes linked servers behave as a unified system:

**Channel Operations:**
- **TOPIC** — Topic changes propagate to all servers instantly
- **KICK** — Kicks remove users network-wide
- **MODE** — Channel modes (+t/+m/+n/+i/+s/+k/+l/+b/+o/+v/+q) sync across network
- **INVITE** — Invites route to users on any server
- **ACCESS/PROP** — IRCX access lists and properties stay synchronized

**User Operations:**
- **NICK** — Nickname changes update across all servers
- **AWAY** — Away status syncs network-wide
- **MODE** — User modes (+i invisible) propagate
- **KILL** — Network operators can terminate connections globally
- **WHISPER** — IRCX whisper messages route to remote users

**Network Queries:**
- **WHO/NAMES** — Show all users in channels (local + remote)
- **WHOIS** — Query users on any linked server
- **MAP** — Visual network topology tree
- **LUSERS** — Network-wide user statistics

**Advanced:**
- **KNOCK** — Channel knock requests reach remote channel owners/hosts
- **Ban Lists** — +b mode ban masks synchronize across servers
- **Channel Keys** — +k mode keys sync to all servers
- **User Limits** — +l mode limits propagate network-wide

#### Admin Commands
- `CONNECT <server>` — Link to a remote server
- `SQUIT <server>` — Disconnect a linked server
- `LINKS` — Show network topology
- `MAP` — Visual tree display of network

**Example Trunk/Branch Topology:**
```
        ┌──────────────────────┐
        │   Trunk Server       │
        │  (Services Hub)      │
        │  - Registrar         │
        │  - Messenger         │
        │  - Staff Auth        │
        └──────────┬───────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
   ┌───▼────┐  ┌──▼─────┐  ┌──▼─────┐
   │Branch1 │  │Branch2 │  │Branch3 │
   │US-East │  │US-West │  │Europe  │
   └────────┘  └────────┘  └────────┘
```

**🎉 All automated tests passing!** See [TRUNK_BRANCH_PROGRESS.md](TRUNK_BRANCH_PROGRESS.md) for implementation details.

### IRCX Protocol Extensions

pyIRCX implements the full IRCX specification developed by Microsoft:

- **Three-tier channel privileges**: Owner (.), Host (@), Voice (+)
- **ACCESS command**: Granular access control lists (DENY, GRANT, VOICE, HOST, OWNER)
- **PROP command**: Channel properties (TOPIC, ONJOIN, ONPART, MEMBERKEY, HOSTKEY, OWNERKEY, LAG)
- **WHISPER command**: Private messages within channels
- **LISTX command**: Extended channel listing with metadata
- **KNOCK command**: Request invitation to invite-only channels
- **CREATE command**: Create channels with initial modes
- **ISIRCX command**: Protocol capability detection

### Channel Cloning (Overflow Rooms)

Just like the original MSN Chat, pyIRCX supports **automatic channel cloning**:

```
#Lobby (50 users, +dl 50)  →  #Lobby1 (50 users)  →  #Lobby2 (37 users)
```

When a channel with clone mode (+d) reaches its user limit (+l), new joiners automatically get placed in numbered overflow channels. Mode changes on the original propagate to all clones.

### Security & Authentication

- **SASL PLAIN authentication** with IRCv3 capability negotiation
- **Nickname registration** with email verification
- **Two-factor authentication** support
- **DNSBL checking** (Spamhaus, DroneBL, etc.)
- **Open proxy detection**
- **Connection throttling** and flood protection
- **Failed auth lockout** with configurable thresholds
- **TLS 1.2/1.3** with automatic certificate management
- **IP masking** (+x user mode)

### Network Services

Built-in service bots that can be invited to channels for moderation:

- **System** — Server announcements and administrative messages
- **Registrar** — Handles nickname registration and authentication
- **Messenger** — Offline messaging / memo service
- **NewsFlash** — Network-wide announcements
- **ServiceBots** — Configurable monitoring bots for content filtering

### Staff Management

Three-tier staff hierarchy matching the original MECS design:

| Level | Mode | Capabilities |
|-------|------|--------------|
| **ADMIN** | +a | Full server control, CONFIG access, can promote SYSOPs, **can link servers** |
| **SYSOP** | +o | Server operator, can KILL/KLINE, promote GUIDEs, **can link servers** |
| **GUIDE** | +g | Channel moderation assistance, limited staff commands |

### Modern Infrastructure

- **Pure Python 3.8+** with asyncio for high concurrency
- **SQLite database** with connection pooling for persistence
- **Dual-stack IPv4/IPv6** support out of the box
- **Systemd integration** for production deployments
- **Hot-reloadable configuration**
- **Comprehensive logging** with configurable verbosity
- **Web Administration Panel** with PHP/Apache (optional)

---

## Technical Deep Dive

### Async Architecture

pyIRCX is built from the ground up on Python's `asyncio` framework, enabling efficient handling of thousands of concurrent connections without threading overhead:

```python
# Non-blocking I/O for all client operations
async def handle_client(self, reader, writer):
    # Each client runs in its own coroutine
    # No thread pools, no blocking, pure async
```

- **Event-driven command dispatch** — Commands are processed asynchronously with per-command rate limiting
- **Coroutine-per-client model** — Each connection is an independent async task
- **Non-blocking database operations** — All SQLite queries use `aiosqlite` for async I/O
- **Server linking** — Async server-to-server communication with message routing

### Server Linking Architecture

The linking system enables distributed IRC networks:

```
┌─────────────────────────────────────────────────────────────┐
│  Server Linking Protocol                                     │
├─────────────────────────────────────────────────────────────┤
│  1. Handshake          — SERVER command with authentication  │
│  2. State Burst        — Sync all users and channels         │
│  3. Message Routing    — Propagate messages across network   │
│  4. Collision Handling — Timestamp-based nick resolution     │
│  5. Netsplit Recovery  — Automatic cleanup and rejoins       │
└─────────────────────────────────────────────────────────────┘
```

**Protocol Features:**
- Password-authenticated server connections
- Full state synchronization on link establishment
- Efficient message routing with loop prevention
- Automatic netsplit detection and cleanup
- Nick/channel timestamp collision resolution

### Database Layer

Persistent storage with enterprise-grade reliability:

- **Connection pooling** — Configurable pool size (default: 5 connections) eliminates connection overhead
- **Automatic schema migration** — Database structure updates seamlessly between versions
- **Atomic transactions** — All multi-step operations are transaction-safe
- **Stored data includes:**
  - Registered nicknames with bcrypt-hashed passwords
  - Channel registrations with ACCESS lists and PROPs
  - Offline messages (memos) with expiration
  - Staff credentials and privilege levels
  - Server access rules (bans) with expiration timestamps

### Multi-Layer Security

pyIRCX implements defense-in-depth with multiple security layers:

#### Connection Security
```
┌─────────────────────────────────────────────────────────────┐
│  Incoming Connection                                         │
├─────────────────────────────────────────────────────────────┤
│  1. Connection Throttle    — Max N connections/IP/window     │
│  2. DNSBL Check            — Query Spamhaus, DroneBL, etc.   │
│  3. Proxy Detection        — Scan for open proxy ports       │
│  4. Connection Scoring     — Aggregate risk score            │
│  5. TLS Handshake          — TLS 1.2/1.3 with modern ciphers │
│  6. Rate Limiting          — Per-command cooldowns           │
│  7. Flood Protection       — Message frequency limits        │
└─────────────────────────────────────────────────────────────┘
```

#### DNSBL Integration
- **IPv4 and IPv6 support** — Full nibble-reversed IPv6 DNSBL queries
- **Multiple blocklist support** — Configure any DNSBL (Spamhaus ZEN, DroneBL, etc.)
- **Whitelist bypass** — Exempt trusted IPs/ranges from checks
- **Async DNS resolution** — Non-blocking blocklist queries

#### Authentication Security
- **bcrypt password hashing** — Industry-standard password storage
- **Failed attempt lockout** — Configurable threshold and duration
- **SASL PLAIN over TLS** — Secure credential transmission
- **MFA support** — Two-factor authentication via verification codes

### Performance Characteristics

| Metric | Value |
|--------|-------|
| Concurrent connections | 1,000+ per server |
| Network scalability | Unlimited (add more servers) |
| Message throughput | Limited by network I/O |
| Memory per connection | ~50KB typical |
| Database operations | Pooled, non-blocking |
| Server link latency | <10ms (LAN), varies (WAN) |
| Startup time | <1 second |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX

# Automated installation (recommended)
sudo ./install.sh

# OR manual installation
pip install aiosqlite bcrypt pyotp cryptography
python3 pyircx.py
```

The server will start listening on ports **6667** (plain) and **7000** (alternative) by default.

### Upgrading

```bash
# Pull latest changes
cd pyIRCX
git pull

# Upgrade existing installation
sudo ./upgrade.sh
```

### Maintenance

```bash
# Validate and repair installation
sudo ./repair.sh

# Uninstall completely
sudo ./uninstall.sh
```

### Basic Configuration

Edit `pyircx_config.json` to customize your server:

```json
{
  "server": {
    "name": "irc.example.com",
    "network": "MyNetwork"
  },
  "network": {
    "listen_ports": [6667, 7000]
  }
}
```

### Setting Up Server Linking

To create a multi-server network:

**1. Configure the hub server** (`hub.example.com`):
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

**2. Configure leaf servers** similarly with hub details

**3. Link servers** as an admin:
```
/STAFF LOGIN <username> <password>
/CONNECT <servername>
/LINKS
```

See [LINKING.md](docs/user/LINKING.md) for complete server linking documentation.

### SSL/TLS Setup (Recommended)

**Quick automated setup:**
```bash
sudo ./setup_ssl.sh
```

Choose from:
- **Let's Encrypt** - Free, trusted certificates with auto-renewal
- **Self-signed** - For testing/internal use
- **Existing certificate** - Use your own certificate files

The script automatically:
- Obtains and installs certificates
- Configures pyIRCX
- Sets up auto-renewal (Let's Encrypt)
- Restarts the server

### WebChat Browser Client

Access pyIRCX from any web browser:

```bash
# During install.sh, answer "y" to install WebChat
# Or install manually:
sudo cp -r webchat /opt/pyircx/
sudo cp pyircx-webchat.service /etc/systemd/system/
sudo cp webchat.conf.example /etc/pyircx/webchat.conf
sudo systemctl enable --now pyircx-webchat
```

**Configuration** (`/etc/pyircx/webchat.conf`):
```bash
WS_HOST=0.0.0.0
WS_PORT=8765
IRC_HOST=127.0.0.1
IRC_PORT=6667
WEBIRC_PASS=changeme  # Change this!
```

**Apache HTTPS Proxy** (for wss://):
```bash
sudo cp apache/ssl-webchat.conf.example /etc/httpd/conf.d/ssl-webchat.conf
# Edit with your domain, then restart Apache
```

Access at `https://yourserver/` after setup.

### Connecting

Connect with any IRC client:

```
# Plain connection
/server localhost 6667

# SSL/TLS connection (after setup)
/server localhost 6697
```

For IRCX features, use the IRCX command after connecting:

```
/QUOTE IRCX
```

---

## Documentation

- **[LINKING.md](docs/user/LINKING.md)** — Server linking protocol and setup
- **[CONFIG.md](docs/user/CONFIG.md)** — Full configuration reference
- **[MANUAL.md](docs/user/MANUAL.md)** — User and operator command guide
- **[SELINUX.md](docs/user/SELINUX.md)** — SELinux configuration and troubleshooting
- **[STAFF_ACCOUNT_REFERENCE.md](docs/user/STAFF_ACCOUNT_REFERENCE.md)** — Quick reference for staff commands
- **[TESTING.md](docs/testing/TESTING.md)** — Comprehensive testing guide (243 tests)
- **[PERFORMANCE.md](docs/performance/PERFORMANCE.md)** — Performance tuning and optimization

---

## Testing

pyIRCX includes comprehensive test suites to ensure protocol compliance:

```bash
# Run all test suites (recommended)
./run_tests.sh

# Or run individual test suites
cd testing
python3 users.py        # 115 IRC/IRCX protocol tests
python3 commands.py     # 28 core command tests
python3 staff.py        # 39 staff authentication tests
python3 links.py        # 4 server linking tests
python3 access.py       # 10 access control tests
python3 stats.py        # 16 STATS system tests
python3 help.py         # 15 HELP system tests
python3 services.py     # 13 service improvements tests
```

**Test Coverage:**
- ✅ **115 IRC/IRCX Protocol Tests** — Core IRC/IRCX protocol features
- ✅ **28 Core Command Tests** — JOIN/PART/QUIT/MODE/TOPIC/KICK/etc.
- ✅ **39 Staff Authentication Tests** — ADMIN/SYSOP/GUIDE authentication
- ✅ **4 Server Linking Tests** — Server-to-server linking
- ✅ **10 Access Control Tests** — Channel and server ACCESS lists
- ✅ **16 STATS System Tests** — All STATS flags and features
- ✅ **15 HELP System Tests** — HELP topics and permissions
- ✅ **13 Service Tests** — ServiceBot, Registrar, Messenger, NewsFlash
- **Total: 243 tests across 8 suites, 100% passing**

**Automated Logging:**
- Test reports saved as `testing/logs/test_run_<epoch>.md`
- Latest report symlinked to `testing/logs/latest.md`
- Full test output captured for failure diagnosis

See [TESTING.md](docs/testing/TESTING.md) for detailed test harness documentation and [TESTHARNESS.md](docs/testing/TESTHARNESS.md) for test harness implementation details.

---

## Deployment

### Systemd Service

pyIRCX includes systemd integration for production deployment:

```bash
# Install as a system service
sudo cp pyircx.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pyircx
sudo systemctl start pyircx

# View logs
sudo journalctl -u pyircx -f
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install aiosqlite bcrypt pyotp
CMD ["python3", "pyircx.py"]
```

### Web Administration Panel

Optional browser-based administration interface (v1.1.0+):

```bash
# Install during setup (recommended)
sudo ./install.sh
# Choose "yes" when prompted for Web Administration Panel

# Or install manually
sudo dnf install httpd php php-fpm  # Fedora/RHEL
# sudo apt install apache2 php        # Debian/Ubuntu

# Install web admin files
sudo cp -r webadmin/ /var/www/html/webadmin/
sudo chown -R apache:apache /var/www/html/webadmin/

# Install SELinux policies (Fedora/RHEL/CentOS)
cd selinux/
sudo checkmodule -M -m -o pyircx-httpd-systemd.mod pyircx-httpd-systemd.te
sudo semodule_package -o pyircx-httpd-systemd.pp -m pyircx-httpd-systemd.mod
sudo semodule -i pyircx-httpd-systemd.pp
# Repeat for pyircx-httpd-journal-v3.te

# Install polkit rules (for service control)
sudo cp polkit/10-pyircx-admin.rules /etc/polkit-1/rules.d/
sudo chmod 644 /etc/polkit-1/rules.d/10-pyircx-admin.rules

# Add apache to systemd-journal group (for log viewing)
sudo usermod -a -G systemd-journal apache

# Access at http://yourserver/webadmin/
```

The web admin provides:
- **Service Control** — Start/stop/restart pyircx service (via polkit)
- **Real-time Log Viewer** — View server logs from journalctl
- **User Management** — List, search, and paginate registered users
- **Channel Management** — Monitor active channels and modes
- **Staff Administration** — Create/edit/delete ADMIN/SYSOP/GUIDE accounts
- **Access Control** — Manage channel access rules with expiration
- **Mailbox System** — Send messages to user mailboxes
- **Database Viewer** — Inspect database tables
- **Session Authentication** — Login with IRC staff accounts (administrators only)

**Security Features:**
- Session-based authentication (PHP sessions + bcrypt)
- Polkit authorization for service control (no sudo required)
- SELinux policies for production deployments
- Apache user isolation (unprivileged)
- Audit logging via polkit and systemd

See `webadmin/README.md` and `webadmin/INSTALL.md` for detailed setup instructions.

---

## Historical Context

### The IRCX Legacy

IRCX (Internet Relay Chat eXtensions) was developed by Microsoft in the late 1990s as an enhancement to the standard IRC protocol. It was first implemented in **Microsoft Exchange Server 5.5** as the Chat Service component, replacing the older binary Microsoft Chat protocol.

The protocol powered some of the largest chat networks of the era:

- **MSN Chat** served millions of users daily at its peak
- **TalkCity** was one of the pioneering web chat communities
- Countless enterprise deployments for internal communications

When TalkCity [ceased its original operations in 2002](https://en.wikipedia.org/wiki/Talkcity.com) and Microsoft [shut down MSN Chat in 2006](https://en.wikipedia.org/wiki/MSN_Chat), the IRCX protocol largely faded from public use — but not from memory.

### Preserving Chat History

pyIRCX was created to preserve this important piece of internet history. Whether you're:

- **Nostalgic** for the TalkCity or MSN Chat era
- Running a **retro computing** project
- Need a **fully-featured IRC server** with modern enhancements
- Want to understand how **enterprise chat worked** before Slack
- Building a **distributed IRC network**

pyIRCX provides an authentic IRCX experience on modern infrastructure.

---

## Comparison with Other Servers

Comprehensive comparison of pyIRCX with major IRC server implementations:

| Feature/Server | **pyIRCX** | OfficeIRC | UnrealIRCd | InspIRCd | Solanum | ircu | bahamut | ratbox | ngIRCd | Ergo | ircd-hybrid |
|----------------|:----------:|:---------:|:----------:|:--------:|:-------:|:----:|:-------:|:------:|:------:|:----:|:-----------:|
| **Language** | Python | .NET | C | C++ | C | C | C | C | C | Go | C |
| **IRCX Protocol** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Server Linking** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **ACCESS Control** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **PROP Properties** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Channel Cloning** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Comic Chat** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Built-in NickServ** | ✅ | ✅ | ❌* | ❌* | ❌* | ❌* | ❌* | ❌* | ❌* | ✅ | ❌* |
| **Built-in ChanServ** | ✅ | ✅ | ❌* | ❌* | ❌* | ❌* | ❌* | ❌* | ❌* | ✅ | ❌* |
| **Network Services** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **SASL Auth** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **IPv6 Support** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Transcript Logging** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Single-File Deploy** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Web Admin** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Open Source** | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Cost** | Free | Commercial | Free | Free | Free | Free | Free | Free | Free | Free | Free |

*\* Requires external services package (Anope or Atheme)*

**Network Associations:**
- **Solanum** - Libera.Chat
- **ircu** - Undernet (P10 protocol)
- **bahamut** - DALnet
- **ratbox** - EFnet (TS6 protocol)
- **ircd-hybrid** - EFnet
- **ngIRCd** - Lightweight/portable

**pyIRCX is the only open-source server combining full IRCX protocol support with server-to-server linking capabilities.**

---

## Production Deployments

pyIRCX is production-ready and suitable for:

✅ **Small Communities** (10-100 users) — Single server deployment

✅ **Medium Networks** (100-1,000 users) — 2-3 linked servers

✅ **Large Networks** (1,000+ users) — Multi-server distributed network

✅ **Enterprise Deployments** — Secure internal chat with staff hierarchy

✅ **Retro Projects** — Authentic IRCX for vintage client compatibility

### Who Should Use pyIRCX?

pyIRCX is ideal for:

- **Retro computing enthusiasts** preserving IRCX protocol history
- **Gaming communities** needing dedicated chat infrastructure
- **Organizations** wanting self-hosted team communication
- **IRC network operators** building distributed chat networks
- **Researchers** studying IRCX protocol implementation

*Using pyIRCX in production? Let us know via GitHub issues!*

---

## Contributing

Contributions are welcome! Whether it's:

- Bug fixes
- New features
- Documentation improvements
- Test cases
- Protocol compliance improvements

Please open an issue or pull request on GitHub.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX

# Install dev dependencies
pip install aiosqlite bcrypt pyotp

# Run tests
python3 pyIRCX_test_users.py
python3 pyIRCX_test_linking.py

# Check code
python3 -m py_compile pyircx.py linking.py
```

---

## License

GNU General Public License v3.0 — See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- The Microsoft Exchange Chat team for creating IRCX
- The TalkCity community for years of memories
- The IRC protocol designers (RFC 1459, RFC 2812)
- Everyone keeping classic chat protocols alive
- All contributors to this project

---

## Support

- **Documentation**: See docs in this repository
- **Issues**: [GitHub Issues](https://github.com/AI3I/pyIRCX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AI3I/pyIRCX/discussions)

---

## Keywords

*For searchability: IRC server, IRCX server, IRCX protocol, Microsoft Exchange Chat, MECS, MSN Chat server, MSN Chat clone, TalkCity, Comic Chat server, Microsoft Comic Chat, chat server Python, asyncio IRC, self-hosted chat, open source IRC server, IRC with registration, NickServ alternative, ChanServ alternative, SASL IRC, channel cloning, overflow rooms, IRC flood protection, DNSBL IRC, IRC access control, enterprise chat server, team chat self-hosted, Slack alternative self-hosted, Discord alternative self-hosted, retro chat, vintage IRC, 90s chat, web chat server, IRC network, server linking, distributed IRC, IRC hub, IRC services, UnrealIRCd alternative, InspIRCd alternative*

---

<p align="center">
  <i>Bringing back the chat rooms of yesterday, with the technology of today.</i>
  <br><br>
  <b>pyIRCX 1.2.0</b> — The production-ready IRCX server for distributed networks
  <br><br>
  ⭐ <b>Star this project on GitHub if you find it useful!</b> ⭐
</p>
