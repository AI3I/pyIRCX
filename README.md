# pyIRCX

**A production-ready Python implementation of the IRCX protocol — the modern IRCX server for distributed chat networks**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/tests-54%20passing-brightgreen.svg)](#testing)

---

## What is pyIRCX?

pyIRCX is a **production-ready IRCX chat server** built on Python's asyncio framework. It faithfully recreates — and significantly enhances — the functionality of **Microsoft Exchange Chat Service** (MECS 5.5 and 6.0), the technology that powered legendary chat networks like:

- **MSN Chat** (irc.msn.com) — Microsoft's flagship chat service, serving millions daily from 1996-2006
- **TalkCity** — One of the largest chat communities of the late 90s, pioneering web-based chat
- **Enterprise Exchange Chat** — Corporate deployments before Slack and Teams existed

If you remember the days of **Microsoft Comic Chat**, chat rooms with real nickserv-style registration, channel properties, and the unique IRCX extensions — pyIRCX brings all of that back with modern security, scalability, and reliability.

> **Comic Chat Compatible!** pyIRCX works with Microsoft Comic Chat (V2.5), the iconic IRC client that displayed conversations as comic strips. Run it natively or in a VM - pyIRCX speaks the same IRCX protocol.

---

## What's New in 1.0.0

### Server-to-Server Linking
pyIRCX now supports **distributed chat networks** with server-to-server linking. Build a multi-server IRC network just like the traditional networks (EFnet, DALnet, Freenode). Features include:

- **Server linking protocol** with password authentication
- **State synchronization** - users and channels sync across servers
- **Message routing** - seamless communication across the network
- **Netsplit handling** - graceful recovery from server disconnections
- **Admin commands** - CONNECT, SQUIT, LINKS for network management

This makes pyIRCX suitable for large-scale deployments across multiple data centers or geographic regions.

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

pyIRCX offers feature parity with commercial IRCX servers like [OfficeIRC](https://www.officeirc.com/), but as **open-source software** you can deploy anywhere:

| Feature | pyIRCX | OfficeIRC | UnrealIRCd |
|---------|:------:|:---------:|:----------:|
| Full IRCX Protocol Support | ✅ | ✅ | ❌ |
| RFC 1459/2812 Compliance | ✅ | ✅ | ✅ |
| **Server-to-Server Linking** | ✅ | ❌ | ✅ |
| **Distributed Networks** | ✅ | ❌ | ✅ |
| SASL Authentication | ✅ | ✅ | ✅ |
| IPv4 & IPv6 Dual-Stack | ✅ | ✅ | ✅ |
| TLS/SSL Encryption | ✅ | ✅ | ✅ |
| Channel Clone Mode | ✅ | ✅ | ❌ |
| ACCESS Control Lists | ✅ | ✅ | ❌ |
| PROP Channel Properties | ✅ | ✅ | ❌ |
| Nickname Registration | ✅ | ✅ | ❌* |
| Channel Registration | ✅ | ✅ | ❌* |
| Offline Messaging (Memos) | ✅ | ✅ | ❌ |
| ServiceBot Monitoring | ✅ | ✅ | ❌ |
| NewsFlash Announcements | ✅ | ✅ | ❌ |
| Transcript Logging | ✅ | ✅ | ❌ |
| DNSBL Integration | ✅ | ✅ | ✅ |
| Flood Protection | ✅ | ✅ | ✅ |
| Staff Hierarchy (ADMIN/SYSOP/GUIDE) | ✅ | ✅ | ❌ |
| **Open Source** | ✅ | ❌ | ✅ |
| **No Licensing Fees** | ✅ | ❌ | ✅ |
| **Single Executable** | ✅ | ✅ | ❌ |
| **No External Services Needed** | ✅ | ✅ | ❌* |

*\* UnrealIRCd requires Anope or Atheme services for nick/channel registration*

**pyIRCX is the only open-source server with full IRCX protocol support AND server linking.**

---

## Features

### 🌐 Server Linking & Distributed Networks (NEW!)

Build IRC networks that scale:

- **Server-to-Server Protocol** — Custom IRCX-aware linking protocol
- **Authentication** — Password-protected server links
- **State Burst** — Full user/channel synchronization on link
- **Message Routing** — Efficient message propagation across the network
- **Netsplit Handling** — Automatic cleanup and recovery
- **Admin Commands**:
  - `CONNECT <server>` — Link to a remote server
  - `SQUIT <server>` — Disconnect a linked server
  - `LINKS` — Show network topology
- **Collision Detection** — Timestamp-based nick collision resolution
- **Configurable** — Link configuration via JSON config file

**Example Network Topology:**
```
         hub.example.com (Central Hub)
                 |
    +------------+------------+
    |            |            |
  leaf1      leaf2        leaf3
(US-East)  (US-West)    (Europe)
```

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

### ServiceBot System

Built-in service bots that can be invited to channels for moderation:

- **System** — Server announcements and administrative messages
- **Registrar** — Handles nickname registration and authentication
- **Messenger** — Offline messaging / memo service
- **NewsFlash** — Network-wide announcements
- **ServiceBot1-10** — Configurable monitoring bots for content filtering

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
- **Web admin panel** via Cockpit integration (optional)

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

# Install dependencies
pip install aiosqlite bcrypt pyotp

# Run the server
python3 pyircx.py
```

The server will start listening on ports **6667** (plain) and **7000** (alternative) by default.

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

See [LINKING.md](LINKING.md) for complete server linking documentation.

### Connecting

Connect with any IRC client:

```
/server localhost 6667
```

For IRCX features, use the IRCX command after connecting:

```
/QUOTE IRCX
```

---

## Documentation

- **[LINKING.md](LINKING.md)** — Server linking protocol and setup
- **[CONFIG.md](CONFIG.md)** — Full configuration reference
- **[MANUAL.md](MANUAL.md)** — User and operator command guide
- **[DATABASE_USERS_REVIEW.md](DATABASE_USERS_REVIEW.md)** — Staff account management
- **[STAFF_ACCOUNT_REFERENCE.md](STAFF_ACCOUNT_REFERENCE.md)** — Quick reference for staff commands
- **[TEST_RESULTS.md](TEST_RESULTS.md)** — Comprehensive test results

---

## Testing

pyIRCX includes comprehensive test suites to ensure protocol compliance:

```bash
# Start the server
python3 pyircx.py &

# Run user protocol tests (50 tests)
python3 pyIRCX_test_users.py

# Run server linking tests (4 tests)
python3 pyIRCX_test_linking.py
```

**Test Coverage:**
- ✅ **50 User/IRC Tests** — All IRC/IRCX protocol features
- ✅ **4 Linking Tests** — Server linking functionality
- **Total: 54 tests, 100% passing**

See [TEST_RESULTS.md](TEST_RESULTS.md) for detailed test results.

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

### Web Admin Panel (Cockpit)

Optional web-based administration:

```bash
# Install Cockpit
sudo dnf install cockpit

# Copy pyIRCX module
sudo cp -r cockpit/pyircx ~/.local/share/cockpit/

# Access at https://yourserver:9090
```

The web admin provides:
- Real-time server monitoring
- User/channel management
- Configuration editing
- Log viewing
- Staff account management

---

## Historical Context

### The IRCX Legacy

IRCX (Internet Relay Chat eXtensions) was developed by Microsoft in the late 1990s as an enhancement to the standard IRC protocol. It was first implemented in **Microsoft Exchange Server 5.5** as the Chat Service component, replacing the older binary Microsoft Chat protocol.

The protocol powered some of the largest chat networks of the era:

- **MSN Chat** served millions of users daily at its peak
- **TalkCity** was one of the pioneering web chat communities
- Countless enterprise deployments for internal communications

When Microsoft [shut down MSN Chat in 2006](https://en.wikipedia.org/wiki/MSN_Chat), the IRCX protocol largely faded from public use — but not from memory.

### Preserving Chat History

pyIRCX was created to preserve this important piece of internet history. Whether you're:

- **Nostalgic** for the MSN Chat days
- Running a **retro computing** project
- Need a **fully-featured IRC server** with modern enhancements
- Want to understand how **enterprise chat worked** before Slack
- Building a **distributed IRC network**

pyIRCX provides an authentic IRCX experience on modern infrastructure.

---

## Comparison with Other Servers

### Protocol & Network Support Comparison

| Server | Language | IRCX | Linking | ACCESS | PROP | Clone Channels | Open Source | Cost |
|--------|----------|:----:|:-------:|:------:|:----:|:--------------:|:-----------:|:----:|
| **pyIRCX** | Python | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Free |
| OfficeIRC | .NET | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | Commercial |
| UnrealIRCd | C | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | Free |
| InspIRCd | C++ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | Free |
| Solanum | C | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | Free |
| ngIRCd | C | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | Free |
| Ergo | Go | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | Free |
| ircd-hybrid | C | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | Free |

### Feature Comparison

| Feature | pyIRCX | OfficeIRC | UnrealIRCd | Solanum | Ergo |
|---------|:------:|:---------:|:----------:|:-------:|:----:|
| IRCX Protocol | ✅ | ✅ | ❌ | ❌ | ❌ |
| Server Linking | ✅ | ❌ | ✅ | ✅ | ❌ |
| Multi-Server Networks | ✅ | ❌ | ✅ | ✅ | ❌ |
| Comic Chat Compatible | ✅ | ✅ | ❌ | ❌ | ❌ |
| Built-in NickServ | ✅ | ✅ | ❌* | ❌* | ✅ |
| Built-in ChanServ | ✅ | ✅ | ❌* | ❌* | ✅ |
| ServiceBot System | ✅ | ✅ | ❌ | ❌ | ❌ |
| Channel Cloning | ✅ | ✅ | ❌ | ❌ | ❌ |
| SASL Authentication | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv6 Support | ✅ | ✅ | ✅ | ✅ | ✅ |
| Transcript Logging | ✅ | ✅ | ❌ | ❌ | ❌ |
| Single-File Deploy | ✅ | ✅ | ❌ | ❌ | ✅ |
| No External Services | ✅ | ✅ | ❌* | ❌* | ✅ |
| Web Admin (Optional) | ✅ | ✅ | ❌ | ❌ | ✅ |

*\* Requires Anope or Atheme services package*

pyIRCX is the only open-source server combining full IRCX protocol support with server linking capabilities.

---

## Production Deployments

pyIRCX is production-ready and suitable for:

✅ **Small Communities** (10-100 users) — Single server deployment
✅ **Medium Networks** (100-1,000 users) — 2-3 linked servers
✅ **Large Networks** (1,000+ users) — Multi-server distributed network
✅ **Enterprise Deployments** — Secure internal chat with staff hierarchy
✅ **Retro Projects** — Authentic IRCX for vintage client compatibility

### Who's Using pyIRCX?

- Retro computing communities
- Gaming guilds and clans
- Self-hosted team chat
- IRC network operators
- IRCX protocol researchers

*Want to be listed? Open an issue on GitHub!*

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

MIT License — See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- The Microsoft Exchange Chat team for creating IRCX
- The MSN Chat community for years of memories
- The IRC protocol designers (RFC 1459, RFC 2812)
- Everyone keeping classic chat protocols alive
- All contributors to this project

---

## Support

- **Documentation**: See docs in this repository
- **Issues**: [GitHub Issues](https://github.com/AI3I/pyIRCX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AI3I/pyIRCX/discussions)

---

## Roadmap

Future enhancements planned:

- [ ] WebSocket support for browser clients
- [ ] IRCv3 capability extensions
- [ ] PostgreSQL/MySQL database backends
- [ ] Cluster mode with Redis pub/sub
- [ ] S2S link encryption (TLS)
- [ ] REST API for integrations
- [ ] Prometheus metrics export

---

## Keywords

*For searchability: IRC server, IRCX server, IRCX protocol, Microsoft Exchange Chat, MECS, MSN Chat server, MSN Chat clone, TalkCity, Comic Chat server, Microsoft Comic Chat, chat server Python, asyncio IRC, self-hosted chat, open source IRC server, IRC with registration, NickServ alternative, ChanServ alternative, SASL IRC, channel cloning, overflow rooms, IRC flood protection, DNSBL IRC, IRC access control, enterprise chat server, team chat self-hosted, Slack alternative self-hosted, Discord alternative self-hosted, retro chat, vintage IRC, 90s chat, web chat server, IRC network, server linking, distributed IRC, IRC hub, IRC services, UnrealIRCd alternative, InspIRCd alternative*

---

<p align="center">
  <i>Bringing back the chat rooms of yesterday, with the technology of today.</i>
  <br><br>
  <b>pyIRCX 1.0.0</b> — The production-ready IRCX server for distributed networks
  <br><br>
  ⭐ <b>Star this project on GitHub if you find it useful!</b> ⭐
</p>
