# Changelog

All notable changes to pyIRCX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-17

### The Friendly, Modern IRCX Server

pyIRCX v2.0.0 is a production-ready IRC/IRCX server that brings the nostalgia of classic chat networks (MSN Chat, TalkCity) into the modern era with friendly, conversational user experience and enterprise-grade distributed networking capabilities.

### 🎨 User Experience Revolution

#### Personalized Messaging System
- **~185+ improved messages** across the entire system
- All error messages now use **personal pronouns** and conversational language
- Messages provide **actionable guidance** on what to do next
- Examples:
  - "Invalid nickname" → "That nickname is not valid"
  - "No such nick/channel" → "That nickname or channel doesn't exist"
  - "Cannot send to channel" → "You cannot send to that channel - check modes/permissions"
  - "Permission denied" → "You do not have permission - IRC administrator or operator privileges are required"

#### Enhanced Help System
- **100% command coverage** - Every command documented with examples
- **Fuzzy matching** - "Did you mean?" suggestions for typos
- **Comprehensive examples** - Real usage patterns for all commands
- **Service help improved** - Registrar, Messenger, NewsFlash with detailed examples
- Help topics: JOIN, PART, MODE, TOPIC, KICK, INVITE, ACCESS, PROP, WHISPER, WHOIS, WHO, REGISTER, IDENTIFY, MFA, LIST, MSG, AWAY, KILL, MOTD, MEMO, GAG/UNGAG, CREATE, CONNECT/SQUIT

#### Command Aliases
- **12 shortcut commands** for faster typing:
  - `/J` → `/JOIN`, `/P` → `/PART`, `/W` → `/WHOIS`, `/M` → `/MSG`
  - `/N` → `/NICK`, `/Q` → `/QUIT`, `/T` → `/TOPIC`, `/K` → `/KICK`
  - `/I` → `/INVITE`, `/L` → `/LIST`, `/WW` → `/WHOWAS`, `/WH` → `/WHISPER`
- IRC standard compatible, zero overhead

#### Staff Experience Improvements
- **Enhanced STATS output** with counts, idle times, and professional formatting
- **Detailed STAFF confirmations** with audit trails
- **Comprehensive webadmin tooltips** (60+ fields across all configuration tabs)
- **Reserved nicknames reference** showing active and unused service names

### 🌐 Distributed Networking

#### Server Linking
- **Trunk-and-branch topology** for scalable multi-server networks
- **Centralized services** - Trunk servers host Registrar, Messenger, NewsFlash, ServiceBots
- **Branch routing** - Branch servers automatically route service requests to trunk
- **Network-wide staff authentication** - Centralized credentials with branch routing

#### Seamless Cross-Server Operations
- **Channel operations propagate** across linked servers (TOPIC, KICK, MODE, INVITE)
- **User state synchronization** - NICK, AWAY, QUIT propagate network-wide
- **Channel state synchronization** - Modes, ban lists, access controls sync automatically
- **WHISPER and KNOCK** work across server boundaries
- Network behaves as a unified system

### 🔐 Core Features

#### IRC Protocol Support
- **48 command handlers** - Full IRC/IRCX protocol implementation
- **RFC 1459/2812 compliant** - Works with any IRC client
- **IRCX extensions** - PROP, ACCESS, WHISPER, EVENT, KNOCK, AUTH, IRCVERS
- **User modes** - +i, +o, +a, +g, +r, +z, +k, +x, +w
- **Channel modes** - Standard IRC + IRCX extensions

#### Services
- **Registrar** - Nickname and channel registration
- **Messenger** - Offline messages and memos
- **NewsFlash** - Server-wide announcements
- **ServiceBot pool** - Automated moderation with profanity filtering
- **Traditional aliases** - NickServ, ChanServ, MemoServ compatibility

#### Security & Moderation
- **Flood protection** - Rate limiting and threshold detection
- **Profanity filtering** - Regex pattern support with live management
- **DNSBL integration** - Block known proxy/VPN networks
- **Channel access controls** - Fine-grained permissions with ACCESS lists
- **Staff hierarchy** - ADMIN/SYSOP/GUIDE with graduated privileges
- **SSL/TLS support** - Encrypted connections

#### Web Interfaces
- **WebChat** - Browser-based IRC client with modern UI
- **WebAdmin** - Full server administration panel
- **REST API** - Programmatic management interface

#### Deployment & Operations
- **systemd integration** - Native Linux service management
- **SELinux policies** - Mandatory access control support
- **polkit rules** - Fine-grained authorization
- **Multi-distro support** - Apache/httpd setup scripts for all major distributions
- **Comprehensive testing** - 243 passing tests

### 📝 Technical Details

#### Code Changes
- **pyircx.py** - ~185+ message improvements, enhanced help system
- **linking.py** - Cross-server operation propagation
- **api.py** - WebAdmin backend updates
- **webadmin/** - Tooltip system, reserved nicknames reference

#### Configuration
- **Backward compatible** - Existing configurations work without changes
- **New fields** - `limits.client_timeout` for ghost connection prevention
- **Enhanced profanity filter** - Regex patterns and live management via `/PROFANITY` command

#### Testing
- **243 tests passing** - Full test coverage maintained
- **Linking tests** - Trunk/branch and cross-server operation validation
- **Service tests** - Registrar, Messenger, NewsFlash verification
- **Command tests** - All 48 commands validated

### 📚 Documentation

- **README.md** - Updated for v2.0.0 with new tagline and feature highlights
- **MANUAL.md** - All numeric replies updated with friendly messages
- **Removed** - 11 v1.x release notes, 2 historical bugfix docs (fresh start)

---

## Version History

**v2.0.0** represents a fresh start for pyIRCX. Previous development versions (v1.0-v1.2) focused on feature implementation and protocol compliance. v2.0.0 refines the entire user experience with a focus on friendly, conversational communication while adding enterprise-grade distributed networking capabilities.

### Development Leading to v2.0.0

The path to v2.0.0 included:
- **Protocol Implementation** - Full IRC/IRCX protocol support with 48 commands
- **Services Development** - Registrar, Messenger, NewsFlash, ServiceBots
- **Security Features** - Flood protection, DNSBL, SSL/TLS, staff hierarchy
- **Web Interfaces** - WebChat and WebAdmin with full functionality
- **Linking Architecture** - Trunk-and-branch topology with centralized services
- **Message Personalization** - ~185+ improvements making pyIRCX the friendliest IRC server
- **Testing Framework** - 243 comprehensive tests ensuring reliability

v2.0.0 is the culmination of this development, ready for production use.
