# Changelog

All notable changes to pyIRCX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-01-02

### Changed
- **License Migration**: Migrated from MIT License to GNU General Public License v3.0
- Updated copyright to "pyIRCX Project" across all source files
- Added comprehensive GPLv3 headers to all Python source files
- Updated all documentation and badges to reflect GPLv3 licensing

### Added
- Full GPLv3 license headers in all Python files (pyircx.py, linking.py, test files, cockpit/pyircx/api.py)

## [1.0.3] - 2026-01-02

### Added
- **Staff Management Interface**: Full CRUD interface in Cockpit dashboard for managing ADMIN/SYSOP/GUIDE accounts
- **Enhanced Server Statistics**: Detailed stats with staff breakdowns and access rule counts
- **Channel Modes Display**: Active channels now show modes (+nt, +mnst, etc.) in Cockpit
- Reorganized Cockpit dashboard with 3-column Server Overview layout
- Integrated search functionality in dashboard

### Fixed
- **Security Fix**: Prevented manual setting of +r (registered) mode on channels via MODE command
  - Registered mode can now only be set through proper REGISTER command
  - Ensures channel registration goes through database for data integrity

### Changed
- Improved Cockpit dashboard layout and visual hierarchy
- Standardized terminology: "Nicknames" and "NewsFlash" throughout interface
- Enhanced visual consistency across all interface elements
- Smaller, more compact button sizing and tighter spacing

## [1.0.1] - 2026-01-02

### Added
- **Comprehensive Linux Distribution Support**: Automatic package manager detection for 20+ distributions
  - Debian derivatives: Linux Mint, Pop!_OS, Elementary, Zorin, Kali, Parrot, Raspbian
  - RHEL derivatives: Rocky Linux, AlmaLinux, Oracle Linux, Scientific Linux
  - Arch derivatives: Manjaro, EndeavourOS, Garuda, Artix
  - Additional: Gentoo, Funtoo, Void Linux, Alpine, Solus, NixOS, Clear Linux, Mageia, Slackware
- **Uninstall Script** (`uninstall.sh`): Complete removal with interactive prompts and database backup option
- **Upgrade Script** (`upgrade.sh`): Intelligent upgrade with automatic detection and backup
- **Repair Script** (`repair.sh`): Comprehensive validation and repair functionality

### Fixed
- **Critical**: Fixed service startup failure - linking.py module was not being copied during installation
- Fixed Cockpit web admin not finding files after system installation
- Fixed Cockpit integration with hardcoded user path - now works system-wide
- Fixed Cockpit service control - systemctl now works with proper permissions
- Fixed Cockpit not reloading when already installed - now auto-restarts
- Fixed systemd security settings that were too restrictive (relaxed ProtectSystem, removed MemoryDenyWriteExecute)
- Fixed installation failures on non-mainstream distributions
- Fixed test runner failures when netcat not installed (added bash TCP socket fallback)

### Changed
- Improved `setup_ssl.sh` with better OS detection and error messages
- Enhanced `run_tests.sh` - no longer requires netcat (nc)
- Updated Cockpit module to install system-wide (/usr/share/cockpit/)
- Improved Cockpit path handling to support both system and user installations
- Updated database error messages with helpful instructions

## [1.0.0] - 2026-01-01

### Added
- **Server-to-Server Linking**: Distributed chat networks with multi-server support
  - Server linking protocol with password authentication
  - State synchronization - users and channels sync across servers
  - Message routing - seamless communication across the network
  - Netsplit handling - graceful recovery from server disconnections
  - Admin commands: CONNECT, SQUIT, LINKS for network management
  - Collision detection with timestamp-based nick collision resolution
- **Full IRCX Protocol Implementation**:
  - Three-tier channel privileges: Owner (.), Host (@), Voice (+)
  - ACCESS command: Granular access control lists (DENY, GRANT, VOICE, HOST, OWNER)
  - PROP command: Channel properties (TOPIC, ONJOIN, ONPART, MEMBERKEY, HOSTKEY, OWNERKEY, LAG)
  - WHISPER command: Private messages within channels
  - LISTX command: Extended channel listing with metadata
  - KNOCK command: Request invitation to invite-only channels
  - CREATE command: Create channels with initial modes
  - ISIRCX command: Protocol capability detection
- **Channel Cloning** (Overflow Rooms): Automatic channel cloning like MSN Chat
  - When a channel with clone mode (+d) reaches user limit (+l), new joiners placed in numbered overflow channels
  - Mode changes on original propagate to all clones
- **Security & Authentication**:
  - SASL PLAIN authentication with IRCv3 capability negotiation
  - Nickname registration with email verification
  - Two-factor authentication support
  - DNSBL checking (Spamhaus, DroneBL, etc.) with IPv4 and IPv6 support
  - Open proxy detection
  - Connection throttling and flood protection
  - Failed auth lockout with configurable thresholds
  - TLS 1.2/1.3 with automatic certificate management
  - IP masking (+x user mode)
- **Network Services** (ServiceBot System):
  - System - Server announcements and administrative messages
  - Registrar - Nickname registration and authentication
  - Messenger - Offline messaging / memo service
  - NewsFlash - Network-wide announcements
  - ServiceBots - Configurable monitoring bots for content filtering
- **Staff Management**: Three-tier staff hierarchy
  - ADMIN (+a): Full server control, CONFIG access, can link servers
  - SYSOP (+o): Server operator, can KILL/KLINE, can link servers
  - GUIDE (+g): Channel moderation assistance, limited staff commands
- **Modern Infrastructure**:
  - Pure Python 3.8+ with asyncio for high concurrency
  - SQLite database with connection pooling for persistence
  - Dual-stack IPv4/IPv6 support
  - Systemd integration for production deployments
  - Hot-reloadable configuration
  - Comprehensive logging with configurable verbosity
  - Web admin panel via Cockpit integration (optional)
- **Database Layer**:
  - Connection pooling (default: 5 connections)
  - Automatic schema migration
  - Atomic transactions
  - Persistent storage for nicknames, channels, ACCESS lists, PROPs, memos, staff, bans
- **Testing**: 54 passing tests
  - 50 User/IRC tests covering all IRC/IRCX protocol features
  - 4 Server linking tests

### Documentation
- Comprehensive README with feature descriptions and comparisons
- LINKING.md - Server linking protocol and setup guide
- CONFIG.md - Full configuration reference
- MANUAL.md - User and operator command guide
- TESTING.md - Test suite documentation
- SECURITY.md - Security features and best practices
- PERFORMANCE.md - Performance characteristics and benchmarks

[1.0.4]: https://github.com/AI3I/pyIRCX/releases/tag/v1.0.4
