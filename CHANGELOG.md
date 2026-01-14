# Changelog

All notable changes to pyIRCX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 2026-01-14

### Fixed - CRITICAL
- **Channel Broadcast Async Bug**: Fixed catastrophic bug in `Channel.broadcast()` that crashed connections when users joined channels
  - Bug: `tasks.append(await member.send(msg))` awaited immediately and appended None
  - Fix: `tasks.append(member.send(msg))` properly collects coroutines for concurrent execution
  - Impact: All channel broadcasts (joins, parts, messages, modes) were broken with multiple users
  - Affected: WebChat and any multi-user channel operations since asyncio.gather migration

### Fixed
- **KILL Command Format**: Now sends proper IRC NOTICE instead of malformed message
  - No more "GARBAGE" display in IRC clients
  - Format: `:servername NOTICE staffnick :*** User killed (reason)`
- **QUIT Command Disconnect**: Users now disconnect immediately (no lingering connections)
  - Added `user.disconnected` flag for reliable disconnect detection
  - Works for all user types: registered, unregistered, CAP negotiation, webchat
- **CAP Negotiation**: Clients can now complete capability negotiation without disconnection
  - Fixed disconnect check to skip unregistered users (nickname "*")
- **WebChat IRCX Order**: IRCX command now sent after registration (001) instead of before
  - Correct order: WEBIRC → NICK/USER → 001 welcome → IRCX → JOIN
- **Database Write Access**: Web server user automatically added to pyircx group
  - Fixes "readonly database" errors in web admin
  - Applied to install.sh, upgrade.sh, and repair.sh scripts

### Changed
- **Web Admin Directory**: `/var/www/html/pyircx-admin` → `/var/www/html/webadmin`
- **WebChat Directory**: Frontend now installed to `/var/www/html/webchat/` with index.html
- **WEBIRC Default**: Now enabled by default in pyircx_config.json template
- **WebChat Access**: http://localhost/webadmin/ and http://localhost/webchat/

### Added
- **WebChat Favicon**: Blue SVG favicon with # symbol for IRC theme
- **Enhanced Debug Logging**: Added traceback logging for client errors in debug mode

## [1.1.2] - 2026-01-12

### Fixed
- **Channel Unlock Button**: Services (+s) can now set/unset MODE +z (locked mode)
  - System user no longer incorrectly has +a (admin) mode
  - Web admin unlock button now works correctly
  - Permission check updated to allow `is_service()` in addition to `is_high_staff()`
- **Configuration Template**: Removed static `modes` section from pyircx_config.json
  - Mode strings are now hardcoded in server (not user-configurable)
  - Prevents mode inconsistencies from configuration errors
- **User Mode String**: Fixed inconsistency - now consistently `agiorsxz` (includes 's' for services)
- **Channel Mode Documentation**: Corrected mode descriptions (x=auditorium, u=knock-mode, z=locked)
- **STATS s Command**: Now correctly shows virtual services (System, Registrar, etc.)
- **Channel +r Mode Consistency**: Synchronized `channel.registered` flag with `channel.modes['r']`
- **UNREGISTER Command**: Now properly removes +r mode and broadcasts MODE change
- **ADMIN Unregister Permissions**: Check ADMIN privileges before database entries

### Changed
- **Database Schema**: Migrated from `reg_chans` to `registered_channels` with JSON properties
  - Added `properties` TEXT column to store channel state as JSON
  - Channels are now dynamic by default (created on-demand, lost when empty)
  - Registered channels persist full state (owners, hosts, voices, ACCESS, topic, keys, modes)
  - Removed legacy `reg_chans` table entirely
- **API Updates**: Migrated api.py to use `registered_channels.properties` instead of `reg_chans.data`
  - Updated 8 functions: search_channels, get_registered_channels, edit_channel, get_channel_details, get_channel_access, set_channel_access, get_registered_channels_paginated, unregister_channel
  - ACCESS list management now requires channels to be registered first
- **Database Permissions**: Apache user added to pyircx group for web admin write access
- **MODE -r**: High staff can now use MODE -r to unregister channels directly

### Removed
- **DEFAULT Configuration Block**: Removed hardcoded configuration from pyircx.py (lines 112-229)
  - Server now requires config file to start (raises FileNotFoundError if missing)
  - Configuration should be provided by installation script only
- **Legacy Channel Persistence**: Removed load_channels(), save_channels(), periodic_save()
  - Channel state now persists via database for registered channels only

## [1.1.0] - 2026-01-11

### Added
- **Web Administration Panel**: Standalone PHP-based admin interface (replaces Cockpit)
  - Session-based authentication using IRC staff accounts
  - Service control (start/stop/restart) via polkit
  - Real-time log viewer with journalctl integration
  - User management (list, search, pagination)
  - Channel management (list, search, pagination)
  - Staff management (create/edit/delete staff accounts)
  - Mailbox message system
  - Access control management with expiration
  - Database viewer
  - Responsive design with improved navigation
- **Staff Profile Support**: Enhanced staff account system
  - Email address field for staff accounts
  - Real name field with force_realname option
  - Profile updates via admin panel
- **Access Control Expiration**: Timeout field for temporary channel access
- **Mailbox Message Sending**: Send messages to user mailboxes via admin panel
- **SELinux Policies**: Production-ready security policies
  - `pyircx-httpd-systemd.te` - Allow Apache to control pyircx service via D-Bus
  - `pyircx-httpd-journal-v3.te` - Allow Apache to read systemd journal logs
- **Polkit Authorization**: Passwordless service management for web admin
  - `10-pyircx-admin.rules` - Grant apache user permission to manage pyircx.service
- **Database Migration Script**: `migrate_1.0_to_1.1.sh` for upgrading v1.0.x to v1.1.0
  - Adds email, realname, force_realname columns to users table
  - Adds timeout column to server_access table
  - Safe column existence checking
- **Comprehensive Test Suites**:
  - `test_access_control.py` - Complete access control system tests (449 lines)
  - `test_servicebot.py` - ServiceBot functionality tests (204 lines)
- **API Enhancements**: Moved to `/opt/pyircx/api.py` with new commands
  - `test-staff-login` - Staff authentication for web admin
  - `send-mailbox-message` - Send messages to user mailboxes
  - `update-staff-profile` - Update staff email/realname
  - `list-nicks-paginated` / `search-nicks` - Paginated user lists
  - `list-channels-paginated` / `search-channels` - Paginated channel lists
  - Enhanced `get_logs()` with journalctl integration

### Changed
- **Version**: Bumped to 1.1.0
- **Timestamp**: Updated to "Sun Jan 11 09:21:32 PM EST 2026"
- **API Location**: Moved from `/usr/share/cockpit/pyircx/api.py` to `/opt/pyircx/api.py`
- **Installation Script**: Complete rewrite for web admin installation
  - Installs Apache and PHP with OS-specific packages
  - Automatic SELinux policy compilation and installation
  - Automatic polkit rules installation
  - Configures apache user for systemd-journal group membership
  - Removed Cockpit installation option
- **Upgrade Script**: Intelligent v1.0.5 → v1.1.0 migration
  - Detects what needs upgrading (API, web admin, database, SELinux, polkit)
  - Automatic database schema migration
  - Cockpit to Web Admin migration
  - SELinux policy installation with detection
  - Polkit rules installation
  - Complete backup before changes
- **Repair Script**: Updated for web admin validation
  - Checks web admin files and permissions
  - Verifies SELinux policies (if enabled)
  - Verifies polkit rules
  - Checks apache group membership
  - Fixes API file ownership and permissions

### Fixed
- **User Mode +s (Invisibility)**: Fixed to properly hide invisible users from WHO/NAMES
- **JOIN/MODE Logic**: Fixed channel mode behavior and JOIN command handling
- **WHO Command**: Fixed response format and numeric compliance
- **IRC Numeric Formats**: Fixed colon placement in numerous numerics for RFC compliance
  - Fixed 366 NAMES reply format (no extra colon before channel)
  - Corrected numerous other numeric response formats

### Removed
- **Cockpit Module Dependency**: Replaced with standalone Web Administration Panel
  - No longer requires Cockpit installation
  - Removed `/usr/share/cockpit/pyircx/` directory
  - Removed Cockpit admin token system
  - Removed Cockpit-specific files from repository

### Security
- **SELinux Support**: Production-ready policies for web admin on RHEL/Fedora/CentOS
- **Polkit Authorization**: More secure than sudo for service control
- **Session-based Authentication**: Web admin uses PHP sessions with bcrypt passwords
- **Apache User Isolation**: Web admin runs as unprivileged apache user

### Migration Notes
- **From v1.0.5 to v1.1.0**: Run `./upgrade.sh` or `migrate_1.0_to_1.1.sh` (as root)
- **Cockpit Users**: Web admin replaces Cockpit - no configuration migration needed
- **Database Changes**: Automatic schema updates via migration script
- **Web Admin Access**: Login with existing IRC staff accounts (administrators only)

## [1.0.5] - 2026-01-09

### Added
- **WebChat Browser Client**: Full-featured web-based IRC client
  - WebSocket-to-IRC gateway (`webchat/gateway.py`)
  - Modern responsive HTML5 client (`webchat/index.html`)
  - Dark mode toggle with localStorage persistence
  - Staff user detection and icons (ADMIN/SYSOP/GUIDE)
  - Channel owner/host/voice icons
  - Status window for server messages
  - Full IRCX command support (PROP, ACCESS, WHISPER, LISTX)
- **WEBIRC Protocol Support**: Forward real client IPs through gateway
  - Configurable trusted hosts and passwords
  - IPv4 and IPv6 support
- **WebChat Systemd Service**: `pyircx-webchat.service` with config file support
- **WebChat Configuration**: `/etc/pyircx/webchat.conf` for gateway settings
- **Apache HTTPS Template**: `apache/ssl-webchat.conf.example` for WSS proxy
- **WebChat Test Harness**: `pyIRCX_test_webchat.py` for comprehensive testing
- **Certbot Auto-Renewal**: `pyircx-certbot-renew.service` and `.timer` for Let's Encrypt

### Changed
- **Install Script**: Now enables and starts services automatically
- **Install Script**: Added optional WebChat installation prompt
- **Repair Script**: Added WebChat validation and repair capabilities
- **Setup SSL Script**: Fixed ssl-cert group creation on non-Debian systems
- **Setup SSL Script**: Improved Let's Encrypt directory permissions

### Fixed
- **366 Numeric Format**: Fixed NAMES reply format (no extra colon before channel)
- **SSL Certificate Permissions**: ssl-cert group now created if missing (Fedora/RHEL)

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
