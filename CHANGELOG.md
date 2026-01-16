# Changelog

All notable changes to pyIRCX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-16

### Added
- **Command Aliases**: 12 shortcut commands for faster typing
  - `/J` → `/JOIN`, `/P` → `/PART`, `/W` → `/WHOIS`, `/M` → `/MSG`
  - `/N` → `/NICK`, `/Q` → `/QUIT`, `/T` → `/TOPIC`, `/K` → `/KICK`
  - `/I` → `/INVITE`, `/L` → `/LIST`, `/WW` → `/WHOWAS`, `/WH` → `/WHISPER`
  - IRC standard compatible, zero overhead, transparent to users
- **Configurable Client Timeout**: Prevents ghost connections from dead clients
  - New config field: `limits.client_timeout` (default: 300 seconds)
  - Webadmin field added with tooltip explaining ghost connection prevention
  - Automatic disconnect after period of no data (commands, PING/PONG, etc.)
  - Logs timeout events for monitoring
- **Complete Help System**: 7 new help pages for 100% command coverage
  - `/HELP MOTD` - Display server Message of the Day
  - `/HELP MEMO` - Offline message system (SEND, LIST, READ, DEL)
  - `/HELP GAG`/`/HELP UNGAG` - Staff command to mute/unmute users
  - `/HELP CREATE` - Alias for JOIN (creates or joins channel)
  - `/HELP CONNECT` - ADMIN command for server linking
  - `/HELP SQUIT` - ADMIN command to disconnect linked servers
  - Fuzzy matching updated with all new topics for typo suggestions
- **Enhanced STATS Formatting**: Professional output with counts and idle times
  - `STATS a`, `STATS o`, `STATS g` now show: count in header, idle time per user, "No X currently online" messages
  - Visual improvements: === separators, indentation, "End of X" footers
  - Format: `username!user@host (idle: 5m)`
- **Enhanced STAFF Commands**: Detailed confirmations with audit trails
  - `STAFF LIST`: Count in header, counts per level, [ONLINE] status indicators
  - `STAFF ADD/DEL/SET/PASS`: "=== SUCCESS ===" header, full details, "Created/Changed/Deleted by" tracking
  - All operations show when changes take effect
- **Webadmin Comprehensive Tooltips**: 60+ tooltip fields across all 7 configuration tabs
  - Server tab: All fields with defaults and examples, IPv6 address field added
  - Limits tab: All limits with IRC standard notes, client timeout explanation
  - Security tab: Flood protection, DNSBL, proxy detection with clear explanations
  - Services tab: ServiceBot settings, profanity filter, malicious detection thresholds
  - SSL/TLS tab: Certificate paths, TLS versions, Let's Encrypt examples
  - Linking tab: Server-to-server binding, ports, firewall guidance
  - Advanced tab: Transcripts, persistence, NewsFlash intervals with defaults
  - All fields now self-documenting
- **Reserved Nicknames Reference**: Comprehensive reference on Access Control page
  - Active Virtual Services (4): System, Registrar, Messenger, NewsFlash
  - ServiceBot Pool (dynamic): Updates based on configuration
  - Reserved IRC Services (12): NickServ, ChanServ, MemoServ, OperServ, BotServ, HostServ, HelpServ, InfoServ, StatServ, Global, ALIS, Services
  - Color-coded sections, clear notes about access control implications
  - Explains both active and unused reserved names
- **IPv6 Configuration**: New `network.listen_addr_ipv6` configuration field
  - Default: `::` (all IPv6 interfaces)
  - Webadmin field with tooltip explaining usage
  - Dual-stack deployment support

### Fixed
- **MOTD Whitespace Preservation**: ASCII art and formatted content now displays correctly
  - Problem: Leading/trailing spaces were stripped when saving MOTD
  - Solution: Removed `.trim()` from MOTD save in webadmin
  - Backend already correct (uses `.rstrip()` only)
  - Impact: MOTD ASCII art aligns perfectly
- **MOTD Auto-Load**: MOTD tab now loads content automatically when clicked
  - Problem: Required manual "Reload" button click
  - Solution: Added auto-load trigger in config tab click handler
  - Improves user workflow
- **Message Quality**: ~40 error and system messages improved for clarity
  - Grammar: Consistent punctuation, proper sentence case, trailing periods
  - Clarity: "Invalid nickname" (not "Erroneous"), "No such nickname or channel" (not "No such nick/channel")
  - Actionable: "See /HELP {command}" added to parameter errors, "check modes/permissions" added to channel errors
  - KNOCK messages: Clearer rate limiting guidance
  - MFA messages: Step-by-step instructions
  - Database errors: "contact administrator if persists"
  - Rate limiting: "please wait" guidance

### Changed
- **Webadmin Number Inputs**: Compact 150px width for number fields (was full-width)
  - Better for 4-digit values like ports, timeouts, limits
- **MOTD Button Layout**: Green "Load MOTD" button moved to left of "Save MOTD"
  - More intuitive workflow (load first, then save)
- **Profanity Word List Format**: Changed from "comma-separated" to "one per line"
  - Clearer placeholder showing correct format
  - Note added about /PROFANITY command for regex support

### Documentation
- **README.md**: Updated version to 1.2.0, added v1.2.0 to latest releases
- **RELEASE_v1.2.0.md**: Comprehensive release notes with all 150+ improvements
- **CHANGELOG.md**: This comprehensive v1.2.0 entry
- Documentation for all features pending: MANUAL.md updates for command aliases, client timeout, reserved nicknames

### Code Quality
- **Lines Modified**: ~200 across 4 files (pyircx.py, index.php, admin.js, style.css)
- **Breaking Changes**: None - all changes are additive or improvements
- **Test Coverage**: 243 passing tests (needs updates for v1.2.0 features)
- **Message Quality**: Professional, clear, actionable across all user-facing text
- **Help Coverage**: 100% - every command now documented
- **Configuration Documentation**: 100% - all fields have tooltips

## [1.1.9] - 2026-01-16

### Added
- **Traditional IRC Service Alias Routing**: Case-insensitive routing for classic IRC service names
  - `NickServ` → Routes to Registrar (nickname registration/authentication)
  - `ChanServ` → Routes to Registrar (channel registration/management)
  - `MemoServ` → Routes to Messenger (offline messages)
  - `OperServ`, `HelpServ`, `InfoServ`, `BotServ`, `HostServ`, `StatServ`, `Global`, `ALIS`, `Services` → Provide help information directing users to active services
  - Maintains compatibility with traditional IRC client configurations
  - Proper CamelCase formatting for service names

## [1.1.8] - 2026-01-16

### Added
- **Apache/httpd Multi-Distribution Setup Script**: `setup_apache.sh`
  - Auto-detects distribution (RHEL, Fedora, CentOS, Rocky, Alma, Amazon Linux, Debian, Ubuntu)
  - Configures Apache for both WebAdmin and WebChat
  - Handles SELinux contexts automatically on RHEL-based systems
  - Sets proper permissions (apache:pyircx group membership)
  - Installs and configures PHP and required modules
  - Tests configuration before applying
  - Provides clear success/error messages with troubleshooting steps

### Documentation
- **Complete Documentation Reorganization**: Restructured all documentation into organized subdirectories
  - `docs/user/` - User and admin guides (CONFIG, MANUAL, LINKING, SELINUX, STAFF_ACCOUNT_REFERENCE)
  - `docs/testing/` - Testing documentation (TESTING, TESTHARNESS, TEST_COVERAGE_ANALYSIS)
  - `docs/performance/` - Performance guides (PERFORMANCE, SECURITY_AND_PERFORMANCE_AUDIT)
  - `docs/development/` - Development docs (RELEASE_CHECKLIST, VERSION_MANAGEMENT)
  - `docs/releases/` - All release notes (RELEASE_v1.1.x)
  - Cleaner repository root (20 → 4 markdown files)
- **New WebChat Documentation**: `webchat/README.md` - Complete configuration and troubleshooting guide
- **Documentation Updates**: CONFIG.md, webadmin/README.md, README.md updated with new paths

## [1.1.7] - 2026-01-16

### Added
- **WebChat Configuration System**: Externalized webchat settings to `config.js`
  - Default channel, WebSocket URL, performance tuning parameters now configurable
  - Easy customization without editing HTML
  - Comprehensive inline documentation of all parameters
- **SELINUX.md**: Comprehensive SELinux reference documentation
  - Complete context requirements for all directories
  - Quick reference table and setup script
  - Troubleshooting guide with common issues
- **Merged TESTING.md**: Consolidated all testing documentation
  - Merged TESTING_v1.1.5.md and TESTING_UPDATES.md
  - Comprehensive guide covering all 243 tests across 8 suites
  - Test account setup, CI/CD integration, troubleshooting

### Fixed
- **MOTD Editor**: Preserves blank lines for proper formatting
  - Changed from `if line.strip()` to preserve empty lines
  - MOTD now displays with proper spacing in IRC clients
- **MOTD Configuration Save**: Fixed "Save Configuration" overwriting MOTD with stale cached version
  - saveConfigForm() now reloads config from file before saving
  - Added get-config command to api.py
  - Added cache-busting version parameter to force browser reload
- **Hardcoded Defaults**: Removed hardcoded MOTD defaults from code
  - Removed from api.py and pyircx.py
  - Added default MOTD to pyircx_config.json template
  - All defaults now properly in config file
- **WebChat Default Channel**: Changed from #lobby to #pyIRCX
- **SELinux Contexts**: Comprehensive configuration across all installation scripts
  - install.sh, upgrade.sh, repair.sh now handle all pyIRCX directories
  - webadmin requires httpd_sys_rw_content_t (not httpd_sys_content_t)
  - webchat.conf requires etc_t context for systemd environment files
- **Script References**: All bash scripts now properly install and update config.js

### Changed
- **Documentation Reorganization**: Simplified README.md to reference CHANGELOG.md
  - Removed duplicate version history from README.md
  - CHANGELOG.md is now single source of truth for releases
- **Test Documentation**: Renamed TESTHARNESS_v1.1.5.md to TESTHARNESS.md

### Documentation
- **CONFIG.md**: Updated pool_size default (5 → 10)
- **SECURITY.md**: Documented v1.1.6 web admin security features
- **webadmin/README.md**: Added v1.1.6 security features section
- **webadmin/INSTALL.md**: Added comprehensive SELinux and permissions setup

## [1.1.6] - 2026-01-16

### Security
- **CSRF Token Protection**: Comprehensive CSRF token validation across all web admin API endpoints
- **Secure Session Handling**: Fixed session cookie security to work with both HTTP and HTTPS deployments
- **Stdin Password Input**: Added `test-staff-login-stdin` API command for secure password handling
- **SELinux Context Hardening**: Extended httpd_sys_rw_content_t contexts to cover `/etc/pyircx` directory

### Added
- **HTTP/HTTPS Auto-Detection**: Web admin automatically adapts session security based on protocol
- **Null-Safe Form Handling**: Configuration editor handles missing form fields gracefully with safe getter/setter functions
- **PHP-FPM Restart**: Scripts now automatically restart PHP-FPM after adding apache to pyircx group

### Fixed
- **Web Admin Login**: Fixed "Invalid username or password" error on new installations
- **CSRF Validation**: Fixed CSRF token validation failures on service control and configuration save operations
- **Permission Denied**: Fixed permission denied errors when web admin tried to save configuration files
- **Configuration Save**: Fixed configuration save crashes due to missing nested object properties
- **Session Cookies**: Fixed session cookies not being set on HTTP-only deployments

### Changed
- **Database Pool**: Increased default pool_size from 5 to 10 connections for better concurrency
- **Installation Scripts**: All installation, upgrade, and repair scripts now properly configure web admin permissions (775/664)
- **Group Permissions**: Web server now uses group permissions instead of requiring world-writable files

## [1.1.5] - 2026-01-15

### Added
- **Channel Mode +g (guide-op)**: New channel mode to auto-grant owner to guides
  - When channel has mode +g, any user with guide mode (+g usermode) automatically receives owner (+q) on join
  - Can be set on registered or dynamic channels
  - Settable by: channel owners, hosts, services, admins, or sysops
  - Usage: `MODE #channel +g` to enable, `MODE #channel -g` to disable
- **VOICEKEY Property**: New channel property for granting voice (+v) on join
  - Similar to OWNERKEY and HOSTKEY, but grants +v instead of +q/+o
  - Works with registered and dynamic channels
  - Set via: `PROP #channel VOICEKEY password`
  - Join with: `JOIN #channel password` to automatically receive +v
  - Case-insensitive key matching
  - Integrated into web admin channel edit modal
  - API support: `edit-channel` command now accepts voicekey parameter
- **WebChat Service Detection**: Robot emoji (🤖) for service bots (+s mode)
  - Services sorted first in user list (before ADMIN)
  - Detects 's' flag in WHO replies (352 numeric)
- **WebChat Button Icons**: Added emoji icons to all buttons
  - ➕ Join, ➖ Leave, 👥 Users, ⚙️ Properties, 📤 Send, 🔌 Connect
- **WebChat Join with Key**: Join button now prompts for optional channel key
  - First prompt: channel name
  - Second prompt: channel key (leave empty if none)
- **WebChat Connection Info**: Now shows server information during connection
  - Displays 004 numeric (server version, user modes, channel modes)
  - Displays 005 numeric (ISUPPORT features)
  - Shows all unhandled numerics in status window with [NNN] prefix

### Fixed
- **Case-Sensitive Channel Lookups**: Fixed 7 critical handlers that failed when channel names used different case
  - PROP: Query/set properties now works regardless of #Lobby vs #lobby
  - TRANSCRIPT: Transcript operations now case-insensitive
  - KNOCK: Knocking on channels now case-insensitive
  - INVITE: Inviting users now case-insensitive
  - REGISTER: Channel registration now case-insensitive
  - DROP (UNREGISTER): Channel unregistration now case-insensitive
  - Registrar service: Automatic registration now case-insensitive
- **Case-Sensitive Key Matching**: All channel keys now case-insensitive
  - MEMBERKEY: `/JOIN #channel MyPassword` matches "mypassword"
  - OWNERKEY: Case-insensitive matching for +q grant
  - HOSTKEY: Case-insensitive matching for +o grant
  - VOICEKEY: Case-insensitive matching for +v grant
- **ACCESS GRANT Mode Bypasses**: Users with ACCESS GRANT can now bypass restricted modes
  - Mode +j (no-invitations): ACCESS GRANT users can send INVITE despite +j
  - Mode +u (knock-mode): ACCESS GRANT users can KNOCK despite +u restrictions
  - Previously only staff and services could bypass these modes

### Changed
- **Property Names**: Already case-insensitive (VOICEKEY = voicekey = VoiceKey)
- **Web Admin API**: Updated edit-channel to accept 11 parameters (added voicekey)
- **Web Admin Key Order**: Reordered channel key fields for logical privilege hierarchy
  - New order: Member Key → Voice Key → Host Key → Owner Key
- **IRC Numerics (004/005)**: Fixed channel modes to IRCv3 standard format
  - Added missing 'l' (limit) mode to channel mode list
  - Added new 'g' (guide-op) mode to channel mode list
  - CHANMODES now properly formatted as A,B,C,D: `,k,l,adefghijmnprstuwxyz`
    - A = list modes (empty - we use ACCESS for bans)
    - B = always parameter: k (key)
    - C = parameter on set only: l (limit)
    - D = no parameters: all others (including new +g)
  - Added standard IRC parameters for better protocol compliance:
    - TOPICLEN=390 (max topic length, enforced in TOPIC and PROP commands)
    - MAXNICKLEN (max nickname length)
    - CASEMAPPING=rfc1459 (standard IRC case mapping)
    - STATUSMSG=.@+ (messages to status groups: . owner, @ host, + voice)
    - MODES=6 (max mode changes per command, now enforced)
- **MODE Permissions**: Services can now set channel modes (previously only owners, hosts, and admins)
- **MODE Enforcement**: Maximum modes per command now enforced (default 6, configurable in limits.max_modes_per_command)
- **Shutdown Performance**: Significantly improved startup/shutdown/restart times
  - Added overall 10-second shutdown timeout (prevents hanging)
  - Client disconnections now concurrent instead of sequential
  - Database pool properly closes during shutdown
  - Background task cancellation with 2-second timeout
  - Individual operations have sub-timeouts (link manager: 2s, servers: 2s, clients: 3s, database: 2s)

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

## [1.1.3] - 2026-01-14

### Security
- **Error Handling Specificity**: Replaced all bare `except:` clauses with specific exception types
  - Improved error handling in 17 locations across codebase
  - Better exception specificity prevents masking unexpected errors
  - Examples: Database migrations use `except aiosqlite.OperationalError`, file operations use `except (FileNotFoundError, PermissionError, IOError)`
- **Server Link Password Security**: Implemented bcrypt authentication for server-to-server links
  - Server link passwords now use bcrypt hashing instead of plaintext
  - Backwards compatible with plaintext fallback
  - Added `utils/hash_link_password.py` utility for generating bcrypt hashes
- **Configuration Security**: Added config file permission validation on startup
  - Warns if `/etc/pyircx/pyircx_config.json` is world-readable/writable
  - Logs security warning with remediation instructions

### Changed
- **Database Connection Pooling**: Increased default pool size from 5 to 10 connections
  - Added pool saturation monitoring and warnings
  - Helps identify when pool size needs adjustment under load

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

## [1.1.1] - 2026-01-12

### Added
- **Web Admin Channel Mode Control**: SET_CHANNEL_MODE admin command handler
  - Allows web admin to set channel modes directly
  - Used by Lock/Unlock buttons in web admin
  - Applies modes using System user
- **Web Admin Topic Editor**: SET_CHANNEL_TOPIC admin command handler
  - Fixes broken topic editing from web admin
  - Sets channel topic using System user
- **Register/Unlock Functions**: Added channel registration and unlocking features to web admin

### Fixed
- **Topic Editing**: Fixed topic editor not working from web admin
- **Modal Data Loading**: Fixed 3 critical bugs in web admin modal data handling
- **Button Styling**: Standardized all web admin buttons with emoji icons

### Changed
- **Test File Naming**: Renamed test_*.py → pyIRCX_test_*.py for consistency
- **Config Generation**: Added generate_default_config.py utility

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
