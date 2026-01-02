# pyIRCX v1.0.1 - Installation & Compatibility Improvements

**Patch release improving installation experience across all Linux distributions**

---

## What's New in v1.0.1

### Comprehensive Linux Distribution Support

The installation scripts now support virtually **any Linux distribution** with automatic package manager detection:

#### Newly Added Distribution Support:

**Debian Derivatives:**
- Linux Mint, Pop!_OS, Elementary OS, Zorin OS
- Kali Linux, Parrot OS, Raspbian

**RHEL Derivatives:**
- Rocky Linux, AlmaLinux, Oracle Linux, Scientific Linux

**Arch Derivatives:**
- Manjaro, EndeavourOS, Garuda Linux, Artix

**Additional Distributions:**
- Gentoo & Funtoo (Portage)
- Void Linux (XBPS)
- Alpine Linux (APK)
- Solus (eopkg)
- NixOS (with guidance)
- Clear Linux (swupd)
- Mageia (urpmi)
- Slackware

**Generic Fallback:**
- Automatic package manager detection for unknown distributions
- Support for apt, dnf, yum, pacman, zypper, apk, emerge, and more

### New Features

#### Uninstall Script (`uninstall.sh`)

Complete and safe removal of pyIRCX with interactive prompts:

```bash
sudo ./uninstall.sh
```

**Features:**
- Interactive removal with confirmation prompts
- **Database backup option** before deletion
- Removes systemd services and timers
- Cleans up SSL certificates (with warnings)
- Optional removal of:
  - Installation directory
  - Configuration files
  - Service user account
  - Cockpit web module
  - Python packages
  - Let's Encrypt certificates (with extra confirmation)

#### Enhanced setup_ssl.sh

- Improved certbot installation across all distributions
- Better error messages with helpful links
- Fallback to package manager detection

#### Improved run_tests.sh

- **No longer requires netcat** (nc) to be installed
- Falls back to bash TCP socket connections
- More portable across minimal installations
- Works on Alpine, Gentoo, and other minimal distros

#### Fixed Cockpit Web Admin Paths

- **Cockpit now works with system installation**
- Automatically detects system install location (`/opt/pyircx`, `/etc/pyircx`)
- Falls back to user installation (`~/pyIRCX`) for development setups
- Correctly handles both installation methods seamlessly

---

## Installation

### Quick Install

```bash
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX
sudo ./install.sh
```

The installer now works on **20+ Linux distributions** out of the box!

### Uninstallation

```bash
sudo ./uninstall.sh
```

Safe removal with database backup option and interactive prompts.

---

## Upgrade from v1.0.0

If you installed v1.0.0, use the new upgrade script:

```bash
cd pyIRCX
git pull
sudo ./upgrade.sh
```

The upgrade script will:
- Detect and fix missing linking.py module
- Update systemd service file
- Migrate Cockpit to system-wide installation
- Fix any permission issues
- Preserve your existing configuration

---

## Changes Since v1.0.0

### Enhanced Files

**install.sh**
- Added support for 15+ new Linux distributions
- Improved Cockpit installation for all distros
- Generic package manager detection fallback
- Better error messages and user guidance

**setup_ssl.sh**
- Comprehensive OS detection for certbot installation
- Support for Alpine, Gentoo, Void, and other distros
- Improved error messages with certbot.eff.org link

**run_tests.sh**
- Removed netcat dependency
- Bash TCP socket fallback for connectivity checks
- Works on minimal Linux installations

**cockpit/pyircx/api.py**
- Fixed paths to work with system installation
- Auto-detects install location (/opt/pyircx vs ~/pyIRCX)
- Correctly handles both system and user installations
- Improved database error messages with helpful instructions

**cockpit/pyircx/pyircx.js**
- Removed hardcoded user-specific path
- Now uses system-wide Cockpit installation path
- Works for all users, not just the installer
- Added proper superuser permissions for systemctl commands
- Fixed service status checking and control

**install.sh**
- Now copies linking.py module (was missing - caused service failures!)
- Changed Cockpit module to install system-wide (/usr/share/cockpit/)
- Makes api.py executable during installation
- Restarts Cockpit if already running (picks up new module immediately)
- Accessible to all users on the system

**pyircx.service**
- Relaxed ProtectSystem from 'strict' to 'full' for proper operation
- Removed MemoryDenyWriteExecute (can interfere with Python)
- Added explicit ReadOnlyPaths for /etc/pyircx
- Changed PrivateDevices to false (needed for system devices)

**uninstall.sh**
- Removes Cockpit from both system and user locations
- Handles upgrades from old installation method

### New Files

**upgrade.sh** ⭐ NEW
- Intelligent upgrade script for existing installations
- Detects what needs updating (missing files, old configs, etc.)
- Creates backup before upgrading
- Preserves existing configuration
- Handles migration from old Cockpit location
- Restarts service automatically if it was running

**repair.sh** ⭐ NEW
- Comprehensive validation and repair script
- Checks: files, permissions, service, database, Cockpit, dependencies
- Offers to fix issues automatically
- Non-destructive repairs
- Perfect for troubleshooting installations

**uninstall.sh**
- Complete uninstallation script with safety features
- Database backup functionality
- Interactive removal prompts

**RELEASE_NOTES_v1.0.0.md**
- Properly formatted release notes for GitHub

---

## Bug Fixes

- Fixed installation failures on non-mainstream distributions
- Fixed test runner failures when netcat not installed
- Fixed Cockpit installation on Arch derivatives
- **Fixed Cockpit web admin not finding files after system installation**
- **Fixed Cockpit integration with hardcoded user path - now works system-wide**
- **Fixed Cockpit service control - systemctl now works with proper permissions**
- **Fixed Cockpit not reloading when already installed - now auto-restarts**
- **CRITICAL: Fixed service startup failure - linking.py module was not being copied**
- **Fixed systemd security settings that were too restrictive**

---

## Compatibility

**Tested on:**
- ✅ Ubuntu 20.04, 22.04, 24.04
- ✅ Debian 11, 12
- ✅ Fedora 38, 39, 40
- ✅ CentOS Stream 8, 9
- ✅ Rocky Linux 8, 9
- ✅ Arch Linux
- ✅ Manjaro
- ✅ openSUSE Tumbleweed
- ✅ Alpine Linux 3.18+
- ✅ Void Linux

**Should work on** (not extensively tested):
- Gentoo, Funtoo, Solus, Clear Linux, Mageia, Slackware
- And any distribution with a standard package manager

---

## Full v1.0.0 Features

All features from v1.0.0 are included:

- ✅ **Server-to-Server Linking** - Build distributed IRC networks
- ✅ **Full IRCX Protocol** - ACCESS, PROP, WHISPER, channel cloning
- ✅ **Security** - SASL auth, TLS, DNSBL, flood protection
- ✅ **ServiceBot System** - Built-in moderation bots
- ✅ **Staff Hierarchy** - ADMIN/SYSOP/GUIDE levels
- ✅ **Modern Infrastructure** - asyncio, SQLite, systemd integration
- ✅ **54 Passing Tests** - Comprehensive test coverage

See [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) for full v1.0.0 feature list.

---

## Documentation

- **[README.md](README.md)** - Full documentation
- **[LINKING.md](LINKING.md)** - Server linking guide
- **[CONFIG.md](CONFIG.md)** - Configuration reference
- **[MANUAL.md](MANUAL.md)** - User and operator commands
- **[TEST_RESULTS.md](TEST_RESULTS.md)** - Test suite results

---

## Known Issues

None at this time. Report issues at: https://github.com/AI3I/pyIRCX/issues

---

## Contributors

Thanks to all contributors and users who reported compatibility issues!

---

## Links

- **GitHub Repository**: https://github.com/AI3I/pyIRCX
- **Issues**: https://github.com/AI3I/pyIRCX/issues
- **Discussions**: https://github.com/AI3I/pyIRCX/discussions

---

⭐ **Star this project on GitHub if you find it useful!** ⭐

---

**pyIRCX 1.0.1** - Now installs everywhere!
