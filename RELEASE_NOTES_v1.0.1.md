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

If you installed v1.0.0, simply pull the latest changes:

```bash
cd pyIRCX
git pull
```

The new scripts are compatible with existing installations. No configuration changes needed.

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

### New Files

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
