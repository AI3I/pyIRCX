# SELinux Configuration for pyIRCX

## Overview

This document provides comprehensive SELinux configuration for pyIRCX on RHEL, Fedora, CentOS, and other SELinux-enabled systems.

## Required SELinux Contexts

### `/opt/pyircx/` - Main Installation Directory

**Context:** `httpd_sys_rw_content_t` (read-write for web admin API access)

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?"
sudo restorecon -Rv /opt/pyircx
```

**Files:**
- `pyircx.py` - Main server (needs read for web admin status)
- `api.py` - Web admin API (needs execute by web server)
- `linking.py` - Server linking module
- `pyircx.db` - Main database (needs read-write by web admin)
- `pyircx.log` - Log file (needs read-write)
- `pyircx_status.json` - Status file (needs read-write)
- `__pycache__/` - Python cache directory

### `/opt/pyircx/webchat/` - WebChat Gateway

**Context:** `httpd_sys_rw_content_t` (gateway runtime files accessed alongside the web stack)

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx/webchat(/.*)?"
sudo restorecon -Rv /opt/pyircx/webchat
```

**Files:**
- `gateway.py` - WebSocket gateway (executed by systemd)
- `index.html` - WebChat HTML interface source

### `/opt/pyircx/transcripts/` - Channel Transcripts

**Context:** `httpd_sys_rw_content_t` (read-write by server and web admin)

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx/transcripts(/.*)?"
sudo restorecon -Rv /opt/pyircx/transcripts
```

### `/etc/pyircx/` - Configuration Directory

**Context:** `httpd_sys_rw_content_t` (read-write for web admin config editor)

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?"
sudo restorecon -Rv /etc/pyircx
```

**Files:**
- `pyircx_config.json` - Main configuration source of truth (real file in `/etc`, symlinked from `/opt/pyircx`)

**Exception:** `webchat.conf` needs different context for systemd:

```bash
sudo semanage fcontext -a -t etc_t "/etc/pyircx/webchat.conf"
sudo restorecon -v /etc/pyircx/webchat.conf
```

### `/var/www/html/webadmin/` - Web Administration Panel

**Context:** `httpd_sys_rw_content_t` (read-write for API operations)

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?"
sudo restorecon -Rv /var/www/html/webadmin
```

**Files:**
- `index.php` - Main admin interface
- `login.php` - Login page
- `logout.php` - Logout handler
- `api.php` - PHP API router
- `admin.js` - JavaScript frontend
- `style.css` - Stylesheets
- `.htaccess` - Apache configuration
- `README.md`, `INSTALL.md` - Documentation

### `/var/www/html/webchat/` - WebChat Frontend

**Context:** `httpd_sys_content_t` (read-only, standard web content)

```bash
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/html/webchat(/.*)?"
sudo restorecon -Rv /var/www/html/webchat
```

**Files:**
- `index.html` - WebChat HTML interface
- `config.js` - WebChat configuration file (can be customized)
- `favicon.svg` - Icon file
- `version.json` - Shared version metadata for CTCP/version display

## Quick Reference Table

| Path | Context | Reason |
|------|---------|--------|
| `/opt/pyircx/` | `httpd_sys_rw_content_t` | API access, status files |
| `/opt/pyircx/webchat/` | `httpd_sys_rw_content_t` | Symlink target |
| `/opt/pyircx/transcripts/` | `httpd_sys_rw_content_t` | Web admin read access |
| `/etc/pyircx/` | `httpd_sys_rw_content_t` | Config editor |
| `/etc/pyircx/webchat.conf` | `etc_t` | WebChat gateway config |
| `/var/www/html/webadmin/` | `httpd_sys_rw_content_t` | API operations |
| `/var/www/html/webchat/` | `httpd_sys_content_t` | Static content |

## Complete Setup Script

Run this script after installing pyIRCX to configure all SELinux contexts:

```bash
#!/bin/bash
# SELinux setup for pyIRCX

# Main installation directory (read-write for web admin)
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?"
sudo restorecon -Rv /opt/pyircx

# Configuration directory (read-write for web admin)
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?"
sudo restorecon -Rv /etc/pyircx

# WebChat config (gateway INI config)
sudo semanage fcontext -a -t etc_t "/etc/pyircx/webchat.conf"
sudo restorecon -v /etc/pyircx/webchat.conf

# Web admin (read-write for API operations)
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?"
sudo restorecon -Rv /var/www/html/webadmin

# WebChat frontend (read-only static content)
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/html/webchat(/.*)?"
sudo restorecon -Rv /var/www/html/webchat

echo "SELinux contexts configured successfully"
```

## Verification

Verify all contexts are correct:

```bash
# Check /opt/pyircx
ls -Z /opt/pyircx/ | head -10

# Check /etc/pyircx
ls -Z /etc/pyircx/

# Check web directories
ls -Z /var/www/html/webadmin/ | head -10
ls -Z /var/www/html/webchat/
```

Expected output should show:
- `httpd_sys_rw_content_t` for writable directories
- `httpd_sys_content_t` for static web content
- `etc_t` for webchat.conf

## Troubleshooting

### Permission Denied Errors

Check audit logs for SELinux denials:

```bash
sudo ausearch -m avc -ts recent
```

Common issues:
- Wrong context on config files: Use `httpd_sys_rw_content_t` for `/etc/pyircx/`
- Wrong context on web admin: Use `httpd_sys_rw_content_t` not `httpd_sys_content_t`
- Wrong context on webchat.conf: Must be `etc_t` for systemd

### Restoring Contexts

If contexts get corrupted:

```bash
# Restore all contexts based on policy
sudo restorecon -Rv /opt/pyircx
sudo restorecon -Rv /etc/pyircx
sudo restorecon -Rv /var/www/html/webadmin
sudo restorecon -Rv /var/www/html/webchat
```

### Removing Old Contexts

If you need to remove and re-add contexts:

```bash
# Remove old context
sudo semanage fcontext -d "/opt/pyircx(/.*)?"

# Add new context
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?"

# Apply
sudo restorecon -Rv /opt/pyircx
```

## SELinux Booleans

pyIRCX does not require any SELinux booleans to be enabled beyond the default httpd permissions. The contexts above are sufficient.

## Integration with install.sh

The `install.sh` script automatically configures all SELinux contexts. If you're installing manually, use the complete setup script above.

## Version History

- **v2.0.1** - Updated for `/etc` config source-of-truth and static WebChat assets
- Clarified that `/var/www/html/webchat/` serves copied frontend files, including `version.json`
- **v2.0.0** - Initial comprehensive SELinux documentation
- Added webchat.conf special handling for systemd
- Fixed webadmin contexts (httpd_sys_rw_content_t required)

---

For questions or issues, see: https://github.com/0x8007000E/pyIRCX
