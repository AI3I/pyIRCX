# pyIRCX Web Admin

The Web Admin panel is the supported browser-based management interface for pyIRCX.

## Overview

- Runs on a standard PHP-capable web server
- Uses [`api.php`](/home/jdlewis/GitHub/pyIRCX/webadmin/api.php) as a thin router to [`api.py`](/home/jdlewis/GitHub/pyIRCX/api.py)
- Authenticates with IRC staff accounts
- Supports service control, configuration edits, and day-to-day network administration

## Main Areas

- Dashboard: live stats, service status, linked server state
- Users: connected and registered users
- Channels: active and registered channels
- Staff: add/remove staff, level changes, password resets
- Access: deny/grant management
- NewsFlash: announcements and broadcast settings
- Mailbox: recent memo visibility
- Config: MOTD and JSON configuration editing
- Logs: journal-backed log viewing

## Security Model

- Session auth with absolute and idle expiry
- CSRF protection on API operations
- Password-bearing admin actions sent to the backend over stdin, not argv
- Polkit-based service control for `pyircx.service`
- Group-based access to shared runtime/config files
- SELinux-compatible deployment model

## Deployment Notes

- Web root: usually `/var/www/html/webadmin/`
- Backend API path: usually `/opt/pyircx/api.py`
- Shared config source of truth: `/etc/pyircx/pyircx_config.json`
- Runtime compatibility path: `/opt/pyircx/pyircx_config.json` symlinked to `/etc`

See [`INSTALL.md`](/home/jdlewis/GitHub/pyIRCX/webadmin/INSTALL.md) for installation details.
