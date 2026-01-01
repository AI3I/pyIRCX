# pyIRCX Cockpit Module

A web-based administration interface for pyIRCX IRC server, integrated with Cockpit.

## Installation

The module is already installed in your user-local Cockpit directory:
```
~/.local/share/cockpit/pyircx/
```

## Enabling Cockpit

1. Enable and start the Cockpit service:
```bash
sudo systemctl enable --now cockpit.socket
```

2. Access Cockpit in your web browser:
```
https://localhost:9090
```

3. Log in with your system credentials

4. Look for "pyIRCX Server" in the menu on the left side

## Features

### Service Management
- View service status (Running/Stopped/Failed)
- Start, Stop, and Restart the pyIRCX service
- View service uptime

### Server Statistics
- Staff member counts by level
- Registered nicknames count
- Registered channels count
- Server access rules (bans/glines)
- Mailbox and memo statistics
- News items count

### Configuration View
- Server name and network
- Port configuration
- SSL status and port

### Staff Management
- View all staff members
- Staff levels displayed with color-coded badges

### Channel Management
- View registered channels
- See channel owners
- Registration and last-used timestamps

### User Registrations
- Recent nickname registrations
- Last-seen information
- MFA status indicators

### Log Viewing
- Real-time log viewing
- Refresh button for manual updates
- Fallback to journalctl if log file unavailable

## Components

- **manifest.json** - Module metadata and configuration
- **index.html** - Main UI structure
- **pyircx.js** - Frontend logic and API calls
- **pyircx.css** - Custom styling
- **api.py** - Python backend for database queries

## API Backend

The `api.py` script provides JSON data from the pyIRCX database:

```bash
# Get server statistics
python3 api.py stats

# Get recent registrations (default 10)
python3 api.py recent-registrations [limit]

# Get registered channels (default 50)
python3 api.py channels [limit]

# Get staff list
python3 api.py staff

# Get server configuration
python3 api.py config
```

## Auto-Refresh

The interface automatically refreshes:
- Service status: every 10 seconds
- Statistics and data: every 30 seconds

## Permissions

The module uses your Cockpit login credentials. Service control operations (start/stop/restart) require sudo privileges and will prompt for elevation through Cockpit's PolicyKit integration.

## Troubleshooting

**Module doesn't appear in Cockpit:**
- Ensure Cockpit is running: `systemctl status cockpit.socket`
- Check module files exist: `ls ~/.local/share/cockpit/pyircx/`
- Clear browser cache and reload

**Database errors:**
- Verify pyIRCX database path in `~/pyIRCX/pyircx_config.json`
- Check database file permissions
- Ensure database file exists at configured path

**Service control fails:**
- Ensure pyircx.service is installed: `systemctl status pyircx.service`
- Verify your user has sudo privileges
- Check PolicyKit configuration

## Development

To modify the module:

1. Edit files in `~/.local/share/cockpit/pyircx/`
2. Reload the page in your browser (Ctrl+Shift+R for hard reload)
3. Check browser console for JavaScript errors
4. Test API calls: `python3 ~/.local/share/cockpit/pyircx/api.py stats`

## Security Notes

- The API only exposes read-only database queries
- Sensitive data (passwords, secrets) are never exposed
- Service management requires proper system permissions
- All data is accessed locally (no external network calls)
