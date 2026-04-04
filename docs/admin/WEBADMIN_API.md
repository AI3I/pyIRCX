# pyIRCX WebAdmin API Documentation

**Version:** Current release (see [`../../version.json`](../../version.json))
**Last Updated:** 2026-01-16

## Overview

The pyIRCX webadmin interface provides a REST API for server configuration and management. All API endpoints use JSON for request/response bodies and require authentication.

## Base URL

```
http://your-server/webadmin/api.php
```

## Authentication

The API uses session-based authentication. After logging in through the webadmin interface, your session cookie is used to authenticate API requests.

## Common Response Format

### Success Response
```json
{
    "success": true,
    "data": { ... }
}
```

### Error Response
```json
{
    "success": false,
    "error": "Error message description"
}
```

## API Endpoints

### 1. Get Configuration
**Endpoint:** `get-config`

Retrieves the current server configuration.

**Request:**
```json
{
    "action": "get-config"
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "server": {
            "name": "irc.example.com",
            "network": "ExampleNet",
            "location": "Earth",
            ...
        },
        "limits": {
            "max_users": 1000,
            "max_channels": 500,
            "client_timeout": 300,
            ...
        },
        ...
    }
}
```

**Fields:** Returns complete configuration JSON matching `pyircx_config.json` structure.

---

### 2. Save Configuration
**Endpoint:** `save-config`

Saves configuration changes to `pyircx_config.json`.

**Request:**
```json
{
    "action": "save-config",
    "config": {
        "server": { ... },
        "limits": { ... },
        ...
    }
}
```

**Response:**
```json
{
    "success": true
}
```

**Notes:**
- Validates JSON structure before saving
- Does not restart server (requires manual restart or reload command)
- Creates backup of previous config

---

### 3. Get Access Lists
**Endpoint:** `get-access`

Retrieves server-level access lists (GRANT and DENY).

**Request:**
```json
{
    "action": "get-access"
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "grant": [
            {
                "mask": "*@trusted.domain.com",
                "reason": "Trusted users",
                "added": "2026-01-15T10:30:00",
                "added_by": "admin"
            }
        ],
        "deny": [
            {
                "mask": "spammer@*",
                "reason": "Known spammer",
                "added": "2026-01-16T09:15:00",
                "added_by": "sysop"
            }
        ]
    }
}
```

---

### 4. Add Access Entry
**Endpoint:** `add-access`

Adds an entry to GRANT or DENY access list.

**Request:**
```json
{
    "action": "add-access",
    "type": "deny",
    "mask": "*@spamhaus.org",
    "reason": "Spam source"
}
```

**Parameters:**
- `type`: `"grant"` or `"deny"`
- `mask`: Hostmask pattern (e.g., `nick!user@host`)
- `reason`: Optional reason string

**Response:**
```json
{
    "success": true
}
```

---

### 5. Delete Access Entry
**Endpoint:** `delete-access`

Removes an entry from GRANT or DENY access list.

**Request:**
```json
{
    "action": "delete-access",
    "type": "deny",
    "mask": "*@spamhaus.org"
}
```

**Parameters:**
- `type`: `"grant"` or `"deny"`
- `mask`: Exact hostmask to remove

**Response:**
```json
{
    "success": true
}
```

---

### 6. Get MOTD
**Endpoint:** `get-motd`

Retrieves the Message of the Day text.

**Request:**
```json
{
    "action": "get-motd"
}
```

**Response:**
```json
{
    "success": true,
    "data": "Welcome to pyIRCX!\n\nServer rules:\n1. Be respectful\n..."
}
```

**Notes:**
- Preserves whitespace and newlines
- Returns empty string if MOTD file doesn't exist

---

### 7. Save MOTD
**Endpoint:** `save-motd`

Saves Message of the Day text to file.

**Request:**
```json
{
    "action": "save-motd",
    "content": "Welcome to pyIRCX!\n\nNew MOTD text..."
}
```

**Response:**
```json
{
    "success": true
}
```

**Notes:**
- Overwrites existing MOTD file
- Whitespace is preserved
- Requires manual server reload to take effect

---

### 8. Get Server Stats
**Endpoint:** `get-stats`

Retrieves real-time server statistics.

**Request:**
```json
{
    "action": "get-stats"
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "users": {
            "current": 42,
            "max": 150,
            "peak": 200
        },
        "channels": {
            "current": 15,
            "registered": 8
        },
        "uptime": {
            "seconds": 86400,
            "formatted": "1d 0h 0m"
        },
        "commands_processed": 15420,
        "connections_total": 312
    }
}
```

---

### 9. Reload Server
**Endpoint:** `reload-server`

Sends reload command to running server (via socket).

**Request:**
```json
{
    "action": "reload-server"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Server reload command sent"
}
```

**Notes:**
- Reloads config without disconnecting users
- Reloads MOTD, access lists, and profanity filters
- Does not reload SSL certificates (requires full restart)

---

### 10. Get Logs
**Endpoint:** `get-logs`

Retrieves recent server log entries.

**Request:**
```json
{
    "action": "get-logs",
    "lines": 100,
    "level": "INFO"
}
```

**Parameters:**
- `lines`: Number of recent log lines (default: 100, max: 1000)
- `level`: Optional filter (`DEBUG`, `INFO`, `WARNING`, `ERROR`)

**Response:**
```json
{
    "success": true,
    "data": {
        "lines": [
            "[2026-01-16 10:30:15] INFO: User alice joined #lobby",
            "[2026-01-16 10:30:20] WARNING: Failed login attempt from 192.168.1.100"
        ],
        "total": 2
    }
}
```

---

### 11. Test Config
**Endpoint:** `test-config`

Validates configuration JSON without saving.

**Request:**
```json
{
    "action": "test-config",
    "config": {
        "server": { ... },
        ...
    }
}
```

**Response (Valid):**
```json
{
    "success": true,
    "valid": true
}
```

**Response (Invalid):**
```json
{
    "success": true,
    "valid": false,
    "errors": [
        "server.port must be between 1-65535",
        "limits.max_users must be positive integer"
    ]
}
```

---

### 12. Get Staff Accounts
**Endpoint:** `get-staff`

Retrieves list of staff accounts from database.

**Request:**
```json
{
    "action": "get-staff"
}
```

**Response:**
```json
{
    "success": true,
    "data": [
        {
            "username": "admin",
            "level": "ADMIN",
            "created": "2026-01-01T00:00:00"
        },
        {
            "username": "moderator",
            "level": "SYSOP",
            "created": "2026-01-10T12:00:00"
        }
    ]
}
```

---

## Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 400 | Bad Request (invalid JSON or missing parameters) |
| 401 | Unauthorized (not logged in) |
| 403 | Forbidden (insufficient permissions) |
| 500 | Internal Server Error |

## Security Considerations

### Authentication
- Session-based authentication required for all endpoints
- Session timeout after 30 minutes of inactivity
- HTTPS strongly recommended for production

### Input Validation
- All inputs are sanitized and validated
- JSON structure is strictly validated
- File paths are restricted to safe directories
- Hostmasks are validated against regex patterns

### Rate Limiting
- API requests limited to 100 per minute per session
- Reload commands limited to 1 per minute

### Permissions
- Access lists require SYSOP level or higher
- Configuration changes require ADMIN level
- MOTD editing requires SYSOP level
- Log viewing requires SYSOP level

## Common Usage Examples

### JavaScript (Fetch API)

```javascript
// Get configuration
async function getConfig() {
    const response = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'get-config' })
    });
    const data = await response.json();
    return data.data;
}

// Save configuration
async function saveConfig(config) {
    const response = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            action: 'save-config',
            config: config
        })
    });
    return await response.json();
}

// Add deny entry
async function blockUser(mask, reason) {
    const response = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            action: 'add-access',
            type: 'deny',
            mask: mask,
            reason: reason
        })
    });
    return await response.json();
}
```

### Python (requests)

```python
import requests

API_URL = 'http://irc.example.com/webadmin/api.php'
session = requests.Session()

# Login first (establish session)
# session.post(...login...)

# Get configuration
response = session.post(API_URL, json={'action': 'get-config'})
config = response.json()['data']

# Update config
config['server']['name'] = 'new.server.com'
response = session.post(API_URL, json={
    'action': 'save-config',
    'config': config
})

# Reload server
response = session.post(API_URL, json={'action': 'reload-server'})
```

## Changelog

### v1.2.0 (2026-01-16)
- Initial API documentation
- Added support for all configuration sections
- Added access list management endpoints
- Added MOTD management endpoints
- Added server stats and log viewing

## Support

For API issues or questions:
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
- Documentation: docs/admin/MANUAL.md
