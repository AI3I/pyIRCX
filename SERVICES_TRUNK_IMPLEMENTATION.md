# Centralized Services Hub Implementation

## Overview

pyIRCX now supports **centralized services** using a hub-and-spoke topology. Services (Registrar, Messenger, ServiceBots, etc.) run on a designated hub server, and leaf servers route service requests to the hub.

## Architecture

```
        ┌─────────────────┐
        │   Hub Server    │
        │  (Services Hub) │
        │                 │
        │  - System       │
        │  - Registrar    │
        │  - Messenger    │
        │  - ServiceBots  │
        └────────┬────────┘
                 │
       ┌─────────┼─────────┐
       │         │         │
   ┌───▼───┐ ┌──▼────┐ ┌──▼────┐
   │ Leaf1 │ │ Leaf2 │ │ Leaf3 │
   │       │ │       │ │       │
   │ Users │ │ Users │ │ Users │
   └───────┘ └───────┘ └───────┘
```

## Server Roles

### Hub Server
- **Role:** `"hub"`
- **Purpose:** Hosts services, handles registrations/authentication
- **Services:** Creates all services locally (System, Registrar, Messenger, ServiceBots)
- **Linking:** Accepts connections from leaf servers only
- **Database:** Maintains authoritative registration/authentication data

### Leaf Server
- **Role:** `"leaf"`
- **Purpose:** Handles user connections, routes to hub
- **Services:** Receives service proxies from hub (no local services created)
- **Linking:** Connects to hub server only
- **Database:** Optional local database (not used for services)

### Standalone Server
- **Role:** `"standalone"`
- **Purpose:** Single server, no linking
- **Services:** Creates all services locally
- **Linking:** Cannot link to other servers

## Configuration

### Hub Server Example

```json
{
  "server": {
    "name": "hub.network.com"
  },
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": true,
    "hub_server": null
  },
  "linking": {
    "enabled": true,
    "server_role": "hub",
    "bind_host": "0.0.0.0",
    "bind_port": 7001,
    "links": [
      {
        "name": "leaf1.network.com",
        "host": "leaf1.network.com",
        "port": 7001,
        "password": "$2b$12$...",
        "autoconnect": false
      }
    ]
  }
}
```

### Leaf Server Example

```json
{
  "server": {
    "name": "leaf1.network.com"
  },
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": false,
    "hub_server": "hub.network.com"
  },
  "linking": {
    "enabled": true,
    "server_role": "leaf",
    "bind_host": "0.0.0.0",
    "bind_port": 7001,
    "links": [
      {
        "name": "hub.network.com",
        "host": "hub.network.com",
        "port": 7001,
        "password": "$2b$12$...",
        "autoconnect": true
      }
    ]
  }
}
```

## Link Validation Rules

The system enforces a flat hub-and-spoke topology with these rules:

| My Role      | Remote Role  | Allowed? | Reason                              |
|--------------|--------------|----------|-------------------------------------|
| hub          | leaf         | ✅ Yes   | Standard hub-and-spoke              |
| leaf         | hub          | ✅ Yes   | Standard hub-and-spoke              |
| hub          | hub          | ❌ No    | Prevents multi-tier topology        |
| leaf         | leaf         | ❌ No    | Leaves must connect to hub          |
| standalone   | any          | ❌ No    | Standalone servers don't link       |
| any          | standalone   | ❌ No    | Standalone servers don't link       |

## How It Works

### 1. Server Startup

**Hub Server:**
1. Creates all services locally (System, Registrar, Messenger, ServiceBots)
2. Starts listening on linking port
3. Logs: `Services initialized in centralized mode (services hub)`

**Leaf Server:**
1. Does NOT create services
2. Starts listening on linking port
3. Logs: `Services disabled: Running as leaf server in centralized mode`
4. Logs: `Services will be provided by hub: hub.network.com`

### 2. Server Linking Handshake

**Leaf → Hub:**
```
Leaf sends:  SERVER leaf1.network.com <password> 0 leaf :Description
Hub validates role compatibility (hub ↔ leaf = OK)
Hub responds: SERVER hub.network.com <password> 0 hub :Description
Hub bursts services:
  SVCNICK System 1 <ts> System hub.network.com +s :Network Services
  SVCNICK Registrar 1 <ts> Registrar hub.network.com +s :Registration Services
  SVCNICK Messenger 1 <ts> Messenger hub.network.com +s :Message Services
  SVCNICK ServiceBot01 1 <ts> ServiceBot hub.network.com +s :Service Bot #1
  ...
```

**Leaf receives service proxies:**
- Creates virtual users for each service
- Marks them as `is_service_proxy = True`
- Marks them as `is_remote = True`
- Stores `from_server = "hub.network.com"`

### 3. Service Message Routing

**User on Leaf → Service:**
```
User: /msg Registrar REGISTER mypass
Leaf checks: services_mode = "centralized" AND not services_hub
Leaf routes to hub: :nick!user@host PRIVMSG Registrar :REGISTER mypass
Hub processes: Registrar handles registration
Hub responds: :Registrar!Registrar@hub NOTICE nick :Nickname registered
Leaf receives response
Leaf routes back to user: User receives NOTICE
```

### 4. Service Response Routing

When a service (running on hub) sends a message to a remote user (on leaf):
1. Service calls `user.send(message)`
2. `User.send()` detects `user.is_remote = True`
3. Message is routed through `link_manager` to the leaf server
4. Leaf server delivers message to local user

## Protocol Details

### SERVER Command Format

**New format with role:**
```
SERVER <servername> <password> <hopcount> <role> :<description>
```

**Example:**
```
SERVER hub.network.com secretpass 0 hub :TestNet Hub Server
SERVER leaf1.network.com secretpass 0 leaf :TestNet Leaf Server
```

### SVCNICK Command

**Format:**
```
SVCNICK <nickname> <hopcount> <timestamp> <username> <hostname> <servername> <modes> :<realname>
```

**Example:**
```
SVCNICK Registrar 1 1737001234 Registrar hub.network.com +s :Registration Services
```

**Purpose:** Bursts service users from hub to leaf servers during handshake.

## Service Discovery

On a leaf server, users can discover services via:
- `/msg System` - Lists all available services
- `/HELP` - Shows all commands including service commands
- `/WHOIS Registrar` - Shows service info

Services appear as regular users in `/WHO` (if staff) and `/NAMES #System`.

## Conflict Resolution

**Rule: Hub Always Wins**

- Services only exist on the hub
- Hub maintains authoritative registration database
- Leaf servers have no local services to conflict with
- If hub goes offline, leaves show: "Services temporarily unavailable (hub offline)"

## Failover (Future Enhancement)

**v1.4 planned features:**
- Backup hub configuration
- Automatic failover if primary hub disconnects
- Hub synchronization protocol

## Benefits

1. **Single Source of Truth:** All registration/auth data on hub
2. **Simple Deployment:** Leaves don't need service configuration
3. **Easy Maintenance:** Update services on hub, all leaves benefit
4. **Proven Architecture:** Traditional IRC network model
5. **No Database Replication:** Avoid distributed database complexity

## Limitations

1. **Hub Dependency:** Services unavailable if hub is down
2. **Latency:** Service requests go through network link
3. **Single Hub:** No load balancing (yet)

## Testing

### Local Test Setup

```bash
# Run test script
./test_hub_leaf.sh

# Connect to hub
telnet 127.0.0.1 6667

# Connect to leaf
telnet 127.0.0.1 6668

# From leaf, test service:
NICK testnick
USER test test test :Test User
PRIVMSG Registrar :REGISTER mypassword
```

### Verify Service Routing

**On leaf server logs, you should see:**
```
Routed service message from testnick to Registrar via hub
```

**On hub server logs, you should see:**
```
Registrar: testnick registered with password (hashed)
```

## Troubleshooting

### Error: "Hub-to-Hub linking not allowed"
**Cause:** Both servers configured as `server_role: "hub"`
**Fix:** Set one server to `server_role: "leaf"`

### Error: "Leaf-to-Leaf linking not allowed"
**Cause:** Both servers configured as `server_role: "leaf"`
**Fix:** Set one server to `server_role: "hub"` and configure as services hub

### Error: "Services temporarily unavailable (hub offline)"
**Cause:** Leaf server cannot reach hub
**Fix:**
1. Check hub is running
2. Check linking configuration
3. Verify network connectivity
4. Check firewall rules

### Services not created on leaf
**Expected:** This is correct behavior. Leaves don't create services.
**Verify:** Check logs for "Services disabled: Running as leaf server in centralized mode"

## Migration Guide

### From Standalone to Centralized

**Before:**
```json
{
  "services": {
    "enabled": true,
    "mode": "local"
  },
  "linking": {
    "enabled": false
  }
}
```

**After (Hub):**
```json
{
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": true,
    "hub_server": null
  },
  "linking": {
    "enabled": true,
    "server_role": "hub",
    "bind_port": 7001,
    "links": []
  }
}
```

**After (Leaf):**
```json
{
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": false,
    "hub_server": "hub.network.com"
  },
  "linking": {
    "enabled": true,
    "server_role": "leaf",
    "bind_port": 7001,
    "links": [
      {
        "name": "hub.network.com",
        "host": "hub.network.com",
        "port": 7001,
        "password": "linkpassword",
        "autoconnect": true
      }
    ]
  }
}
```

## Implementation Version

- **Version:** 1.3.0-dev
- **Status:** Testing
- **Date:** 2026-01-16

## Related Files

- `linking.py` - Server linking implementation
- `pyircx.py` - Service creation and routing logic
- `config_hub.json` - Example hub configuration
- `config_leaf.json` - Example leaf configuration
- `test_hub_leaf.sh` - Test script
