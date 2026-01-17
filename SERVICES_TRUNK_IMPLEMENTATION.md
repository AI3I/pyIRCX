# Centralized Services Trunk Implementation

## Overview

pyIRCX now supports **centralized services** using a trunk-and-branch topology. Services (Registrar, Messenger, ServiceBots, etc.) run on a designated trunk server, and branch servers route service requests to the trunk.

## Architecture

```
        ┌──────────────────────┐
        │   Trunk Server       │
        │  (Services Trunk)    │
        │                      │
        │  - System            │
        │  - Registrar         │
        │  - Messenger         │
        │  - ServiceBots       │
        │  - Staff Auth        │
        └──────────┬───────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
   ┌───▼────┐  ┌──▼─────┐  ┌──▼─────┐
   │Branch1 │  │Branch2 │  │Branch3 │
   │        │  │        │  │        │
   │ Users  │  │ Users  │  │ Users  │
   └────────┘  └────────┘  └────────┘
```

## Server Roles

### Trunk Server
- **Role:** `"trunk"`
- **Purpose:** Hosts services, handles registrations and staff authentication
- **Services:** Creates all services locally (System, Registrar, Messenger, ServiceBots)
- **Staff Auth:** Validates staff credentials against local database
- **Linking:** Accepts connections from branch servers only
- **Database:** Maintains authoritative registration and staff authentication data

### Branch Server
- **Role:** `"branch"`
- **Purpose:** Handles user connections, routes to trunk
- **Services:** Receives service proxies from trunk (no local services created)
- **Staff Auth:** Routes staff authentication requests to trunk
- **Linking:** Connects to trunk server only
- **Database:** Optional local database (not used for services or staff auth)

### Standalone Server
- **Role:** `"standalone"`
- **Purpose:** Single server, no linking
- **Services:** Creates all services locally
- **Staff Auth:** Validates credentials locally
- **Linking:** Cannot link to other servers

## Configuration

### Trunk Server Example

```json
{
  "server": {
    "name": "trunk.testnet.local",
    "network": "TestNet"
  },
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": true,
    "hub_server": null,
    "servicebot_count": 5
  },
  "linking": {
    "enabled": true,
    "server_role": "trunk",
    "bind_host": "127.0.0.1",
    "bind_port": 7001,
    "links": [
      {
        "name": "branch.testnet.local",
        "host": "127.0.0.1",
        "port": 7002,
        "password": "testlink123",
        "autoconnect": false
      }
    ]
  }
}
```

### Branch Server Example

```json
{
  "server": {
    "name": "branch.testnet.local",
    "network": "TestNet"
  },
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": false,
    "hub_server": "trunk.testnet.local",
    "servicebot_count": 0
  },
  "linking": {
    "enabled": true,
    "server_role": "branch",
    "bind_host": "127.0.0.1",
    "bind_port": 7002,
    "links": [
      {
        "name": "trunk.testnet.local",
        "host": "127.0.0.1",
        "port": 7001,
        "password": "testlink123",
        "autoconnect": true
      }
    ]
  }
}
```

## Link Validation Rules

The system enforces a flat trunk-and-branch topology with these rules:

| My Role      | Remote Role  | Allowed? | Reason                              |
|--------------|--------------|----------|-------------------------------------|
| trunk        | branch       | ✅ Yes   | Standard trunk-and-branch           |
| branch       | trunk        | ✅ Yes   | Standard trunk-and-branch           |
| trunk        | trunk        | ❌ No    | Prevents multi-tier topology        |
| branch       | branch       | ❌ No    | Branches must connect to trunk      |
| standalone   | any          | ❌ No    | Standalone servers don't link       |
| any          | standalone   | ❌ No    | Standalone servers don't link       |

## How It Works

### 1. Server Startup

**Trunk Server:**
1. Creates all services locally (System, Registrar, Messenger, ServiceBots)
2. Initializes staff authentication database
3. Starts listening on linking port
4. Logs: `Services initialized in centralized mode (services hub)`

**Branch Server:**
1. Does NOT create services
2. Starts listening on linking port
3. Logs: `Services disabled: Running as branch server in centralized mode`
4. Logs: `Services will be provided by trunk: trunk.testnet.local`

### 2. Server Linking Handshake

**Branch → Trunk:**
```
Branch sends:  SERVER branch.testnet.local <password> 0 branch :Description
Trunk validates role compatibility (trunk ↔ branch = OK)
Trunk responds: SERVER trunk.testnet.local <password> 0 trunk :Description
Trunk bursts services:
  SVCNICK System 1 <ts> System trunk.testnet.local +s :Network Services
  SVCNICK Registrar 1 <ts> Registrar trunk.testnet.local +s :Registration Services
  SVCNICK Messenger 1 <ts> Messenger trunk.testnet.local +s :Message Services
  SVCNICK ServiceBot01 1 <ts> ServiceBot trunk.testnet.local +s :Service Bot #1
  ...
```

**Branch receives service proxies:**
- Creates virtual users for each service
- Marks them as `is_service_proxy = True`
- Marks them as `is_remote = True`
- Stores `from_server = "trunk.testnet.local"`

### 3. Service Message Routing

**User on Branch → Service:**
```
User: /msg Registrar REGISTER mypass
Branch checks: services_mode = "centralized" AND not services_hub
Branch routes to trunk: :nick!user@host PRIVMSG Registrar :REGISTER mypass
Trunk processes: Registrar handles registration
Trunk responds: :Registrar!Registrar@trunk NOTICE nick :Nickname registered
Branch receives response
Branch routes back to user: User receives NOTICE
```

### 4. Service Response Routing

When a service (running on trunk) sends a message to a remote user (on branch):
1. Service calls `user.send(message)`
2. `User.send()` detects `user.is_remote = True`
3. Message is routed through `link_manager` to the branch server
4. Branch server delivers message to local user

### 5. Staff Authentication Routing

**User on Branch authenticates as staff:**
```
User connects to branch: PASS mypassword
Branch checks: services_mode = "centralized" AND not services_hub
Branch routes to trunk: STAFFAUTH <uuid> admin mypassword
Trunk validates: Checks local database, verifies bcrypt hash
Trunk responds: STAFFOK <uuid> ADMIN admin@example.com "Admin Name" 1
Branch receives response
Branch applies modes: Sets user.level = "ADMIN", grants staff modes
User sees: Successfully authenticated as ADMIN
```

**Authentication failure:**
```
Branch routes: STAFFAUTH <uuid> baduser wrongpass
Trunk validates: User not found or password mismatch
Trunk responds: STAFFFAIL <uuid>
Branch receives: Authentication denied
User sees: "Invalid username or password"
```

**Timeout handling:**
```
If trunk doesn't respond within 5 seconds:
- Branch times out the auth request
- User authentication fails
- Logs: "Staff auth timeout for username"
```

## Protocol Details

### SERVER Command Format

**New format with role:**
```
SERVER <servername> <password> <hopcount> <role> :<description>
```

**Example:**
```
SERVER trunk.testnet.local secretpass 0 trunk :TestNet Trunk Server
SERVER branch.testnet.local secretpass 0 branch :TestNet Branch Server
```

### SVCNICK Command

**Format:**
```
SVCNICK <nickname> <hopcount> <timestamp> <username> <hostname> <servername> <modes> :<realname>
```

**Example:**
```
SVCNICK Registrar 1 1737001234 Registrar trunk.testnet.local +s :Registration Services
```

**Purpose:** Bursts service users from trunk to branch servers during handshake.

### STAFFAUTH Command

**Format:**
```
STAFFAUTH <auth_id> <username> <password>
```

**Example:**
```
STAFFAUTH a1b2c3d4 admin mypassword
```

**Direction:** Branch → Trunk
**Purpose:** Request staff authentication from trunk server. The auth_id is a unique identifier (UUID) used to match the response.

### STAFFOK Command

**Format:**
```
STAFFOK <auth_id> <level> <email> <realname> <force_realname>
```

**Example:**
```
STAFFOK a1b2c3d4 ADMIN admin@example.com "Admin User" 1
```

**Direction:** Trunk → Branch
**Purpose:** Indicate successful staff authentication. Returns user level, email, realname, and force_realname flag (0 or 1).

### STAFFFAIL Command

**Format:**
```
STAFFFAIL <auth_id>
```

**Example:**
```
STAFFFAIL a1b2c3d4
```

**Direction:** Trunk → Branch
**Purpose:** Indicate failed staff authentication (user not found or password mismatch).

## Service Discovery

On a branch server, users can discover services via:
- `/msg System` - Lists all available services
- `/HELP` - Shows all commands including service commands
- `/WHOIS Registrar` - Shows service info

Services appear as regular users in `/WHO` (if staff) and `/NAMES #System`.

## Conflict Resolution

**Rule: Trunk Always Wins**

- Services only exist on the trunk
- Trunk maintains authoritative registration and staff authentication database
- Branch servers have no local services or staff auth to conflict with
- If trunk goes offline, branches show: "Services temporarily unavailable (trunk offline)"

## Failover (Future Enhancement)

**v1.4 planned features:**
- Backup trunk configuration
- Automatic failover if primary trunk disconnects
- Trunk synchronization protocol

## Benefits

1. **Single Source of Truth:** All registration and staff auth data on trunk
2. **Simple Deployment:** Branches don't need service or staff configuration
3. **Easy Maintenance:** Update services on trunk, all branches benefit
4. **Proven Architecture:** Traditional IRC network model
5. **No Database Replication:** Avoid distributed database complexity
6. **Centralized Staff Management:** Consistent staff permissions across network

## Limitations

1. **Trunk Dependency:** Services and staff auth unavailable if trunk is down
2. **Latency:** Service and auth requests go through network link
3. **Single Trunk:** No load balancing (yet)

## Testing

### Local Test Setup

```bash
# Run test script
./test_trunk_branch.sh

# Connect to trunk
telnet 127.0.0.1 6667

# Connect to branch
telnet 127.0.0.1 6668

# From branch, test service:
NICK testnick
USER test test test :Test User
PRIVMSG Registrar :REGISTER mypassword

# From branch, test staff auth:
PASS adminpassword
NICK staffuser
USER staff staff staff :Staff User
```

### Verify Service Routing

**On branch server logs, you should see:**
```
Routed service message from testnick to Registrar via trunk
```

**On trunk server logs, you should see:**
```
Registrar: testnick registered with password (hashed)
```

### Verify Staff Authentication

**On branch server logs, you should see:**
```
Sent staff auth request to trunk: staffuser (id: a1b2c3d4)
Staff auth via trunk: staffuser as ADMIN
```

**On trunk server logs, you should see:**
```
Trunk: Staff auth SUCCESS for staffuser (ADMIN)
```

## Troubleshooting

### Error: "Trunk-to-Trunk linking not allowed"
**Cause:** Both servers configured as `server_role: "trunk"`
**Fix:** Set one server to `server_role: "branch"`

### Error: "Branch-to-Branch linking not allowed"
**Cause:** Both servers configured as `server_role: "branch"`
**Fix:** Set one server to `server_role: "trunk"` and configure as services hub

### Error: "Services temporarily unavailable (trunk offline)"
**Cause:** Branch server cannot reach trunk
**Fix:**
1. Check trunk is running
2. Check linking configuration
3. Verify network connectivity
4. Check firewall rules

### Services not created on branch
**Expected:** This is correct behavior. Branches don't create services.
**Verify:** Check logs for "Services disabled: Running as branch server in centralized mode"

### Staff authentication failing on branch
**Cause:** Branch cannot route auth request to trunk
**Fix:**
1. Verify trunk is running and linked
2. Check trunk has staff database initialized
3. Verify credentials exist on trunk server
4. Check trunk logs for auth attempts
5. Verify network connectivity between servers

### Error: "Staff auth timeout for username"
**Cause:** Trunk didn't respond to STAFFAUTH within 5 seconds
**Fix:**
1. Check trunk server load and performance
2. Verify network latency is acceptable
3. Check trunk logs for errors processing auth
4. Verify trunk database is accessible

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

**After (Trunk):**
```json
{
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": true,
    "hub_server": null,
    "servicebot_count": 5
  },
  "linking": {
    "enabled": true,
    "server_role": "trunk",
    "bind_host": "127.0.0.1",
    "bind_port": 7001,
    "links": []
  }
}
```

**After (Branch):**
```json
{
  "services": {
    "enabled": true,
    "mode": "centralized",
    "is_services_hub": false,
    "hub_server": "trunk.testnet.local",
    "servicebot_count": 0
  },
  "linking": {
    "enabled": true,
    "server_role": "branch",
    "bind_host": "127.0.0.1",
    "bind_port": 7002,
    "links": [
      {
        "name": "trunk.testnet.local",
        "host": "127.0.0.1",
        "port": 7001,
        "password": "testlink123",
        "autoconnect": true
      }
    ]
  }
}
```

**Key Migration Steps:**
1. **Choose your trunk server** - Pick one server to host services and staff auth
2. **Migrate staff database** - Copy `users` table from branches to trunk (if needed)
3. **Update configurations** - Set roles and linking parameters
4. **Start trunk first** - Ensure trunk is running before starting branches
5. **Test authentication** - Verify staff can auth through branches
6. **Test services** - Verify services accessible from all branches

## Implementation Version

- **Version:** 1.3.0-dev
- **Status:** Testing
- **Date:** 2026-01-16

## Related Files

- `linking.py` - Server linking and staff authentication routing
- `pyircx.py` - Service creation, routing, and staff auth logic
- `config_trunk.json` - Example trunk configuration
- `config_branch.json` - Example branch configuration
- `test_trunk_branch.sh` - Test script for trunk-branch setup
