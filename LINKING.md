# pyIRCX Server Linking Protocol

## Overview

pyIRCX uses a custom server-to-server linking protocol designed specifically for IRCX features.

## Configuration

Add to `pyircx_config.json`:

```json
{
  "linking": {
    "enabled": true,
    "bind_host": "0.0.0.0",
    "bind_port": 7000,
    "links": [
      {
        "name": "hub.example.com",
        "host": "hub.example.com",
        "port": 7000,
        "password": "secure-link-password",
        "autoconnect": true
      }
    ]
  }
}
```

## Protocol

### Handshake

**Outgoing connection (initiator):**
```
SERVER <servername> <password> <hopcount> :<description>
```

**Response from receiving server:**
```
SERVER <servername> <password> <hopcount> :<description>
```

### State Burst

After successful handshake, both servers exchange full state:

**User introduction:**
```
NICK <nickname> <hopcount> <timestamp> <username> <hostname> <servername> <modes> :<realname>
```

**Channel sync:**
```
SJOIN <timestamp> <channel> <modes> :<prefixed-nicklist>
```
- Prefixed nicklist: `@nick1 +nick2 nick3` (@ = op, + = voice)

**Channel topic:**
```
TOPIC <channel> <setter> <timestamp> :<topic>
```

### Runtime Messages

**User actions (routed):**
```
:nickname PRIVMSG target :message
:nickname JOIN #channel
:nickname PART #channel :reason
:nickname QUIT :reason
:nickname NICK newnick
```

**Server commands:**
```
SQUIT <servername> :reason
PING <source> <target>
PONG <source> <target>
```

## Message Routing

- Messages from local users: Broadcast to all linked servers
- Messages from remote servers: Route only to destination or broadcast
- No loops: Track message origin, don't send back to source

## Collision Handling

**Nick collision:**
- Timestamp wins (older keeps nick)
- Tie: Alphabetically lower servername wins

**Channel timestamp:**
- Older timestamp = authoritative
- Merge modes/ops based on timestamp

## Splits (Netsplits)

When a server disconnects:
1. Send SQUIT to remaining servers
2. QUIT all users from that server
3. Clean up empty channels
4. Log the split

## Security

- Password authentication for each link
- Optional: IP whitelisting
- All admin commands (CONNECT, SQUIT) require ADMIN/SYSOP level
