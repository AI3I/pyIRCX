# Phase 2: Complete Server Linking Commands

## Scope
Ensure ALL user, channel, staff, and network commands work correctly across server links.

## Command Categories

### 1. Channel Commands
- [x] JOIN - ✅ Working (Phase 1)
- [x] PART - ✅ Working (Phase 1)
- [x] PRIVMSG (channel) - ✅ Working (Phase 1)
- [ ] **TOPIC** - Propagate topic changes
- [ ] **KICK** - Propagate kicks
- [ ] **INVITE** - Propagate invites
- [ ] **MODE** (channel) - Propagate channel mode changes
- [ ] **NAMES** - Show users from all servers
- [ ] **LIST** - Show channels from all servers
- [ ] **WHO** - Query users in channel across servers

### 2. User Commands
- [x] PRIVMSG (user-to-user) - ✅ Working (Phase 1)
- [x] QUIT - ✅ Working (Phase 1)
- [ ] **WHOIS** - Query user info across servers
- [ ] **WHOWAS** - Query disconnected users across servers
- [ ] **WHO** - Query users matching pattern
- [ ] **USERHOST** - Get user@host for remote users
- [ ] **USERIP** - Get IP for remote users (if allowed)
- [ ] **MODE** (user) - Propagate user mode changes
- [ ] **NICK** (change) - Propagate nickname changes
- [ ] **AWAY** - Propagate away status

### 3. Staff Commands
- [ ] **KILL** - Network-wide kill (terminate user on any server)
- [ ] **GLINE** - Network-wide ban
- [ ] **GAG/UNGAG** - Network-wide gag
- [ ] **STAFF** commands - Work with remote staff members
- [ ] **OPER** - Propagate oper status

### 4. Network Commands
- [ ] **LINKS** - Show all linked servers
- [ ] **MAP** - Show server topology
- [ ] **LUSERS** - Show network-wide user counts
- [ ] **MOTD** - Access MOTD from other servers
- [ ] **ADMIN** - Access admin info from other servers
- [ ] **INFO** - Access server info from other servers
- [ ] **STATS** - Query stats from other servers
- [ ] **VERSION** - Query version from other servers

### 5. IRCX-Specific Commands
- [ ] **ACCESS** - Propagate channel access lists
- [ ] **PROP** - Propagate channel properties
- [ ] **WHISPER** - Propagate whispers in channels
- [ ] **DATA** - Propagate data messages
- [ ] **EVENT** - Propagate events
- [ ] **IRCX** authentication - Work across servers

## Implementation Priority

### Phase 2A (High Priority - Core Functionality)
1. TOPIC propagation
2. KICK propagation
3. MODE propagation (channel & user)
4. NICK change propagation
5. Network-wide KILL

### Phase 2B (Medium Priority - User Experience)
6. WHOIS routing
7. WHO routing
8. NAMES (cross-server)
9. INVITE propagation
10. AWAY propagation

### Phase 2C (Lower Priority - Advanced Features)
11. LINKS/MAP display
12. LUSERS aggregation
13. ACCESS/PROP propagation
14. WHISPER propagation
15. Remote server queries (MOTD, ADMIN, INFO, STATS, VERSION)

## Testing Strategy

For each command:
1. Test local user → local user (baseline)
2. Test local user → remote user (cross-server)
3. Test remote user → local user (reverse)
4. Test remote user → remote user (via hub)
5. Test channel operations with mixed local/remote members
6. Test error conditions (user not found, permission denied, etc.)

## Success Criteria

✅ All commands work identically whether users are local or remote
✅ No permission bypass via server links
✅ No information leakage across servers
✅ Consistent behavior with standalone server
✅ Proper error messages for remote operations
✅ No message loops or duplicates
✅ Performance acceptable (minimal latency)

## Notes

- Commands MUST respect original server's permissions and modes
- Staff commands MUST verify staff level across servers
- Channel modes MUST be consistent across servers
- User modes MUST propagate correctly
- Services MUST work with remote users (already tested in Phase 1)
