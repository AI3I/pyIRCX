# Staff Account Quick Reference

## Current Production Accounts

| Username | Level | Password  | Purpose                    |
|----------|-------|-----------|----------------------------|
| admin    | ADMIN | changeme  | Primary administrator      |
| sysop    | SYSOP | sysop123  | System operator example    |
| guide    | GUIDE | guide123  | Helper/guide example       |

⚠️ **SECURITY WARNING:** Change all passwords before production use!

## Staff Commands Quick Reference

### Authentication
```
/STAFF LOGIN <username> <password>  - Login as staff
/STAFF LOGOUT                        - Logout from staff session
```

### Password Management
```
/STAFF PASS <new-password>           - Change your own password
/STAFF PASS <username> <new-password>    - Change another user's password (ADMIN only)
```

### Account Management (ADMIN only)
```
/STAFF ADD <username> <password> <level>  - Create new staff account
                                            Levels: ADMIN, SYSOP, GUIDE
/STAFF DEL <username>                     - Delete staff account
/STAFF LIST                               - List all staff accounts
/STAFF LEVEL <username> <new-level>       - Change user's privilege level
```

### Server Management
```
/STAFF REHASH        - Reload configuration
/STAFF SHUTDOWN      - Shutdown server (ADMIN only)
/STAFF CONNECT <servername> - Link to another server (ADMIN/SYSOP)
/STAFF SQUIT <servername>   - Unlink from server (ADMIN/SYSOP)
```

## Privilege Levels

### ADMIN (Highest)
- Full access to all commands
- Can manage other staff accounts
- Can shutdown/restart server
- Can modify server configuration
- Can link/unlink servers

### SYSOP (Medium)
- Can kick/ban users
- Can manage channels
- Can link/unlink servers
- Cannot manage staff accounts
- Cannot shutdown server

### GUIDE (Basic)
- Can help users
- Limited administrative access
- Cannot kick/ban
- Cannot link servers
- Cannot manage staff accounts

## Initial Setup Example

After server deployment, immediately:

```
1. Connect to IRC server
   /SERVER irc.local

2. Login as admin
   /STAFF LOGIN admin changeme

3. Change password
   /STAFF PASS MyStr0ngP@ssw0rd!

4. (Optional) Create your personal admin account
   /STAFF ADD myname SecurePass123! ADMIN

5. Logout and login with new credentials
   /STAFF LOGOUT
   /STAFF LOGIN myname SecurePass123!

6. (Optional) Delete example accounts if not needed
   /STAFF DEL sysop
   /STAFF DEL guide
```

## Security Best Practices

✅ Change all default passwords immediately  
✅ Use strong passwords (12+ characters, mixed case, numbers, symbols)  
✅ Delete unused staff accounts  
✅ Use SYSOP level for trusted operators (not ADMIN)  
✅ Use GUIDE level for helpers (not SYSOP)  
✅ Regularly audit staff account list with `/STAFF LIST`  
✅ Never share staff credentials  

## Troubleshooting

**Forgot admin password?**
- Stop the server
- Delete `pyircx.db`
- Restart server (will recreate with default admin/changeme)
- Change password immediately

**Locked out?**
- Check server logs for connection issues
- Verify username/password spelling
- Try logging out and back in: `/STAFF LOGOUT` then `/STAFF LOGIN`

**Need to demote an admin?**
- Must be logged in as a different ADMIN
- Use: `/STAFF LEVEL <username> SYSOP`

## Files Reference

- Database: `pyircx.db`
- Config: `pyircx_config.json`
- Review script: `python3 review_users.py`
- Cleanup script: `python3 cleanup_users.py`

---

*Last updated: 2026-01-01*  
*After database cleanup*
