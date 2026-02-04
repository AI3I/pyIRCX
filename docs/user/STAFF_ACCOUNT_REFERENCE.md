# Staff Account Quick Reference

## Current Production Accounts

| Username | Level | Password  | Purpose                    |
|----------|-------|-----------|----------------------------|
| admin    | ADMIN | password  | Primary administrator      |
| sysop    | SYSOP | password  | System operator            |
| guide    | GUIDE | password  | Helper/guide               |

⚠️ **SECURITY WARNING:** Change all passwords before production use!

---

## Staff Authentication Commands

### Post-Connection Authentication (AUTH)

The AUTH command provides secure post-connection authentication for IRC staff. Unlike PASS authentication which occurs during connection, AUTH allows staff to elevate privileges after connecting as a regular user.

```
/AUTH <username> <password>  - Authenticate as staff (elevate to IRC administrator/operator/guide)
```

**Features:**
- Credentials transmitted only after SSL/TLS connection established
- Multi-factor authentication (MFA) support
- Progressive delays on failed attempts (2s, 5s, 10s)
- Account lockout after 5 failures (15 minute timeout)
- All attempts logged to #System channel
- Configurable SSL/TLS requirement

**Example:**
```
/AUTH admin mypassword
```

If MFA is enabled, you will be prompted:
```
Password accepted. MFA verification required.
Enter code: /AUTH VERIFY <6-digit code>
```

**SSL/TLS Requirement:**
- By default, AUTH requires SSL/TLS connection (port 6697)
- Configurable via `security.auth_require_ssl` in config
- Prevents credential transmission over plaintext connections

---

### MFA (Multi-Factor Authentication) Commands

#### AUTH VERIFY - Complete MFA Login
```
/AUTH VERIFY <6-digit code>  - Complete MFA verification after password accepted
```

**Example:**
```
/AUTH VERIFY 123456
```

**Notes:**
- Use after successful password authentication when MFA is enabled
- Code must be entered within 5 minutes (pending session timeout)
- Modes (+a/+o/+g) NOT applied until successful verification
- Invalid codes are logged to #System channel

---

#### AUTH ENABLE - Self-Service MFA Setup
```
/AUTH ENABLE <password>  - Enable MFA for your staff account
```

**Example:**
```
# First, authenticate normally
/AUTH admin mypassword

# Then enable MFA
/AUTH ENABLE mypassword
```

**Process:**
1. Confirms your password
2. Generates unique MFA secret
3. Displays QR code and manual entry key
4. Prompts for verification: `/AUTH VERIFY <code>`
5. MFA auto-enabled on first successful verification

**Scan QR Code:**
- Use Google Authenticator, Authy, or compatible TOTP app
- Or manually enter the displayed secret key

---

#### AUTH DISABLE - Remove MFA
```
/AUTH DISABLE <password> <6-digit code>  - Disable MFA for your account
```

**Example:**
```
/AUTH DISABLE mypassword 123456
```

**Requirements:**
- Must provide both current password AND valid MFA code
- Prevents unauthorized MFA removal
- Action logged to #System channel and audit log

---

### De-authentication (DROP)

The DROP command voluntarily removes staff privileges and returns you to regular user status.

```
/DROP  - Drop staff authentication and return to regular user mode
```

**What happens:**
- Removes your +a, +o, or +g mode
- Reverts username and host to regular user
- Clears any pending authentication state
- Logs action to #System channel

**Use cases:**
- Testing features as a regular user
- Participating in events without staff status
- Temporarily reducing privileges for security
- You can re-authenticate with `/AUTH` anytime

**Example:**
```
# Drop privileges
/DROP

# Later, re-authenticate
/AUTH admin mypassword
```

---

## STAFF Command Reference

### Account Management (ADMIN only)

```
/STAFF ADD <username> <password> <level>  - Create new staff account
                                            Levels: ADMIN, SYSOP, GUIDE
/STAFF DEL <username>                     - Delete staff account
/STAFF LIST                               - List all staff accounts
/STAFF SET <username> <level>             - Change user's privilege level
```

**Example:**
```
# Create new guide
/STAFF ADD alice SecurePass123! GUIDE

# Promote to sysop
/STAFF SET alice SYSOP

# List all staff
/STAFF LIST
```

---

### Password Management

```
/STAFF PASS <username> <old-password> <new-password>  - Change password
```

**Permissions:**
- Any staff can change their own password
- ADMIN can change any staff password

**Example:**
```
# Change your own password
/STAFF PASS admin oldpass newpass

# Admin changes another user's password (ADMIN only)
/STAFF PASS alice oldpass newpass
```

---

### MFA Management (ADMIN only)

```
/STAFF MFA <username> STATUS          - Show MFA status for staff account
/STAFF MFA <username> ENABLE <code>   - Enable MFA (requires user ran AUTH ENABLE first)
/STAFF MFA <username> DISABLE <code>  - Disable MFA (requires valid code)
```

**Example:**
```
# Check if alice has MFA enabled
/STAFF MFA alice STATUS

# User alice first runs: /AUTH ENABLE password
# Then admin enables with verification:
/STAFF MFA alice ENABLE 123456

# Disable MFA (requires current valid code)
/STAFF MFA alice DISABLE 123456
```

**Notes:**
- User must run `AUTH ENABLE` first to generate secret
- Admin verifies with code to complete setup
- Provides admin control over MFA enforcement
- All actions logged to audit trail

---

## Privilege Levels

### ADMIN (Highest - Mode +a)
- Full access to all commands
- Can manage other staff accounts (ADD/DEL/SET)
- Can shutdown/restart server
- Can modify server configuration
- Can link/unlink servers
- Can manage MFA for all staff
- Bypasses all channel restrictions

### SYSOP (Medium - Mode +o)
- Can kick/ban users globally
- Can manage channels
- Can link/unlink servers
- Cannot manage staff accounts
- Cannot shutdown server
- Can change own password only
- Bypasses all channel restrictions

### GUIDE (Basic - Mode +g)
- Can help users
- Limited administrative access
- Cannot kick/ban globally
- Cannot link servers
- Cannot manage staff accounts
- Can change own password only
- Bypasses channel invite-only (+i)

---

## Security Features

### Progressive Delays
Failed AUTH attempts trigger increasing delays:
- Attempts 1-2: No delay (0s)
- Attempt 3: 2 second delay
- Attempt 4: 5 second delay
- Attempt 5+: 10 second delay

### Account Lockout
- 5 failed attempts = account locked
- 15 minute lockout duration
- Tracked per username AND IP address
- Lockout notice sent to #System channel

### Logging & Monitoring
All AUTH activity logged:
- ✅ Successful authentications
- ❌ Failed attempts (wrong password, unknown user)
- 🔒 Lockout events
- 🔐 MFA setup/removal
- 📤 DROP commands

Logs appear in:
- #System channel (real-time alerts)
- Staff audit database
- Server log file

### SSL/TLS Protection
- `auth_require_ssl` - Require SSL for AUTH command (default: true)
- `pass_require_ssl` - Require SSL for PASS staff auth (default: true)
- Prevents credential interception on non-encrypted connections

---

## Initial Setup Example

After server deployment, immediately secure your installation:

```bash
# 1. Connect to IRC server via SSL (recommended)
/SERVER irc.local 6697 (SSL)

# 2. Authenticate as admin
/AUTH admin password

# 3. Change password immediately
/STAFF PASS admin password MyStr0ngP@ssw0rd!

# 4. Enable MFA for admin account
/AUTH ENABLE MyStr0ngP@ssw0rd!
# Scan QR code with authenticator app
/AUTH VERIFY 123456

# 5. (Optional) Create your personal admin account
/STAFF ADD myname SecurePass123! ADMIN

# 6. Drop and re-authenticate with new credentials
/DROP
/AUTH myname SecurePass123!
/AUTH VERIFY 654321

# 7. (Optional) Delete example accounts if not needed
/STAFF DEL sysop
/STAFF DEL guide

# 8. Change remaining default passwords
/STAFF PASS admin MyStr0ngP@ssw0rd! NewEvenBetterP@ss!
```

---

## Security Best Practices

✅ **Always use SSL/TLS** - Connect via port 6697, never transmit credentials in plaintext
✅ **Change all default passwords immediately** - First action after deployment
✅ **Enable MFA for all ADMIN accounts** - Use `AUTH ENABLE` for two-factor protection
✅ **Use strong passwords** - 12+ characters, mixed case, numbers, symbols
✅ **Delete unused staff accounts** - Remove example accounts (sysop, guide) if not needed
✅ **Use SYSOP for trusted operators** - Don't give everyone ADMIN
✅ **Use GUIDE for helpers** - Minimal privileges for support staff
✅ **Regularly audit staff list** - Use `/STAFF LIST` monthly
✅ **Never share staff credentials** - One account per person
✅ **Monitor #System channel** - Watch for suspicious AUTH attempts
✅ **Use DROP when not needed** - Reduce privileges during normal chatting

---

## Troubleshooting

### Forgot admin password?

**Option 1: Database Reset**
```bash
# Stop the server
systemctl stop pyircx

# Delete database (WARNING: Deletes all data)
rm pyircx.db

# Restart server (recreates with default admin/password)
systemctl start pyircx

# Login and change password immediately
/AUTH admin password
/STAFF PASS admin password NewSecureP@ss!
```

**Option 2: Direct Database Edit**
```bash
# Stop the server
systemctl stop pyircx

# Reset password using Python
python3 << EOF
import bcrypt
import sqlite3

new_password = "resetpass123"
hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

db = sqlite3.connect("pyircx.db")
db.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (hash,))
db.commit()
print(f"Admin password reset to: {new_password}")
EOF

# Restart server
systemctl start pyircx

# Login and change to secure password
/AUTH admin resetpass123
/STAFF PASS admin resetpass123 SecureP@ss!
```

### Locked out after failed attempts?

Wait 15 minutes, then try again. Or clear lockout manually:
```bash
# Stop server
systemctl stop pyircx

# Clear auth failures
sqlite3 pyircx.db "DELETE FROM auth_failures WHERE username = 'admin';"

# Restart server
systemctl start pyircx
```

### MFA device lost?

**If you're an ADMIN:**
```
# Login as another admin
/AUTH otheradmin password

# Disable MFA for affected account
/STAFF MFA affecteduser DISABLE 123456
```

**If you're the only ADMIN:**
```bash
# Stop server
systemctl stop pyircx

# Disable MFA via database
sqlite3 pyircx.db "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = 'admin';"

# Restart server
systemctl start pyircx

# Re-enable MFA with new device
/AUTH admin password
/AUTH ENABLE password
# Scan new QR code
```

### "SSL/TLS connection required" error?

AUTH command requires SSL by default. Connect via port 6697:
```
/SERVER irc.local 6697 (SSL)
```

Or disable SSL requirement (NOT recommended for production):
```json
// In pyircx_config.json
{
  "security": {
    "auth_require_ssl": false
  }
}
```

### PASS authentication not working on non-SSL?

PASS staff authentication can be restricted to SSL via config:
```json
// In pyircx_config.json
{
  "security": {
    "pass_require_ssl": true  // Requires SSL for PASS-based staff auth
  }
}
```

This prevents staff credentials from being sent during initial connection on plaintext connections.

---

## Configuration Reference

### security.auth_require_ssl
**Type:** Boolean
**Default:** `true`
**Description:** Require SSL/TLS for AUTH command

```json
{
  "security": {
    "auth_require_ssl": true
  }
}
```

### security.pass_require_ssl
**Type:** Boolean
**Default:** `true`
**Description:** Require SSL/TLS for PASS-based staff authentication

```json
{
  "security": {
    "pass_require_ssl": true
  }
}
```

**Note:** This is enabled by default for security. Staff credentials will only be accepted during connection if transmitted over SSL/TLS. Set to `false` only if you need to support legacy clients without SSL support.

---

## Files Reference

- **Database:** `pyircx.db` (or configured path)
- **Config:** `pyircx_config.json`
- **Logs:** Server logs + #System channel
- **Audit:** Staff actions logged in database

---

## Migration from Old Authentication

If upgrading from a version with `/STAFF LOGIN`:

**Old commands (deprecated):**
```
/STAFF LOGIN <username> <password>
/STAFF LOGOUT
```

**New commands:**
```
/AUTH <username> <password>
/DROP
```

**Key differences:**
- AUTH is post-connection (more secure)
- MFA support built-in
- Progressive delays and lockouts
- SSL/TLS requirement (configurable)
- Better logging and monitoring

No database migration needed - existing staff accounts work with AUTH.

---

*Last updated: 2026-01-17*
*AUTH command implementation - v2.0.0+*
