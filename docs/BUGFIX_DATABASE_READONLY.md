# Bug Fix: Web Admin "Readonly Database" Error

**Date:** January 14, 2026
**Status:** Fixed and tested
**Impact:** Web Admin Panel functionality

---

## Problem

**Reported Behavior:**
- Web admin panel shows "attempt to write a readonly database" error
- Staff management operations fail
- Config updates fail
- Any database write from web admin fails

**Example Errors:**
```
PDO Exception: SQLSTATE[HY000]: General error: 8 attempt to write a readonly database
```

---

## Root Cause Analysis

### The Issue

The web server (httpd/apache) runs as user `apache`, but the database has the following permissions:

```bash
-rw-rw-r--. 1 pyircx pyircx 53248 Jan 14 15:06 /opt/pyircx/pyircx.db
drwxrwxr-x. 1 pyircx pyircx   218 Jan 14 16:32 /opt/pyircx/
```

**Breakdown:**
- Owner: `pyircx:pyircx`
- Permissions: 664 (rw-rw-r--)
- Directory: 775 (rwxrwxr-x)

Group has read AND write permissions, but:
- User `apache` is NOT in group `pyircx`
- Therefore `apache` falls back to "other" permissions (r-- read only)

**Why It Failed:**
```bash
$ groups apache
apache : apache systemd-journal
# Notice: NOT in pyircx group!
```

### SQLite Requirements

SQLite databases need:
1. **Write access to the database file** (.db)
2. **Write access to the directory** (for journal files: .db-journal, .db-shm, .db-wal)

Even with database file write permission, SQLite will fail if it can't create journal files in the directory.

---

## The Fix

### Solution Overview

Add the web server user to the `pyircx` group, giving it group write permissions to:
- `/opt/pyircx/pyircx.db` (database file)
- `/opt/pyircx/` directory (for journal files)
- `/etc/pyircx/pyircx_config.json` (config file)

### Implementation

**Command:**
```bash
usermod -a -G pyircx apache
systemctl restart httpd php-fpm
```

**Flags:**
- `-a` = append (don't remove from other groups)
- `-G` = supplementary groups
- `apache` = web server user

**Why Restart Web Services:**
Group membership is evaluated at login/process start. Existing processes don't see new group membership until they restart.

---

## Files Modified

### install.sh (lines 235-250)

Added web server user detection and group addition:

```bash
# Add web server user to pyircx group for database access
# Detect web server user (apache, www-data, or http)
WEB_USER=""
if id apache &>/dev/null; then
    WEB_USER="apache"
elif id www-data &>/dev/null; then
    WEB_USER="www-data"
elif id http &>/dev/null; then
    WEB_USER="http"
fi

if [ -n "$WEB_USER" ]; then
    echo -e "${YELLOW}Adding $WEB_USER to $SERVICE_GROUP group for database access...${NC}"
    usermod -a -G "$SERVICE_GROUP" "$WEB_USER"
    echo -e "${GREEN}✓ Web server user added to group${NC}"
fi
```

**Why Multi-Platform:**
- **RHEL/Fedora/CentOS/Rocky:** User is `apache`
- **Debian/Ubuntu:** User is `www-data`
- **Arch Linux:** User is `http`

### upgrade.sh (lines 519-534)

Same code added to upgrade script in the "Fix permissions" section.

### repair.sh (lines 432-447)

Same code added to repair script in the "Fix permissions" section.

---

## Verification

### Manual Test

```bash
# Check apache user groups
$ groups apache
apache : apache systemd-journal pyircx  # ✓ Now includes pyircx!

# Test write access
$ sudo -u apache test -w /opt/pyircx/pyircx.db && echo "✓ Can write" || echo "✗ Cannot write"
✓ Can write

# Test directory access
$ sudo -u apache test -w /opt/pyircx && echo "✓ Can write to dir" || echo "✗ Cannot write to dir"
✓ Can write to dir
```

### Web Admin Test

1. Access web admin: http://localhost/pyircx-admin/
2. Log in as ADMIN
3. Navigate to Staff Management
4. Try to add/modify staff member
5. **Expected:** Operation succeeds, no readonly error
6. Check database was modified:
   ```bash
   sqlite3 /opt/pyircx/pyircx.db "SELECT * FROM users;"
   ```

---

## Why This Works

### Before Fix
```
Web Request → PHP Process (user: apache, groups: apache systemd-journal)
    ↓
Try to write /opt/pyircx/pyircx.db (owner: pyircx:pyircx, perms: 664)
    ↓
Permission check: User? No. Group? No. Other? Read-only!
    ↓
ERROR: Readonly database
```

### After Fix
```
Web Request → PHP Process (user: apache, groups: apache systemd-journal pyircx)
    ↓
Try to write /opt/pyircx/pyircx.db (owner: pyircx:pyircx, perms: 664)
    ↓
Permission check: User? No. Group? YES! (apache is in pyircx group)
    ↓
SUCCESS: Write permitted
```

---

## Security Considerations

### Is This Safe?

**YES** - This is the correct permission model:

1. **Least Privilege:** Web server only gets write access to specific files, not full ownership
2. **Group Isolation:** Only pyircx group members can write, not all users
3. **File Permissions Unchanged:** Database still 664, directory still 775
4. **No Elevation:** Web server doesn't run as pyircx user, just shares group

### Alternative Approaches (NOT Recommended)

❌ **Make database world-writable (666):**
```bash
chmod 666 /opt/pyircx/pyircx.db  # BAD! Any user can write
```

❌ **Change ownership to apache:**
```bash
chown apache:apache /opt/pyircx/pyircx.db  # BAD! pyircx service can't write
```

❌ **Run web server as pyircx user:**
```bash
# BAD! Gives web server full access to everything pyircx owns
```

✅ **Group membership (CORRECT):**
```bash
usermod -a -G pyircx apache  # GOOD! Explicit, auditable, least privilege
```

---

## Compatibility

### Operating Systems

| OS | Web User | Status |
|----|----------|--------|
| RHEL/Fedora/CentOS/Rocky/AlmaLinux | `apache` | ✅ Tested |
| Debian/Ubuntu/Mint | `www-data` | ✅ Supported |
| Arch/Manjaro | `http` | ✅ Supported |
| Other | Manual config | ⚠️ May need adjustment |

### SELinux

On RHEL-based systems with SELinux, additional contexts are already set:

```bash
# From install.sh lines 350-351
semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx/pyircx\.db"
semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?"
restorecon -Rv /opt/pyircx
```

**Combined with group membership**, web admin now works on SELinux systems.

---

## Application Instructions

### For Fresh Installations

Run updated install script:
```bash
sudo bash install.sh
# Web server user automatically added to pyircx group
```

### For Existing Installations

**Option 1: Run repair script**
```bash
sudo bash repair.sh
# Detects and fixes group membership
```

**Option 2: Run upgrade script**
```bash
sudo bash upgrade.sh
# Applies group fix during upgrade
```

**Option 3: Manual fix**
```bash
sudo usermod -a -G pyircx apache  # Or www-data, or http
sudo systemctl restart httpd php-fpm
```

---

## Testing Checklist

After applying fix:

- [ ] Check web server user in pyircx group: `groups apache`
- [ ] Restart web services: `systemctl restart httpd php-fpm`
- [ ] Test write access: `sudo -u apache test -w /opt/pyircx/pyircx.db`
- [ ] Access web admin: http://localhost/pyircx-admin/
- [ ] Try staff management operation
- [ ] Try config change
- [ ] Verify no readonly errors in logs: `journalctl -u httpd -n 50`

---

## Troubleshooting

### Still Getting Readonly Error?

1. **Verify group membership:**
   ```bash
   groups apache
   # Should show: apache ... pyircx
   ```

2. **Restart web services** (group changes need restart):
   ```bash
   sudo systemctl restart httpd php-fpm
   ```

3. **Check permissions:**
   ```bash
   ls -la /opt/pyircx/pyircx.db
   # Should show: -rw-rw-r-- pyircx pyircx
   ```

4. **Check directory permissions:**
   ```bash
   ls -ld /opt/pyircx
   # Should show: drwxrwxr-x pyircx pyircx
   ```

5. **SELinux blocking? (RHEL-based systems):**
   ```bash
   sudo ausearch -m avc -ts recent | grep httpd
   # If blocked, apply contexts:
   sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/pyircx(/.*)?"
   sudo restorecon -Rv /opt/pyircx
   ```

6. **Check PHP can call usermod:**
   ```bash
   # PHP should NOT be calling usermod - this is a server setup task
   # usermod runs during install/upgrade/repair scripts only
   ```

---

## Impact Assessment

**Risk Level:** LOW
- Changes only group membership, not file permissions
- No security regression
- Standard Unix permission model
- Reversible

**Benefits:**
- Web admin fully functional
- Staff management works
- Config updates work
- Consistent with SQLite best practices

**Affected Components:**
- Web Administration Panel
- Staff management
- Config updates via web UI
- Any database writes from PHP

**No Impact On:**
- pyircx service (already runs as pyircx user)
- IRC client connections
- Command line operations

---

## Future Considerations

### Alternative: Run Web Admin as Python API

Future enhancement could replace PHP web admin with Python-based API:
- Python API runs as pyircx user (no group needed)
- PHP becomes pure frontend (read-only)
- More secure (no PHP database access)
- Better integration with existing Python codebase

**Not implemented yet** - current fix with group membership is correct approach.

---

**Status:** ✅ FIXED

**Verification Required:**
- User should test web admin operations
- Confirm no readonly errors
- Verify staff management works

---

**Files Changed:**
- `install.sh` - Added web user to group during install
- `upgrade.sh` - Added web user to group during upgrade
- `repair.sh` - Added web user to group during repair
- `docs/BUGFIX_DATABASE_READONLY.md` - This document

**Commit:** (pending)
