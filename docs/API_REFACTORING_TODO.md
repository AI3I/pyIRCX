# API Refactoring TODO List

**Status:** In Progress 🚧
**Started:** 2026-01-17
**Last Updated:** 2026-01-17
**Progress:** 18/33+ functions refactored (55%)
**Commit:** 483a62d - Refactor API functions to use connection pool

---

## ✅ Completed

### Infrastructure (100%)
- [x] Created `db_pool.py` - Connection pooling module
- [x] Created `api_helpers.py` - Error handling and validation
- [x] Added imports to `api.py`
- [x] Added `init_db_pool()` function
- [x] Pool initialized on module import
- [x] Logging infrastructure added

### Phase 1: Read-Only Functions (14/14 completed) ✅
- [x] get_server_stats() - Server statistics
- [x] get_server_access_list() - Server access rules
- [x] get_newsflash_list() - Newsflash messages
- [x] get_mailbox_messages() - Mailbox messages
- [x] search_registered_nicks() - Nickname search
- [x] search_channels() - Channel search
- [x] get_recent_registrations() - Recent registrations
- [x] get_registered_channels() - Registered channels
- [x] get_staff_list() - Staff list
- [x] get_staff_details() - Staff details
- [x] get_registered_nicks_paginated() - Paginated nicknames
- [x] get_registered_channels_paginated() - Paginated channels
- [x] get_channel_details() - Channel details
- [x] get_channel_access() - Channel access lists

### Phase 2: Write Functions (4/17+ completed)
- [x] add_server_access() - Add ban/gline (with validation)
- [x] remove_server_access() - Remove ban/gline (with validation)
- [x] add_newsflash() - Add newsflash (with validation)
- [x] delete_newsflash() - Delete newsflash (with validation)

---

## 📋 Remaining Work

### Phase 1: Read-Only Functions ✅ COMPLETE
All read-only functions have been refactored!

**Refactoring Pattern (Read-Only):**
```python
# BEFORE:
def get_something():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM table")
    results = cursor.fetchall()

    conn.close()
    return {"data": results}

# AFTER:
@api_error_handler
def get_something():
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM table")
        results = cursor.fetchall()
        return {"data": results}
```

---

### Phase 2: Write Functions (13+ remaining) - Priority: P2

These functions write to the database. Need error handler AND input validation.

**Completed:** ✅
- [x] add_server_access() - Add ban/gline
- [x] remove_server_access() - Remove ban/gline
- [x] add_newsflash() - Add newsflash
- [x] delete_newsflash() - Delete newsflash

**Remaining:** (estimated ~13+ functions)
- [ ] add_staff() - Add staff account
- [ ] remove_staff() - Remove staff account
- [ ] update_staff_password() - Update staff password
- [ ] test_staff_login() - Test staff login (read-only, may not need refactoring)
- [ ] register_nickname() - Register nickname
- [ ] unregister_nickname() - Unregister nickname
- [ ] update_nickname_password() - Update nickname password
- [ ] update_nickname_email() - Update nickname email
- [ ] register_channel() - Register channel
- [ ] unregister_channel() - Unregister channel
- [ ] edit_channel() - Edit channel properties
- [ ] set_channel_access() - Set channel access lists
- [ ] send_server_message() - Send server message (write)
- [ ] Additional functions discovered during grep scan

**Refactoring Pattern (Write):**
```python
# BEFORE:
def add_something(pattern, type, timeout):
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO table (pattern, type, timeout) VALUES (?, ?, ?)",
                  (pattern, type, timeout))
    conn.commit()
    conn.close()
    return {"success": True}

# AFTER:
@api_error_handler
def add_something(pattern, type, timeout):
    # Validate inputs
    validate_pattern(pattern)
    validate_access_type(type)
    validate_timeout(timeout)

    # Execute with pool
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO table (pattern, type, timeout) VALUES (?, ?, ?)",
                      (pattern, type, timeout))
        # Auto-commits on context exit
        return {"success": True}
```

---

## Refactoring Checklist

For each function being refactored:

- [ ] Replace `db_path = get_db_path()` with nothing (use pool)
- [ ] Replace `conn = sqlite3.connect(db_path)` with `with db_pool.get_connection() as conn:`
- [ ] Remove `conn.row_factory = sqlite3.Row` (pool sets this)
- [ ] Remove `conn.commit()` (auto-commits on context exit)
- [ ] Remove `conn.close()` (pool manages this)
- [ ] Remove `try/except` blocks (use @api_error_handler instead)
- [ ] Add `@api_error_handler` decorator
- [ ] Add input validation for write functions
- [ ] Test function still works
- [ ] Verify error handling works

---

## Testing Strategy

After refactoring each batch:

1. **Unit Test:**
   ```python
   import api
   result = api.get_something()
   assert 'error' not in result or result.get('success') == True
   ```

2. **Error Test:**
   ```python
   # Test with invalid database path
   db_pool.close_pool()
   db_pool.init_pool("/nonexistent/path.db")
   result = api.get_something()
   assert result['success'] == False
   assert 'error' in result
   ```

3. **Connection Pool Test:**
   ```python
   stats = db_pool.get_pool_stats()
   print(f"Pool size: {stats['pool_size']}")
   print(f"Available: {stats['available']}")
   print(f"In use: {stats['in_use']}")
   ```

---

## Estimated Effort

| Phase | Functions | Effort/Function | Total |
|-------|-----------|-----------------|-------|
| Phase 1 (Read) | 16 | 10 min | 2.7h |
| Phase 2 (Write) | 17 | 15 min | 4.3h |
| **Total** | **33** | **~12 min avg** | **7h** |

**Note:** Original estimate was 4h, but adding validation and testing increases to ~7h.

---

## Performance Impact (Estimated)

### Before (Direct Connections)
- **Connection overhead:** ~2-5ms per operation
- **33 functions** × 2.5ms average = **82.5ms wasted per request** (if all called)
- **Under load:** Each function blocks waiting for sqlite3.connect()
- **Concurrency:** Limited by file locks, no connection reuse

### After (Connection Pool)
- **Connection overhead:** ~0ms (reused from pool)
- **Same 33 functions:** **0ms wasted** (connections ready in pool)
- **Under load:** Non-blocking pool access, queued if needed
- **Concurrency:** 10 simultaneous operations (pool_size=10)

**Expected improvement:**
- Single operation: **10-30% faster**
- Under load (10+ concurrent requests): **10-50x faster**
- Memory usage: **Slightly higher** (10 persistent connections vs on-demand)
- Scalability: **Much better** (connection reuse, proper queuing)

---

## Known Issues to Address

1. **Pool initialization on import** - May fail silently if DB doesn't exist
   - Solution: Check pool status before operations, fall back to direct connection

2. **Long-running transactions** - Could exhaust pool
   - Solution: Set timeout on get_connection(), log warnings

3. **Thread safety** - Pool is thread-safe, but individual functions may not be
   - Solution: Review for race conditions, add locks if needed

4. **Testing** - No API test suite exists
   - Solution: Create `testing/test_api.py` (see SPECIALIZED_TESTS.md)

---

## Progress Tracking

**Last updated:** 2026-01-17
**Progress:** 0/33 (0%)
**Blocked by:** None
**Next step:** Refactor Phase 1 read-only functions

---

## Quick Reference: Connection Pool Usage

```python
# Simple read
@api_error_handler
def get_data():
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM table")
        return {"data": cursor.fetchall()}

# Write with validation
@api_error_handler
def add_data(name, value):
    validate_pattern(name)  # Raises ValueError if invalid

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO table (name, value) VALUES (?, ?)", (name, value))
        return {"success": True}  # Auto-commit on exit

# Multiple operations (single transaction)
@api_error_handler
def complex_operation():
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO table1 ...")
        cursor.execute("UPDATE table2 ...")
        cursor.execute("DELETE FROM table3 ...")
        return {"success": True}  # All commit together

# Pool stats
stats = db_pool.get_pool_stats()
print(f"Pool: {stats['available']}/{stats['pool_size']} available")
```

---

*Next Milestone: Complete Phase 1 (16 read-only functions)*
