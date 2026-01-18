# API Refactoring TODO List

**Status:** Infrastructure Complete ✅
**Started:** 2026-01-17
**Progress:** 0/33 functions refactored (0%)

---

## ✅ Completed

### Infrastructure (100%)
- [x] Created `db_pool.py` - Connection pooling module
- [x] Created `api_helpers.py` - Error handling and validation
- [x] Added imports to `api.py`
- [x] Added `init_db_pool()` function
- [x] Pool initialized on module import
- [x] Logging infrastructure added

---

## 📋 Remaining Work

### Phase 1: Read-Only Functions (16 functions) - Priority: P1

These functions only read from the database and are straightforward to refactor.

| # | Function | Line | Current Pattern | Status |
|---|----------|------|-----------------|--------|
| 1 | `get_server_access_list()` | ~566 | `sqlite3.connect()` | ⏳ TODO |
| 2 | `get_newsflash_list()` | ~639 | `sqlite3.connect()` | ⏳ TODO |
| 3 | `get_registered_nicks()` | ~699 | `sqlite3.connect()` | ⏳ TODO |
| 4 | `get_channels()` | ~770 | `sqlite3.connect()` | ⏳ TODO |
| 5 | `get_channel_modes()` | ~849 | `sqlite3.connect()` | ⏳ TODO |
| 6 | `get_channel_access()` | ~918 | `sqlite3.connect()` | ⏳ TODO |
| 7 | `get_staff_accounts()` | ~990 | `sqlite3.connect()` | ⏳ TODO |
| 8 | `get_banned_users()` | ~1060 | `sqlite3.connect()` | ⏳ TODO |
| 9 | `get_user_registrations()` | ~1127 | `sqlite3.connect()` | ⏳ TODO |
| 10 | `get_user_audit_log()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 11 | `get_servicebot_tracking()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 12 | `get_profanity_list()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 13 | `get_channel_props()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 14 | `get_server_links()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 15 | `get_nickname_info()` | TBD | `sqlite3.connect()` | ⏳ TODO |
| 16 | `search_audit_log()` | TBD | `sqlite3.connect()` | ⏳ TODO |

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

### Phase 2: Write Functions (17 functions) - Priority: P2

These functions write to the database. Need error handler AND input validation.

| # | Function | Line | Needs Validation | Status |
|---|----------|------|------------------|--------|
| 1 | `add_server_access()` | ~574 | access_type, pattern, timeout | ⏳ TODO |
| 2 | `remove_server_access()` | ~608 | access_type, pattern | ⏳ TODO |
| 3 | `add_newsflash()` | ~673 | title, content | ⏳ TODO |
| 4 | `delete_newsflash()` | ~728 | newsflash_id | ⏳ TODO |
| 5 | `edit_newsflash()` | ~806 | newsflash_id, title, content | ⏳ TODO |
| 6 | `create_channel()` | TBD | channel_name | ⏳ TODO |
| 7 | `delete_channel()` | TBD | channel_name | ⏳ TODO |
| 8 | `add_channel_access()` | ~883 | channel, access_type, pattern | ⏳ TODO |
| 9 | `delete_channel_access()` | TBD | channel, pattern | ⏳ TODO |
| 10 | `create_staff_account()` | ~1024 | username, level | ⏳ TODO |
| 11 | `delete_staff_account()` | TBD | username | ⏳ TODO |
| 12 | `update_staff_password()` | TBD | username, password | ⏳ TODO |
| 13 | `create_nickname_registration()` | ~1301 | nickname | ⏳ TODO |
| 14 | `delete_nickname_registration()` | ~1354 | nickname | ⏳ TODO |
| 15 | `add_profanity_word()` | TBD | word | ⏳ TODO |
| 16 | `delete_profanity_word()` | TBD | word | ⏳ TODO |
| 17 | `update_channel_props()` | TBD | channel, props | ⏳ TODO |

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
