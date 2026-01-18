# Test Harness Updates for v1.1.5

## Summary

All test harnesses have been updated and modernized for pyIRCX v1.1.5 release.

## Files Updated

### 1. tests/integration/access.py - Modernized (466 lines, 10 tests)
**Changes:**
- Converted from synchronous socket-based to async/await pattern
- Now uses IRCTestClient and TestRunner from users.py
- Added staff account documentation (admin/sysop/guide)
- Uses decorator pattern: `@runner.test("name")`
- Follows same pattern as other test files

**Tests:**
- ACCESS - Channel OWNER
- ACCESS - Channel HOST
- ACCESS - Channel VOICE  
- ACCESS - Channel DENY
- ACCESS - Remove entry
- ACCESS - Clear list
- ACCESS - Service DENY protection
- ACCESS - Wildcard patterns
- ACCESS - Server GRANT (ADMIN)
- ACCESS - Server DENY (ADMIN)

### 2. tests/integration/stats.py - Created (595 lines, 16 tests)
**New test file for v1.1.5 STATS enhancements**

**Tests:**
- STATS p - Basic functionality
- STATS p - Peak time display
- STATS f - Basic functionality
- STATS m - Basic functionality
- STATS m - No 'top 10' limit
- STATS b - Basic functionality
- STATS n - Basic functionality
- STATS v - Staff only access
- STATS v - Works with admin
- STATS v - Works with sysop
- STATS v - Works with guide
- STATS v - No 'top 10' limit
- STATS k - No 10-entry limit
- STATS * - Hierarchical indentation
- STATS * - No 'top X' limits
- STATS * - Admin only (deny sysop)

### 3. tests/integration/help.py - Created (507 lines, 15 tests)
**New test file for v1.1.5 HELP enhancements**

**Tests:**
- HELP - Main menu
- HELP - Topic count
- HELP REGISTER - Topic exists
- HELP REGISTER - Nickname section
- HELP REGISTER - Channel section
- HELP REGISTER - MFA section
- HELP COMMANDS - Has Registration
- HELP CHANNEL - Shows commands
- HELP IRCX - Shows commands
- HELP USERMODES - Shows modes
- HELP CHANMODES - Shows modes
- HELP SERVICES - Shows services
- HELP STAFF - Requires staff
- HELP STAFF - Works with auth
- HELP INVALID - Shows topics

### 4. tests/integration/services.py - Created (416 lines, 13 tests)
**New test file for v1.1.5 service improvements**

**Tests:**
- Registrar HELP - Exists
- Registrar HELP - Comprehensive
- ServiceBot - Uppercase routing
- ServiceBot - Lowercase routing (FIX)
- ServiceBot - Mixed case routing (FIX)
- ServiceBot STATUS - Case insensitive
- ServiceBot HELP - Comprehensive
- ServiceBot HELP - Shows actions
- ServiceBot HELP - Shows invitation
- ServiceBot STATUS - Shows channels
- ServiceBot STATUS - Shows detection
- Messenger HELP - Still works
- NewsFlash HELP - Still works

### 5. tests/integration/test_auth.py - Created (900 lines, 18 tests)
**NEW v1.1.8: AUTH command for post-connection staff authentication with MFA**

**Tests:**
- AUTH - Basic Authentication (No MFA)
- AUTH - Wrong Password
- AUTH - Unknown User
- DROP - De-authentication
- DROP - Not Authenticated
- AUTH ENABLE - Self-Service MFA Setup
- AUTH ENABLE - Wrong Password
- STAFF MFA STATUS - Check MFA Status (ADMIN)
- STAFF MFA - Non-Admin Denied
- AUTH - SSL Required (Non-SSL Blocked)
- AUTH - SSL Connection Works
- AUTH - Progressive Delays on Failures
- AUTH - Account Lockout After 5 Failures
- AUTH - Pending State No Modes Until Verify
- HELP AUTH - Documentation Exists
- HELP DROP - Documentation Exists

**Coverage:**
- ✅ Basic AUTH authentication (username/password)
- ✅ DROP de-authentication
- ✅ MFA self-service enrollment (AUTH ENABLE/VERIFY/DISABLE)
- ✅ STAFF MFA management (ADMIN only - STATUS/ENABLE/DISABLE)
- ✅ SSL/TLS requirements (auth_require_ssl, pass_require_ssl)
- ✅ Progressive delays (0s, 0s, 2s, 5s, 10s)
- ✅ Account lockout (5 failures → 15 min lockout)
- ✅ Pending state (modes NOT applied until MFA verification)
- ✅ HELP documentation (AUTH and DROP)

### 6. run_tests.sh - Updated (330 lines)
**Major rewrite for v1.1.8**

**Changes:**
- Updated to v1.1.8
- Changed from `pyIRCX_test_*.py` to `tests/integration/*.py` directory structure
- Added all 8 test suites (4 core + 3 v1.1.5 + 1 v1.1.8)
- Enhanced output with version feature separation
- Increased test timeout to 120 seconds
- Total test count: ~230 tests across 8 suites

**Test Execution Order:**
1. tests/integration/users.py - IRC/IRCX Protocol (115 tests)
2. tests/integration/staff.py - Staff PASS Authentication (39 tests)
3. tests/integration/test_auth.py - AUTH Command v1.1.8 (18 tests)
4. tests/integration/links.py - Server Linking (4 tests)
5. tests/integration/access.py - Access Control (10 tests)
6. tests/integration/stats.py - STATS System v1.1.5 (16 tests)
7. tests/integration/help.py - HELP System v1.1.5 (15 tests)
8. tests/integration/services.py - Service Improvements v1.1.5 (13 tests)

## Test Pattern

All test files now use consistent async/await pattern:

```python
# Import test infrastructure
import asyncio
import sys
sys.path.insert(0, '.')
from users import IRCTestClient, TestRunner

# Create test runner instance
runner = TestRunner()

# Define tests with decorators
@runner.test("Test description")
async def test_something():
    client = IRCTestClient("test_id")
    await client.connect("TestNick")
    # ... test code ...
    await client.disconnect()

# Main function
async def main():
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")
    
    # Test server connection
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 6667),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        print("✅ Server is reachable\n")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return False
    
    # Run all tests
    success = await runner.run_all()
    return success

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
```

## Running Tests

### Run all tests:
```bash
./run_tests.sh
```

### Run individual test file:
```bash
cd testing
python3 users.py
python3 staff.py
python3 test_auth.py
python3 links.py
python3 access.py
python3 stats.py
python3 help.py
python3 services.py
```

## Test Coverage Summary

**Total Test Suites:** 8
**Total Test Cases:** ~230

**Core IRC/IRCX:**
- IRC Protocol: 115 tests
- Staff PASS Auth: 39 tests
- Server Linking: 4 tests
- Access Control: 10 tests

**v1.1.5 Features:**
- STATS System: 16 tests
- HELP System: 15 tests
- Service Improvements: 13 tests

**v1.1.8 Features:**
- AUTH Command & MFA: 18 tests

## Test Accounts

All test files document available test accounts:
- **admin/changeme** (ADMIN) - Full privileges
- **sysop/changeme** (SYSOP) - Staff privileges
- **guide/changeme** (GUIDE) - Limited staff privileges

## Status

✅ All test harnesses modernized
✅ All test files use consistent async/await pattern
✅ All test files independently executable
✅ Test runner updated for v1.1.5 structure
✅ Test documentation complete
