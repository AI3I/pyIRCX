# pyIRCX Testing Guide

This guide explains how to run the comprehensive test suites for pyIRCX.

## Test Overview

pyIRCX includes **54 comprehensive tests** covering all major functionality:

- **50 User/IRC Tests** - IRC and IRCX protocol compliance
- **4 Server Linking Tests** - Server-to-server linking functionality

**Current Status: 54/54 tests passing (100%)**

## Prerequisites

### System Requirements
- Python 3.8 or higher
- pyIRCX server installed and configured
- Network access to localhost

### Python Dependencies
All dependencies are already included in pyIRCX:
- `asyncio` - Async I/O (built-in)
- `ssl` - SSL/TLS support (built-in)

No additional packages required for testing.

## Quick Start

### Option 1: Automated Test Runner (Recommended)

Run all tests with a single command:

```bash
./run_tests.sh
```

This script will:
1. Check if the server is running
2. Start a temporary test server if needed
3. Run all test suites
4. Display results summary
5. Clean up test server

### Option 2: Manual Testing

#### Step 1: Start the Test Server

**Important:** Tests require a running pyIRCX server on `localhost:6667`.

```bash
# Option A: Start your installed server
sudo systemctl start pyircx

# Option B: Run server directly for testing
python3 pyircx.py --config pyircx_config.json
```

#### Step 2: Run Test Suites

In a separate terminal, run the tests:

```bash
# Run all User/IRC protocol tests (50 tests)
python3 pyIRCX_test_users.py

# Run server linking tests (4 tests)
python3 pyIRCX_test_links.py

# Run staff authentication tests (optional)
python3 pyIRCX_test_staff.py
```

#### Step 3: Review Results

Tests output results in real-time:
- ✅ `PASSED` - Test succeeded
- ❌ `FAILED` - Test failed (includes error details)

## Test Suites

### 1. User/IRC Protocol Tests (`pyIRCX_test_users.py`)

**Tests: 50 | Duration: ~30 seconds**

Covers all IRC and IRCX protocol features:

**Core IRC Protocol:**
- Basic connection and registration
- NICK/USER commands
- Nick collision handling
- PING/PONG keepalive
- MOTD display
- VERSION command

**Channel Operations:**
- JOIN/PART commands
- Channel modes (+m, +s, +p, +n, +t, +i, +k, +l)
- Owner (.), Host (@), Voice (+) privileges
- TOPIC command
- WHO/WHOIS commands
- PRIVMSG/NOTICE to users and channels
- KICK command

**IRCX Extensions:**
- IRCX protocol negotiation
- ISIRCX command
- ACCESS command (OWNER, HOST, VOICE, GRANT, DENY)
- PROP command (channel properties)
- WHISPER command (private channel messages)
- LISTX command (extended channel listing)
- Clone channels (+d mode)

**Services:**
- Built-in service bots (System, Registrar, Messenger)
- Nickname registration
- Channel registration
- Offline messaging

**Advanced Features:**
- IRCv3 capabilities (CAP LS/REQ/ACK/END)
- SASL authentication
- Multi-prefix support
- User modes (+i, +w, +s, +o)
- Away status (AWAY command)

### 2. Server Linking Tests (`pyIRCX_test_links.py`)

**Tests: 4 | Duration: ~5 seconds**

Tests server-to-server linking functionality:

- LINKS command (single server)
- LINKS command (linked servers)
- CONNECT command permission check
- SQUIT command permission check

**Note:** Full linking tests require two server instances. Basic tests verify commands work correctly on a single server.

### 3. Staff Authentication Tests (`pyIRCX_test_staff.py`)

**Tests: Variable | Duration: ~10 seconds**

Tests staff authentication system:

- STAFF LOGIN command
- STAFF LOGOUT command
- STAFF LIST command
- STAFF ADD/DEL commands (ADMIN only)
- STAFF PASS command (password changes)
- STAFF LEVEL command (privilege changes)
- Permission level enforcement

## Interpreting Test Results

### Successful Test Run

```
======================================================================
pyIRCX REGRESSION TEST SUITE
======================================================================

======================================================================
TEST: Basic Connection
======================================================================
✅ PASSED: Basic Connection

[... more tests ...]

======================================================================
SUMMARY
======================================================================
Total tests run: 50
Passed: 50
Failed: 0

✅ All tests passed!
```

### Failed Test

If a test fails, you'll see detailed error information:

```
❌ FAILED: Channel Join
Error: Expected 353 (NAMES) but didn't receive it
Buffer contents: [...]
```

Common failure reasons:
- Server not running on localhost:6667
- Server configuration issues
- Network connectivity problems
- Database errors

## Troubleshooting

### Test Fails: "Connection refused"

**Problem:** Server is not running or not listening on localhost:6667

**Solution:**
```bash
# Check if server is running
sudo systemctl status pyircx

# Or check port
netstat -tlnp | grep 6667

# Start the server
sudo systemctl start pyircx
# OR
python3 pyircx.py
```

### Test Fails: Database Errors

**Problem:** Database file is locked or permissions issue

**Solution:**
```bash
# Stop any running servers
sudo systemctl stop pyircx

# Check database permissions
ls -la pyircx.db

# If needed, fix permissions
sudo chown pyircx:pyircx /opt/pyircx/pyircx.db
```

### Test Timeouts

**Problem:** Server is slow to respond or overloaded

**Solution:**
- Increase timeout values in test scripts
- Ensure server has adequate resources
- Check server logs: `journalctl -u pyircx -n 50`

### Tests Pass Locally but Fail in CI/CD

**Problem:** Different environment or timing issues

**Solution:**
- Ensure CI environment has adequate resources
- Add delays between tests if needed
- Check firewall rules in CI environment

## Writing New Tests

### Test Structure

```python
@runner.test("Test Name")
async def test_something():
    """Test description"""
    client = IRCTestClient("test_something")
    await client.connect("TestNick")

    # Send command
    await client.send_raw("COMMAND params")

    # Wait for response
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Assert expected result
    assert await client.expect("NUMERIC"), "Error message"

    # Cleanup
    await client.disconnect()
```

### Best Practices

1. **Use descriptive test names** - Clear indication of what's being tested
2. **Add cleanup** - Disconnect clients, leave channels
3. **Appropriate delays** - Allow server time to process (0.2-0.5s usually sufficient)
4. **Check both success and failure** - Test that invalid input is properly rejected
5. **Isolate tests** - Each test should be independent

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install bcrypt aiosqlite pyotp
      - name: Run tests
        run: |
          ./run_tests.sh
```

## Performance Testing

For performance/load testing:

```bash
# Run multiple concurrent clients
for i in {1..100}; do
  python3 -c "
import asyncio
from pyIRCX_test_users import IRCTestClient

async def connect():
    client = IRCTestClient('perf_test')
    await client.connect('User$i')
    await asyncio.sleep(60)
    await client.disconnect()

asyncio.run(connect())
" &
done

# Monitor with
watch -n 1 'netstat -an | grep 6667 | wc -l'
```

## Test Coverage Goals

Current coverage: **100% of core functionality**

Future test additions:
- Server linking with 2+ servers (network topology tests)
- SSL/TLS connection tests
- Load testing (1000+ concurrent users)
- Stress testing (rapid connect/disconnect)
- Fuzzing (malformed protocol messages)
- Security testing (authentication bypass attempts)

## Contributing Tests

When contributing new features:

1. Add tests for new functionality
2. Ensure existing tests still pass
3. Update this documentation
4. Add test results to TEST_RESULTS.md

## Support

If tests fail unexpectedly:

1. Check [TEST_RESULTS.md](TEST_RESULTS.md) for known issues
2. Review server logs: `journalctl -u pyircx -f`
3. Open an issue on GitHub with:
   - Test output
   - Server logs
   - System information (OS, Python version)
   - Configuration (sanitized)

---

**Last Updated:** 2026-01-02
**Test Suite Version:** 1.0.4
