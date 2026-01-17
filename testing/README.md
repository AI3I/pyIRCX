# pyIRCX v2.0.0 Test Suite

Comprehensive test infrastructure for pyIRCX IRC/IRCX server.

## Quick Start

### Run All Tests

```bash
# From project root
python3 run_tests.py
```

### Run Individual Test Suite

```bash
cd testing
python3 users.py          # User management tests
python3 commands.py       # IRC command tests
python3 staff.py          # Staff features
python3 services.py       # Service bots
python3 access.py         # IRCX access control
python3 help.py           # Help system
python3 stats.py          # STATS command
python3 distributed.py    # Distributed networking
```

---

## Test Suites

### Core IRC Functionality

#### `users.py` - User Management (80+ tests)
- User registration and authentication
- Nickname management (NICK)
- User modes (+i, +o, +a, +g, +r, +z, +k, +x, +w)
- WHOIS, WHO, WHOWAS commands
- User information queries

**Example:**
```bash
python3 users.py
```

#### `commands.py` - IRC Commands (60+ tests)
- Channel operations (JOIN, PART, QUIT)
- Channel modes
- TOPIC, KICK, INVITE
- PRIVMSG, NOTICE
- LIST, NAMES
- Standard IRC command suite

**Example:**
```bash
python3 commands.py
```

### Staff & Administration

#### `staff.py` - Staff Features (45+ tests)
- ADMIN, SYSOP, GUIDE authentication
- STAFF command (LIST, ADD, DEL, SET, PASS)
- Staff-only commands (KILL, GAG, REHASH)
- Permission hierarchies
- Staff mode propagation

**Example:**
```bash
python3 staff.py
```

### Services

#### `services.py` - Service Bots (40+ tests)
- **Registrar**: Nickname/channel registration
- **Messenger**: Offline messages
- **NewsFlash**: Server announcements
- **ServiceBots**: Automated moderation
- HELP commands for all services
- Case-insensitive routing

**Example:**
```bash
python3 services.py
```

### IRCX Extensions

#### `access.py` - Access Control (15+ tests)
- ACCESS command (GRANT, DENY, LIST, CLEAR)
- Permission masks and wildcards
- Owner/Host/Voice privileges
- Access list management

**Example:**
```bash
python3 access.py
```

### User Experience

#### `help.py` - Help System (15+ tests)
- HELP command for all topics
- Fuzzy matching ("Did you mean?")
- Command examples
- Service help text
- v2.0.0 personalized help

**Example:**
```bash
python3 help.py
```

#### `stats.py` - STATS Command (16+ tests)
- STATS u (uptime)
- STATS c (connections)
- STATS a/o/g (admins/operators/guides)
- STATS v (version)
- Enhanced v2.0.0 formatting

**Example:**
```bash
python3 stats.py
```

### Distributed Networking

#### `distributed.py` - Network Operations (20+ tests)
Comprehensive tests for trunk/branch topology and cross-server operations.

**Test Categories:**
1. **Trunk/Branch Authentication** (2 tests)
   - Staff auth routing from branch → trunk
   - Service command routing

2. **Cross-Server Communication** (3 tests)
   - PRIVMSG between servers
   - Users in same channel across servers
   - QUIT propagation

3. **Command Propagation** (8 tests)
   - TOPIC, KICK, NICK, AWAY
   - MODE changes
   - WHO, NAMES, WHISPER
   
4. **Multi-Branch Network** (4 tests)
   - 3-server topology (trunk + 2 branches)
   - Branch-to-branch messaging
   - Network-wide channel operations
   - MODE propagation across network

5. **End User Scenarios** (5 tests)
   - Basic workflow (join, chat, leave)
   - Cross-server registration
   - Offline messages
   - Command aliases
   
6. **Staff Scenarios** (5 tests)
   - Admin authentication on branch
   - STAFF command from branch
   - Cross-server KILL
   - GAG functionality
   - Network-wide STATS

**Example:**
```bash
python3 distributed.py
```

---

## Test Infrastructure

### TestRunner Framework

All tests use the `TestRunner` class from `users.py`:

```python
from users import IRCTestClient, TestRunner

runner = TestRunner()

@runner.test("Test description")
async def test_something():
    client = IRCTestClient("test_user")
    await client.connect("TestNick")
    
    await client.send_raw("JOIN #test")
    await asyncio.sleep(0.5)
    
    assert any('JOIN' in line for line in client.buffer)

if __name__ == "__main__":
    asyncio.run(runner.run_all())
```

### IRCTestClient API

```python
# Create client
client = IRCTestClient("client_id", host="127.0.0.1", port=6667)

# Connect and register
await client.connect("Nickname", "username")

# Send raw IRC commands
await client.send_raw("JOIN #channel")
await client.send_raw("PRIVMSG #channel :Hello!")

# Check buffer for responses
assert any('JOIN' in line for line in client.buffer)

# Clear buffer
client.buffer.clear()

# Disconnect
await client.disconnect()
```

---

## Testing Requirements

### Server Setup

Tests expect the following servers running:

- **Trunk Server**: 127.0.0.1:6667 (services hub)
- **Branch Server 1**: 127.0.0.1:6668
- **Branch Server 2**: 127.0.0.1:6669 (for multi-branch tests)

### Test Accounts

Tests use these pre-configured staff accounts:

- **admin/changeme** (ADMIN)
- **sysop/testpass** (SYSOP)
- **guide/testpass** (GUIDE)

### Configuration

Ensure your test servers have:
- `services.enabled = true`
- `services.is_services_hub = true` (trunk only)
- `linking.enabled = true`
- `linking.server_role = "trunk"` or `"branch"`

---

## Test Coverage

### Current Coverage

**Total Tests:** ~260
- Unit Tests (testing/): 241 tests
- Distributed Tests: 20+ tests

### v2.0.0 Features Covered

- ✅ Distributed networking (trunk/branch)
- ✅ Cross-server operations
- ✅ Core IRC protocol (48 commands)
- ✅ IRCX extensions
- ✅ Services (Registrar, Messenger, NewsFlash, ServiceBot)
- ✅ Staff hierarchy
- ✅ Access control

### Gaps to Address

See `docs/testing/TEST_AUDIT_v2.0.0.md` for detailed gap analysis:
- ❌ v2.0.0 personalized messages
- ❌ Command aliases comprehensive tests
- ❌ ServiceBot dispatcher
- ❌ PROFANITY command
- ❌ Enhanced STATS formatting verification

---

## Writing New Tests

### Template

```python
#!/usr/bin/env python3
"""
Test Suite Description
"""

import asyncio
import sys
from typing import List

sys.path.insert(0, '.')
from users import IRCTestClient, TestRunner

runner = TestRunner()

@runner.test("Test name")
async def test_feature():
    """Test description"""
    client = IRCTestClient("test_id")
    await client.connect("TestNick")
    
    # Test logic here
    await client.send_raw("COMMAND params")
    await asyncio.sleep(0.5)
    
    # Assertions
    assert condition, "Error message"

if __name__ == "__main__":
    asyncio.run(runner.run_all())
```

### Best Practices

1. **Use descriptive test names** - Explain what's being tested
2. **Add sleep delays** - Allow server processing (0.5-1s)
3. **Clear buffers** - `client.buffer.clear()` before checking responses
4. **Check multiple conditions** - Verify expected behavior thoroughly
5. **Clean up** - Disconnect clients when done

---

## Continuous Integration

### GitHub Actions (Future)

```yaml
# .github/workflows/tests.yml
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
          python-version: 3.8
      - name: Install dependencies
        run: pip install aiosqlite bcrypt
      - name: Run tests
        run: python3 run_tests.py
```

---

## Troubleshooting

### Tests Fail to Connect

**Problem:** `Connection refused to 127.0.0.1:6667`

**Solution:**
```bash
# Start pyIRCX server
python3 pyircx.py

# Or with config
python3 pyircx.py config_trunk.json
```

### Tests Time Out

**Problem:** Tests hang waiting for responses

**Solution:**
- Increase `await asyncio.sleep()` delays
- Check server logs for errors
- Verify server is processing commands

### Buffer Assertions Fail

**Problem:** `assert` fails even though response looks correct

**Solution:**
```python
# Debug by printing buffer
print("Buffer contents:")
for line in client.buffer:
    print(f"  {line}")

# Check with 'in' instead of exact match
assert any('expected text' in line.lower() for line in client.buffer)
```

---

## Contributing

When adding new features to pyIRCX:

1. **Write tests first** (TDD approach)
2. **Add to appropriate test suite** (or create new one)
3. **Update run_tests.py** if new suite created
4. **Run full test suite** before committing
5. **Update this README** with new test descriptions

---

## License

All test code is licensed under AGPL v3.

Copyright (C) 2026 pyIRCX Project

---

## Stress Testing & Load Testing

### `stress_test.py` - Load Testing Tool

Simulates realistic IRC usage with hundreds of concurrent clients for performance validation.

**⚠️ IMPORTANT:** Only use on YOUR OWN servers. See `STRESS_TEST.md` for full documentation.

**Quick Test (50 users, 1 minute):**
```bash
python3 testing/stress_test.py --quick
```

**Standard Test (100 users, 5 minutes):**
```bash
python3 testing/stress_test.py
```

**Heavy Load (500 users, 10 minutes):**
```bash
python3 testing/stress_test.py --heavy
```

**Features:**
- Regular users: Join/part channels, chat, change nicks
- Staff users: Mode changes, topics, STATS commands
- Service users: Register nicks, offline messages
- Cross-server load: Distributed across trunk + branches

**See:** `STRESS_TEST.md` for complete documentation, safety guidelines, and benchmarking instructions.

---

## For End Users

The test suite is included in pyIRCX releases so you can:

1. **Validate your installation** - Run tests after setup
2. **Verify upgrades** - Ensure nothing broke
3. **Test configuration** - Validate server settings
4. **Performance testing** - Benchmark your hardware
5. **Development** - Add tests for custom features

### Quick Validation

After installing pyIRCX:

```bash
# Run core functionality tests
python3 testing/users.py
python3 testing/commands.py

# Test your specific deployment
python3 testing/distributed.py  # If using server linking
python3 testing/services.py     # If using services

# Load test (optional)
python3 testing/stress_test.py --quick
```

---
