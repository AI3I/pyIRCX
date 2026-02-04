# Specialized Test Suites

These test suites are **not** included in the standard `run_tests.sh` execution.
They are specialized tests for specific scenarios and should be run manually when needed.

---

## Distributed/Multi-Server Testing

### distributed.py
**Size:** ~30K, ~50+ tests
**Purpose:** Multi-server distributed network testing
**Consolidated from:**
- test_trunk_branch_auth.py (staff authentication routing)
- test_multi_branch.py (multi-server communication)
- test_phase2_commands.py (cross-server command propagation)

**What it tests:**
- Server-to-server linking across multiple nodes
- User state synchronization across network
- Staff authentication routing (trunk → branch)
- Cross-server command propagation
- Network splits and rejoins
- User migration between servers
- Channel state sync across servers

**When to use:**
- Testing distributed network deployments
- Validating multi-server linking
- Testing hub-and-spoke topology
- Verifying authentication routing

**How to run:**
```bash
# Requires multiple server instances running
python3 testing/distributed.py
```

**Prerequisites:**
- Multiple pyIRCX instances configured and running
- Server linking configured in config files
- Correct server passwords and link settings

---

### network_topology.py
**Size:** ~18K
**Purpose:** Network topology testing (divergences and convergences)

**What it tests:**
- Network split scenarios
- Network merge/rejoin scenarios
- Server state after split
- Channel state during network divergence
- User state consistency
- Message routing during topology changes

**When to use:**
- Testing network resilience
- Validating split/merge handling
- Testing netsplit recovery
- Verifying state consistency

**How to run:**
```bash
python3 testing/network_topology.py
```

**Prerequisites:**
- Multiple pyIRCX instances
- Server linking enabled
- Ability to simulate network splits

---

## Performance Testing

### stress_test.py
**Size:** ~16K
**Purpose:** Load testing and stress testing

**What it tests:**
- Connection handling under load
- Message throughput
- Channel scalability (many users per channel)
- User scalability (many simultaneous users)
- Command processing performance
- Memory usage under load
- Connection limits

**When to use:**
- Performance benchmarking
- Capacity planning
- Pre-production load testing
- Regression testing for performance
- Identifying bottlenecks

**How to run:**
```bash
# Quick stress test (default settings)
python3 testing/stress_test.py

# Custom parameters (see script for options)
python3 testing/stress_test.py --users 1000 --channels 50
```

**Prerequisites:**
- Server configured for high connection limits
- Adequate system resources (RAM, file descriptors)
- May require `ulimit` adjustments

**Metrics measured:**
- Connections per second
- Messages per second
- Average latency
- Memory usage
- CPU usage

---

## WebChat Testing

### webchat.py
**Size:** ~19K
**Purpose:** WebChat WebSocket gateway and IRC compliance testing

**What it tests:**
- WebSocket gateway connection
- WebSocket → IRC protocol translation
- IRC → WebSocket message delivery
- Authentication via WebSocket
- Channel operations via WebSocket
- Private messages via WebSocket
- WebSocket reconnection handling
- IRC protocol compliance for WebChat users

**When to use:**
- Testing WebChat deployment
- Validating WebSocket gateway
- Testing web client compatibility
- Verifying protocol translation

**How to run:**
```bash
# Default (ws://localhost:8080)
python3 testing/webchat.py

# Custom WebSocket URL
python3 testing/webchat.py --ws-url ws://example.com:8080

# Verbose output
python3 testing/webchat.py --verbose

# Quick test (subset of tests)
python3 testing/webchat.py --quick
```

**Prerequisites:**
- WebChat gateway running (webchat/gateway.py)
- IRC server running
- WebSocket libraries installed (websockets)

---

## Alternative Test Suites

### commands.py
**Size:** ~32K, 29 tests
**Purpose:** Alternative focused test suite for core IRC commands
**Status:** Redundant with users.py

**What it tests:**
Same functionality as users.py, but with more granular, focused tests:
- JOIN (basic, with key, multiple joins)
- PART (basic, broadcast)
- QUIT (basic, broadcast)
- INVITE (basic, invite-only channels)
- MODE (user modes, channel modes, voice/op)
- WHO (channel members, specific user)
- WHOIS (user info)
- TOPIC (query, set, clear)
- KICK (as op, permission denied)
- PRIVMSG (channel, private)
- NOTICE
- LIST (channel list)
- NAMES (channel members)
- PING/PONG
- MOTD

**Why not in run_tests.sh:**
- users.py already comprehensively tests these commands (115 tests)
- Redundant test execution wastes time
- users.py has broader integration testing
- commands.py has narrower unit-style tests

**When to use:**
- Debugging specific command behavior
- Focused testing during development
- Quick validation of core commands
- When you want more granular test output

**How to run:**
```bash
python3 testing/commands.py
```

---

## Deleted One-Off Tests

The following test files were one-off development/debugging tests and have been **removed**:

- ❌ **final_test.py** - System/God capitalization test (superseded by users.py)
- ❌ **quick_test.py** - Quick manual System/God test (superseded by users.py)
- ❌ **test_joke.py** - JOKE command test (superseded by users.py)
- ❌ **test_mystical_entities.py** - System/God entities test (superseded by users.py)
- ❌ **test_events.py** - EVENT command test (superseded by users.py)

These were development/debugging scripts that are no longer needed.

---

## Utilities

### setup_test_accounts.py
**Size:** ~4.3K
**Purpose:** Create test accounts in database for testing

**What it does:**
- Creates admin/password (ADMIN)
- Creates sysop/password (SYSOP)
- Creates guide/password (GUIDE)
- Hashes passwords with bcrypt
- Useful for quickly setting up test environment

**How to run:**
```bash
# Default database (trunk_pyircx.db)
python3 testing/setup_test_accounts.py

# Custom database
python3 testing/setup_test_accounts.py --db /path/to/pyircx.db
```

---

## Standard Test Suite (run_tests.sh)

For comparison, here are the tests that **are** included in standard `run_tests.sh` execution:

1. **testing/users.py** - IRC/IRCX Protocol (115 tests)
2. **testing/staff.py** - Staff PASS Authentication (39 tests)
3. **testing/test_auth.py** - AUTH Command & MFA (18 tests)
4. **testing/links.py** - Server Linking (4 tests)
5. **testing/access.py** - Access Control (10 tests)
6. **testing/stats.py** - STATS System (16 tests)
7. **testing/help.py** - HELP System (15 tests)
8. **testing/services.py** - Service Improvements (13 tests)

**Total:** 8 suites, ~230 tests

---

## Testing the Management API

### api.py Testing (NOT YET IMPLEMENTED)

**api.py** (2351 lines) - Standalone Management API

**Currently:** No test suite exists for api.py
**Needed:** Test suite for API endpoints

**What should be tested:**
- User management endpoints
- Channel management endpoints
- Server statistics endpoints
- Configuration management endpoints
- Authentication/authorization
- Error handling
- JSON response validation
- Database operations

**Proposed test file:** `testing/test_api.py`

**How it would work:**
```python
# Example structure
import api
import unittest

class TestUserAPI(unittest.TestCase):
    def test_get_users(self):
        result = api.get_users()
        self.assertIsInstance(result, list)

    def test_create_user(self):
        result = api.create_user("testuser", "password", "USER")
        self.assertTrue(result['success'])
```

---

## Summary

**Standard Tests (run_tests.sh):** 8 suites, ~230 tests
- Core IRC/IRCX functionality
- Staff authentication
- Server linking
- Access control
- STATS, HELP, Services

**Specialized Tests (manual):** 4 suites
- Distributed/multi-server testing
- Network topology testing
- Performance/stress testing
- WebChat testing

**Alternative Tests:** 1 suite
- commands.py (redundant with users.py)

**Utilities:** 1 script
- setup_test_accounts.py

**Not Yet Implemented:** 1 needed
- API testing (api.py)

---

*Last updated: 2026-01-17*
*Test suite consolidation - v2.0.0*
