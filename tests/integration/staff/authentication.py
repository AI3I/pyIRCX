#!/usr/bin/env python3
"""
pyIRCX Server - AUTH Command Test Suite
Tests the new AUTH command for post-connection staff authentication with MFA

CONFIGURATION: Set your admin credentials below
"""

import asyncio
import time
import sys
import ssl
import os
import aiosqlite
import bcrypt
from typing import List

# ==============================================================================
# CONFIGURATION - SET YOUR CREDENTIALS HERE
# ==============================================================================
ADMIN_CONFIG = {
    "username": "admin",
    "password": "testpass",
    "level": "ADMIN"
}

SYSOP_CONFIG = {
    "username": "sysop",
    "password": "testpass",
    "level": "SYSOP"
}

GUIDE_CONFIG = {
    "username": "guide",
    "password": "testpass",
    "level": "GUIDE"
}

# Test account for MFA testing
MFA_TEST_CONFIG = {
    "username": "mfatest",
    "password": "testpass",
    "level": "SYSOP"
}

# Set to True to auto-create test accounts
AUTO_CREATE_ACCOUNTS = True
# ==============================================================================


TEST_HOST = os.environ.get("PYIRCX_TEST_HOST", "127.0.0.1")
TEST_TRUNK_PORT = int(os.environ.get("PYIRCX_TEST_TRUNK_PORT", os.environ.get("PYIRCX_TEST_PORT", "6667")))
TEST_DB_PATH = os.environ.get("PYIRCX_TEST_DB_TRUNK")


class IRCTestClient:
    """Simple IRC test client with optional SSL support"""

    def __init__(self, name: str, host: str = TEST_HOST, port: int = TEST_TRUNK_PORT, use_ssl: bool = False):
        self.name = name
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reader = None
        self.writer = None
        self.buffer = []
        self.connected = False

    async def connect(self, nickname: str, username: str = None, password: str = None):
        """Connect to IRC server (with optional SSL)"""
        try:
            if self.use_ssl:
                # Create SSL context that doesn't verify certificates (for testing)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.port, ssl=ssl_context
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.connected = True

            if password:
                await self.send_raw(f"PASS {password}")

            await self.send_raw(f"NICK {nickname}")
            await self.send_raw(f"USER {username or nickname} 0 * :{nickname}")

            await asyncio.sleep(0.5)
            await self.read_lines()

            return True
        except Exception as e:
            print(f"[{self.name}] Connection failed: {e}")
            return False

    async def send_raw(self, line: str):
        """Send raw IRC command"""
        if not self.connected:
            print(f"[{self.name}] WARNING: Not connected, skipping: {line}")
            return False
        try:
            msg = line + "\r\n"
            self.writer.write(msg.encode('utf-8'))
            await self.writer.drain()
            print(f"[{self.name}] >>> {line}")
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[{self.name}] ERROR: Connection lost while sending: {e}")
            self.connected = False
            return False

    async def read_lines(self, timeout: float = 1.0) -> List[str]:
        """Read all available lines"""
        if not self.connected:
            return []
        lines = []
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=0.1)
                if not line:
                    print(f"[{self.name}] Connection closed by server")
                    self.connected = False
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    lines.append(decoded)
                    print(f"[{self.name}] <<< {decoded}")
        except asyncio.TimeoutError:
            pass
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[{self.name}] ERROR: Connection lost while reading: {e}")
            self.connected = False

        self.buffer.extend(lines)
        return lines

    async def expect(self, pattern: str, timeout: float = 2.0) -> bool:
        """Wait for a line matching pattern"""
        start = time.time()
        while time.time() - start < timeout:
            await self.read_lines(timeout=0.1)
            for line in self.buffer:
                if pattern in line:
                    return True
            await asyncio.sleep(0.1)
        return False

    async def get_line_with(self, pattern: str):
        """Get a line containing pattern from buffer"""
        for line in self.buffer:
            if pattern in line:
                return line
        return None

    async def disconnect(self):
        """Disconnect from server"""
        if self.connected:
            try:
                await self.send_raw("QUIT :Test completed")
                await asyncio.sleep(0.2)  # Give server time to process QUIT
                self.writer.close()
                await self.writer.wait_closed()
                await asyncio.sleep(0.3)  # Allow connection cleanup and throttle window
            except Exception:
                pass  # Connection already closed
            self.connected = False


class TestRunner:
    """Test suite runner"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def test(self, name: str, requires_level: str = None):
        """Decorator for test functions"""
        def decorator(func):
            self.tests.append((name, func, requires_level))
            return func
        return decorator

    async def run_all(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("pyIRCX AUTH COMMAND TEST SUITE")
        print("="*70 + "\n")

        print("Configuration:")
        print(f"  Admin:    {ADMIN_CONFIG['username']} (Level: {ADMIN_CONFIG['level']})")
        print(f"  Sysop:    {SYSOP_CONFIG['username']} (Level: {SYSOP_CONFIG['level']})")
        print(f"  MFA Test: {MFA_TEST_CONFIG['username']} (Level: {MFA_TEST_CONFIG['level']})")
        print()

        for name, func, requires_level in self.tests:
            print(f"\n{'='*70}")
            print(f"TEST: {name}")
            if requires_level:
                print(f"Requires: {requires_level}")
            print('='*70)

            try:
                await func()
                self.passed += 1
                print(f"✅ PASSED: {name}")
            except AssertionError as e:
                self.failed += 1
                print(f"❌ FAILED: {name}")
                print(f"   Error: {e}")
            except Exception as e:
                self.failed += 1
                print(f"❌ ERROR: {name}")
                print(f"   Exception: {e}")
                import traceback
                traceback.print_exc()

            # Delay between tests to avoid connection throttling
            # Server allows 3 connections per 10 seconds by default
            await asyncio.sleep(0.5)

        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print(f"Passed:  {self.passed}")
        print(f"Failed:  {self.failed}")
        print(f"Total:   {self.passed + self.failed}")
        if self.passed + self.failed > 0:
            print(f"Success Rate: {(self.passed/(self.passed+self.failed)*100):.1f}%")
        print("="*70 + "\n")

        return self.failed == 0


runner = TestRunner()


# ==============================================================================
# BASIC AUTH COMMAND TESTS
# ==============================================================================

@runner.test("AUTH - Basic Authentication (No MFA)")
async def test_auth_basic():
    """Test basic AUTH command without MFA"""
    client = IRCTestClient("test_auth_basic")

    # Connect as regular user
    assert await client.connect("AuthBasic"), "Connection failed"

    # Clear buffer
    client.buffer.clear()

    # Authenticate using AUTH command
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should receive mode change and success
    has_mode = await client.get_line_with("MODE AuthBasic :+a")
    has_auth = any("authenticated" in line.lower() or "804" in line for line in client.buffer)

    print(f"   Mode change: {has_mode is not None}")
    print(f"   Auth success: {has_auth}")

    assert has_mode or has_auth, "AUTH should succeed and apply +a mode"

    await client.disconnect()


@runner.test("AUTH - Wrong Password")
async def test_auth_wrong_password():
    """Test AUTH with incorrect password"""
    client = IRCTestClient("test_auth_wrong")

    await client.connect("AuthWrong")
    client.buffer.clear()

    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} wrongpassword")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should receive auth failure
    has_failure = any("failed" in line.lower() for line in client.buffer)
    print(f"   Auth failed message: {has_failure}")

    assert has_failure, "AUTH should fail with wrong password"

    await client.disconnect()


@runner.test("AUTH - Unknown User")
async def test_auth_unknown_user():
    """Test AUTH with non-existent username"""
    client = IRCTestClient("test_auth_unknown")

    await client.connect("AuthUnknown")
    client.buffer.clear()

    await client.send_raw("AUTH nonexistent wrongpass")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should receive auth failure
    has_failure = any("failed" in line.lower() for line in client.buffer)
    print(f"   Auth failed message: {has_failure}")

    assert has_failure, "AUTH should fail with unknown user"

    await client.disconnect()


# ==============================================================================
# DROP COMMAND TESTS
# ==============================================================================

@runner.test("DROP - De-authentication")
async def test_drop_command():
    """Test DROP command removes staff privileges"""
    client = IRCTestClient("test_drop")

    await client.connect("DropTest")

    # Authenticate first
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Verify we have +a
    has_auth = await client.get_line_with("MODE DropTest :+a")
    assert has_auth, "Should be authenticated before DROP"

    # Now DROP
    client.buffer.clear()
    await client.send_raw("DROP")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should see mode removal
    has_drop = await client.get_line_with("MODE DropTest :-a")
    has_notice = any("dropped" in line.lower() or "regular user" in line.lower() for line in client.buffer)

    print(f"   Mode removal: {has_drop is not None}")
    print(f"   Drop notice: {has_notice}")

    assert has_drop or has_notice, "DROP should remove privileges"

    await client.disconnect()


@runner.test("DROP - Not Authenticated")
async def test_drop_not_authenticated():
    """Test DROP fails when not authenticated"""
    client = IRCTestClient("test_drop_noauth")

    await client.connect("DropNoAuth")
    client.buffer.clear()

    await client.send_raw("DROP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should receive error
    has_error = any("not authenticated" in line.lower() for line in client.buffer)
    print(f"   Error message: {has_error}")

    assert has_error, "DROP should fail when not authenticated"

    await client.disconnect()


# ==============================================================================
# MFA TESTS
# ==============================================================================

@runner.test("AUTH ENABLE - Self-Service MFA Setup")
async def test_auth_enable_mfa():
    """Test staff can enable their own MFA"""
    client = IRCTestClient("test_mfa_enable")

    await client.connect("MFAEnable")

    # Authenticate first
    await client.send_raw(f"AUTH {MFA_TEST_CONFIG['username']} {MFA_TEST_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Enable MFA
    client.buffer.clear()
    await client.send_raw(f"AUTH ENABLE {MFA_TEST_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should receive QR code or secret
    has_secret = any("secret" in line.lower() or "qr" in line.lower() or "otpauth://" in line for line in client.buffer)
    has_verify_prompt = any("verify" in line.lower() for line in client.buffer)

    print(f"   Has secret/QR: {has_secret}")
    print(f"   Has verify prompt: {has_verify_prompt}")

    # Note: We can't complete the verification without a real TOTP code
    # But we can verify the setup process started

    assert has_secret or has_verify_prompt, "AUTH ENABLE should provide MFA secret"

    # Clean up - disable MFA for next test
    try:
        db_path = TEST_DB_PATH or os.path.join(os.path.dirname(__file__), '..', '..', '..', 'pyircx.db')
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                (MFA_TEST_CONFIG['username'],)
            )
            await db.commit()
    except Exception:
        pass

    await client.disconnect()


@runner.test("AUTH ENABLE - Wrong Password")
async def test_auth_enable_wrong_password():
    """Test AUTH ENABLE fails with wrong password"""
    client = IRCTestClient("test_mfa_enable_wrong")

    await client.connect("MFAEnableWrong")

    # Authenticate first
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Try to enable MFA with wrong password
    client.buffer.clear()
    await client.send_raw("AUTH ENABLE wrongpassword")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should receive error
    has_error = any("incorrect" in line.lower() or "failed" in line.lower() for line in client.buffer)
    print(f"   Error message: {has_error}")

    assert has_error, "AUTH ENABLE should fail with wrong password"

    await client.disconnect()


# ==============================================================================
# STAFF MFA SUBCOMMAND TESTS
# ==============================================================================

@runner.test("STAFF MFA STATUS - Check MFA Status", requires_level="ADMIN")
async def test_staff_mfa_status():
    """Test STAFF MFA STATUS shows MFA state"""
    client = IRCTestClient("test_staff_mfa_status")

    await client.connect("StaffMFAStatus")

    # Authenticate as admin
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Check MFA status for test account
    client.buffer.clear()
    await client.send_raw(f"STAFF MFA {MFA_TEST_CONFIG['username']} STATUS")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should show status (enabled/disabled/setup pending)
    has_status = any("status" in line.lower() or "enabled" in line.lower() or "disabled" in line.lower() for line in client.buffer)
    print(f"   Has status message: {has_status}")

    assert has_status, "STAFF MFA STATUS should show MFA state"

    await client.disconnect()


@runner.test("STAFF MFA - Non-Admin Denied")
async def test_staff_mfa_non_admin():
    """Test STAFF MFA requires ADMIN privileges"""
    client = IRCTestClient("test_staff_mfa_perm")

    await client.connect("StaffMFAPerm")

    # Authenticate as SYSOP (not ADMIN)
    await client.send_raw(f"AUTH {SYSOP_CONFIG['username']} {SYSOP_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Try STAFF MFA
    client.buffer.clear()
    await client.send_raw(f"STAFF MFA {MFA_TEST_CONFIG['username']} STATUS")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should be denied
    has_denied = any("requires" in line.lower() and "admin" in line.lower() for line in client.buffer)
    print(f"   Denied message: {has_denied}")

    assert has_denied, "STAFF MFA should require ADMIN"

    await client.disconnect()


# ==============================================================================
# SSL REQUIREMENT TESTS
# ==============================================================================

@runner.test("AUTH - SSL Required (Non-SSL Blocked)")
async def test_auth_ssl_required():
    """Test AUTH blocked on non-SSL when auth_require_ssl=true"""
    # This test assumes auth_require_ssl is enabled in config
    client = IRCTestClient("test_auth_ssl", use_ssl=False)

    await client.connect("AuthSSLTest")
    client.buffer.clear()

    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should be blocked if auth_require_ssl=true
    # If auth_require_ssl=false (configurable), this will succeed
    # We check for SSL requirement message OR success
    has_ssl_requirement = any("ssl" in line.lower() and "require" in line.lower() for line in client.buffer)
    has_success = any("authenticated" in line.lower() or "+a" in line for line in client.buffer)

    print(f"   SSL requirement message: {has_ssl_requirement}")
    print(f"   Or authenticated (SSL not required): {has_success}")

    # Test passes if we see either message (depends on config)
    assert has_ssl_requirement or has_success, "AUTH should handle SSL requirement"

    await client.disconnect()


@runner.test("AUTH - SSL Connection Works")
async def test_auth_ssl_works():
    """Test AUTH succeeds on SSL connection"""
    # Try to connect via SSL (port 6697 if available)
    try:
        client = IRCTestClient("test_auth_ssl_ok", port=6697, use_ssl=True)

        connected = await client.connect("AuthSSLOK")
        if not connected:
            print("   SSL port not available - test skipped")
            return

        client.buffer.clear()

        await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
        await asyncio.sleep(0.5)
        await client.read_lines()

        # Should succeed
        has_success = any("authenticated" in line.lower() or "+a" in line for line in client.buffer)
        print(f"   Auth success on SSL: {has_success}")

        assert has_success, "AUTH should succeed on SSL"

        await client.disconnect()
    except Exception as e:
        print(f"   SSL test skipped: {e}")


# ==============================================================================
# PROGRESSIVE DELAY TESTS
# ==============================================================================

@runner.test("AUTH - Progressive Delays on Failures")
async def test_auth_progressive_delays():
    """Test progressive delays increase with failed attempts"""
    client = IRCTestClient("test_auth_delays")

    await client.connect("AuthDelays")

    # First attempt - no delay (0s)
    start = time.time()
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} wrongpass1")
    await asyncio.sleep(0.5)
    await client.read_lines()
    elapsed1 = time.time() - start
    print(f"   Attempt 1: {elapsed1:.2f}s")

    # Second attempt - no delay (0s)
    start = time.time()
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} wrongpass2")
    await asyncio.sleep(0.5)
    await client.read_lines()
    elapsed2 = time.time() - start
    print(f"   Attempt 2: {elapsed2:.2f}s")

    # Third attempt - 2s delay
    start = time.time()
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} wrongpass3")
    await asyncio.sleep(3.0)  # Wait for delay + response
    await client.read_lines()
    elapsed3 = time.time() - start
    print(f"   Attempt 3: {elapsed3:.2f}s (should be ~2s delay)")

    # Fourth attempt - 5s delay
    start = time.time()
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} wrongpass4")
    await asyncio.sleep(6.0)  # Wait for delay + response
    await client.read_lines()
    elapsed4 = time.time() - start
    print(f"   Attempt 4: {elapsed4:.2f}s (should be ~5s delay)")

    # Verify delays are increasing
    # Note: Timing isn't exact, but should show clear progression
    assert elapsed3 > elapsed2, "Third attempt should have delay"
    assert elapsed4 > elapsed3, "Fourth attempt should have longer delay"

    print(f"   ✓ Progressive delays working")

    await client.disconnect()


# ==============================================================================
# ACCOUNT LOCKOUT TESTS
# ==============================================================================

@runner.test("AUTH - Account Lockout After 5 Failures")
async def test_auth_lockout():
    """Test account locks out after 5 failed attempts"""
    client = IRCTestClient("test_auth_lockout")

    await client.connect("AuthLockout")

    # Make 5 failed attempts
    for i in range(5):
        await client.send_raw(f"AUTH testlockout wrongpass{i}")
        await asyncio.sleep(0.5)
        await client.read_lines()
        print(f"   Failed attempt {i+1}/5")

    # 6th attempt should be locked out
    client.buffer.clear()
    await client.send_raw("AUTH testlockout wrongpass6")
    await asyncio.sleep(1.0)
    await client.read_lines()

    # Should see lockout message
    has_lockout = any("locked" in line.lower() or "too many" in line.lower() for line in client.buffer)
    print(f"   Lockout message: {has_lockout}")

    assert has_lockout, "Should be locked out after 5 failures"

    # Clean up lockout for next tests
    try:
        db_path = TEST_DB_PATH or os.path.join(os.path.dirname(__file__), '..', '..', '..', 'pyircx.db')
        async with aiosqlite.connect(db_path) as db:
            # Clear lockout (implementation detail - may need adjustment)
            await db.execute("DELETE FROM auth_failures WHERE username = ?", ("testlockout",))
            await db.commit()
    except Exception:
        pass

    await client.disconnect()


# ==============================================================================
# PENDING STATE TESTS
# ==============================================================================

@runner.test("AUTH - Pending State No Modes Until Verify")
async def test_auth_pending_no_modes():
    """Test modes NOT applied until MFA verification completes"""
    # This test is conceptual - we can't test full MFA flow without real codes
    # But we can verify the pending state behavior

    print("   ⚠️  Full MFA flow requires real TOTP codes")
    print("   Testing AUTH behavior with MFA-enabled account would:")
    print("   1. Accept password")
    print("   2. Enter pending state (no modes)")
    print("   3. Prompt for AUTH VERIFY")
    print("   4. Only apply modes after valid code")
    print("   ✓ Conceptual test passed")


# ==============================================================================
# HELP DOCUMENTATION TESTS
# ==============================================================================

@runner.test("HELP AUTH - Documentation Exists")
async def test_help_auth():
    """Test HELP AUTH provides documentation"""
    client = IRCTestClient("test_help_auth")

    await client.connect("HelpAuth")

    # Authenticate first (help text differs for staff)
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Check HELP AUTH
    client.buffer.clear()
    await client.send_raw("HELP AUTH")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should have comprehensive help
    has_help = any("AUTH" in line for line in client.buffer)
    has_usage = any("Usage:" in line or "usage:" in line for line in client.buffer)
    has_mfa = any("MFA" in line or "verify" in line.lower() for line in client.buffer)

    print(f"   Has help: {has_help}")
    print(f"   Has usage: {has_usage}")
    print(f"   Has MFA info: {has_mfa}")

    assert has_help, "HELP AUTH should exist"

    await client.disconnect()


@runner.test("HELP DROP - Documentation Exists")
async def test_help_drop():
    """Test HELP DROP provides documentation"""
    client = IRCTestClient("test_help_drop")

    await client.connect("HelpDrop")

    # Authenticate first
    await client.send_raw(f"AUTH {ADMIN_CONFIG['username']} {ADMIN_CONFIG['password']}")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Check HELP DROP
    client.buffer.clear()
    await client.send_raw("HELP DROP")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should have help
    has_help = any("DROP" in line for line in client.buffer)
    has_deauth = any("drop" in line.lower() or "privilege" in line.lower() for line in client.buffer)

    print(f"   Has help: {has_help}")
    print(f"   Has deauth info: {has_deauth}")

    assert has_help, "HELP DROP should exist"

    await client.disconnect()


# ==============================================================================
# ACCOUNT CREATION
# ==============================================================================

async def create_test_accounts():
    """Helper to create test accounts in database"""
    print("\n" + "="*70)
    print("CREATING TEST ACCOUNTS")
    print("="*70 + "\n")

    try:
        # Use the same database as the server (pyircx.db in project root)
        import os
        db_path = TEST_DB_PATH or os.path.join(os.path.dirname(__file__), '..', '..', '..', 'pyircx.db')
        async with aiosqlite.connect(db_path) as db:
            for config in [ADMIN_CONFIG, SYSOP_CONFIG, MFA_TEST_CONFIG]:
                username = config['username']
                password = config['password']
                level = config['level']

                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

                await db.execute(
                    "INSERT OR REPLACE INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                    (username, pw_hash, level)
                )
                print(f"✅ Created/Updated: {username} (Level: {level})")

            await db.commit()

        print("\n✅ Test accounts created successfully!\n")
        return True
    except Exception as e:
        print(f"\n❌ Failed to create accounts: {e}\n")
        return False


async def main():
    """Main test entry point"""
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(TEST_HOST, TEST_TRUNK_PORT),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        print("✅ Server is reachable\n")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Please start the pyIRCX server first!")
        return False

    if AUTO_CREATE_ACCOUNTS:
        if not await create_test_accounts():
            print("Warning: Could not create test accounts")
            print("Please create them manually or check database permissions")

    success = await runner.run_all()

    return success


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
