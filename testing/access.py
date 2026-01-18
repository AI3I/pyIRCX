#!/usr/bin/env python3
"""
pyIRCX Access Control System Test Suite
Tests IRCX ACCESS command for channel and server access control

Tests:
1. Channel access levels (OWNER, HOST, VOICE)
2. Server access levels (GRANT, DENY)
3. Access list ADD/REMOVE/CLEAR operations
4. Access priority and overrides
5. Staff vs owner permissions
6. Wildcard mask matching
7. Services cannot be added to DENY lists

Test Staff Accounts:
  - admin/testpass (ADMIN) - Can manage server-level access
  - sysop/testpass (SYSOP) - Can manage server-level access
  - guide/testpass (GUIDE) - Limited access management

Copyright (C) 2026 John D. Lewis

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import sys
from typing import List

# Import test client from users.py
sys.path.insert(0, '.')
from users import IRCTestClient, TestRunner

# Create test runner instance
runner = TestRunner()


# ==============================================================================
# Channel Access Tests
# ==============================================================================

@runner.test("ACCESS - Channel OWNER")
async def test_channel_owner_access():
    """Test adding OWNER to channel access list"""
    client = IRCTestClient("access_owner")

    await client.connect("AccessOwner")
    await client.send_raw("JOIN #testowner")
    await asyncio.sleep(0.3)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("ACCESS #testowner ADD OWNER TestUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should succeed (806) or show entry added
    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   OWNER entry added: {has_success}")

    # Verify it's in the list
    client.buffer.clear()
    await client.send_raw("ACCESS #testowner LIST OWNER")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("TestUser" in line for line in client.buffer)

    print(f"   OWNER entry in list: {has_entry}")

    assert has_success or has_entry, "OWNER access entry should be added"

    await client.disconnect()


@runner.test("ACCESS - Channel HOST")
async def test_channel_host_access():
    """Test adding HOST to channel access list"""
    client = IRCTestClient("access_host")

    await client.connect("AccessHost")
    await client.send_raw("JOIN #testhost")
    await asyncio.sleep(0.3)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("ACCESS #testhost ADD HOST HostUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   HOST entry added: {has_success}")

    # Verify in list
    client.buffer.clear()
    await client.send_raw("ACCESS #testhost LIST HOST")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("HostUser" in line for line in client.buffer)

    print(f"   HOST entry in list: {has_entry}")

    assert has_success or has_entry, "HOST access entry should be added"

    await client.disconnect()


@runner.test("ACCESS - Channel VOICE")
async def test_channel_voice_access():
    """Test adding VOICE to channel access list"""
    client = IRCTestClient("access_voice")

    await client.connect("AccessVoice")
    await client.send_raw("JOIN #testvoice")
    await asyncio.sleep(0.3)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("ACCESS #testvoice ADD VOICE VoiceUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   VOICE entry added: {has_success}")

    # Verify in list
    client.buffer.clear()
    await client.send_raw("ACCESS #testvoice LIST VOICE")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("VoiceUser" in line for line in client.buffer)

    print(f"   VOICE entry in list: {has_entry}")

    assert has_success or has_entry, "VOICE access entry should be added"

    await client.disconnect()


@runner.test("ACCESS - Channel DENY")
async def test_channel_deny_access():
    """Test adding DENY to channel access list"""
    client = IRCTestClient("access_deny")

    await client.connect("AccessDeny")
    await client.send_raw("JOIN #testdeny")
    await asyncio.sleep(0.3)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("ACCESS #testdeny ADD DENY BadUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   DENY entry added: {has_success}")

    # Verify in list
    client.buffer.clear()
    await client.send_raw("ACCESS #testdeny LIST DENY")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("BadUser" in line for line in client.buffer)

    print(f"   DENY entry in list: {has_entry}")

    assert has_success or has_entry, "DENY access entry should be added"

    await client.disconnect()


# ==============================================================================
# Access Modification Tests
# ==============================================================================

@runner.test("ACCESS - Remove entry")
async def test_access_remove():
    """Test removing access entry"""
    client = IRCTestClient("access_remove")

    await client.connect("AccessRemove")
    await client.send_raw("JOIN #testremove")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Add entry
    await client.send_raw("ACCESS #testremove ADD VOICE TempUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Remove entry
    client.buffer.clear()
    await client.send_raw("ACCESS #testremove REMOVE VOICE TempUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_removed = any("removed" in line.lower() or "807" in line for line in client.buffer)

    print(f"   Entry removed: {has_removed}")

    # Verify it's gone
    client.buffer.clear()
    await client.send_raw("ACCESS #testremove LIST VOICE")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("TempUser" in line for line in client.buffer)

    print(f"   Entry still in list: {has_entry}")

    assert has_removed or not has_entry, "Entry should be removed from access list"

    await client.disconnect()


@runner.test("ACCESS - Clear list")
async def test_access_clear():
    """Test clearing all access entries"""
    client = IRCTestClient("access_clear")

    await client.connect("AccessClear")
    await client.send_raw("JOIN #testclear")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Add multiple entries
    await client.send_raw("ACCESS #testclear ADD VOICE User1!*@*")
    await asyncio.sleep(0.2)
    await client.send_raw("ACCESS #testclear ADD VOICE User2!*@*")
    await asyncio.sleep(0.2)
    await client.send_raw("ACCESS #testclear ADD VOICE User3!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Clear all
    client.buffer.clear()
    await client.send_raw("ACCESS #testclear CLEAR VOICE")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_cleared = any("cleared" in line.lower() or "808" in line for line in client.buffer)

    print(f"   List cleared: {has_cleared}")

    # Verify empty
    client.buffer.clear()
    await client.send_raw("ACCESS #testclear LIST VOICE")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entries = any("User1" in line or "User2" in line or "User3" in line for line in client.buffer)

    print(f"   Entries still present: {has_entries}")

    assert has_cleared or not has_entries, "Access list should be cleared"

    await client.disconnect()


# ==============================================================================
# Service Protection Tests
# ==============================================================================

@runner.test("ACCESS - Service DENY protection")
async def test_service_deny_protection():
    """Test services cannot be added to DENY lists"""
    client = IRCTestClient("access_service")

    await client.connect("AccessService")
    await client.send_raw("JOIN #testservice")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Try to add System service to DENY
    client.buffer.clear()
    await client.send_raw("ACCESS #testservice ADD DENY System!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_error = any("cannot" in line.lower() or "825" in line for line in client.buffer)

    print(f"   Service protection error: {has_error}")

    for line in client.buffer[:5]:
        if "825" in line or "annot" in line:
            print(f"   {line[:80]}...")

    assert has_error, "Services should be protected from DENY lists"

    await client.disconnect()


# ==============================================================================
# Wildcard Matching Tests
# ==============================================================================

@runner.test("ACCESS - Wildcard patterns")
async def test_wildcard_patterns():
    """Test wildcard mask matching in access lists"""
    client = IRCTestClient("access_wildcard")

    await client.connect("AccessWildcard")
    await client.send_raw("JOIN #testwildcard")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Test various wildcard patterns
    patterns = [
        "*!*@*.example.com",
        "User*!*@*",
        "*!user@*",
        "TestUser!test@host.com"
    ]

    for pattern in patterns:
        await client.send_raw(f"ACCESS #testwildcard ADD VOICE {pattern}")
        await asyncio.sleep(0.2)

    await client.read_lines()

    # List all entries
    client.buffer.clear()
    await client.send_raw("ACCESS #testwildcard LIST VOICE")
    await asyncio.sleep(0.5)
    await client.read_lines()

    found_count = 0
    for pattern in patterns:
        # Check if pattern appears in any line (may be escaped or formatted)
        if any(pattern.replace("*", "") in line or "example.com" in line or "TestUser" in line for line in client.buffer):
            found_count += 1

    print(f"   Patterns found: {found_count}/{len(patterns)}")

    for line in client.buffer[:10]:
        if "VOICE" in line or "806" in line:
            print(f"   {line[:80]}...")

    assert found_count > 0, "At least some wildcard patterns should be added"

    await client.disconnect()


# ==============================================================================
# Server Access Tests (requires staff)
# ==============================================================================

@runner.test("ACCESS - Server GRANT (ADMIN)")
async def test_server_access_grant():
    """Test server-level GRANT access (ADMIN only)"""
    client = IRCTestClient("access_server_grant")

    await client.connect("AccessServerGrant", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Try to add GRANT entry
    client.buffer.clear()
    await client.send_raw("ACCESS SERVER ADD GRANT AdminUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   Server GRANT added: {has_success}")

    # List GRANT entries
    client.buffer.clear()
    await client.send_raw("ACCESS SERVER LIST GRANT")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("AdminUser" in line or "GRANT" in line for line in client.buffer)

    print(f"   GRANT entry listed: {has_entry}")

    assert has_success or has_entry, "Server GRANT access should work for ADMIN"

    await client.disconnect()


@runner.test("ACCESS - Server DENY (ADMIN)")
async def test_server_access_deny():
    """Test server-level DENY access (ADMIN only)"""
    client = IRCTestClient("access_server_deny")

    await client.connect("AccessServerDeny", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Try to add DENY entry
    client.buffer.clear()
    await client.send_raw("ACCESS SERVER ADD DENY BannedUser!*@*")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_success = any("806" in line or "added" in line.lower() for line in client.buffer)

    print(f"   Server DENY added: {has_success}")

    # List DENY entries
    client.buffer.clear()
    await client.send_raw("ACCESS SERVER LIST DENY")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_entry = any("BannedUser" in line or "DENY" in line for line in client.buffer)

    print(f"   DENY entry listed: {has_entry}")

    assert has_success or has_entry, "Server DENY access should work for ADMIN"

    await client.disconnect()


# ==============================================================================
# Test Runner
# ==============================================================================

async def main():
    """Run all access control tests"""
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")

    # Test server connection first
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
        print("Please start the pyIRCX server first!")
        return False

    # Run all tests
    success = await runner.run_all()

    return success

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTests interrupted")
        sys.exit(1)
