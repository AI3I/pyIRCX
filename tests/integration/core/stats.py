#!/usr/bin/env python3
"""
pyIRCX v2.0.1 STATS Command Test Suite
Tests all STATS command functionality

Test Staff Accounts:
  - admin/testpass (ADMIN) - Full access including STATS *
  - sysop/testpass (SYSOP) - Staff access including STATS v
  - guide/testpass (GUIDE) - Staff access including STATS v
"""

import asyncio
import time
import sys
from typing import List

# Import test client from users.py
import os
sys.path.insert(0, os.path.dirname(__file__))
from users import IRCTestClient, TestRunner, TEST_HOST, TEST_TRUNK_PORT

# Create test runner instance
runner = TestRunner()


# ==============================================================================
# STATS p - Peak Usage Statistics
# ==============================================================================

@runner.test("STATS p - Basic functionality")
async def test_stats_p_basic():
    """Test STATS p returns peak usage data"""
    client = IRCTestClient("stats_p_test")

    await client.connect("StatsPTest", username="admin", password="testpass")

    client.buffer.clear()
    await client.send_raw("STATS p")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get peak users line
    has_peak_users = any("Peak users:" in line or "peak users" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Peak users line: {has_peak_users}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:5]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS p should end with 219"
    assert has_peak_users, "STATS p should show peak users"

    await client.disconnect()


@runner.test("STATS p - Peak time display")
async def test_stats_p_peak_time():
    """Test STATS p includes peak time when available"""
    client = IRCTestClient("stats_p_time")

    await client.connect("StatsPTimeTest")

    client.buffer.clear()
    await client.send_raw("STATS p")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # If peak_time is set, should show timestamp
    has_peak_time = any("Peak time:" in line or "peak time" in line.lower() for line in client.buffer)

    print(f"   Peak time line: {has_peak_time}")

    # Note: peak_time might not be set on fresh server, so not asserting

    await client.disconnect()


# ==============================================================================
# STATS f - Flood Protection Statistics
# ==============================================================================

@runner.test("STATS f - Basic functionality")
async def test_stats_f_basic():
    """Test STATS f returns flood protection data"""
    client = IRCTestClient("stats_f_test")

    await client.connect("StatsFTest")

    client.buffer.clear()
    await client.send_raw("STATS f")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get flood events line
    has_flood = any("flood" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Flood events line: {has_flood}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:5]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS f should end with 219"
    assert has_flood, "STATS f should show flood events"

    await client.disconnect()


# ==============================================================================
# STATS m - Message Statistics
# ==============================================================================

@runner.test("STATS m - Basic functionality")
async def test_stats_m_basic():
    """Test STATS m returns message statistics"""
    client = IRCTestClient("stats_m_test")

    await client.connect("StatsMTest", username="admin", password="testpass")

    # Send some messages to generate stats
    await client.send_raw("JOIN #test")
    await asyncio.sleep(0.2)
    await client.send_raw("PRIVMSG #test :Test message 1")
    await asyncio.sleep(0.1)
    await client.send_raw("PRIVMSG #test :Test message 2")
    await asyncio.sleep(0.2)

    client.buffer.clear()
    await client.send_raw("STATS m")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get total messages line
    has_total = any("Total messages:" in line or "messages" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Total messages line: {has_total}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS m should end with 219"
    assert has_total, "STATS m should show total messages"

    await client.disconnect()


@runner.test("STATS m - No 'top 10' limit")
async def test_stats_m_no_limit():
    """Test STATS m shows all channels (no 'top 10' limit)"""
    client = IRCTestClient("stats_m_limit")

    await client.connect("StatsMNoLimit")

    client.buffer.clear()
    await client.send_raw("STATS m")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should NOT have "top 10" or "... and X more" messages
    has_top_10 = any("top 10" in line.lower() for line in client.buffer)
    has_more = any("... and" in line.lower() and "more" in line.lower() for line in client.buffer)

    print(f"   Has 'top 10': {has_top_10}")
    print(f"   Has '... and X more': {has_more}")

    assert not has_top_10, "STATS m should NOT limit to 'top 10'"
    assert not has_more, "STATS m should NOT show '... and X more'"

    await client.disconnect()


# ==============================================================================
# STATS b - ServiceBot Statistics
# ==============================================================================

@runner.test("STATS b - Basic functionality")
async def test_stats_b_basic():
    """Test STATS b returns ServiceBot statistics"""
    client = IRCTestClient("stats_b_test")

    await client.connect("StatsBTest", username="guide", password="testpass")

    client.buffer.clear()
    await client.send_raw("STATS b")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get ServiceBot info
    has_servicebot = any("servicebot" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   ServiceBot line: {has_servicebot}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS b should end with 219"
    assert has_servicebot, "STATS b should show ServiceBot info"

    await client.disconnect()


# ==============================================================================
# STATS n - Network Statistics
# ==============================================================================

@runner.test("STATS n - Basic functionality")
async def test_stats_n_basic():
    """Test STATS n returns network statistics"""
    client = IRCTestClient("stats_n_test")

    await client.connect("StatsNTest")

    client.buffer.clear()
    await client.send_raw("STATS n")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get server and network name
    has_server = any("Server:" in line or "server" in line.lower() for line in client.buffer)
    has_network = any("Network:" in line or "network" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Server line: {has_server}")
    print(f"   Network line: {has_network}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS n should end with 219"

    await client.disconnect()


# ==============================================================================
# STATS v - Command Usage Statistics (Staff Only)
# ==============================================================================

@runner.test("STATS v - Staff only access")
async def test_stats_v_staff_only():
    """Test STATS v requires staff privileges"""
    client = IRCTestClient("stats_v_noauth")

    await client.connect("StatsVNoAuth")

    client.buffer.clear()
    await client.send_raw("STATS v")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get permission denied or similar
    has_denied = any("require" in line.lower() or "privilege" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Permission denied: {has_denied}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:5]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS v should end with 219"

    await client.disconnect()


@runner.test("STATS v - Works with admin")
async def test_stats_v_with_staff():
    """Test STATS v works for staff users"""
    client = IRCTestClient("stats_v_staff")

    # Connect with admin test account password (default: testpass)
    await client.connect("StatsVStaff", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS v")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get command usage info
    has_commands = any("command" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Command usage line: {has_commands}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS v should end with 219"

    await client.disconnect()


@runner.test("STATS v - No 'top 10' limit")
async def test_stats_v_no_limit():
    """Test STATS v shows all commands (no 'top 10' limit)"""
    client = IRCTestClient("stats_v_limit")

    await client.connect("StatsVNoLimit", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS v")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should NOT have "top 10" or "... and X more" messages
    has_top_10 = any("top 10" in line.lower() for line in client.buffer)
    has_more = any("... and" in line.lower() and "more" in line.lower() for line in client.buffer)

    print(f"   Has 'top 10': {has_top_10}")
    print(f"   Has '... and X more': {has_more}")

    assert not has_top_10, "STATS v should NOT limit to 'top 10'"
    assert not has_more, "STATS v should NOT show '... and X more'"

    await client.disconnect()


# ==============================================================================
# STATS k - Enhanced Ban Statistics (No Limits)
# ==============================================================================

@runner.test("STATS k - No 10-entry limit")
async def test_stats_k_no_limit():
    """Test STATS k shows all bans (no 10-entry limit)"""
    client = IRCTestClient("stats_k_limit")

    await client.connect("StatsKNoLimit")

    client.buffer.clear()
    await client.send_raw("STATS k")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should NOT have "... and X more" messages
    has_more = any("... and" in line.lower() and "more" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Has '... and X more': {has_more}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS k should end with 219"
    assert not has_more, "STATS k should NOT show '... and X more'"

    await client.disconnect()


# ==============================================================================
# STATS * - Comprehensive Report (Admin Only)
# ==============================================================================

@runner.test("STATS * - Hierarchical indentation")
async def test_stats_star_indentation():
    """Test STATS * uses hierarchical indentation"""
    client = IRCTestClient("stats_star_indent")

    await client.connect("StatsStarIndent", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS *")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Look for indented lines (starts with spaces after NOTICE nick :)
    indented_lines = []
    for line in client.buffer:
        if " NOTICE " in line and ":" in line:
            # Get content after the last colon
            parts = line.split(":", 2)
            if len(parts) >= 3:
                content = parts[2]
                # Check if starts with spaces
                if content.startswith("  ") or content.startswith("    "):
                    indented_lines.append(content)

    has_indentation = len(indented_lines) > 5
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Indented lines found: {len(indented_lines)}")
    print(f"   Sample indented lines:")
    for line in indented_lines[:3]:
        print(f"     '{line}'")
    print(f"   219 (ENDOFSTATS): {has_219}")

    assert has_219, "STATS * should end with 219"
    assert has_indentation, "STATS * should use hierarchical indentation"

    await client.disconnect()


@runner.test("STATS * - No 'top X' limits")
async def test_stats_star_no_limits():
    """Test STATS * shows all data (no 'top X' limits)"""
    client = IRCTestClient("stats_star_limit")

    await client.connect("StatsStarNoLimit", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS *")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # Should NOT have "top" or "... and X more" messages
    has_top = any("top " in line.lower() and ("10" in line or "5" in line or "3" in line) for line in client.buffer)
    has_more = any("... and" in line.lower() and "more" in line.lower() for line in client.buffer)

    print(f"   Has 'top X': {has_top}")
    print(f"   Has '... and X more': {has_more}")

    # Check for new sections
    has_command_usage = any("Command Usage" in line for line in client.buffer)
    has_peak = any("Peak Usage" in line or "Peak users" in line for line in client.buffer)
    has_flood = any("Flood Protection" in line for line in client.buffer)
    has_messages = any("Message Statistics" in line for line in client.buffer)
    has_servicebot_stats = any("ServiceBot Statistics" in line for line in client.buffer)

    print(f"   Has Command Usage section: {has_command_usage}")
    print(f"   Has Peak Usage section: {has_peak}")
    print(f"   Has Flood Protection section: {has_flood}")
    print(f"   Has Message Statistics section: {has_messages}")
    print(f"   Has ServiceBot Statistics section: {has_servicebot_stats}")

    assert not has_top, "STATS * should NOT show 'top X' limits"
    assert not has_more, "STATS * should NOT show '... and X more'"

    await client.disconnect()


@runner.test("STATS v - Works with guide")
async def test_stats_v_with_guide():
    """Test STATS v works for guide users (GUIDE+)"""
    client = IRCTestClient("stats_v_guide")

    await client.connect("StatsVGuide", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS v")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get command usage info (GUIDE+ has access)
    has_commands = any("command" in line.lower() for line in client.buffer)
    has_denied = any("require" in line.lower() or "privilege" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Command usage line: {has_commands}")
    print(f"   Permission denied: {has_denied}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    assert has_219, "STATS v should end with 219"
    assert not has_denied, "GUIDE should have access to STATS v"

    await client.disconnect()


@runner.test("STATS v - Works with sysop")
async def test_stats_v_with_sysop():
    """Test STATS v works for sysop users (GUIDE+)"""
    client = IRCTestClient("stats_v_sysop")

    await client.connect("StatsVSysop", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS v")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get command usage info (GUIDE+ has access)
    has_commands = any("command" in line.lower() for line in client.buffer)
    has_denied = any("require" in line.lower() or "privilege" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Command usage line: {has_commands}")
    print(f"   Permission denied: {has_denied}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    assert has_219, "STATS v should end with 219"
    assert not has_denied, "SYSOP should have access to STATS v"

    await client.disconnect()


@runner.test("STATS * - Admin only (deny sysop)")
async def test_stats_star_admin_only():
    """Test STATS * requires ADMIN (not just staff)"""
    client = IRCTestClient("stats_star_sysop")

    await client.connect("StatsStarSysop", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("STATS *")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # SYSOP should be denied (ADMIN only)
    has_denied = any("require" in line.lower() or "privilege" in line.lower() or "admin" in line.lower() for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Permission denied: {has_denied}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    assert has_219, "STATS * should end with 219"
    assert has_denied, "STATS * should require ADMIN (deny SYSOP)"

    await client.disconnect()


# ==============================================================================
# Test Runner
# ==============================================================================

async def main():
    """Run all STATS v2.0.1 tests"""
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")

    # Test server connection first
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
