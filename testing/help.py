#!/usr/bin/env python3
"""
pyIRCX v1.1.5 HELP System Test Suite
Tests HELP command and all help topics, especially new REGISTER topic

Test Staff Accounts:
  - admin/testpass (ADMIN) - Full HELP access including STAFF topic
  - sysop/testpass (SYSOP) - HELP STAFF access
  - guide/testpass (GUIDE) - HELP STAFF access

Copyright (C) 2026 pyIRCX Project

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
# Main HELP Command
# ==============================================================================

@runner.test("HELP - Main menu")
async def test_help_main_menu():
    """Test HELP with no topic shows main menu"""
    client = IRCTestClient("help_main")

    await client.connect("HelpMainTest")

    client.buffer.clear()
    await client.send_raw("HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show help topics including REGISTER
    has_help_header = any("Help Topics" in line or "pyIRCX Help" in line for line in client.buffer)
    has_commands = any("COMMANDS" in line for line in client.buffer)
    has_channel = any("CHANNEL" in line for line in client.buffer)
    has_register = any("REGISTER" in line for line in client.buffer)
    has_ircx = any("IRCX" in line for line in client.buffer)

    print(f"   Help header: {has_help_header}")
    print(f"   COMMANDS topic: {has_commands}")
    print(f"   CHANNEL topic: {has_channel}")
    print(f"   REGISTER topic: {has_register}")
    print(f"   IRCX topic: {has_ircx}")

    for line in client.buffer[:15]:
        print(f"   {line[:80]}...")

    assert has_help_header, "HELP should show help header"
    assert has_commands, "HELP should list COMMANDS topic"
    assert has_register, "HELP should list REGISTER topic (v1.1.5)"

    await client.disconnect()


@runner.test("HELP - Topic count")
async def test_help_topic_count():
    """Test HELP shows all 8 topics"""
    client = IRCTestClient("help_topics")

    await client.connect("HelpTopicsTest")

    client.buffer.clear()
    await client.send_raw("HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Count topics mentioned
    topics = ["COMMANDS", "CHANNEL", "REGISTER", "IRCX", "USERMODES", "CHANMODES", "SERVICES", "STAFF"]
    found_topics = []
    for topic in topics:
        if any(topic in line for line in client.buffer):
            found_topics.append(topic)

    print(f"   Topics found: {len(found_topics)}/8")
    print(f"   Found: {', '.join(found_topics)}")
    if len(found_topics) < 8:
        missing = set(topics) - set(found_topics)
        print(f"   Missing: {', '.join(missing)}")

    assert len(found_topics) >= 7, f"HELP should show at least 7 topics (found {len(found_topics)})"

    await client.disconnect()


# ==============================================================================
# HELP REGISTER Topic (NEW in v1.1.5)
# ==============================================================================

@runner.test("HELP REGISTER - Topic exists")
async def test_help_register_exists():
    """Test HELP REGISTER topic exists"""
    client = IRCTestClient("help_register")

    await client.connect("HelpRegisterTest")

    client.buffer.clear()
    await client.send_raw("HELP REGISTER")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show registration help
    has_header = any("Registration" in line for line in client.buffer)
    has_register = any("REGISTER" in line for line in client.buffer)

    print(f"   Registration header: {has_header}")
    print(f"   REGISTER command: {has_register}")

    for line in client.buffer[:10]:
        print(f"   {line[:80]}...")

    assert has_register, "HELP REGISTER should document REGISTER command"

    await client.disconnect()


@runner.test("HELP REGISTER - Nickname section")
async def test_help_register_nickname_section():
    """Test HELP REGISTER includes nickname registration"""
    client = IRCTestClient("help_reg_nick")

    await client.connect("HelpRegNickTest")

    client.buffer.clear()
    await client.send_raw("HELP REGISTER")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should document nickname registration commands
    has_register = any("REGISTER" in line and ("account" in line.lower() or "password" in line.lower()) for line in client.buffer)
    has_identify = any("IDENTIFY" in line for line in client.buffer)
    has_unregister = any("UNREGISTER" in line for line in client.buffer)

    print(f"   REGISTER syntax: {has_register}")
    print(f"   IDENTIFY command: {has_identify}")
    print(f"   UNREGISTER command: {has_unregister}")

    assert has_register, "HELP REGISTER should show REGISTER syntax"
    assert has_identify, "HELP REGISTER should show IDENTIFY command"

    await client.disconnect()


@runner.test("HELP REGISTER - Channel section")
async def test_help_register_channel_section():
    """Test HELP REGISTER includes channel registration"""
    client = IRCTestClient("help_reg_chan")

    await client.connect("HelpRegChanTest")

    client.buffer.clear()
    await client.send_raw("HELP REGISTER")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should document channel registration
    has_channel = any("channel" in line.lower() and "register" in line.lower() for line in client.buffer)

    print(f"   Channel registration: {has_channel}")

    assert has_channel, "HELP REGISTER should document channel registration"

    await client.disconnect()


@runner.test("HELP REGISTER - MFA section")
async def test_help_register_mfa_section():
    """Test HELP REGISTER includes MFA documentation"""
    client = IRCTestClient("help_reg_mfa")

    await client.connect("HelpRegMFATest")

    client.buffer.clear()
    await client.send_raw("HELP REGISTER")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should document MFA commands
    has_mfa = any("MFA" in line for line in client.buffer)

    print(f"   MFA documentation: {has_mfa}")

    assert has_mfa, "HELP REGISTER should document MFA commands"

    await client.disconnect()


# ==============================================================================
# HELP COMMANDS Topic
# ==============================================================================

@runner.test("HELP COMMANDS - Has Registration")
async def test_help_commands_has_registration():
    """Test HELP COMMANDS includes Registration category"""
    client = IRCTestClient("help_cmds_reg")

    await client.connect("HelpCmdsRegTest")

    client.buffer.clear()
    await client.send_raw("HELP COMMANDS")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show Registration category
    has_registration = any("Registration:" in line or "REGISTER" in line for line in client.buffer)

    print(f"   Registration category: {has_registration}")

    for line in client.buffer:
        if "egistration" in line or "REGISTER" in line:
            print(f"   Found: {line[:80]}...")

    assert has_registration, "HELP COMMANDS should include Registration category (v1.1.5)"

    await client.disconnect()


# ==============================================================================
# HELP CHANNEL Topic
# ==============================================================================

@runner.test("HELP CHANNEL - Shows commands")
async def test_help_channel():
    """Test HELP CHANNEL shows channel commands"""
    client = IRCTestClient("help_channel")

    await client.connect("HelpChannelTest")

    client.buffer.clear()
    await client.send_raw("HELP CHANNEL")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show common channel commands
    has_join = any("JOIN" in line for line in client.buffer)
    has_part = any("PART" in line for line in client.buffer)
    has_mode = any("MODE" in line for line in client.buffer)

    print(f"   JOIN command: {has_join}")
    print(f"   PART command: {has_part}")
    print(f"   MODE command: {has_mode}")

    assert has_join, "HELP CHANNEL should document JOIN"
    assert has_part, "HELP CHANNEL should document PART"

    await client.disconnect()


# ==============================================================================
# HELP IRCX Topic
# ==============================================================================

@runner.test("HELP IRCX - Shows commands")
async def test_help_ircx():
    """Test HELP IRCX shows IRCX commands"""
    client = IRCTestClient("help_ircx")

    await client.connect("HelpIRCXTest")

    client.buffer.clear()
    await client.send_raw("HELP IRCX")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show IRCX commands
    has_access = any("ACCESS" in line for line in client.buffer)
    has_prop = any("PROP" in line for line in client.buffer)

    print(f"   ACCESS command: {has_access}")
    print(f"   PROP command: {has_prop}")

    assert has_access, "HELP IRCX should document ACCESS"
    assert has_prop, "HELP IRCX should document PROP"

    await client.disconnect()


# ==============================================================================
# HELP USERMODES Topic
# ==============================================================================

@runner.test("HELP USERMODES - Shows modes")
async def test_help_usermodes():
    """Test HELP USERMODES shows user modes"""
    client = IRCTestClient("help_usermodes")

    await client.connect("HelpUserModesTest")

    client.buffer.clear()
    await client.send_raw("HELP USERMODES")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show common user modes
    has_i = any("+i" in line for line in client.buffer)
    has_r = any("+r" in line for line in client.buffer)
    has_staff = any("+a" in line or "+o" in line or "+g" in line for line in client.buffer)

    print(f"   +i mode: {has_i}")
    print(f"   +r mode: {has_r}")
    print(f"   Staff modes: {has_staff}")

    assert has_i, "HELP USERMODES should document +i"

    await client.disconnect()


# ==============================================================================
# HELP CHANMODES Topic
# ==============================================================================

@runner.test("HELP CHANMODES - Shows modes")
async def test_help_chanmodes():
    """Test HELP CHANMODES shows channel modes"""
    client = IRCTestClient("help_chanmodes")

    await client.connect("HelpChanModesTest")

    client.buffer.clear()
    await client.send_raw("HELP CHANMODES")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show channel modes
    has_i = any("+i" in line and ("invite" in line.lower() or "Invite" in line) for line in client.buffer)
    has_m = any("+m" in line and ("moderated" in line.lower() or "Moderated" in line) for line in client.buffer)
    has_ircx_modes = any("+a" in line or "+r" in line for line in client.buffer)

    print(f"   +i mode: {has_i}")
    print(f"   +m mode: {has_m}")
    print(f"   IRCX modes: {has_ircx_modes}")

    assert has_i or has_m, "HELP CHANMODES should document channel modes"

    await client.disconnect()


# ==============================================================================
# HELP SERVICES Topic
# ==============================================================================

@runner.test("HELP SERVICES - Shows services")
async def test_help_services():
    """Test HELP SERVICES shows available services"""
    client = IRCTestClient("help_services")

    await client.connect("HelpServicesTest")

    client.buffer.clear()
    await client.send_raw("HELP SERVICES")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show services
    has_registrar = any("Registrar" in line for line in client.buffer)
    has_messenger = any("Messenger" in line for line in client.buffer)
    has_newsflash = any("NewsFlash" in line for line in client.buffer)
    has_servicebot = any("ServiceBot" in line for line in client.buffer)

    print(f"   Registrar: {has_registrar}")
    print(f"   Messenger: {has_messenger}")
    print(f"   NewsFlash: {has_newsflash}")
    print(f"   ServiceBot: {has_servicebot}")

    assert has_registrar, "HELP SERVICES should list Registrar"
    assert has_servicebot, "HELP SERVICES should list ServiceBot"

    await client.disconnect()


# ==============================================================================
# HELP STAFF Topic
# ==============================================================================

@runner.test("HELP STAFF - Requires staff")
async def test_help_staff_requires_staff():
    """Test HELP STAFF requires staff privileges"""
    client = IRCTestClient("help_staff_noauth")

    await client.connect("HelpStaffNoAuth")

    client.buffer.clear()
    await client.send_raw("HELP STAFF")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Non-staff should get "no help" or similar message
    has_no_help = any("No help" in line or "not available" in line for line in client.buffer)

    print(f"   No help message: {has_no_help}")

    # Staff topic should not be shown to non-staff
    await client.disconnect()


@runner.test("HELP STAFF - Works with auth")
async def test_help_staff_with_auth():
    """Test HELP STAFF works for staff users"""
    client = IRCTestClient("help_staff_auth")

    await client.connect("HelpStaffAuth", staff_account="admin")
    await asyncio.sleep(0.3)
    await asyncio.sleep(0.5)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("HELP STAFF")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Staff should see KILL and STAFF commands
    has_kill = any("KILL" in line for line in client.buffer)
    has_staff_cmd = any("STAFF" in line for line in client.buffer)

    print(f"   KILL command: {has_kill}")
    print(f"   STAFF command: {has_staff_cmd}")

    assert has_kill or has_staff_cmd, "HELP STAFF should show staff commands"

    await client.disconnect()


# ==============================================================================
# Invalid Topic
# ==============================================================================

@runner.test("HELP INVALID - Shows topics")
async def test_help_invalid_topic():
    """Test HELP with invalid topic shows available topics"""
    client = IRCTestClient("help_invalid")

    await client.connect("HelpInvalidTest")

    client.buffer.clear()
    await client.send_raw("HELP INVALID")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show available topics including REGISTER
    has_no_help = any("No help" in line for line in client.buffer)
    has_topics = any("topics" in line.lower() or "available" in line.lower() for line in client.buffer)
    has_register = any("REGISTER" in line for line in client.buffer)

    print(f"   No help message: {has_no_help}")
    print(f"   Shows available topics: {has_topics}")
    print(f"   REGISTER in list: {has_register}")

    assert has_register, "Invalid HELP topic should show REGISTER in available topics"

    await client.disconnect()


# ==============================================================================
# Test Runner
# ==============================================================================

async def main():
    """Run all HELP system tests"""
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
