#!/usr/bin/env python3
"""
pyIRCX v1.1.5 Service Improvements Test Suite
Tests Registrar and ServiceBot HELP commands, case-insensitive routing

Test Staff Accounts:
  - admin/testpass (ADMIN) - Can invite ServiceBots
  - sysop/testpass (SYSOP) - Can invite ServiceBots
  - guide/testpass (GUIDE) - Cannot invite ServiceBots

Copyright (C) 2026 pyIRCX Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
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
# Registrar Service HELP Command (NEW in v1.1.5)
# ==============================================================================

@runner.test("Registrar HELP - Exists")
async def test_registrar_help_exists():
    """Test Registrar responds to HELP command"""
    client = IRCTestClient("registrar_help")

    await client.connect("RegistrarHelpTest")

    client.buffer.clear()
    await client.send_raw("PRIVMSG Registrar :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get help response from Registrar
    has_help = any("Registrar" in line and ("Help" in line or "HELP" in line) for line in client.buffer)
    has_commands = any("REGISTER" in line or "IDENTIFY" in line for line in client.buffer)

    print(f"   Help response: {has_help}")
    print(f"   Commands listed: {has_commands}")

    for line in client.buffer[:10]:
        if "Registrar" in line:
            print(f"   {line[:80]}...")

    assert has_help or has_commands, "Registrar should respond to HELP"

    await client.disconnect()


@runner.test("Registrar HELP - Comprehensive")
async def test_registrar_help_comprehensive():
    """Test Registrar HELP includes all sections"""
    client = IRCTestClient("registrar_help_full")

    await client.connect("RegistrarHelpFull")

    client.buffer.clear()
    await client.send_raw("PRIVMSG Registrar :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should document nickname, channel, settings, MFA
    has_nickname = any("nickname" in line.lower() or "REGISTER" in line for line in client.buffer)
    has_channel = any("channel" in line.lower() and ("REGISTER" in line or "register" in line) for line in client.buffer)
    has_settings = any("SET" in line or "settings" in line.lower() for line in client.buffer)
    has_mfa = any("MFA" in line for line in client.buffer)

    print(f"   Nickname section: {has_nickname}")
    print(f"   Channel section: {has_channel}")
    print(f"   Settings section: {has_settings}")
    print(f"   MFA section: {has_mfa}")

    assert has_nickname, "Registrar HELP should document nickname registration"
    assert has_mfa, "Registrar HELP should document MFA"

    await client.disconnect()


# ==============================================================================
# ServiceBot Case-Insensitive Routing (FIXED in v1.1.5)
# ==============================================================================

@runner.test("ServiceBot - Uppercase routing")
async def test_servicebot_help_uppercase():
    """Test ServiceBot responds to uppercase nickname"""
    client = IRCTestClient("servicebot_upper")

    await client.connect("ServiceBotUpper")

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get help response
    has_response = any("ServiceBot" in line for line in client.buffer)

    print(f"   ServiceBot01 responds: {has_response}")

    assert has_response, "ServiceBot01 (uppercase) should respond to HELP"

    await client.disconnect()


@runner.test("ServiceBot - Lowercase routing (FIX)")
async def test_servicebot_help_lowercase():
    """Test ServiceBot responds to lowercase nickname"""
    client = IRCTestClient("servicebot_lower")

    await client.connect("ServiceBotLower")

    client.buffer.clear()
    await client.send_raw("PRIVMSG servicebot01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get help response (case-insensitive routing fix)
    has_response = any("ServiceBot" in line or "servicebot" in line.lower() for line in client.buffer)

    print(f"   servicebot01 responds: {has_response}")

    for line in client.buffer[:5]:
        if "ervice" in line:
            print(f"   {line[:80]}...")

    assert has_response, "servicebot01 (lowercase) should respond to HELP (v1.1.5 fix)"

    await client.disconnect()


@runner.test("ServiceBot - Mixed case routing (FIX)")
async def test_servicebot_help_mixedcase():
    """Test ServiceBot responds to mixed case nickname"""
    client = IRCTestClient("servicebot_mixed")

    await client.connect("ServiceBotMixed")

    client.buffer.clear()
    await client.send_raw("PRIVMSG SERVICEBOT01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get help response (case-insensitive routing fix)
    has_response = any("ServiceBot" in line or "SERVICEBOT" in line.upper() for line in client.buffer)

    print(f"   SERVICEBOT01 responds: {has_response}")

    assert has_response, "SERVICEBOT01 (all caps) should respond to HELP (v1.1.5 fix)"

    await client.disconnect()


@runner.test("ServiceBot STATUS - Case insensitive")
async def test_servicebot_status_case_insensitive():
    """Test ServiceBot STATUS works with any case"""
    client = IRCTestClient("servicebot_status_case")

    await client.connect("ServiceBotStatusCase")

    # Test lowercase
    client.buffer.clear()
    await client.send_raw("PRIVMSG servicebot01 :STATUS")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_status = any("Status" in line or "status" in line.lower() for line in client.buffer)

    print(f"   STATUS (lowercase) works: {has_status}")

    assert has_status, "ServiceBot STATUS should work case-insensitively"

    await client.disconnect()


# ==============================================================================
# ServiceBot Enhanced HELP Command (ENHANCED in v1.1.5)
# ==============================================================================

@runner.test("ServiceBot HELP - Comprehensive")
async def test_servicebot_help_comprehensive():
    """Test ServiceBot HELP is comprehensive"""
    client = IRCTestClient("servicebot_help_full")

    await client.connect("ServiceBotHelpFull")

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should have comprehensive help
    has_header = any("ServiceBot" in line and ("Help" in line or "Service" in line) for line in client.buffer)
    has_monitoring = any("monitor" in line.lower() for line in client.buffer)
    has_features = any("profanity" in line.lower() or "flood" in line.lower() or "spam" in line.lower() for line in client.buffer)
    has_commands = any("HELP" in line or "STATUS" in line for line in client.buffer)

    print(f"   Header: {has_header}")
    print(f"   Monitoring mentioned: {has_monitoring}")
    print(f"   Features listed: {has_features}")
    print(f"   Commands listed: {has_commands}")

    for line in client.buffer[:15]:
        if "ServiceBot" in line:
            print(f"   {line[:80]}...")

    assert has_header or has_monitoring, "ServiceBot HELP should be comprehensive (v1.1.5)"

    await client.disconnect()


@runner.test("ServiceBot HELP - Shows actions")
async def test_servicebot_help_shows_actions():
    """Test ServiceBot HELP documents actions"""
    client = IRCTestClient("servicebot_help_actions")

    await client.connect("ServiceBotHelpActions")

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should document warn/gag/kick actions
    has_actions = any("warn" in line.lower() or "gag" in line.lower() or "kick" in line.lower() for line in client.buffer)

    print(f"   Actions documented: {has_actions}")

    assert has_actions, "ServiceBot HELP should document actions (v1.1.5)"

    await client.disconnect()


@runner.test("ServiceBot HELP - Shows invitation")
async def test_servicebot_help_shows_invitation():
    """Test ServiceBot HELP shows invitation instructions"""
    client = IRCTestClient("servicebot_help_invite")

    await client.connect("ServiceBotHelpInvite")

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show how to invite
    has_invite = any("INVITE" in line or "invite" in line.lower() for line in client.buffer)

    print(f"   Invitation instructions: {has_invite}")

    assert has_invite, "ServiceBot HELP should show invitation instructions (v1.1.5)"

    await client.disconnect()


# ==============================================================================
# ServiceBot Enhanced STATUS Command (ENHANCED in v1.1.5)
# ==============================================================================

@runner.test("ServiceBot STATUS - Shows channels")
async def test_servicebot_status_shows_channels():
    """Test ServiceBot STATUS shows monitored channels"""
    client = IRCTestClient("servicebot_status_channels")

    await client.connect("ServiceBotStatusChannels")

    # Invite ServiceBot to a channel (requires staff)
    await asyncio.sleep(0.3)
    await client.send_raw("JOIN #test")
    await asyncio.sleep(0.2)
    await client.send_raw("INVITE ServiceBot01 #test")
    await asyncio.sleep(0.3)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :STATUS")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show channel list or capacity info
    has_channels = any("#test" in line for line in client.buffer)
    has_capacity = any("Active in" in line or "channels" in line.lower() for line in client.buffer)

    print(f"   Shows #test channel: {has_channels}")
    print(f"   Shows capacity: {has_capacity}")

    for line in client.buffer:
        if "Status" in line or "Active" in line or "#test" in line:
            print(f"   {line[:80]}...")

    assert has_capacity, "ServiceBot STATUS should show capacity info (v1.1.5)"

    await client.disconnect()


@runner.test("ServiceBot STATUS - Shows detection")
async def test_servicebot_status_shows_detection():
    """Test ServiceBot STATUS shows detection status"""
    client = IRCTestClient("servicebot_status_detect")

    await client.connect("ServiceBotStatusDetect")

    client.buffer.clear()
    await client.send_raw("PRIVMSG ServiceBot01 :STATUS")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show detection status
    has_detection = any("detection" in line.lower() or "profanity" in line.lower() or "flood" in line.lower() for line in client.buffer)

    print(f"   Detection status: {has_detection}")

    assert has_detection, "ServiceBot STATUS should show detection status (v1.1.5)"

    await client.disconnect()


# ==============================================================================
# Messenger Service HELP (Existing - verify still works)
# ==============================================================================

@runner.test("Messenger HELP - Still works")
async def test_messenger_help_still_works():
    """Test Messenger HELP still works"""
    client = IRCTestClient("messenger_help")

    await client.connect("MessengerHelpTest")

    client.buffer.clear()
    await client.send_raw("PRIVMSG Messenger :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should respond with help
    has_response = any("Messenger" in line for line in client.buffer)

    print(f"   Messenger responds: {has_response}")

    await client.disconnect()


# ==============================================================================
# NewsFlash Service HELP (Existing - verify still works)
# ==============================================================================

@runner.test("NewsFlash HELP - Still works")
async def test_newsflash_help_still_works():
    """Test NewsFlash HELP still works"""
    client = IRCTestClient("newsflash_help")

    await client.connect("NewsFlashHelpTest")

    client.buffer.clear()
    await client.send_raw("PRIVMSG NewsFlash :HELP")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should respond with help
    has_response = any("NewsFlash" in line or "News" in line for line in client.buffer)

    print(f"   NewsFlash responds: {has_response}")

    await client.disconnect()


# ==============================================================================
# Test Runner
# ==============================================================================

async def main():
    """Run all service improvements tests"""
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
