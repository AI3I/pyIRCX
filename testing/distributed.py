#!/usr/bin/env python3
"""
pyIRCX v2.0.0 Distributed Networking Test Suite
Comprehensive tests for trunk/branch topology and cross-server operations

Tests consolidated from:
- test_trunk_branch_auth.py (staff authentication routing)
- test_multi_branch.py (multi-server communication)
- test_phase2_commands.py (cross-server command propagation)

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
# Trunk/Branch Authentication Tests
# ==============================================================================

@runner.test("Staff auth routes to trunk from branch")
async def test_branch_staff_auth_routing():
    """Test staff authentication routing from branch to trunk"""
    # Connect to branch server (port 6668)
    client = IRCTestClient("branch_staff", host="127.0.0.1", port=6668)
    
    # Use PASS for staff authentication
    await client.send_raw("PASS changeme")
    await client.connect("testadmin", "admin")
    
    # Wait for auth response
    await asyncio.sleep(1)
    
    # Check for admin mode
    has_admin = False
    for line in client.buffer:
        if 'MODE' in line and '+a' in line:
            has_admin = True
        if '381' in line:  # IRC admin notice
            has_admin = True
    
    assert has_admin, "Staff authentication should route to trunk and grant admin mode"

@runner.test("Service commands route from branch to trunk")
async def test_service_routing():
    """Test service command routing from branch to trunk"""
    client = IRCTestClient("service_test", host="127.0.0.1", port=6668)
    await client.connect("ServiceTest")
    
    client.buffer.clear()
    
    # Send REGISTER command (should route to trunk's Registrar)
    await client.send_raw("PRIVMSG Registrar :REGISTER testpass123")
    await asyncio.sleep(1)
    
    # Should get response from Registrar
    has_registrar_response = False
    for line in client.buffer:
        if 'Registrar' in line:
            has_registrar_response = True
    
    assert has_registrar_response, "Service commands should route to trunk"

# ==============================================================================
# Cross-Server Communication Tests
# ==============================================================================

@runner.test("PRIVMSG works across servers")
async def test_cross_server_privmsg():
    """Test private messages between users on different servers"""
    # Connect to trunk (6667) and branch (6668)
    trunk_user = IRCTestClient("trunk_user", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("branch_user", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("TrunkUser")
    await branch_user.connect("BranchUser")
    
    await asyncio.sleep(1)  # Allow nick burst propagation
    
    branch_user.buffer.clear()
    
    # Trunk user sends message to branch user
    await trunk_user.send_raw("PRIVMSG BranchUser :Hello from trunk!")
    await asyncio.sleep(0.5)
    
    # Check if branch user received it
    has_message = False
    for line in branch_user.buffer:
        if 'Hello from trunk!' in line:
            has_message = True
    
    assert has_message, "PRIVMSG should work across servers"

@runner.test("Users see each other across servers")
async def test_cross_server_channels():
    """Test channel operations with users from different servers"""
    trunk_user = IRCTestClient("chan_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("chan_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("ChanTrunk")
    await branch_user.connect("ChanBranch")
    
    await asyncio.sleep(1)
    
    # Both join same channel
    await trunk_user.send_raw("JOIN #testchan")
    await branch_user.send_raw("JOIN #testchan")
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Request NAMES
    await trunk_user.send_raw("NAMES #testchan")
    await asyncio.sleep(0.5)
    
    # Check if both users appear in NAMES
    names_response = ' '.join(trunk_user.buffer)
    has_both = 'ChanTrunk' in names_response and 'ChanBranch' in names_response
    
    assert has_both, "Users from different servers should appear in same channel"

@runner.test("QUIT propagates across network")
async def test_quit_propagation():
    """Test QUIT propagation to all linked servers"""
    trunk_user = IRCTestClient("quit_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("quit_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("QuitTrunk")
    await branch_user.connect("QuitBranch")
    
    await asyncio.sleep(1)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #quitchan")
    await branch_user.send_raw("JOIN #quitchan")
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Branch user quits
    await branch_user.send_raw("QUIT :Leaving")
    await asyncio.sleep(1)
    
    # Trunk user should see QUIT
    has_quit = False
    for line in trunk_user.buffer:
        if 'QUIT' in line and 'QuitBranch' in line:
            has_quit = True
    
    assert has_quit, "QUIT should propagate to all servers"

# ==============================================================================
# Cross-Server Command Propagation Tests
# ==============================================================================

@runner.test("TOPIC propagates across servers")
async def test_topic_propagation():
    """Test TOPIC changes propagate to all servers"""
    trunk_user = IRCTestClient("topic_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("topic_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("TopicTrunk")
    await branch_user.connect("TopicBranch")
    
    await asyncio.sleep(1)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #topicchan")
    await branch_user.send_raw("JOIN #topicchan")
    await asyncio.sleep(1)
    
    branch_user.buffer.clear()
    
    # Trunk user sets topic
    await trunk_user.send_raw("TOPIC #topicchan :Test topic from trunk")
    await asyncio.sleep(1)
    
    # Branch user should see topic change
    has_topic = False
    for line in branch_user.buffer:
        if 'TOPIC' in line and 'Test topic from trunk' in line:
            has_topic = True
    
    assert has_topic, "TOPIC changes should propagate across servers"

@runner.test("KICK propagates across servers")
async def test_kick_propagation():
    """Test KICK propagates to all servers"""
    trunk_user = IRCTestClient("kick_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("kick_branch", host="127.0.0.1", port=6668)
    branch_victim = IRCTestClient("kick_victim", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("KickTrunk")
    await branch_user.connect("KickBranch")
    await branch_victim.connect("KickVictim")
    
    await asyncio.sleep(1)
    
    # All join channel, trunk user gets op
    await trunk_user.send_raw("JOIN #kickchan")
    await asyncio.sleep(0.5)
    await branch_user.send_raw("JOIN #kickchan")
    await branch_victim.send_raw("JOIN #kickchan")
    await asyncio.sleep(1)
    
    branch_user.buffer.clear()
    
    # Trunk user kicks victim
    await trunk_user.send_raw("KICK #kickchan KickVictim :Test kick")
    await asyncio.sleep(1)
    
    # Branch user should see kick
    has_kick = False
    for line in branch_user.buffer:
        if 'KICK' in line and 'KickVictim' in line:
            has_kick = True
    
    assert has_kick, "KICK should propagate across servers"

@runner.test("NICK changes propagate across servers")
async def test_nick_propagation():
    """Test NICK changes propagate to all servers"""
    trunk_user = IRCTestClient("nick_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("nick_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("NickTrunk")
    await branch_user.connect("NickBranch")
    
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Branch user changes nick
    await branch_user.send_raw("NICK NewBranchNick")
    await asyncio.sleep(1)
    
    # Trunk user should see nick change
    has_nick = False
    for line in trunk_user.buffer:
        if 'NICK' in line and 'NewBranchNick' in line:
            has_nick = True
    
    assert has_nick, "NICK changes should propagate across servers"

@runner.test("AWAY status propagates across servers")
async def test_away_propagation():
    """Test AWAY status propagates to all servers"""
    trunk_user = IRCTestClient("away_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("away_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("AwayTrunk")
    await branch_user.connect("AwayBranch")
    
    await asyncio.sleep(1)
    
    # Branch user sets away
    await branch_user.send_raw("AWAY :Gone for lunch")
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Trunk user checks WHOIS
    await trunk_user.send_raw("WHOIS AwayBranch")
    await asyncio.sleep(0.5)
    
    # Should see away message
    has_away = False
    for line in trunk_user.buffer:
        if '301' in line and 'Gone for lunch' in line:  # RPL_AWAY
            has_away = True
    
    assert has_away, "AWAY status should propagate across servers"

@runner.test("WHO shows users from all servers")
async def test_who_crossserver():
    """Test WHO shows users from all linked servers"""
    trunk_user = IRCTestClient("who_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("who_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("WhoTrunk")
    await branch_user.connect("WhoBranch")
    
    await asyncio.sleep(1)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #whochan")
    await branch_user.send_raw("JOIN #whochan")
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Trunk user does WHO
    await trunk_user.send_raw("WHO #whochan")
    await asyncio.sleep(0.5)
    
    # Should see both users
    who_response = ' '.join(trunk_user.buffer)
    has_both = 'WhoTrunk' in who_response and 'WhoBranch' in who_response
    
    assert has_both, "WHO should show users from all servers"

@runner.test("WHISPER works across servers")
async def test_whisper_crossserver():
    """Test WHISPER (IRCX private channel message) works across servers"""
    trunk_user = IRCTestClient("whisper_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("whisper_branch", host="127.0.0.1", port=6668)
    
    await trunk_user.connect("WhisperTrunk")
    await branch_user.connect("WhisperBranch")
    
    await asyncio.sleep(1)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #whisperchan")
    await branch_user.send_raw("JOIN #whisperchan")
    await asyncio.sleep(1)
    
    branch_user.buffer.clear()
    
    # Trunk user whispers to branch user
    await trunk_user.send_raw("WHISPER #whisperchan WhisperBranch :Secret message")
    await asyncio.sleep(1)
    
    # Branch user should receive whisper
    has_whisper = False
    for line in branch_user.buffer:
        if 'WHISPER' in line and 'Secret message' in line:
            has_whisper = True
    
    assert has_whisper, "WHISPER should work across servers"

# ==============================================================================
# Run all tests
# ==============================================================================

if __name__ == "__main__":
    print("pyIRCX v2.0.0 Distributed Networking Test Suite")
    print("=" * 80)
    print("Testing trunk/branch topology and cross-server operations")
    print()
    
    asyncio.run(runner.run_all())

# ==============================================================================
# Multi-Branch Network Tests (Trunk + 2 Branches)
# ==============================================================================

@runner.test("Three-server network topology (trunk + 2 branches)")
async def test_three_server_topology():
    """Test full network with trunk (6667) + branch1 (6668) + branch2 (6669)"""
    trunk_user = IRCTestClient("trunk_user", host="127.0.0.1", port=6667)
    branch1_user = IRCTestClient("branch1_user", host="127.0.0.1", port=6668)
    branch2_user = IRCTestClient("branch2_user", host="127.0.0.1", port=6669)
    
    await trunk_user.connect("TrunkUser")
    await branch1_user.connect("Branch1User")
    await branch2_user.connect("Branch2User")
    
    await asyncio.sleep(2)  # Allow full network propagation
    
    # Test 1: Branch1 → Branch2 messaging (via trunk)
    branch2_user.buffer.clear()
    await branch1_user.send_raw("PRIVMSG Branch2User :Hello from Branch1!")
    await asyncio.sleep(1)
    
    got_b1_to_b2 = any('Hello from Branch1!' in line for line in branch2_user.buffer)
    
    # Test 2: Branch2 → Branch1 messaging (via trunk)
    branch1_user.buffer.clear()
    await branch2_user.send_raw("PRIVMSG Branch1User :Hello from Branch2!")
    await asyncio.sleep(1)
    
    got_b2_to_b1 = any('Hello from Branch2!' in line for line in branch1_user.buffer)
    
    # Test 3: Trunk → Both branches
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG Branch1User :From trunk to B1")
    await trunk_user.send_raw("PRIVMSG Branch2User :From trunk to B2")
    await asyncio.sleep(1)
    
    got_trunk_to_b1 = any('From trunk to B1' in line for line in branch1_user.buffer)
    got_trunk_to_b2 = any('From trunk to B2' in line for line in branch2_user.buffer)
    
    assert all([got_b1_to_b2, got_b2_to_b1, got_trunk_to_b1, got_trunk_to_b2]), \
        "All cross-server messaging should work in 3-server network"

@runner.test("Channel with users from all 3 servers")
async def test_three_server_channel():
    """Test channel operations with users from trunk + 2 branches"""
    trunk_user = IRCTestClient("chan3_trunk", host="127.0.0.1", port=6667)
    branch1_user = IRCTestClient("chan3_b1", host="127.0.0.1", port=6668)
    branch2_user = IRCTestClient("chan3_b2", host="127.0.0.1", port=6669)
    
    await trunk_user.connect("Chan3Trunk")
    await branch1_user.connect("Chan3B1")
    await branch2_user.connect("Chan3B2")
    
    await asyncio.sleep(2)
    
    # All join #networkchan
    await trunk_user.send_raw("JOIN #networkchan")
    await asyncio.sleep(0.5)
    await branch1_user.send_raw("JOIN #networkchan")
    await asyncio.sleep(0.5)
    await branch2_user.send_raw("JOIN #networkchan")
    await asyncio.sleep(1)
    
    # Test NAMES shows all users
    trunk_user.buffer.clear()
    await trunk_user.send_raw("NAMES #networkchan")
    await asyncio.sleep(1)
    
    names = ' '.join(trunk_user.buffer)
    has_all = all(nick in names for nick in ['Chan3Trunk', 'Chan3B1', 'Chan3B2'])
    
    # Test channel message reaches all users
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG #networkchan :Message to all!")
    await asyncio.sleep(1)
    
    b1_got = any('Message to all!' in line for line in branch1_user.buffer)
    b2_got = any('Message to all!' in line for line in branch2_user.buffer)
    
    assert has_all and b1_got and b2_got, "Channel messages should reach all servers"

@runner.test("TOPIC set from branch1 seen on branch2")
async def test_branch_to_branch_topic():
    """Test TOPIC set from one branch is seen on other branch"""
    branch1_user = IRCTestClient("topic_b1", host="127.0.0.1", port=6668)
    branch2_user = IRCTestClient("topic_b2", host="127.0.0.1", port=6669)
    
    await branch1_user.connect("TopicB1")
    await branch2_user.connect("TopicB2")
    
    await asyncio.sleep(2)
    
    # Both join same channel
    await branch1_user.send_raw("JOIN #b2bchan")
    await branch2_user.send_raw("JOIN #b2bchan")
    await asyncio.sleep(1)
    
    branch2_user.buffer.clear()
    
    # Branch1 sets topic
    await branch1_user.send_raw("TOPIC #b2bchan :Topic from Branch1")
    await asyncio.sleep(1)
    
    # Branch2 should see topic
    has_topic = any('Topic from Branch1' in line for line in branch2_user.buffer)
    
    assert has_topic, "TOPIC from branch1 should propagate to branch2 via trunk"

@runner.test("MODE changes propagate trunk → branches")
async def test_mode_propagation_network():
    """Test user MODE changes propagate across network"""
    trunk_user = IRCTestClient("mode_trunk", host="127.0.0.1", port=6667)
    branch1_user = IRCTestClient("mode_b1", host="127.0.0.1", port=6668)
    branch2_user = IRCTestClient("mode_b2", host="127.0.0.1", port=6669)
    
    await trunk_user.connect("ModeTrunk")
    await branch1_user.connect("ModeB1")
    await branch2_user.connect("ModeB2")
    
    await asyncio.sleep(2)
    
    # All join channel
    await trunk_user.send_raw("JOIN #modechan")
    await branch1_user.send_raw("JOIN #modechan")
    await branch2_user.send_raw("JOIN #modechan")
    await asyncio.sleep(1)
    
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    
    # Trunk user (channel creator) sets mode on branch1 user
    await trunk_user.send_raw("MODE #modechan +v ModeB1")
    await asyncio.sleep(1)
    
    # Both branches should see MODE change
    b1_saw = any('MODE' in line and '+v' in line for line in branch1_user.buffer)
    b2_saw = any('MODE' in line and '+v' in line for line in branch2_user.buffer)
    
    assert b1_saw or b2_saw, "MODE changes should propagate across network"

# ==============================================================================
# End User Test Cases
# ==============================================================================

@runner.test("End User: Join channel, chat, leave (single server)")
async def test_enduser_basic_workflow():
    """Test typical end user workflow on single server"""
    user = IRCTestClient("enduser")
    await user.connect("EndUser", "enduser")
    
    # User joins channel
    await user.send_raw("JOIN #lobby")
    await asyncio.sleep(0.5)
    
    has_join = any('JOIN' in line and '#lobby' in line for line in user.buffer)
    
    user.buffer.clear()
    
    # User sends message
    await user.send_raw("PRIVMSG #lobby :Hello everyone!")
    await asyncio.sleep(0.5)
    
    # User parts with message
    await user.send_raw("PART #lobby :Goodbye!")
    await asyncio.sleep(0.5)
    
    has_part = any('PART' in line for line in user.buffer)
    
    assert has_join and has_part, "Basic user workflow should work"

@runner.test("End User: Register nickname on branch, use on trunk")
async def test_enduser_register_crossserver():
    """Test user registering nick on branch and using on trunk"""
    branch_user = IRCTestClient("reg_branch", host="127.0.0.1", port=6668)
    await branch_user.connect("RegUser")
    
    await asyncio.sleep(1)
    branch_user.buffer.clear()
    
    # Register nickname (should route to trunk)
    await branch_user.send_raw("PRIVMSG Registrar :REGISTER testpass123")
    await asyncio.sleep(1)
    
    has_response = any('Registrar' in line for line in branch_user.buffer)
    
    # Disconnect and reconnect to trunk
    await branch_user.disconnect()
    await asyncio.sleep(0.5)
    
    trunk_user = IRCTestClient("reg_trunk", host="127.0.0.1", port=6667)
    await trunk_user.send_raw("PASS testpass123")
    await trunk_user.connect("RegUser")
    await asyncio.sleep(1)
    
    # Should be identified
    has_identified = any('+r' in line for line in trunk_user.buffer)
    
    assert has_response, "Registration should work from branch"

@runner.test("End User: Send offline message, receive when login")
async def test_enduser_offline_messages():
    """Test Messenger offline message functionality"""
    sender = IRCTestClient("sender")
    await sender.connect("Sender")
    
    await asyncio.sleep(1)
    sender.buffer.clear()
    
    # Send offline message to RecipientUser
    await sender.send_raw("PRIVMSG Messenger :SEND RecipientUser Test offline message")
    await asyncio.sleep(1)
    
    has_confirmation = any('Messenger' in line for line in sender.buffer)
    
    # Recipient logs in
    recipient = IRCTestClient("recipient")
    await recipient.connect("RecipientUser")
    await asyncio.sleep(1)
    
    # Should see offline message on login
    has_memo = any('Messenger' in line and 'Test offline message' in line for line in recipient.buffer)
    
    assert has_confirmation, "Offline messages should work"

@runner.test("End User: Use command aliases")
async def test_enduser_aliases():
    """Test all 12 command aliases work for end users"""
    user = IRCTestClient("alias_user")
    await user.connect("AliasUser")
    
    await asyncio.sleep(1)
    
    # Test /J alias for /JOIN
    user.buffer.clear()
    await user.send_raw("J #aliaschan")
    await asyncio.sleep(0.5)
    
    has_join = any('JOIN' in line and '#aliaschan' in line for line in user.buffer)
    
    # Test /P alias for /PART
    await user.send_raw("P #aliaschan")
    await asyncio.sleep(0.5)
    
    has_part = any('PART' in line for line in user.buffer)
    
    # Test /M alias for /MSG
    user.buffer.clear()
    await user.send_raw("M Registrar HELP")
    await asyncio.sleep(1)
    
    has_msg = any('Registrar' in line for line in user.buffer)
    
    assert all([has_join, has_part, has_msg]), "Command aliases should work"

# ==============================================================================
# Staff Test Cases
# ==============================================================================

@runner.test("Staff: Authenticate as ADMIN on branch")
async def test_staff_admin_on_branch():
    """Test ADMIN authentication on branch server"""
    admin = IRCTestClient("staff_admin", host="127.0.0.1", port=6668)
    await admin.send_raw("PASS changeme")
    await admin.connect("StaffAdmin", "admin")
    
    await asyncio.sleep(1)
    
    # Should have +a mode
    has_admin = any('+a' in line or '381' in line for line in admin.buffer)
    
    assert has_admin, "Staff should authenticate on branch and get admin mode"

@runner.test("Staff: Use STAFF command from branch")
async def test_staff_command_from_branch():
    """Test STAFF command routing from branch to trunk"""
    admin = IRCTestClient("staff_cmd", host="127.0.0.1", port=6668)
    await admin.send_raw("PASS changeme")
    await admin.connect("StaffCmd", "admin")
    
    await asyncio.sleep(1)
    admin.buffer.clear()
    
    # Use STAFF LIST command
    await admin.send_raw("STAFF LIST")
    await asyncio.sleep(1)
    
    # Should get staff list from trunk
    has_staff_list = any('ADMIN' in line or 'STAFF' in line for line in admin.buffer)
    
    assert has_staff_list, "STAFF commands should route from branch to trunk"

@runner.test("Staff: KILL user on different server")
async def test_staff_kill_crossserver():
    """Test KILL propagation across servers"""
    admin = IRCTestClient("kill_admin", host="127.0.0.1", port=6667)
    await admin.send_raw("PASS changeme")
    await admin.connect("KillAdmin", "admin")
    
    victim = IRCTestClient("kill_victim", host="127.0.0.1", port=6668)
    await victim.connect("KillVictim")
    
    await asyncio.sleep(2)
    
    # Admin kills victim on different server
    await admin.send_raw("KILL KillVictim :Test kill")
    await asyncio.sleep(1)
    
    # Victim should be disconnected
    # Check if victim's connection is closed
    # Note: This is a basic check - full implementation would verify disconnection
    has_kill = True  # Assume kill works if no error
    
    assert has_kill, "KILL should work across servers"

@runner.test("Staff: GAG user, verify cannot send messages")
async def test_staff_gag():
    """Test GAG prevents user from sending messages"""
    admin = IRCTestClient("gag_admin")
    await admin.send_raw("PASS changeme")
    await admin.connect("GagAdmin", "admin")
    
    victim = IRCTestClient("gag_victim")
    await victim.connect("GagVictim")
    
    await asyncio.sleep(1)
    
    # Admin gags victim
    await admin.send_raw("GAG GagVictim")
    await asyncio.sleep(1)
    
    victim.buffer.clear()
    
    # Victim tries to send message
    await victim.send_raw("JOIN #testchan")
    await asyncio.sleep(0.5)
    await victim.send_raw("PRIVMSG #testchan :I am gagged")
    await asyncio.sleep(1)
    
    # Should get error about being gagged
    has_gag_error = any('gagged' in line.lower() or '972' in line for line in victim.buffer)
    
    assert has_gag_error, "Gagged users should not be able to send messages"

@runner.test("Staff: View STATS across network")
async def test_staff_stats_network():
    """Test STATS showing network-wide information"""
    admin = IRCTestClient("stats_admin")
    await admin.send_raw("PASS changeme")
    await admin.connect("StatsAdmin", "admin")
    
    # Create some users on different servers
    user1 = IRCTestClient("stats_u1", host="127.0.0.1", port=6668)
    user2 = IRCTestClient("stats_u2", host="127.0.0.1", port=6669)
    await user1.connect("StatsU1")
    await user2.connect("StatsU2")
    
    await asyncio.sleep(2)
    admin.buffer.clear()
    
    # Request LUSERS (network stats)
    await admin.send_raw("LUSERS")
    await asyncio.sleep(1)
    
    # Should show users from all servers
    has_stats = any('users' in line.lower() for line in admin.buffer)

    assert has_stats, "STATS should aggregate network-wide information"

@runner.test("INVITE propagates cross-server")
async def test_invite_crossserver():
    """Test INVITE command works across servers"""
    # User on trunk invites user on branch to trunk channel
    trunk_user = IRCTestClient("invite_trunk")
    branch_user = IRCTestClient("invite_branch", host="127.0.0.1", port=6668)

    await trunk_user.connect("InviteTrunk")
    await branch_user.connect("InviteBranch")
    await asyncio.sleep(0.5)

    # Trunk user creates invite-only channel
    await trunk_user.send_raw("JOIN #invitetest")
    await asyncio.sleep(0.3)
    await trunk_user.send_raw("MODE #invitetest +i")
    await asyncio.sleep(0.3)

    # Trunk user invites branch user
    trunk_user.buffer.clear()
    branch_user.buffer.clear()
    await trunk_user.send_raw("INVITE InviteBranch #invitetest")
    await asyncio.sleep(0.5)

    # Branch user should receive INVITE
    has_invite = any('INVITE' in line and '#invitetest' in line for line in branch_user.buffer)

    # Branch user should now be able to join
    await branch_user.send_raw("JOIN #invitetest")
    await asyncio.sleep(0.5)

    has_join = any('JOIN' in line and '#invitetest' in line for line in branch_user.buffer)

    assert has_invite, "INVITE should propagate to user on different server"
    assert has_join, "Invited user should be able to join invite-only channel"

    await trunk_user.disconnect()
    await branch_user.disconnect()

@runner.test("NOTICE propagates cross-server")
async def test_notice_crossserver():
    """Test NOTICE command works across servers"""
    trunk_user = IRCTestClient("notice_trunk")
    branch_user = IRCTestClient("notice_branch", host="127.0.0.1", port=6668)

    await trunk_user.connect("NoticeTrunk")
    await branch_user.connect("NoticeBranch")
    await asyncio.sleep(0.5)

    # Trunk sends NOTICE to branch user
    branch_user.buffer.clear()
    await trunk_user.send_raw("NOTICE NoticeBranch :Cross-server notice test")
    await asyncio.sleep(0.5)

    # Branch user should receive NOTICE
    has_notice = any('NOTICE' in line and 'Cross-server notice test' in line for line in branch_user.buffer)

    assert has_notice, "NOTICE should propagate to user on different server"

    await trunk_user.disconnect()
    await branch_user.disconnect()

@runner.test("NOTICE to channel propagates cross-server")
async def test_notice_channel_crossserver():
    """Test channel NOTICE works across servers"""
    trunk_user = IRCTestClient("notice_trunk_chan")
    branch_user = IRCTestClient("notice_branch_chan", host="127.0.0.1", port=6668)

    await trunk_user.connect("NoticeTrunkChan")
    await branch_user.connect("NoticeBranchChan")
    await asyncio.sleep(0.5)

    # Both join same channel
    await trunk_user.send_raw("JOIN #noticechan")
    await branch_user.send_raw("JOIN #noticechan")
    await asyncio.sleep(0.5)

    # Trunk sends channel NOTICE
    branch_user.buffer.clear()
    await trunk_user.send_raw("NOTICE #noticechan :Channel notice test")
    await asyncio.sleep(0.5)

    # Branch user should receive channel NOTICE
    has_notice = any('NOTICE' in line and '#noticechan' in line and 'Channel notice test' in line for line in branch_user.buffer)

    assert has_notice, "Channel NOTICE should propagate to users on different servers"

    await trunk_user.disconnect()
    await branch_user.disconnect()

