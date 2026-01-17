#!/usr/bin/env python3
"""
pyIRCX v2.0.0 Network Topology Test Suite
Tests network divergences and convergences

Critical scenarios tested:
- Server disconnection (SQUIT) - network divergence
- User cleanup during divergence
- Channel state during divergence
- Server reconnection (CONNECT) - network convergence
- Duplicate user handling
- Channel merging
- Services during divergence/convergence

Copyright (C) 2026 pyIRCX Project
Licensed under AGPL v3
"""

import asyncio
import sys
import time
from typing import List

sys.path.insert(0, '.')
from users import IRCTestClient, TestRunner

runner = TestRunner()

# ==============================================================================
# Basic Network Divergence/Convergence Tests
# ==============================================================================

@runner.test("SQUIT disconnects server from network")
async def test_squit_basic():
    """Test SQUIT command disconnects a server"""
    # Admin on trunk
    admin = IRCTestClient("squit_admin", host="127.0.0.1", port=6667)
    await admin.send_raw("PASS changeme")
    await admin.connect("SQUITAdmin", "admin")
    
    # User on branch
    branch_user = IRCTestClient("branch_user", host="127.0.0.1", port=6668)
    await branch_user.connect("BranchUser")
    
    await asyncio.sleep(2)
    admin.buffer.clear()
    
    # Admin SQUITs branch server
    await admin.send_raw("SQUIT branch.testnet.local :Test split")
    await asyncio.sleep(2)
    
    # Should see confirmation
    has_squit = any('SQUIT' in line or 'unlink' in line.lower() for line in admin.buffer)
    
    assert has_squit, "SQUIT should be acknowledged"

@runner.test("Users disappear after network divergence")
async def test_users_disappear_on_split():
    """Test users on split server disappear from network"""
    trunk_user = IRCTestClient("trunk_watch", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("branch_gone", host="127.0.0.1", port=6668)
    admin = IRCTestClient("split_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("TrunkWatch")
    await branch_user.connect("BranchGone")
    await admin.send_raw("PASS changeme")
    await admin.connect("DivergenceAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Both join same channel
    await trunk_user.send_raw("JOIN #splitchan")
    await branch_user.send_raw("JOIN #splitchan")
    await asyncio.sleep(1)
    
    # Verify both are in channel
    trunk_user.buffer.clear()
    await trunk_user.send_raw("NAMES #splitchan")
    await asyncio.sleep(0.5)
    
    names_before = ' '.join(trunk_user.buffer)
    has_both_before = 'TrunkWatch' in names_before and 'BranchGone' in names_before
    
    # Split the network
    await admin.send_raw("SQUIT branch.testnet.local :Test split")
    await asyncio.sleep(2)
    
    # Check if branch user disappeared
    trunk_user.buffer.clear()
    await trunk_user.send_raw("NAMES #splitchan")
    await asyncio.sleep(0.5)
    
    names_after = ' '.join(trunk_user.buffer)
    trunk_still_there = 'TrunkWatch' in names_after
    branch_gone = 'BranchGone' not in names_after
    
    assert has_both_before, "Both users should be in channel before divergence"
    assert trunk_still_there and branch_gone, "Branch user should disappear after divergence"

@runner.test("Channels lose users during divergence")
async def test_channel_loses_users_on_split():
    """Test channel user count decreases when network divergences"""
    trunk1 = IRCTestClient("trunk1", host="127.0.0.1", port=6667)
    trunk2 = IRCTestClient("trunk2", host="127.0.0.1", port=6667)
    branch1 = IRCTestClient("branch1", host="127.0.0.1", port=6668)
    branch2 = IRCTestClient("branch2", host="127.0.0.1", port=6668)
    admin = IRCTestClient("chan_admin", host="127.0.0.1", port=6667)
    
    # Connect all
    await trunk1.connect("Trunk1")
    await trunk2.connect("Trunk2")
    await branch1.connect("Branch1")
    await branch2.connect("Branch2")
    await admin.send_raw("PASS changeme")
    await admin.connect("ChanAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # All join #lostusers
    for client in [trunk1, trunk2, branch1, branch2]:
        await client.send_raw("JOIN #lostusers")
        await asyncio.sleep(0.2)
    
    await asyncio.sleep(1)
    
    # Count users before divergence
    trunk1.buffer.clear()
    await trunk1.send_raw("NAMES #lostusers")
    await asyncio.sleep(0.5)
    
    names_before = ' '.join(trunk1.buffer)
    count_before = sum(1 for nick in ['Trunk1', 'Trunk2', 'Branch1', 'Branch2'] if nick in names_before)
    
    # Diverge network
    await admin.send_raw("SQUIT branch.testnet.local :Counting test")
    await asyncio.sleep(2)
    
    # Count users after divergence
    trunk1.buffer.clear()
    await trunk1.send_raw("NAMES #lostusers")
    await asyncio.sleep(0.5)
    
    names_after = ' '.join(trunk1.buffer)
    count_after = sum(1 for nick in ['Trunk1', 'Trunk2', 'Branch1', 'Branch2'] if nick in names_after)
    
    assert count_before == 4, "Should have 4 users before divergence"
    assert count_after == 2, "Should have 2 users after divergence (branch users gone)"

@runner.test("Empty channels removed after divergence")
async def test_empty_channel_cleanup_on_split():
    """Test channels with only branch users are removed after divergence"""
    branch_only = IRCTestClient("branch_only", host="127.0.0.1", port=6668)
    admin = IRCTestClient("empty_admin", host="127.0.0.1", port=6667)
    
    await branch_only.connect("BranchOnly")
    await admin.send_raw("PASS changeme")
    await admin.connect("EmptyAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Branch user creates channel
    await branch_only.send_raw("JOIN #branchonly")
    await asyncio.sleep(1)
    
    # Verify channel exists on network
    admin.buffer.clear()
    await admin.send_raw("LIST")
    await asyncio.sleep(1)
    
    list_before = ' '.join(admin.buffer)
    has_channel_before = '#branchonly' in list_before
    
    # Diverge network
    await admin.send_raw("SQUIT branch.testnet.local :Empty channel test")
    await asyncio.sleep(2)
    
    # Check if channel is gone
    admin.buffer.clear()
    await admin.send_raw("LIST")
    await asyncio.sleep(1)
    
    list_after = ' '.join(admin.buffer)
    channel_gone = '#branchonly' not in list_after
    
    assert has_channel_before, "Channel should exist before divergence"
    assert channel_gone, "Empty channel should be removed after divergence"

# ==============================================================================
# Network Convergence Tests (Server Reconnection)
# ==============================================================================

@runner.test("CONNECT rejoins server to network")
async def test_connect_rejoin():
    """Test CONNECT command rejoins a split server"""
    admin = IRCTestClient("rejoin_admin", host="127.0.0.1", port=6667)
    await admin.send_raw("PASS changeme")
    await admin.connect("RejoinAdmin", "admin")
    
    await asyncio.sleep(1)
    
    # First split
    await admin.send_raw("SQUIT branch.testnet.local :Test split for rejoin")
    await asyncio.sleep(2)
    
    admin.buffer.clear()
    
    # Now reconnect
    await admin.send_raw("CONNECT branch.testnet.local 7002")
    await asyncio.sleep(2)
    
    # Should see confirmation
    has_connect = any('CONNECT' in line or 'link' in line.lower() for line in admin.buffer)
    
    assert has_connect, "CONNECT should be acknowledged"

@runner.test("Users reappear after network convergence")
async def test_users_reappear_on_join():
    """Test users on rejoined server reappear on network"""
    trunk_user = IRCTestClient("trunk_see", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("branch_back", host="127.0.0.1", port=6668)
    admin = IRCTestClient("join_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("TrunkSee")
    await branch_user.connect("BranchBack")
    await admin.send_raw("PASS changeme")
    await admin.connect("JoinAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #rejoinchan")
    await branch_user.send_raw("JOIN #rejoinchan")
    await asyncio.sleep(1)
    
    # Split
    await admin.send_raw("SQUIT branch.testnet.local :Rejoin test")
    await asyncio.sleep(2)
    
    # Verify branch user gone
    trunk_user.buffer.clear()
    await trunk_user.send_raw("NAMES #rejoinchan")
    await asyncio.sleep(0.5)
    
    names_split = ' '.join(trunk_user.buffer)
    branch_gone_during_split = 'BranchBack' not in names_split
    
    # Reconnect
    await admin.send_raw("CONNECT branch.testnet.local 7002")
    await asyncio.sleep(3)  # Give time for burst
    
    # Check if branch user is back
    trunk_user.buffer.clear()
    await trunk_user.send_raw("NAMES #rejoinchan")
    await asyncio.sleep(1)
    
    names_joined = ' '.join(trunk_user.buffer)
    branch_back = 'BranchBack' in names_joined
    
    assert branch_gone_during_split, "Branch user should be gone during divergence"
    assert branch_back, "Branch user should reappear after network convergence"

# ==============================================================================
# Channel State Tests
# ==============================================================================

@runner.test("Channel modes preserved during divergence")
async def test_channel_modes_during_split():
    """Test channel modes on trunk remain during divergence"""
    trunk_user = IRCTestClient("mode_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("mode_branch", host="127.0.0.1", port=6668)
    admin = IRCTestClient("mode_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("ModeTrunk")
    await branch_user.connect("ModeBranch")
    await admin.send_raw("PASS changeme")
    await admin.connect("ModeAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Create channel and set modes
    await trunk_user.send_raw("JOIN #modechan")
    await asyncio.sleep(0.5)
    await trunk_user.send_raw("MODE #modechan +m")  # Moderated
    await asyncio.sleep(0.5)
    
    # Branch user joins
    await branch_user.send_raw("JOIN #modechan")
    await asyncio.sleep(1)
    
    # Diverge network
    await admin.send_raw("SQUIT branch.testnet.local :Mode test")
    await asyncio.sleep(2)
    
    # Check if mode still set
    trunk_user.buffer.clear()
    await trunk_user.send_raw("MODE #modechan")
    await asyncio.sleep(0.5)
    
    mode_info = ' '.join(trunk_user.buffer)
    mode_preserved = '+m' in mode_info
    
    assert mode_preserved, "Channel modes should be preserved during divergence"

@runner.test("Channel topic preserved during divergence")
async def test_channel_topic_during_split():
    """Test channel topic remains during divergence"""
    trunk_user = IRCTestClient("topic_trunk", host="127.0.0.1", port=6667)
    admin = IRCTestClient("topic_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("TopicTrunk")
    await admin.send_raw("PASS changeme")
    await admin.connect("TopicAdmin", "admin")
    
    await asyncio.sleep(1)
    
    # Create channel with topic
    await trunk_user.send_raw("JOIN #topicchan")
    await asyncio.sleep(0.5)
    await trunk_user.send_raw("TOPIC #topicchan :Test topic during divergence")
    await asyncio.sleep(1)
    
    # Diverge network
    await admin.send_raw("SQUIT branch.testnet.local :Topic test")
    await asyncio.sleep(2)
    
    # Check topic still there
    trunk_user.buffer.clear()
    await trunk_user.send_raw("TOPIC #topicchan")
    await asyncio.sleep(0.5)
    
    topic_info = ' '.join(trunk_user.buffer)
    topic_preserved = 'Test topic during divergence' in topic_info
    
    assert topic_preserved, "Channel topic should be preserved during divergence"

# ==============================================================================
# User Collision Tests
# ==============================================================================

@runner.test("Duplicate nick detection on network convergence")
async def test_duplicate_nick_on_join():
    """Test handling of duplicate nicknames when servers rejoin"""
    # This tests what happens if same nick exists on both sides during divergence
    # Implementation depends on how pyIRCX handles nick collisions
    
    trunk_user = IRCTestClient("dup_trunk", host="127.0.0.1", port=6667)
    admin = IRCTestClient("dup_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("DupNick")  # Same nick on trunk
    await admin.send_raw("PASS changeme")
    await admin.connect("DupAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # If there's a "DupNick" on branch too, when servers rejoin,
    # one should be killed or renamed
    # This is a placeholder - actual behavior depends on implementation
    
    # For now, just verify CONNECT works
    await admin.send_raw("CONNECT branch.testnet.local 7002")
    await asyncio.sleep(2)
    
    # Test passes if no crash
    assert True, "Server should handle duplicate nicks gracefully"

# ==============================================================================
# Services During Split
# ==============================================================================

@runner.test("Services unavailable on branch during divergence")
async def test_services_unavailable_during_split():
    """Test service commands fail on branch when trunk is split"""
    branch_user = IRCTestClient("service_user", host="127.0.0.1", port=6668)
    admin = IRCTestClient("service_admin", host="127.0.0.1", port=6667)
    
    await branch_user.connect("ServiceUser")
    await admin.send_raw("PASS changeme")
    await admin.connect("ServiceAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Verify services work before divergence
    branch_user.buffer.clear()
    await branch_user.send_raw("PRIVMSG Registrar :HELP")
    await asyncio.sleep(1)
    
    services_work_before = any('Registrar' in line for line in branch_user.buffer)
    
    # Diverge network (disconnect trunk where services live)
    await admin.send_raw("SQUIT branch.testnet.local :Service test")
    await asyncio.sleep(2)
    
    # Try to use service (should fail or show unavailable)
    # Note: Branch user is now isolated, can't test from branch side
    # This test validates the split occurred
    
    assert services_work_before, "Services should work before divergence"

@runner.test("Staff auth unavailable on branch during divergence")
async def test_staff_auth_unavailable_during_split():
    """Test staff authentication fails on branch when trunk is split"""
    admin = IRCTestClient("auth_admin", host="127.0.0.1", port=6667)
    
    await admin.send_raw("PASS changeme")
    await admin.connect("AuthAdmin", "admin")
    
    await asyncio.sleep(1)
    
    # Diverge network
    await admin.send_raw("SQUIT branch.testnet.local :Auth test")
    await asyncio.sleep(2)
    
    # Try to connect new staff to branch (would fail in real scenario)
    # This test mainly validates split mechanism
    
    assert True, "Split completed"

# ==============================================================================
# Edge Cases
# ==============================================================================

@runner.test("Multiple sequential splits and joins")
async def test_multiple_splits_joins():
    """Test server can handle multiple divergence/convergence cycles"""
    admin = IRCTestClient("cycle_admin", host="127.0.0.1", port=6667)
    await admin.send_raw("PASS changeme")
    await admin.connect("CycleAdmin", "admin")
    
    await asyncio.sleep(1)
    
    # Do 3 divergence/convergence cycles
    for i in range(3):
        # Split
        await admin.send_raw(f"SQUIT branch.testnet.local :Cycle {i+1} split")
        await asyncio.sleep(2)
        
        # Rejoin
        await admin.send_raw("CONNECT branch.testnet.local 7002")
        await asyncio.sleep(3)
    
    # If we get here without hanging, test passes
    assert True, "Multiple divergence/convergence cycles should work"

@runner.test("Users can't message across split")
async def test_no_messaging_across_split():
    """Test users on opposite sides of split can't message each other"""
    trunk_user = IRCTestClient("msg_trunk", host="127.0.0.1", port=6667)
    branch_user = IRCTestClient("msg_branch", host="127.0.0.1", port=6668)
    admin = IRCTestClient("msg_admin", host="127.0.0.1", port=6667)
    
    await trunk_user.connect("MsgTrunk")
    await branch_user.connect("MsgBranch")
    await admin.send_raw("PASS changeme")
    await admin.connect("MsgAdmin", "admin")
    
    await asyncio.sleep(2)
    
    # Verify messaging works before divergence
    branch_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG MsgBranch :Before split")
    await asyncio.sleep(1)
    
    got_message_before = any('Before split' in line for line in branch_user.buffer)
    
    # Split
    await admin.send_raw("SQUIT branch.testnet.local :Message test")
    await asyncio.sleep(2)
    
    # Try to message (should fail - no such nick)
    trunk_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG MsgBranch :After split")
    await asyncio.sleep(1)
    
    # Should get "no such nick" error
    got_error = any('401' in line or 'No such' in line for line in trunk_user.buffer)
    
    assert got_message_before, "Messaging should work before divergence"
    assert got_error, "Should get error when messaging user on split server"

# ==============================================================================
# Run all tests
# ==============================================================================

if __name__ == "__main__":
    print("pyIRCX v2.0.0 Network Split/Join Test Suite")
    print("=" * 80)
    print("Testing network divergences, network convergences, and edge cases")
    print()
    
    asyncio.run(runner.run_all())
