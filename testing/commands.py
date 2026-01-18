#!/usr/bin/env python3
"""
pyIRCX Core Command Test Suite
Tests JOIN, PART, QUIT, INVITE, MODE, WHO, MOTD and other core commands

Test Staff Accounts:
  - admin/testpass (ADMIN) - Full privileges
  - sysop/testpass (SYSOP) - Staff privileges
  - guide/testpass (GUIDE) - Limited staff privileges
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
# JOIN Command Tests
# ==============================================================================

@runner.test("JOIN - Basic channel join")
async def test_join_basic():
    """Test basic channel join"""
    client = IRCTestClient("join_basic")

    await client.connect("JoinTest")

    client.buffer.clear()
    await client.send_raw("JOIN #testjoin")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get JOIN confirmation, NAMES list, and end of NAMES
    has_join = any("JOIN #testjoin" in line for line in client.buffer)
    has_353 = any(" 353 " in line for line in client.buffer)  # NAMES
    has_366 = any(" 366 " in line for line in client.buffer)  # End of NAMES

    print(f"   JOIN message: {has_join}")
    print(f"   NAMES list (353): {has_353}")
    print(f"   End NAMES (366): {has_366}")

    assert has_join, "Should receive JOIN confirmation"
    assert has_353, "Should receive NAMES list"
    assert has_366, "Should receive end of NAMES"

    await client.disconnect()


@runner.test("JOIN - First user gets owner")
async def test_join_first_owner():
    """Test first user in new channel gets +q owner mode"""
    client = IRCTestClient("join_owner")

    await client.connect("FirstOwner")

    client.buffer.clear()
    await client.send_raw("JOIN #newchannel")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get MODE message granting +q
    has_owner_mode = any("MODE #newchannel +q FirstOwner" in line for line in client.buffer)

    print(f"   Owner mode granted: {has_owner_mode}")

    for line in client.buffer:
        if "MODE" in line and "+q" in line:
            print(f"   {line[:80]}...")

    assert has_owner_mode, "First user should get +q owner mode"

    await client.disconnect()


@runner.test("JOIN - Multiple joins to same channel")
async def test_join_multiple_users():
    """Test multiple users joining same channel"""
    client1 = IRCTestClient("join_multi1")
    client2 = IRCTestClient("join_multi2")

    await client1.connect("User1")
    await client2.connect("User2")

    # User1 joins
    await client1.send_raw("JOIN #multijoin")
    await asyncio.sleep(0.2)
    await client1.read_lines()

    # User2 joins - User1 should see the join
    client1.buffer.clear()
    client2.buffer.clear()
    await client2.send_raw("JOIN #multijoin")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Client1 should see User2's JOIN
    user1_sees_join = any("User2" in line and "JOIN" in line for line in client1.buffer)
    # Client2 should see their own JOIN and NAMES with User1
    user2_sees_names = any("User1" in line and "353" in line for line in client2.buffer)

    print(f"   User1 sees User2 JOIN: {user1_sees_join}")
    print(f"   User2 sees User1 in NAMES: {user2_sees_names}")

    assert user1_sees_join, "Existing users should see new JOINs"
    assert user2_sees_names, "New user should see existing users in NAMES"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("JOIN - With channel key")
async def test_join_with_key():
    """Test joining channel with key (+k mode)"""
    client1 = IRCTestClient("join_key1")
    client2 = IRCTestClient("join_key2")

    await client1.connect("KeyOwner", staff_account="admin")
    await asyncio.sleep(0.3)

    # Create channel and set key
    await client1.send_raw("JOIN #keychan")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #keychan +k secretkey")
    await asyncio.sleep(0.3)
    await client1.read_lines()

    # Try to join without key - should fail
    await client2.connect("KeyUser")
    client2.buffer.clear()
    await client2.send_raw("JOIN #keychan")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_key_error = any(" 475 " in line for line in client2.buffer)  # ERR_BADCHANNELKEY

    print(f"   Key error (475): {has_key_error}")

    # Join with correct key - should succeed
    client2.buffer.clear()
    await client2.send_raw("JOIN #keychan secretkey")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_join = any("JOIN #keychan" in line for line in client2.buffer)

    print(f"   Joined with key: {has_join}")

    assert has_key_error, "Should get error without key"
    assert has_join, "Should join with correct key"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# PART Command Tests
# ==============================================================================

@runner.test("PART - Leave channel")
async def test_part_basic():
    """Test parting from channel"""
    client = IRCTestClient("part_basic")

    await client.connect("PartTest")

    await client.send_raw("JOIN #testpart")
    await asyncio.sleep(0.2)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("PART #testpart")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should see PART message
    has_part = any("PART #testpart" in line for line in client.buffer)

    print(f"   PART message: {has_part}")

    assert has_part, "Should receive PART confirmation"

    await client.disconnect()


@runner.test("PART - Other users see part")
async def test_part_broadcast():
    """Test PART is broadcast to other channel members"""
    client1 = IRCTestClient("part_bc1")
    client2 = IRCTestClient("part_bc2")

    await client1.connect("PartUser1")
    await client2.connect("PartUser2")

    # Both join
    await client1.send_raw("JOIN #partbc")
    await client2.send_raw("JOIN #partbc")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # User1 parts - User2 should see it
    client2.buffer.clear()
    await client1.send_raw("PART #partbc")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    user2_sees_part = any("PartUser1" in line and "PART" in line for line in client2.buffer)

    print(f"   User2 sees User1 PART: {user2_sees_part}")

    assert user2_sees_part, "Other users should see PART messages"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# QUIT Command Tests
# ==============================================================================

@runner.test("QUIT - Disconnect from server")
async def test_quit_basic():
    """Test QUIT command disconnects user"""
    client = IRCTestClient("quit_basic")

    await client.connect("QuitTest")

    # Send QUIT
    await client.send_raw("QUIT :Testing quit")
    await asyncio.sleep(0.3)

    # Try to read - connection should be closed
    try:
        data = await asyncio.wait_for(client.reader.read(1024), timeout=1.0)
        if not data:
            print("   Connection closed (no data)")
            closed = True
        else:
            print(f"   Got data after QUIT: {data}")
            closed = False
    except asyncio.TimeoutError:
        print("   Timeout waiting for close")
        closed = False
    except Exception as e:
        print(f"   Exception (connection closed): {type(e).__name__}")
        closed = True

    assert closed, "Connection should close after QUIT"


@runner.test("QUIT - Broadcast to channels")
async def test_quit_broadcast():
    """Test QUIT is broadcast to channel members"""
    client1 = IRCTestClient("quit_bc1")
    client2 = IRCTestClient("quit_bc2")

    await client1.connect("QuitUser1")
    await client2.connect("QuitUser2")

    # Both join channel
    await client1.send_raw("JOIN #quitbc")
    await client2.send_raw("JOIN #quitbc")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # User1 quits - User2 should see it
    client2.buffer.clear()
    await client1.send_raw("QUIT :Leaving now")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    user2_sees_quit = any("QuitUser1" in line and "QUIT" in line for line in client2.buffer)

    print(f"   User2 sees User1 QUIT: {user2_sees_quit}")

    for line in client2.buffer:
        if "QUIT" in line:
            print(f"   {line[:80]}...")

    assert user2_sees_quit, "Channel members should see QUIT messages"

    await client2.disconnect()


# ==============================================================================
# INVITE Command Tests
# ==============================================================================

@runner.test("INVITE - Invite user to channel")
async def test_invite_basic():
    """Test inviting user to channel"""
    client1 = IRCTestClient("invite1")
    client2 = IRCTestClient("invite2")

    await client1.connect("Inviter")
    await client2.connect("Invitee")

    # Create channel
    await client1.send_raw("JOIN #invitetest")
    await asyncio.sleep(0.2)
    await client1.read_lines()

    # Invite user
    client1.buffer.clear()
    client2.buffer.clear()
    await client1.send_raw("INVITE Invitee #invitetest")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Inviter should get 341 (RPL_INVITING)
    inviter_sees_341 = any(" 341 " in line for line in client1.buffer)
    # Invitee should get INVITE message
    invitee_gets_invite = any("INVITE" in line and "#invitetest" in line for line in client2.buffer)

    print(f"   Inviter gets 341: {inviter_sees_341}")
    print(f"   Invitee gets INVITE: {invitee_gets_invite}")

    assert inviter_sees_341, "Inviter should get 341 reply"
    assert invitee_gets_invite, "Invitee should receive INVITE message"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("INVITE - Invite-only channel (+i)")
async def test_invite_only_channel():
    """Test invite-only channel requires invite"""
    client1 = IRCTestClient("invite_owner")
    client2 = IRCTestClient("invite_user")

    await client1.connect("InvOwner", staff_account="admin")
    await client2.connect("InvUser")
    await asyncio.sleep(0.3)

    # Create channel and set +i
    await client1.send_raw("JOIN #invonly")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #invonly +i")
    await asyncio.sleep(0.2)
    await client1.read_lines()

    # Try to join without invite - should fail
    client2.buffer.clear()
    await client2.send_raw("JOIN #invonly")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_invite_only_error = any(" 473 " in line for line in client2.buffer)  # ERR_INVITEONLYCHAN

    print(f"   Invite-only error (473): {has_invite_only_error}")

    # Get invited
    await client1.send_raw("INVITE InvUser #invonly")
    await asyncio.sleep(0.2)
    await client1.read_lines()
    await client2.read_lines()

    # Now join should work
    client2.buffer.clear()
    await client2.send_raw("JOIN #invonly")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_join = any("JOIN #invonly" in line for line in client2.buffer)

    print(f"   Joined after invite: {has_join}")

    assert has_invite_only_error, "Should get error without invite"
    assert has_join, "Should join after being invited"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# MODE Command Tests
# ==============================================================================

@runner.test("MODE - User mode query")
async def test_mode_user_query():
    """Test querying own user modes"""
    client = IRCTestClient("mode_user")

    await client.connect("ModeUser")

    client.buffer.clear()
    await client.send_raw("MODE ModeUser")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 221 with mode string
    has_221 = any(" 221 " in line for line in client.buffer)

    print(f"   Mode reply (221): {has_221}")

    for line in client.buffer:
        if " 221 " in line:
            print(f"   {line[:80]}...")

    assert has_221, "Should get 221 reply with modes"

    await client.disconnect()


@runner.test("MODE - Channel mode query")
async def test_mode_channel_query():
    """Test querying channel modes"""
    client = IRCTestClient("mode_chan")

    await client.connect("ModeChan")

    await client.send_raw("JOIN #modetest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("MODE #modetest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 324 with channel modes
    has_324 = any(" 324 " in line for line in client.buffer)

    print(f"   Channel mode reply (324): {has_324}")

    for line in client.buffer:
        if " 324 " in line:
            print(f"   {line[:80]}...")

    assert has_324, "Should get 324 reply with channel modes"

    await client.disconnect()


@runner.test("MODE - Set channel mode")
async def test_mode_set_channel():
    """Test setting channel modes"""
    client = IRCTestClient("mode_set")

    await client.connect("ModeSet")

    await client.send_raw("JOIN #modeset")
    await asyncio.sleep(0.2)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("MODE #modeset +n")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should see MODE change broadcast
    has_mode = any("MODE #modeset +n" in line for line in client.buffer)

    print(f"   MODE change: {has_mode}")

    assert has_mode, "Should see MODE change"

    await client.disconnect()


@runner.test("MODE - Grant channel voice (+v)")
async def test_mode_grant_voice():
    """Test granting voice to user"""
    client1 = IRCTestClient("mode_owner")
    client2 = IRCTestClient("mode_voice")

    await client1.connect("ModeOwner")
    await client2.connect("ModeVoice")

    # Create channel
    await client1.send_raw("JOIN #voicetest")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #voicetest")
    await asyncio.sleep(0.2)
    await client1.read_lines()
    await client2.read_lines()

    # Grant voice
    client1.buffer.clear()
    client2.buffer.clear()
    await client1.send_raw("MODE #voicetest +v ModeVoice")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Both should see MODE change
    owner_sees_mode = any("MODE #voicetest +v ModeVoice" in line for line in client1.buffer)
    voice_sees_mode = any("MODE #voicetest +v ModeVoice" in line for line in client2.buffer)

    print(f"   Owner sees MODE: {owner_sees_mode}")
    print(f"   Voice user sees MODE: {voice_sees_mode}")

    assert owner_sees_mode, "Owner should see MODE change"
    assert voice_sees_mode, "Voice user should see MODE change"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# WHO Command Tests
# ==============================================================================

@runner.test("WHO - Query channel members")
async def test_who_channel():
    """Test WHO command on channel"""
    client = IRCTestClient("who_test")

    await client.connect("WhoTest")

    await client.send_raw("JOIN #whotest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("WHO #whotest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 352 (RPL_WHOREPLY) and 315 (RPL_ENDOFWHO)
    has_352 = any(" 352 " in line for line in client.buffer)
    has_315 = any(" 315 " in line for line in client.buffer)

    print(f"   WHO reply (352): {has_352}")
    print(f"   End of WHO (315): {has_315}")

    for line in client.buffer:
        if " 352 " in line or " 315 " in line:
            print(f"   {line[:80]}...")

    assert has_352, "Should get WHO reply"
    assert has_315, "Should get end of WHO"

    await client.disconnect()


@runner.test("WHO - Query specific user")
async def test_who_user():
    """Test WHO command on specific user"""
    client = IRCTestClient("who_user")

    await client.connect("WhoUser")

    client.buffer.clear()
    await client.send_raw("WHO WhoUser")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 352 and 315
    has_352 = any(" 352 " in line and "WhoUser" in line for line in client.buffer)
    has_315 = any(" 315 " in line for line in client.buffer)

    print(f"   WHO reply for user: {has_352}")
    print(f"   End of WHO: {has_315}")

    assert has_352, "Should get WHO reply for user"
    assert has_315, "Should get end of WHO"

    await client.disconnect()


# ==============================================================================
# TOPIC Command Tests
# ==============================================================================

@runner.test("TOPIC - Query channel topic")
async def test_topic_query():
    """Test querying channel topic"""
    client = IRCTestClient("topic_query")

    await client.connect("TopicQuery")

    await client.send_raw("JOIN #topictest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Set a topic first
    await client.send_raw("TOPIC #topictest :Test Topic")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Query topic
    client.buffer.clear()
    await client.send_raw("TOPIC #topictest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 332 (RPL_TOPIC) and 333 (topic metadata)
    has_332 = any(" 332 " in line and "Test Topic" in line for line in client.buffer)
    has_333 = any(" 333 " in line for line in client.buffer)

    print(f"   Topic (332): {has_332}")
    print(f"   Topic metadata (333): {has_333}")

    assert has_332, "Should get topic"
    assert has_333, "Should get topic metadata"

    await client.disconnect()


@runner.test("TOPIC - Set channel topic")
async def test_topic_set():
    """Test setting channel topic"""
    client1 = IRCTestClient("topic_set1")
    client2 = IRCTestClient("topic_set2")

    await client1.connect("TopicOwner")
    await client2.connect("TopicUser")

    await client1.send_raw("JOIN #topicset")
    await client2.send_raw("JOIN #topicset")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Set topic
    client1.buffer.clear()
    client2.buffer.clear()
    await client1.send_raw("TOPIC #topicset :New Topic Here")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Both should see TOPIC change
    owner_sees = any("TOPIC #topicset :New Topic Here" in line for line in client1.buffer)
    user_sees = any("TOPIC #topicset :New Topic Here" in line for line in client2.buffer)

    print(f"   Owner sees TOPIC: {owner_sees}")
    print(f"   User sees TOPIC: {user_sees}")

    assert owner_sees, "Owner should see TOPIC change"
    assert user_sees, "Other users should see TOPIC change"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("TOPIC - Empty topic clears it")
async def test_topic_clear():
    """Test clearing channel topic"""
    client = IRCTestClient("topic_clear")

    await client.connect("TopicClear")

    await client.send_raw("JOIN #topicclear")
    await asyncio.sleep(0.2)
    await client.send_raw("TOPIC #topicclear :Some Topic")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Clear topic
    client.buffer.clear()
    await client.send_raw("TOPIC #topicclear :")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should see TOPIC with no text
    has_clear = any("TOPIC #topicclear :" in line for line in client.buffer)

    print(f"   Topic cleared: {has_clear}")

    assert has_clear, "Should clear topic"

    await client.disconnect()


# ==============================================================================
# KICK Command Tests
# ==============================================================================

@runner.test("KICK - Remove user from channel")
async def test_kick_basic():
    """Test kicking user from channel"""
    client1 = IRCTestClient("kick_owner")
    client2 = IRCTestClient("kick_user")

    await client1.connect("KickOwner")
    await client2.connect("KickUser")

    await client1.send_raw("JOIN #kicktest")
    await client2.send_raw("JOIN #kicktest")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Kick user
    client1.buffer.clear()
    client2.buffer.clear()
    await client1.send_raw("KICK #kicktest KickUser :Testing kick")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Both should see KICK message
    owner_sees = any("KICK #kicktest KickUser" in line for line in client1.buffer)
    user_sees = any("KICK #kicktest KickUser" in line for line in client2.buffer)

    print(f"   Owner sees KICK: {owner_sees}")
    print(f"   Kicked user sees KICK: {user_sees}")

    assert owner_sees, "Owner should see KICK"
    assert user_sees, "Kicked user should see KICK"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("KICK - Non-op cannot kick")
async def test_kick_no_privilege():
    """Test that non-ops cannot kick"""
    client1 = IRCTestClient("kick_owner2")
    client2 = IRCTestClient("kick_nopriv")

    await client1.connect("KickOwner2")
    await client2.connect("KickNoPriv")

    await client1.send_raw("JOIN #kickpriv")
    await client2.send_raw("JOIN #kickpriv")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Non-op tries to kick - should fail
    client2.buffer.clear()
    await client2.send_raw("KICK #kickpriv KickOwner2 :Trying to kick")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get 482 (not channel operator)
    has_482 = any(" 482 " in line for line in client2.buffer)

    print(f"   No privilege error (482): {has_482}")

    assert has_482, "Non-op should not be able to kick"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# PRIVMSG/NOTICE Tests
# ==============================================================================

@runner.test("PRIVMSG - Send message to channel")
async def test_privmsg_channel():
    """Test sending PRIVMSG to channel"""
    client1 = IRCTestClient("msg_send1")
    client2 = IRCTestClient("msg_send2")

    await client1.connect("MsgSend1")
    await client2.connect("MsgSend2")

    await client1.send_raw("JOIN #msgtest")
    await client2.send_raw("JOIN #msgtest")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Send message
    client2.buffer.clear()
    await client1.send_raw("PRIVMSG #msgtest :Hello everyone")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Client2 should see the message
    has_msg = any("PRIVMSG #msgtest :Hello everyone" in line for line in client2.buffer)

    print(f"   Message received: {has_msg}")

    assert has_msg, "Channel members should receive PRIVMSG"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("PRIVMSG - Send private message")
async def test_privmsg_user():
    """Test sending PRIVMSG to user"""
    client1 = IRCTestClient("pm_send")
    client2 = IRCTestClient("pm_recv")

    await client1.connect("PMSend")
    await client2.connect("PMRecv")

    # Send private message
    client2.buffer.clear()
    await client1.send_raw("PRIVMSG PMRecv :Private hello")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Client2 should receive PM
    has_pm = any("PRIVMSG PMRecv :Private hello" in line for line in client2.buffer)

    print(f"   Private message received: {has_pm}")

    assert has_pm, "User should receive private message"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("NOTICE - Send notice")
async def test_notice():
    """Test NOTICE command"""
    client1 = IRCTestClient("notice_send")
    client2 = IRCTestClient("notice_recv")

    await client1.connect("NoticeSend")
    await client2.connect("NoticeRecv")

    # Send notice
    client2.buffer.clear()
    await client1.send_raw("NOTICE NoticeRecv :Test notice")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Client2 should receive NOTICE
    has_notice = any("NOTICE NoticeRecv :Test notice" in line for line in client2.buffer)

    print(f"   Notice received: {has_notice}")

    assert has_notice, "User should receive NOTICE"

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# LIST Command Tests
# ==============================================================================

@runner.test("LIST - Get channel list")
async def test_list():
    """Test LIST command"""
    client = IRCTestClient("list_test")

    await client.connect("ListTest")

    # Create a channel first
    await client.send_raw("JOIN #listtest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Get channel list
    client.buffer.clear()
    await client.send_raw("LIST")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 321 (start), 322 (channel), 323 (end)
    has_321 = any(" 321 " in line for line in client.buffer)
    has_322 = any(" 322 " in line for line in client.buffer)
    has_323 = any(" 323 " in line for line in client.buffer)

    print(f"   LIST start (321): {has_321}")
    print(f"   Channel entry (322): {has_322}")
    print(f"   LIST end (323): {has_323}")

    assert has_321, "Should get LIST start"
    assert has_322, "Should get channel entries"
    assert has_323, "Should get LIST end"

    await client.disconnect()


# ==============================================================================
# NAMES Command Tests
# ==============================================================================

@runner.test("NAMES - Get channel members")
async def test_names():
    """Test NAMES command"""
    client = IRCTestClient("names_test")

    await client.connect("NamesTest")

    await client.send_raw("JOIN #namestest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Query NAMES
    client.buffer.clear()
    await client.send_raw("NAMES #namestest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 353 (NAMES list) and 366 (end)
    has_353 = any(" 353 " in line for line in client.buffer)
    has_366 = any(" 366 " in line for line in client.buffer)

    print(f"   NAMES list (353): {has_353}")
    print(f"   End of NAMES (366): {has_366}")

    assert has_353, "Should get NAMES list"
    assert has_366, "Should get end of NAMES"

    await client.disconnect()


# ==============================================================================
# WHOIS Command Tests
# ==============================================================================

@runner.test("WHOIS - Query user info")
async def test_whois():
    """Test WHOIS command"""
    client = IRCTestClient("whois_test")

    await client.connect("WhoisTest")

    client.buffer.clear()
    await client.send_raw("WHOIS WhoisTest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 311 (user info) and 318 (end)
    has_311 = any(" 311 " in line for line in client.buffer)
    has_318 = any(" 318 " in line for line in client.buffer)

    print(f"   WHOIS info (311): {has_311}")
    print(f"   End of WHOIS (318): {has_318}")

    for line in client.buffer:
        if " 311 " in line or " 318 " in line:
            print(f"   {line[:80]}...")

    assert has_311, "Should get WHOIS info"
    assert has_318, "Should get end of WHOIS"

    await client.disconnect()


# ==============================================================================
# PING/PONG Tests
# ==============================================================================

@runner.test("PING - Server responds with PONG")
async def test_ping():
    """Test PING/PONG"""
    client = IRCTestClient("ping_test")

    await client.connect("PingTest")

    client.buffer.clear()
    await client.send_raw("PING :testping")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get PONG response
    has_pong = any("PONG" in line and "testping" in line for line in client.buffer)

    print(f"   PONG response: {has_pong}")

    assert has_pong, "Should get PONG response"

    await client.disconnect()


# ==============================================================================
# MOTD Command Tests
# ==============================================================================

@runner.test("MOTD - Get message of the day")
async def test_motd():
    """Test MOTD command"""
    client = IRCTestClient("motd_test")

    await client.connect("MotdTest")

    client.buffer.clear()
    await client.send_raw("MOTD")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 375 (start), 372 (lines), 376 (end)
    has_375 = any(" 375 " in line for line in client.buffer)
    has_372 = any(" 372 " in line for line in client.buffer)
    has_376 = any(" 376 " in line for line in client.buffer)

    print(f"   MOTD start (375): {has_375}")
    print(f"   MOTD line (372): {has_372}")
    print(f"   MOTD end (376): {has_376}")

    assert has_375, "Should get MOTD start"
    assert has_372, "Should get MOTD lines"
    assert has_376, "Should get MOTD end"

    await client.disconnect()


# ==============================================================================
# Test Runner
# ==============================================================================

async def main():
    """Run all core command tests"""
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
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
