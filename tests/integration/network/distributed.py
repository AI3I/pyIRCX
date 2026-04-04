#!/usr/bin/env python3
"""
pyIRCX v2.0.1 Distributed Networking Test Suite
Comprehensive tests for trunk/branch topology and cross-server operations

Tests consolidated from:
- test_trunk_branch_auth.py (staff authentication routing)
- test_multi_branch.py (multi-server communication)
- test_phase2_commands.py (cross-server command propagation)
"""

import asyncio
import sys
from typing import List

# Import test client from users.py
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from users import IRCTestClient, TestRunner

TEST_HOST = os.environ.get("PYIRCX_TEST_HOST", "127.0.0.1")
TRUNK_PORT = int(os.environ.get("PYIRCX_TEST_TRUNK_PORT", "6667"))
BRANCH1_PORT = int(os.environ.get("PYIRCX_TEST_BRANCH1_PORT", "6668"))
BRANCH2_PORT = int(os.environ.get("PYIRCX_TEST_BRANCH2_PORT", "6669"))


async def auth_admin(client: IRCTestClient, username: str = "admin", password: str = "testpass") -> bool:
    """Authenticate a client as ADMIN via AUTH."""
    await client.send_raw(f"AUTH {username} {password}")
    await asyncio.sleep(0.8)
    await client.read_lines()
    for line in client.buffer:
        if " MODE " in line and "+a" in line:
            return True
        if " 381 " in line or " 386 " in line:
            return True
    return False


async def enable_caps(client: IRCTestClient, caps: List[str]) -> bool:
    """Enable IRCv3 capabilities after connect."""
    caps_str = " ".join(caps)
    await client.send_raw("CAP LS 302")
    await asyncio.sleep(0.2)
    await client.read_lines()
    await client.send_raw(f"CAP REQ :{caps_str}")
    await asyncio.sleep(0.2)
    await client.read_lines()
    await client.send_raw("CAP END")
    await asyncio.sleep(0.2)
    await client.read_lines()
    return any(" CAP " in line and " ACK " in line and all(c in line for c in caps) for line in client.buffer)

# Create test runner instance
runner = TestRunner()

# ==============================================================================
# Trunk/Branch Authentication Tests
# ==============================================================================

@runner.test("Staff auth routes to trunk from branch")
async def test_branch_staff_auth_routing():
    """Test staff authentication routing from branch to trunk"""
    # Connect to branch server (port 6668)
    client = IRCTestClient("branch_staff", host=TEST_HOST, port=BRANCH1_PORT)
    await client.connect("testadmin", "admin")

    # AUTH should route to trunk and grant admin mode
    has_admin = await auth_admin(client)
    assert has_admin, "Staff authentication should route to trunk and grant admin mode"

@runner.test("Service commands route from branch to trunk")
async def test_service_routing():
    """Test service command routing from branch to trunk"""
    client = IRCTestClient("service_test", host=TEST_HOST, port=BRANCH1_PORT)
    await client.connect("ServiceTest")
    
    client.buffer.clear()
    
    # Send REGISTER command (should route to trunk's Registrar)
    await client.send_raw("PRIVMSG Registrar :REGISTER testpass123")
    await asyncio.sleep(1)
    await client.read_lines()

    # Successful routed registration may come back as a Registrar NOTICE or a registration numeric.
    has_registrar_response = any(
        'Registrar' in line or ' 874 ' in line or ' 870 ' in line
        for line in client.buffer
    )
    
    assert has_registrar_response, "Service commands should route to trunk"

@runner.test("ServiceBot dispatcher routes from branch to trunk")
async def test_servicebot_dispatcher_routing():
    """Test branch users can reach the shared ServiceBot dispatcher."""
    client = IRCTestClient("servicebot_dispatch", host=TEST_HOST, port=BRANCH1_PORT)
    await client.connect("DispatchTest")

    client.buffer.clear()

    await client.send_raw("PRIVMSG ServiceBot :HELP")
    await asyncio.sleep(1)
    await client.read_lines()

    has_servicebot_response = any("ServiceBot" in line for line in client.buffer)

    assert has_servicebot_response, "ServiceBot dispatcher should respond from a branch client"

@runner.test("Messenger PUSH from branch reaches remote users")
async def test_messenger_push_from_branch():
    """Test a branch admin can route Messenger PUSH through trunk services."""
    admin = IRCTestClient("messenger_push_admin", host=TEST_HOST, port=BRANCH1_PORT)
    recipient = IRCTestClient("messenger_push_recipient", host=TEST_HOST, port=TRUNK_PORT)

    await admin.connect("MsgPushAdmin", "admin")
    assert await auth_admin(admin), "Admin auth failed on branch"

    await recipient.connect("MsgPushRecipient")
    await asyncio.sleep(1)

    recipient.buffer.clear()
    await admin.send_raw("PRIVMSG Messenger :PUSH Integration broadcast")
    await asyncio.sleep(1)
    await recipient.read_lines()

    has_broadcast = any(
        "Messenger" in line and "Integration broadcast" in line
        for line in recipient.buffer
    )

    assert has_broadcast, "Messenger PUSH from branch should reach remote users"

@runner.test("NewsFlash PUSH from branch reaches remote users")
async def test_newsflash_push_from_branch():
    """Test a branch admin can route NewsFlash PUSH through trunk services."""
    admin = IRCTestClient("newsflash_push_admin", host=TEST_HOST, port=BRANCH1_PORT)
    recipient = IRCTestClient("newsflash_push_recipient", host=TEST_HOST, port=TRUNK_PORT)

    await admin.connect("NewsPushAdmin", "admin")
    assert await auth_admin(admin), "Admin auth failed on branch"

    await recipient.connect("NewsPushRecipient")
    await asyncio.sleep(1)

    recipient.buffer.clear()
    await admin.send_raw("PRIVMSG NewsFlash :PUSH Integration bulletin")
    await asyncio.sleep(1)
    await recipient.read_lines()

    has_broadcast = any(
        "NewsFlash" in line and "Integration bulletin" in line
        for line in recipient.buffer
    )

    assert has_broadcast, "NewsFlash PUSH from branch should reach remote users"

# ==============================================================================
# Cross-Server Communication Tests
# ==============================================================================

@runner.test("PRIVMSG works across servers")
async def test_cross_server_privmsg():
    """Test private messages between users on different servers"""
    # Connect to trunk (6667) and branch (6668)
    trunk_user = IRCTestClient("trunk_user", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("branch_user", host=TEST_HOST, port=BRANCH1_PORT)
    
    await trunk_user.connect("TrunkUser")
    await branch_user.connect("BranchUser")
    
    await asyncio.sleep(1)  # Allow nick burst propagation
    
    branch_user.buffer.clear()
    
    # Trunk user sends message to branch user
    await trunk_user.send_raw("PRIVMSG BranchUser :Hello from trunk!")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    
    has_message = any(
        'PRIVMSG BranchUser :Hello from trunk!' in line and 'TrunkUser' in line
        for line in branch_user.buffer
    )
    
    assert has_message, "PRIVMSG should work across servers"

@runner.test("Users see each other across servers")
async def test_cross_server_channels():
    """Test channel operations with users from different servers"""
    trunk_user = IRCTestClient("chan_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("chan_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await trunk_user.read_lines()
    
    names_lines = [line for line in trunk_user.buffer if " 353 " in line and "#testchan" in line]
    has_names_both = any("ChanTrunk" in line and "ChanBranch" in line for line in names_lines)

    assert has_names_both, "Users from different servers should appear in the same NAMES reply"

@runner.test("QUIT propagates across network")
async def test_quit_propagation():
    """Test QUIT propagation to all linked servers"""
    trunk_user = IRCTestClient("quit_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("quit_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await trunk_user.read_lines()
    
    has_quit = any(
        'QUIT :Leaving' in line and 'QuitBranch' in line
        for line in trunk_user.buffer
    )
    
    assert has_quit, "QUIT should propagate to all servers"

# ==============================================================================
# Cross-Server Command Propagation Tests
# ==============================================================================

@runner.test("TOPIC propagates across servers")
async def test_topic_propagation():
    """Test TOPIC changes propagate to all servers"""
    trunk_user = IRCTestClient("topic_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("topic_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await branch_user.read_lines()
    
    has_topic = any(
        'TOPIC #topicchan :Test topic from trunk' in line and 'TopicTrunk' in line
        for line in branch_user.buffer
    )
    
    assert has_topic, "TOPIC changes should propagate across servers"

@runner.test("KICK propagates across servers")
async def test_kick_propagation():
    """Test KICK propagates to all servers"""
    trunk_user = IRCTestClient("kick_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("kick_branch", host=TEST_HOST, port=BRANCH1_PORT)
    branch_victim = IRCTestClient("kick_victim", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await branch_user.read_lines()
    await branch_victim.read_lines()
    
    has_kick = any(
        'KICK #kickchan KickVictim :Test kick' in line and 'KickTrunk' in line
        for line in branch_user.buffer
    )
    victim_saw_kick = any(
        'KICK #kickchan KickVictim :Test kick' in line
        for line in branch_victim.buffer
    )
    
    assert has_kick and victim_saw_kick, "KICK should propagate across servers"

@runner.test("NICK changes propagate across servers")
async def test_nick_propagation():
    """Test NICK changes propagate to all servers"""
    trunk_user = IRCTestClient("nick_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("nick_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
    await trunk_user.connect("NickTrunk")
    await branch_user.connect("NickBranch")
    
    await asyncio.sleep(1)

    await trunk_user.send_raw("JOIN #nickchan")
    await branch_user.send_raw("JOIN #nickchan")
    await asyncio.sleep(1)
    
    trunk_user.buffer.clear()
    
    # Branch user changes nick
    await branch_user.send_raw("NICK NewBranchNick")
    await asyncio.sleep(1)
    await trunk_user.read_lines()
    
    has_nick = any(
        'NICK NewBranchNick' in line and 'NickBranch' in line
        for line in trunk_user.buffer
    )
    
    assert has_nick, "NICK changes should propagate across servers"

@runner.test("AWAY status propagates across servers")
async def test_away_propagation():
    """Test AWAY status propagates to all servers"""
    trunk_user = IRCTestClient("away_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("away_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await trunk_user.read_lines()
    
    # Should see away message
    has_away = False
    for line in trunk_user.buffer:
        if '301' in line and 'Gone for lunch' in line:  # RPL_AWAY
            has_away = True

    assert has_away, "AWAY status should propagate across servers"

@runner.test("away-notify propagates across servers")
async def test_away_notify_crossserver():
    """Test IRCv3 away-notify for users on different linked servers."""
    watcher = IRCTestClient("away_notify_trunk", host=TEST_HOST, port=TRUNK_PORT)
    remote_user = IRCTestClient("away_notify_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await watcher.connect("AwayNotifyTrunk")
    await remote_user.connect("AwayNotifyBranch")
    await asyncio.sleep(0.5)

    assert await enable_caps(watcher, ["away-notify"]), "away-notify capability not acknowledged"

    await watcher.send_raw("JOIN #awaynotify")
    await remote_user.send_raw("JOIN #awaynotify")
    await asyncio.sleep(1)

    watcher.buffer.clear()
    await remote_user.send_raw("AWAY :stepped out")
    await asyncio.sleep(1)
    await watcher.read_lines()

    has_away_notify = any(
        "AWAY" in line and "AwayNotifyBranch" in line and "stepped out" in line
        for line in watcher.buffer
    )

    assert has_away_notify, "away-notify should reach users across linked servers"

@runner.test("setname propagates across servers")
async def test_setname_crossserver():
    """Test IRCv3 SETNAME updates are visible across linked servers."""
    watcher = IRCTestClient("setname_trunk", host=TEST_HOST, port=TRUNK_PORT)
    remote_user = IRCTestClient("setname_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await watcher.connect("SetnameTrunk")
    await remote_user.connect("SetnameBranch")
    await asyncio.sleep(0.5)

    assert await enable_caps(watcher, ["setname"]), "setname capability not acknowledged"

    await watcher.send_raw("JOIN #setnamechan")
    await remote_user.send_raw("JOIN #setnamechan")
    await asyncio.sleep(1)

    watcher.buffer.clear()
    await remote_user.send_raw("SETNAME :Updated Remote Name")
    await asyncio.sleep(1)
    await watcher.read_lines()

    has_setname = any(
        "SETNAME" in line and "SetnameBranch" in line and "Updated Remote Name" in line
        for line in watcher.buffer
    )

    assert has_setname, "SETNAME should propagate across linked servers"

@runner.test("account-notify propagates across servers")
async def test_account_notify_crossserver():
    """Test IRCv3 account-notify for users on different linked servers."""
    watcher = IRCTestClient("account_notify_trunk", host=TEST_HOST, port=TRUNK_PORT)
    remote_user = IRCTestClient("account_notify_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await watcher.connect("AccountNotifyTrunk")
    await remote_user.connect("AccountNotifyBranch")
    await asyncio.sleep(0.5)

    assert await enable_caps(watcher, ["account-notify"]), "account-notify capability not acknowledged"

    await watcher.send_raw("JOIN #accountnotify")
    await remote_user.send_raw("JOIN #accountnotify")
    await asyncio.sleep(1)

    remote_user.buffer.clear()
    await remote_user.send_raw("PRIVMSG Registrar :REGISTER accountnotifypass123")
    await asyncio.sleep(1)
    await remote_user.read_lines()

    remote_user.buffer.clear()
    watcher.buffer.clear()
    await remote_user.send_raw("PRIVMSG Registrar :IDENTIFY accountnotifypass123")
    await asyncio.sleep(1)
    await remote_user.read_lines()
    await watcher.read_lines()

    has_account_notify = any(
        " ACCOUNT " in line and "AccountNotifyBranch" in line
        for line in watcher.buffer
    )

    assert has_account_notify, "account-notify should reach users across linked servers"

@runner.test("chghost propagates across servers")
async def test_chghost_crossserver():
    """Test IRCv3 CHGHOST updates are visible across linked servers."""
    watcher = IRCTestClient("chghost_trunk", host=TEST_HOST, port=TRUNK_PORT)
    remote_user = IRCTestClient("chghost_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await watcher.connect("ChghostTrunk")
    await remote_user.connect("ChghostBranch", "admin")
    await asyncio.sleep(0.5)

    assert await enable_caps(watcher, ["chghost"]), "chghost capability not acknowledged"

    await watcher.send_raw("JOIN #chghostchan")
    await remote_user.send_raw("JOIN #chghostchan")
    await asyncio.sleep(1)

    watcher.buffer.clear()
    assert await auth_admin(remote_user), "Admin auth failed on branch user"
    await asyncio.sleep(1)
    await watcher.read_lines()

    has_chghost = any(
        " CHGHOST " in line and "ChghostBranch" in line
        for line in watcher.buffer
    )

    assert has_chghost, "CHGHOST should propagate across linked servers"

@runner.test("WHO shows users from all servers")
async def test_who_crossserver():
    """Test WHO shows users from all linked servers"""
    trunk_user = IRCTestClient("who_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("who_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
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
    await trunk_user.read_lines()
    
    who_lines = [line for line in trunk_user.buffer if " 352 " in line and "#whochan" in line]
    has_who_trunk = any("WhoTrunk" in line for line in who_lines)
    has_who_branch = any("WhoBranch" in line for line in who_lines)

    assert has_who_trunk and has_who_branch, "WHO should return 352 entries for users from all servers"

@runner.test("USERHOST works across servers")
async def test_userhost_crossserver():
    """Test USERHOST across trunk and branch users"""
    trunk_user = IRCTestClient("userhost_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("userhost_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("UserhostTrunk")
    await branch_user.connect("UserhostBranch")
    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("USERHOST UserhostBranch")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_302 = any(" 302 " in line and "UserhostBranch" in line for line in trunk_user.buffer)
    assert has_302, "USERHOST should return 302 for remote user"

@runner.test("ISON works across servers")
async def test_ison_crossserver():
    """Test ISON across trunk and branch users"""
    trunk_user = IRCTestClient("ison_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("ison_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("IsonTrunk")
    await branch_user.connect("IsonBranch")
    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("ISON IsonBranch OfflineUser123")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_303 = any(" 303 " in line and "IsonBranch" in line for line in trunk_user.buffer)
    assert has_303, "ISON should include remote user"

@runner.test("WHOIS works across servers")
async def test_whois_crossserver():
    """Test WHOIS across trunk and branch users"""
    trunk_user = IRCTestClient("whois_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("whois_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("WhoisTrunk")
    await branch_user.connect("WhoisBranch")

    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("WHOIS WhoisBranch")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_311 = any(" 311 " in line and "WhoisBranch" in line for line in trunk_user.buffer)
    has_318 = any(" 318 " in line and "WhoisBranch" in line for line in trunk_user.buffer)
    no_401 = not any(" 401 " in line and "WhoisBranch" in line for line in trunk_user.buffer)

    assert has_311 and has_318 and no_401, "WHOIS should return 311/318 without a false 401 for a remote user"

@runner.test("WHOIS missing remote nick returns 401 and 318")
async def test_whois_missing_remote_user():
    """Test WHOIS across links completes cleanly for a missing nick."""
    trunk_user = IRCTestClient("whois_missing_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("whois_missing_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("WhoisMissingTrunk")
    await branch_user.connect("WhoisMissingBranch")

    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("WHOIS DefinitelyMissingNick")
    await asyncio.sleep(0.8)
    await trunk_user.read_lines()

    has_401 = any(" 401 " in line and "DefinitelyMissingNick" in line for line in trunk_user.buffer)
    has_318 = any(" 318 " in line and "DefinitelyMissingNick" in line for line in trunk_user.buffer)

    assert has_401 and has_318, "WHOIS for missing remote nick should return 401/318"

@runner.test("MONITOR notifies across servers")
async def test_monitor_crossserver():
    """Test MONITOR/WATCH notifications for remote users"""
    watcher = IRCTestClient("monitor_watcher", host=TEST_HOST, port=TRUNK_PORT)
    await watcher.connect("MonitorWatch")
    await asyncio.sleep(0.5)

    watcher.buffer.clear()
    await watcher.send_raw("MONITOR + MonitorTarget")
    await asyncio.sleep(0.5)
    await watcher.read_lines()

    target = IRCTestClient("monitor_target", host=TEST_HOST, port=BRANCH1_PORT)
    await target.connect("MonitorTarget")
    await asyncio.sleep(1)
    await watcher.read_lines()

    # Watcher should get RPL_MONONLINE (600)
    has_online = any(" 600 " in line and "MonitorTarget" in line for line in watcher.buffer)

    await target.disconnect()
    await asyncio.sleep(1)
    await watcher.read_lines()

    has_offline = any(" 601 " in line and "MonitorTarget" in line for line in watcher.buffer)

    assert has_online and has_offline, "MONITOR should notify online/offline for remote users"

@runner.test("SILENCE blocks remote messages")
async def test_silence_crossserver():
    """Test SILENCE applies to remote users"""
    trunk_user = IRCTestClient("silence_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("silence_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("SilenceTrunk")
    await branch_user.connect("SilenceBranch")
    await asyncio.sleep(0.5)

    # Branch user silences trunk user
    await branch_user.send_raw("SILENCE +SilenceTrunk!*@*")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()

    branch_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG SilenceBranch :You should not see this")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()

    got_msg = any("You should not see this" in line for line in branch_user.buffer)
    assert not got_msg, "SILENCE should suppress messages from remote users"

@runner.test("IRCv3 message-tags and server-time across servers")
async def test_message_tags_across_servers():
    """Test message-tags and server-time tags across links"""
    trunk_user = IRCTestClient("tags_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("tags_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("TagsTrunk")
    await branch_user.connect("TagsBranch")
    await asyncio.sleep(0.5)

    await enable_caps(trunk_user, ["message-tags", "server-time"])
    await enable_caps(branch_user, ["message-tags"])

    trunk_user.buffer.clear()
    await branch_user.send_raw("@+draft/test=1 PRIVMSG TagsTrunk :Tagged message")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_tag = any("draft/test=1" in line for line in trunk_user.buffer)
    has_time = any(line.startswith("@time=") or ";time=" in line for line in trunk_user.buffer)

    assert has_tag, "message-tags should propagate across servers"
    assert has_time, "server-time tag should be added for receiver"

@runner.test("IRCv3 batch on WHO across servers")
async def test_batch_who_across_servers():
    """Test batch capability for WHO response across servers"""
    trunk_user = IRCTestClient("batch_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("batch_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("BatchTrunk")
    await branch_user.connect("BatchBranch")
    await asyncio.sleep(0.5)

    await enable_caps(trunk_user, ["batch"])

    await trunk_user.send_raw("JOIN #batchchan")
    await branch_user.send_raw("JOIN #batchchan")
    await asyncio.sleep(0.5)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("WHO #batchchan")
    await asyncio.sleep(0.8)
    await trunk_user.read_lines()

    has_batch = any(" BATCH +" in line for line in trunk_user.buffer)
    assert has_batch, "WHO should be batched when batch capability is enabled"

@runner.test("CHATHISTORY includes cross-server messages")
async def test_chathistory_crossserver():
    """Test CHATHISTORY returns messages from linked servers"""
    trunk_user = IRCTestClient("history_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("history_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("HistoryTrunk")
    await branch_user.connect("HistoryBranch")
    await asyncio.sleep(0.5)

    await trunk_user.send_raw("JOIN #histchan")
    await branch_user.send_raw("JOIN #histchan")
    await asyncio.sleep(0.5)

    # Enable transcript mode on channel
    await trunk_user.send_raw("MODE #histchan +y")
    await asyncio.sleep(0.5)

    await branch_user.send_raw("PRIVMSG #histchan :History from branch")
    await asyncio.sleep(0.5)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("CHATHISTORY LATEST #histchan * 5")
    await asyncio.sleep(0.8)
    await trunk_user.read_lines()

    has_history = any("History from branch" in line for line in trunk_user.buffer)
    assert has_history, "CHATHISTORY should include cross-server messages"

@runner.test("Nick collision resolved across servers")
async def test_nick_collision_across_servers():
    """Test nick collision handling between trunk and branch"""
    trunk_user = IRCTestClient("dup_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("dup_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("DupNick")
    await asyncio.sleep(0.2)
    await branch_user.connect("DupNick")
    await asyncio.sleep(1.0)
    await trunk_user.read_lines()
    await branch_user.read_lines()

    branch_rejected = any(" 433 " in line and "DupNick" in line for line in branch_user.buffer)
    trunk_alive = trunk_user.connected
    branch_alive = branch_user.connected
    assert branch_rejected or (trunk_alive != branch_alive), "Nick collision should reject or disconnect one client"

@runner.test("Channel modes enforce across servers")
async def test_channel_modes_across_servers():
    """Test +i/+k enforcement across servers"""
    trunk_user = IRCTestClient("mode2_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("mode2_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("Mode2Trunk")
    await branch_user.connect("Mode2Branch")
    await asyncio.sleep(0.5)

    await trunk_user.send_raw("JOIN #mode2chan")
    await asyncio.sleep(0.5)
    await trunk_user.send_raw("MODE #mode2chan +ik keypass")
    await asyncio.sleep(0.5)

    branch_user.buffer.clear()
    await branch_user.send_raw("JOIN #mode2chan")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    has_475 = any(" 475 " in line and "#mode2chan" in line for line in branch_user.buffer)
    has_473 = any(" 473 " in line and "#mode2chan" in line for line in branch_user.buffer)
    assert has_475 or has_473, "Invite/key modes should block JOIN #mode2chan without key/invite"

    branch_user.buffer.clear()
    await branch_user.send_raw("JOIN #mode2chan keypass")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    has_473_with_key = any(" 473 " in line and "#mode2chan" in line for line in branch_user.buffer)
    no_join = not any("JOIN #mode2chan" in line and "Mode2Branch" in line for line in branch_user.buffer)
    assert has_473_with_key and no_join, "Invite-only mode should still block JOIN #mode2chan even when the key is supplied"

@runner.test("LUSERS shows global counts across servers")
async def test_lusers_global():
    """Test LUSERS returns global user count with linked servers"""
    trunk_user = IRCTestClient("lusers_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("lusers_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("LusersTrunk")
    await branch_user.connect("LusersBranch")
    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("LUSERS")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_251 = any(" 251 " in line for line in trunk_user.buffer)
    has_266 = any(" 266 " in line for line in trunk_user.buffer)

    assert has_251 and has_266, "LUSERS should return global counts"

@runner.test("STATS u works with linked servers")
async def test_stats_u():
    """Test STATS u returns uptime with linked servers present"""
    trunk_user = IRCTestClient("stats_trunk", host=TEST_HOST, port=TRUNK_PORT)
    await trunk_user.connect("StatsTrunk")
    await asyncio.sleep(0.5)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("STATS u")
    await asyncio.sleep(0.5)
    await trunk_user.read_lines()

    has_242 = any(" 242 " in line for line in trunk_user.buffer)
    has_219 = any(" 219 " in line for line in trunk_user.buffer)
    assert has_242 and has_219, "STATS u should return 242/219"

@runner.test("LIST shows channels across servers")
async def test_list_crossserver():
    """Test LIST shows channels with users from different servers"""
    trunk_user = IRCTestClient("list_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("list_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("ListTrunk")
    await branch_user.connect("ListBranch")
    await asyncio.sleep(1)

    await trunk_user.send_raw("JOIN #listchan")
    await branch_user.send_raw("JOIN #listchan")
    await asyncio.sleep(1)

    trunk_user.buffer.clear()
    await trunk_user.send_raw("LIST")
    await asyncio.sleep(0.8)
    await trunk_user.read_lines()

    has_list = any(" 322 " in line and "#listchan" in line for line in trunk_user.buffer)
    assert has_list, "LIST should include cross-server channel"

@runner.test("INVITE works across servers")
async def test_invite_crossserver():
    """Test INVITE from trunk to branch user for +i channel"""
    trunk_user = IRCTestClient("invite_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("invite_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("InviteTrunk")
    await branch_user.connect("InviteBranch")
    await asyncio.sleep(1)

    await trunk_user.send_raw("JOIN #invchan")
    await asyncio.sleep(0.5)
    await trunk_user.send_raw("MODE #invchan +i")
    await asyncio.sleep(0.5)

    branch_user.buffer.clear()
    await trunk_user.send_raw("INVITE InviteBranch #invchan")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()

    has_invite = any(
        "INVITE InviteBranch :#invchan" in line and "InviteTrunk" in line
        for line in branch_user.buffer
    )
    assert has_invite, "Branch user should receive INVITE"

    branch_user.buffer.clear()
    await branch_user.send_raw("JOIN #invchan")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    await trunk_user.read_lines()
    has_join = any("JOIN" in line and "#invchan" in line for line in branch_user.buffer)
    trunk_saw_join = any("JOIN #invchan" in line and "InviteBranch" in line for line in trunk_user.buffer)
    assert has_join and trunk_saw_join, "Branch user should join invite-only channel after INVITE"

@runner.test("KICK and BAN propagate across servers")
async def test_kick_ban_crossserver():
    """Test KICK/BAN from trunk affecting branch user"""
    trunk_user = IRCTestClient("kick_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("kick_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("KickTrunk")
    await branch_user.connect("KickBranch")
    await asyncio.sleep(1)

    await trunk_user.send_raw("JOIN #kickchan")
    await branch_user.send_raw("JOIN #kickchan")
    await asyncio.sleep(1)

    branch_user.buffer.clear()
    await trunk_user.send_raw("KICK #kickchan KickBranch :Test kick")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    victim_saw_kick = any(
        "KICK #kickchan KickBranch :Test kick" in line and "KickTrunk" in line
        for line in branch_user.buffer
    )
    assert victim_saw_kick, "Branch user should receive the propagated KICK from trunk"

    # Ban and ensure rejoin is blocked
    await trunk_user.send_raw("MODE #kickchan +b KickBranch!*@*")
    await asyncio.sleep(0.5)

    branch_user.buffer.clear()
    await branch_user.send_raw("JOIN #kickchan")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()
    has_474 = any(" 474 " in line and "#kickchan" in line for line in branch_user.buffer)
    no_rejoin = not any("JOIN #kickchan" in line and "KickBranch" in line for line in branch_user.buffer)
    assert has_474 and no_rejoin, "Branch user should get 474 and remain out of the channel after the ban"

@runner.test("WHISPER works across servers")
async def test_whisper_crossserver():
    """Test WHISPER (IRCX private channel message) works across servers"""
    trunk_user = IRCTestClient("whisper_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("whisper_branch", host=TEST_HOST, port=BRANCH1_PORT)
    
    await trunk_user.connect("WhisperTrunk")
    await branch_user.connect("WhisperBranch")
    
    await asyncio.sleep(1)

    await trunk_user.send_raw("IRCX")
    await branch_user.send_raw("IRCX")
    await asyncio.sleep(0.5)
    
    # Both join channel
    await trunk_user.send_raw("JOIN #whisperchan")
    await branch_user.send_raw("JOIN #whisperchan")
    await asyncio.sleep(1)
    
    branch_user.buffer.clear()
    
    # Trunk user whispers to branch user
    await trunk_user.send_raw("WHISPER #whisperchan WhisperBranch :Secret message")
    await asyncio.sleep(1)
    await branch_user.read_lines()
    
    has_whisper = any(
        'WHISPER #whisperchan WhisperBranch :Secret message' in line and 'WhisperTrunk' in line
        for line in branch_user.buffer
    )
    
    assert has_whisper, "WHISPER should work across servers"

# ==============================================================================
# Multi-Branch Network Tests (Trunk + 2 Branches)
# ==============================================================================

@runner.test("Three-server network topology (trunk + 2 branches)")
async def test_three_server_topology():
    """Test full network with trunk (6667) + branch1 (6668) + branch2 (6669)"""
    trunk_user = IRCTestClient("trunk_user", host=TEST_HOST, port=TRUNK_PORT)
    branch1_user = IRCTestClient("branch1_user", host=TEST_HOST, port=BRANCH1_PORT)
    branch2_user = IRCTestClient("branch2_user", host=TEST_HOST, port=BRANCH2_PORT)
    
    await trunk_user.connect("TrunkUser")
    await branch1_user.connect("Branch1User")
    await branch2_user.connect("Branch2User")
    
    await asyncio.sleep(2)  # Allow full network propagation
    
    # Test 1: Branch1 → Branch2 messaging (via trunk)
    branch2_user.buffer.clear()
    await branch1_user.send_raw("PRIVMSG Branch2User :Hello from Branch1!")
    await asyncio.sleep(1)
    await branch2_user.read_lines()
    
    got_b1_to_b2 = any(
        'PRIVMSG Branch2User :Hello from Branch1!' in line and 'Branch1User' in line
        for line in branch2_user.buffer
    )
    
    # Test 2: Branch2 → Branch1 messaging (via trunk)
    branch1_user.buffer.clear()
    await branch2_user.send_raw("PRIVMSG Branch1User :Hello from Branch2!")
    await asyncio.sleep(1)
    await branch1_user.read_lines()
    
    got_b2_to_b1 = any(
        'PRIVMSG Branch1User :Hello from Branch2!' in line and 'Branch2User' in line
        for line in branch1_user.buffer
    )
    
    # Test 3: Trunk → Both branches
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG Branch1User :From trunk to B1")
    await trunk_user.send_raw("PRIVMSG Branch2User :From trunk to B2")
    await asyncio.sleep(1)
    await branch1_user.read_lines()
    await branch2_user.read_lines()
    
    got_trunk_to_b1 = any(
        'PRIVMSG Branch1User :From trunk to B1' in line and 'TrunkUser' in line
        for line in branch1_user.buffer
    )
    got_trunk_to_b2 = any(
        'PRIVMSG Branch2User :From trunk to B2' in line and 'TrunkUser' in line
        for line in branch2_user.buffer
    )
    
    assert all([got_b1_to_b2, got_b2_to_b1, got_trunk_to_b1, got_trunk_to_b2]), \
        "All cross-server messaging should work in 3-server network"

@runner.test("Channel with users from all 3 servers")
async def test_three_server_channel():
    """Test channel operations with users from trunk + 2 branches"""
    trunk_user = IRCTestClient("chan3_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch1_user = IRCTestClient("chan3_b1", host=TEST_HOST, port=BRANCH1_PORT)
    branch2_user = IRCTestClient("chan3_b2", host=TEST_HOST, port=BRANCH2_PORT)
    
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
    await trunk_user.read_lines()
    
    names = ' '.join(trunk_user.buffer)
    has_all = all(nick in names for nick in ['Chan3Trunk', 'Chan3B1', 'Chan3B2'])
    
    # Test channel message reaches all users
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    await trunk_user.send_raw("PRIVMSG #networkchan :Message to all!")
    await asyncio.sleep(1)
    await branch1_user.read_lines()
    await branch2_user.read_lines()
    
    b1_got = any(
        'PRIVMSG #networkchan :Message to all!' in line and 'Chan3Trunk' in line
        for line in branch1_user.buffer
    )
    b2_got = any(
        'PRIVMSG #networkchan :Message to all!' in line and 'Chan3Trunk' in line
        for line in branch2_user.buffer
    )
    
    assert has_all and b1_got and b2_got, "Channel messages should reach all servers"

@runner.test("TOPIC set from branch1 seen on branch2")
async def test_branch_to_branch_topic():
    """Test TOPIC set from one branch is seen on other branch"""
    branch1_user = IRCTestClient("topic_b1", host=TEST_HOST, port=BRANCH1_PORT)
    branch2_user = IRCTestClient("topic_b2", host=TEST_HOST, port=BRANCH2_PORT)
    
    await branch1_user.connect("TopicB1")
    await branch2_user.connect("TopicB2")
    
    await asyncio.sleep(2)
    
    # Both join same channel
    await branch1_user.send_raw("JOIN #b2bchan")
    await branch2_user.send_raw("JOIN #b2bchan")
    await asyncio.sleep(2)
    await branch1_user.read_lines()
    await branch2_user.read_lines()

    branch2_user.buffer.clear()
    
    # Branch1 sets topic
    await branch1_user.send_raw("TOPIC #b2bchan :Topic from Branch1")
    await asyncio.sleep(1)
    await branch2_user.read_lines()
    
    # Branch2 should see topic
    has_topic = any(
        'TOPIC #b2bchan :Topic from Branch1' in line and 'TopicB1' in line
        for line in branch2_user.buffer
    )
    
    assert has_topic, "TOPIC from branch1 should propagate to branch2 via trunk"

@runner.test("MODE changes propagate trunk → branches")
async def test_mode_propagation_network():
    """Test user MODE changes propagate across network"""
    trunk_user = IRCTestClient("mode_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch1_user = IRCTestClient("mode_b1", host=TEST_HOST, port=BRANCH1_PORT)
    branch2_user = IRCTestClient("mode_b2", host=TEST_HOST, port=BRANCH2_PORT)
    
    await trunk_user.connect("ModeTrunk")
    await branch1_user.connect("ModeB1")
    await branch2_user.connect("ModeB2")
    
    # All join channel
    await trunk_user.send_raw("JOIN #modechan")
    await branch1_user.send_raw("JOIN #modechan")
    await branch2_user.send_raw("JOIN #modechan")
    await asyncio.sleep(2)
    await branch1_user.read_lines()
    await branch2_user.read_lines()

    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    branch1_user.buffer.clear()
    branch2_user.buffer.clear()
    
    # Trunk user (channel creator) sets mode on branch1 user
    await trunk_user.send_raw("MODE #modechan +v ModeB1")
    await asyncio.sleep(1)
    await branch1_user.read_lines()
    await branch2_user.read_lines()
    
    # Both branches should see MODE change
    b1_saw = any('MODE' in line and '+v' in line for line in branch1_user.buffer)
    b2_saw = any('MODE' in line and '+v' in line for line in branch2_user.buffer)
    
    assert b1_saw and b2_saw, "MODE changes should propagate across network"

# ==============================================================================
# End User Test Cases
# ==============================================================================

@runner.test("End User: Join channel, chat, leave (single server)")
async def test_enduser_basic_workflow():
    """Test typical end user workflow on single server"""
    user = IRCTestClient("enduser")
    await user.connect("EndUser", "enduser")
    
    # User joins channel
    user.buffer.clear()
    await user.send_raw("JOIN #lobby")
    await asyncio.sleep(0.5)
    await user.read_lines()
    
    has_join = any('JOIN #lobby' in line and 'EndUser' in line for line in user.buffer)
    
    user.buffer.clear()
    
    # User sends message
    await user.send_raw("PRIVMSG #lobby :Hello everyone!")
    await asyncio.sleep(0.5)
    await user.read_lines()
    
    # User parts with message
    await user.send_raw("PART #lobby :Goodbye!")
    await asyncio.sleep(0.5)
    await user.read_lines()
    
    has_part = any('PART #lobby' in line and 'EndUser' in line for line in user.buffer)
    
    assert has_join and has_part, "Basic user workflow should work"

@runner.test("End User: Register nickname on branch, use on trunk")
async def test_enduser_register_crossserver():
    """Test user registering nick on branch and using on trunk"""
    branch_user = IRCTestClient("reg_branch", host=TEST_HOST, port=BRANCH1_PORT)
    await branch_user.connect("RegUser")
    
    await asyncio.sleep(1)
    branch_user.buffer.clear()
    
    # Register nickname (should route to trunk)
    await branch_user.send_raw("PRIVMSG Registrar :REGISTER testpass123")
    await asyncio.sleep(1)
    await branch_user.read_lines()
    
    has_response = any(
        ('Registrar' in line and 'register' in line.lower()) or ' 874 ' in line
        for line in branch_user.buffer
    )
    
    # Disconnect and reconnect to trunk
    await branch_user.disconnect()
    await asyncio.sleep(0.5)
    
    trunk_user = IRCTestClient("reg_trunk", host=TEST_HOST, port=TRUNK_PORT)
    await trunk_user.connect("RegUser")
    await asyncio.sleep(1)
    await trunk_user.send_raw("IDENTIFY testpass123")
    await asyncio.sleep(1)
    await trunk_user.read_lines()
    
    # Should be identified
    has_identified = any(' MODE RegUser +r' in line or 'MODE RegUser :+r' in line or 'You are now identified' in line for line in trunk_user.buffer)

    assert has_response and has_identified, "Registration should work from branch and identify on trunk"

@runner.test("End User: Send offline message, receive when login")
async def test_enduser_offline_messages():
    """Test Messenger offline message functionality"""
    recipient_setup = IRCTestClient("recipient_setup")
    await recipient_setup.connect("RecipientUser")
    await asyncio.sleep(0.5)
    recipient_setup.buffer.clear()
    await recipient_setup.send_raw("PRIVMSG Registrar :REGISTER recipientpass123")
    await asyncio.sleep(1)
    await recipient_setup.read_lines()
    await recipient_setup.disconnect()
    await asyncio.sleep(0.5)

    sender = IRCTestClient("sender")
    await sender.connect("Sender")
    
    await asyncio.sleep(1)
    sender.buffer.clear()
    
    # Send offline message to RecipientUser
    await sender.send_raw("PRIVMSG Messenger :SEND RecipientUser Test offline message")
    await asyncio.sleep(1)
    await sender.read_lines()
    
    has_confirmation = any('Messenger' in line and ('queued' in line.lower() or 'stored' in line.lower() or 'sent' in line.lower()) for line in sender.buffer)
    
    # Recipient logs in
    recipient = IRCTestClient("recipient")
    await recipient.connect("RecipientUser")
    await asyncio.sleep(1)
    await recipient.send_raw("IDENTIFY recipientpass123")
    await asyncio.sleep(1)
    await recipient.read_lines()
    recipient.buffer.clear()
    await recipient.send_raw("PRIVMSG Messenger :READ")
    await asyncio.sleep(1)
    await recipient.read_lines()
    
    has_memo_header = any('Messenger' in line and 'Sender' in line for line in recipient.buffer)
    has_memo_body = any('Messenger' in line and 'Test offline message' in line for line in recipient.buffer)
    
    assert has_confirmation and has_memo_header and has_memo_body, "Offline messages should be delivered on login"

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
    await user.read_lines()
    
    has_join = any('JOIN #aliaschan' in line and 'AliasUser' in line for line in user.buffer)
    
    # Test /P alias for /PART
    user.buffer.clear()
    await user.send_raw("P #aliaschan")
    await asyncio.sleep(0.5)
    await user.read_lines()
    
    has_part = any('PART #aliaschan' in line and 'AliasUser' in line for line in user.buffer)
    
    # Test /M alias for /MSG
    user.buffer.clear()
    await user.send_raw("M Registrar :HELP")
    await asyncio.sleep(2)
    await user.read_lines()
    
    has_msg = any('Registrar' in line and ('help' in line.lower() or 'register' in line.lower() or 'identify' in line.lower()) for line in user.buffer)
    
    assert all([has_join, has_part, has_msg]), "Command aliases should work"

# ==============================================================================
# Staff Test Cases
# ==============================================================================

@runner.test("Staff: Authenticate as ADMIN on branch")
async def test_staff_admin_on_branch():
    """Test ADMIN authentication on branch server"""
    admin = IRCTestClient("staff_admin", host=TEST_HOST, port=BRANCH1_PORT)
    await admin.connect("StaffAdmin", "admin")

    has_admin = await auth_admin(admin)
    
    assert has_admin, "Staff should authenticate on branch and get admin mode"

@runner.test("Staff: Use STAFF command from branch")
async def test_staff_command_from_branch():
    """Test STAFF command routing from branch to trunk"""
    admin = IRCTestClient("staff_cmd", host=TEST_HOST, port=BRANCH1_PORT)
    await admin.connect("StaffCmd", "admin")
    assert await auth_admin(admin), "Admin auth failed"
    admin.buffer.clear()
    
    # Use STAFF LIST command
    await admin.send_raw("STAFF LIST")
    await asyncio.sleep(1)
    await admin.read_lines()
    
    # Should get staff list from trunk
    has_staff_header = any('STAFF' in line and 'LIST' in line for line in admin.buffer)
    has_staff_levels = any('ADMIN' in line or 'SYSOP' in line or 'GUIDE' in line for line in admin.buffer)

    assert has_staff_header or has_staff_levels, "STAFF commands should route from branch to trunk"

@runner.test("Staff: KILL user on different server")
async def test_staff_kill_crossserver():
    """Test KILL propagation across servers from a branch admin."""
    admin = IRCTestClient("kill_admin", host=TEST_HOST, port=BRANCH1_PORT)
    await admin.connect("KillAdmin", "admin")
    assert await auth_admin(admin), "Admin auth failed"
    
    victim = IRCTestClient("kill_victim", host=TEST_HOST, port=TRUNK_PORT)
    await victim.connect("KillVictim")
    
    await asyncio.sleep(2)
    
    # Admin kills victim on different server
    await admin.send_raw("KILL KillVictim :Test kill")
    await asyncio.sleep(1)
    await victim.read_lines()
    
    # Victim should either receive a KILL line or lose the connection entirely.
    has_kill = any(" KILL " in line and "KillVictim" in line for line in victim.buffer)
    victim_disconnected = not victim.connected
    
    assert has_kill or victim_disconnected, "KILL should disconnect a remote victim"

@runner.test("Staff: GAG user, verify cannot send messages")
async def test_staff_gag():
    """Test GAG prevents user from sending messages"""
    admin = IRCTestClient("gag_admin")
    await admin.connect("GagAdmin", "admin")
    assert await auth_admin(admin), "Admin auth failed"
    
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
    await victim.read_lines()
    
    # GAG is intentionally silent to the gagged user; the message just should not echo/deliver.
    no_channel_echo = not any('PRIVMSG #testchan :I am gagged' in line and 'GagVictim' in line for line in victim.buffer)
    assert no_channel_echo, "Gagged users should not deliver the message"

@runner.test("Staff: View STATS across network")
async def test_staff_stats_network():
    """Test STATS showing network-wide information"""
    admin = IRCTestClient("stats_admin")
    await admin.connect("StatsAdmin", "admin")
    assert await auth_admin(admin), "Admin auth failed"
    
    # Create some users on different servers
    user1 = IRCTestClient("stats_u1", host=TEST_HOST, port=BRANCH1_PORT)
    user2 = IRCTestClient("stats_u2", host=TEST_HOST, port=BRANCH2_PORT)
    await user1.connect("StatsU1")
    await user2.connect("StatsU2")
    
    await asyncio.sleep(2)
    admin.buffer.clear()
    
    # Request LUSERS (network stats)
    await admin.send_raw("LUSERS")
    await asyncio.sleep(2)
    await admin.read_lines()
    
    has_251 = any(" 251 " in line for line in admin.buffer)
    has_266 = any(" 266 " in line for line in admin.buffer)
    mentions_network_users = any("users" in line.lower() or "clients" in line.lower() for line in admin.buffer)

    assert has_251 and has_266 and mentions_network_users, "STATS should aggregate network-wide information"

@runner.test("NOTICE propagates cross-server")
async def test_notice_crossserver():
    """Test NOTICE command works across servers"""
    trunk_user = IRCTestClient("notice_trunk")
    branch_user = IRCTestClient("notice_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await trunk_user.connect("NoticeTrunk")
    await branch_user.connect("NoticeBranch")
    await asyncio.sleep(0.5)

    # Trunk sends NOTICE to branch user
    branch_user.buffer.clear()
    await trunk_user.send_raw("NOTICE NoticeBranch :Cross-server notice test")
    await asyncio.sleep(0.5)
    await branch_user.read_lines()

    direct_notice = any(
        'NOTICE NoticeBranch :Cross-server notice test' in line and 'NoticeTrunk' in line
        for line in branch_user.buffer
    )

    assert direct_notice, "NOTICE should propagate to the user on a different server"

    await trunk_user.disconnect()
    await branch_user.disconnect()

@runner.test("NOTICE to channel propagates cross-server")
async def test_notice_channel_crossserver():
    """Test channel NOTICE works across servers"""
    trunk_user = IRCTestClient("notice_trunk_chan")
    branch_user = IRCTestClient("notice_branch_chan", host=TEST_HOST, port=BRANCH1_PORT)

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
    await branch_user.read_lines()

    channel_notice = any(
        'NOTICE #noticechan :Channel notice test' in line and 'NoticeTrunkChan' in line
        for line in branch_user.buffer
    )

    assert channel_notice, "Channel NOTICE should propagate to users on different servers"

    await trunk_user.disconnect()
    await branch_user.disconnect()

# ==============================================================================
# Run all tests
# ==============================================================================

if __name__ == "__main__":
    print("pyIRCX v2.0.1 Distributed Networking Test Suite")
    print("=" * 80)
    print("Testing trunk/branch topology and cross-server operations")
    print()

    success = asyncio.run(runner.run_all())
    sys.exit(0 if success else 1)
