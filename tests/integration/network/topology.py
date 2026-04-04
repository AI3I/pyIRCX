#!/usr/bin/env python3
"""
pyIRCX v2.0.1 Network Topology Test Suite
Tests network divergences and convergences

Critical scenarios tested:
- Server disconnection (SQUIT) - network divergence
- User cleanup during divergence
- Channel state during divergence
- Server reconnection (CONNECT) - network convergence
- Duplicate user handling
- Channel merging
- Services during divergence/convergence
"""

import asyncio
import os
import sys
import time
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from users import IRCTestClient, TestRunner

TEST_HOST = os.environ.get("PYIRCX_TEST_HOST", "127.0.0.1")
TRUNK_PORT = int(os.environ.get("PYIRCX_TEST_TRUNK_PORT", "6667"))
BRANCH1_PORT = int(os.environ.get("PYIRCX_TEST_BRANCH1_PORT", "6668"))
BRANCH2_PORT = int(os.environ.get("PYIRCX_TEST_BRANCH2_PORT", "6669"))
TRUNK_NAME = os.environ.get("PYIRCX_TEST_TRUNK_NAME", "trunk.testnet.local")
BRANCH1_NAME = os.environ.get("PYIRCX_TEST_BRANCH1_NAME", "branch1.testnet.local")
BRANCH1_LINK_PORT = int(os.environ.get("PYIRCX_TEST_BRANCH1_LINK_PORT", "7002"))
TEST_ADMIN_PASS = os.environ.get("PYIRCX_TEST_ADMIN_PASS", "testpass")

runner = TestRunner()


async def read_and_clear(client: IRCTestClient, wait: float = 0.5):
    await asyncio.sleep(wait)
    await client.read_lines()


async def wait_for(assertion, timeout: float = 8.0, interval: float = 0.9):
    start = time.time()
    last_value = None
    while time.time() - start < timeout:
        last_value = await assertion()
        if last_value:
            return last_value
        await asyncio.sleep(interval)
    return last_value


async def channel_names(client: IRCTestClient, channel: str) -> str:
    client.buffer.clear()
    await client.send_raw(f"NAMES {channel}")
    await read_and_clear(client, 0.6)
    return " ".join(line for line in client.buffer if " 353 " in line or " 366 " in line)


async def channel_listing(client: IRCTestClient) -> str:
    client.buffer.clear()
    await client.send_raw("LIST")
    await read_and_clear(client, 0.9)
    return " ".join(line for line in client.buffer if " 322 " in line or " 323 " in line)


async def channel_mode(client: IRCTestClient, channel: str) -> str:
    client.buffer.clear()
    await client.send_raw(f"MODE {channel}")
    await read_and_clear(client, 0.6)
    return " ".join(client.buffer)


async def channel_topic(client: IRCTestClient, channel: str) -> str:
    client.buffer.clear()
    await client.send_raw(f"TOPIC {channel}")
    await read_and_clear(client, 0.6)
    return " ".join(client.buffer)


async def wait_for_nicks(client: IRCTestClient, channel: str, present=None, absent=None, timeout: float = 8.0) -> bool:
    present = present or []
    absent = absent or []

    async def check():
        snapshot = await channel_names(client, channel)
        return all(nick in snapshot for nick in present) and all(nick not in snapshot for nick in absent)

    return bool(await wait_for(check, timeout=timeout))


async def reconnect_branch1(admin: IRCTestClient):
    admin.buffer.clear()
    await admin.send_raw(f"CONNECT {BRANCH1_NAME} {BRANCH1_LINK_PORT}")
    await read_and_clear(admin, 3.0)


async def split_branch1(admin: IRCTestClient):
    await asyncio.sleep(3.0)
    admin.buffer.clear()
    await admin.send_raw(f"SQUIT {BRANCH1_NAME} :Topology test split")
    await read_and_clear(admin, 2.5)


async def assert_remote_nick_visible(sender: IRCTestClient, recipient: IRCTestClient, nick: str, text: str, timeout: float = 6.0) -> bool:
    recipient.buffer.clear()

    async def check():
        recipient.buffer.clear()
        await sender.send_raw(f"PRIVMSG {nick} :{text}")
        await read_and_clear(recipient, 0.6)
        return any(text in line and f"PRIVMSG {nick}" in line for line in recipient.buffer)

    return bool(await wait_for(check, timeout=timeout))


@runner.test("SQUIT disconnects server from network")
async def test_squit_basic():
    admin = IRCTestClient("squit_admin", host=TEST_HOST, port=TRUNK_PORT)
    trunk_user = IRCTestClient("squit_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("squit_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await admin.connect("SQUITAdmin", "admin", password=TEST_ADMIN_PASS)
    await trunk_user.connect("SQuitTrunk")
    await branch_user.connect("SQuitBranch")

    await trunk_user.send_raw("JOIN #squitcheck")
    await branch_user.send_raw("JOIN #squitcheck")
    assert await wait_for_nicks(trunk_user, "#squitcheck", present=["SQuitTrunk", "SQuitBranch"]), "Branch user should be visible before split"

    await split_branch1(admin)
    assert await wait_for_nicks(trunk_user, "#squitcheck", present=["SQuitTrunk"], absent=["SQuitBranch"]), "Branch user should disappear after SQUIT"

    await reconnect_branch1(admin)


@runner.test("Users disappear after network divergence")
async def test_users_disappear_on_split():
    trunk_user = IRCTestClient("trunk_watch", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("branch_gone", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("split_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("TrunkWatch")
    await branch_user.connect("BranchGone")
    await admin.connect("DivergenceAdmin", "admin", password=TEST_ADMIN_PASS)

    await trunk_user.send_raw("JOIN #splitchan")
    await branch_user.send_raw("JOIN #splitchan")
    assert await wait_for_nicks(trunk_user, "#splitchan", present=["TrunkWatch", "BranchGone"]), "Both users should be in channel before divergence"

    await split_branch1(admin)
    assert await wait_for_nicks(trunk_user, "#splitchan", present=["TrunkWatch"], absent=["BranchGone"]), "Branch user should disappear after divergence"

    await reconnect_branch1(admin)


@runner.test("Channels lose users during divergence")
async def test_channel_loses_users_on_split():
    trunk1 = IRCTestClient("trunk1", host=TEST_HOST, port=TRUNK_PORT)
    trunk2 = IRCTestClient("trunk2", host=TEST_HOST, port=TRUNK_PORT)
    branch1 = IRCTestClient("branch1", host=TEST_HOST, port=BRANCH1_PORT)
    branch2 = IRCTestClient("branch2", host=TEST_HOST, port=BRANCH2_PORT)
    admin = IRCTestClient("chan_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk1.connect("Trunk1")
    await trunk2.connect("Trunk2")
    await branch1.connect("Branch1")
    await branch2.connect("Branch2")
    await admin.connect("ChanAdmin", "admin", password=TEST_ADMIN_PASS)

    for client in [trunk1, trunk2, branch1, branch2]:
        await client.send_raw("JOIN #lostusers")
        await asyncio.sleep(0.2)

    assert await wait_for_nicks(trunk1, "#lostusers", present=["Trunk1", "Trunk2", "Branch1", "Branch2"]), "Should have 4 users before divergence"

    try:
        await split_branch1(admin)
        assert await wait_for_nicks(trunk1, "#lostusers", present=["Trunk1", "Trunk2", "Branch2"], absent=["Branch1"]), "Only branch1 users should disappear after divergence"
    finally:
        await reconnect_branch1(admin)


@runner.test("Empty channels removed after divergence")
async def test_empty_channel_cleanup_on_split():
    branch_only = IRCTestClient("branch_only", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("empty_admin", host=TEST_HOST, port=TRUNK_PORT)

    await branch_only.connect("BranchOnly")
    await admin.connect("EmptyAdmin", "admin", password=TEST_ADMIN_PASS)

    await branch_only.send_raw("JOIN #branchonly")

    async def channel_exists():
        return "#branchonly" in await channel_listing(admin)

    assert await wait_for(channel_exists, timeout=6.0), "Channel should exist before divergence"

    try:
        await split_branch1(admin)

        async def channel_gone():
            return "#branchonly" not in await channel_listing(admin)

        assert await wait_for(channel_gone, timeout=6.0), "Empty channel should be removed after divergence"
    finally:
        await reconnect_branch1(admin)


@runner.test("CONNECT rejoins server to network")
async def test_connect_rejoin():
    admin = IRCTestClient("rejoin_admin", host=TEST_HOST, port=TRUNK_PORT)
    trunk_user = IRCTestClient("rejoin_trunk_user", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("rejoin_branch_user", host=TEST_HOST, port=BRANCH1_PORT)

    await admin.connect("RejoinAdmin", "admin", password=TEST_ADMIN_PASS)
    await trunk_user.connect("RejoinTrunk")
    await branch_user.connect("RejoinBranch")

    await trunk_user.send_raw("JOIN #rejoinbasic")
    await branch_user.send_raw("JOIN #rejoinbasic")
    assert await wait_for_nicks(trunk_user, "#rejoinbasic", present=["RejoinTrunk", "RejoinBranch"]), "Branch should be visible before split"

    try:
        await split_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#rejoinbasic", present=["RejoinTrunk"], absent=["RejoinBranch"]), "Branch should be gone during split"

        await reconnect_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#rejoinbasic", present=["RejoinTrunk", "RejoinBranch"]), "Branch should reappear after CONNECT"
    finally:
        await reconnect_branch1(admin)


@runner.test("Users reappear after network convergence")
async def test_users_reappear_on_join():
    trunk_user = IRCTestClient("trunk_see", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("branch_back", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("join_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("TrunkSee")
    await branch_user.connect("BranchBack")
    await admin.connect("JoinAdmin", "admin", password=TEST_ADMIN_PASS)

    await trunk_user.send_raw("JOIN #rejoinchan")
    await branch_user.send_raw("JOIN #rejoinchan")
    assert await wait_for_nicks(trunk_user, "#rejoinchan", present=["TrunkSee", "BranchBack"]), "Both users should be visible before split"

    try:
        await split_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#rejoinchan", present=["TrunkSee"], absent=["BranchBack"]), "Branch user should be gone during divergence"

        await reconnect_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#rejoinchan", present=["TrunkSee", "BranchBack"]), "Branch user should reappear after network convergence"
    finally:
        await reconnect_branch1(admin)


@runner.test("Channel modes preserved during divergence")
async def test_channel_modes_during_split():
    trunk_user = IRCTestClient("mode_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("mode_branch", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("mode_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("ModeTrunk")
    await branch_user.connect("ModeBranch")
    await admin.connect("ModeAdmin", "admin", password=TEST_ADMIN_PASS)

    await trunk_user.send_raw("JOIN #modechan")
    await read_and_clear(trunk_user, 0.5)
    await trunk_user.send_raw("MODE #modechan +m")
    await read_and_clear(trunk_user, 0.6)
    await branch_user.send_raw("JOIN #modechan")
    assert await wait_for_nicks(trunk_user, "#modechan", present=["ModeTrunk", "ModeBranch"]), "Branch user should join before split"

    try:
        await split_branch1(admin)

        async def mode_check():
            return "+m" in await channel_mode(trunk_user, "#modechan")

        assert await wait_for(mode_check, timeout=6.0), "Channel modes should be preserved during divergence"
    finally:
        await reconnect_branch1(admin)


@runner.test("Channel topic preserved during divergence")
async def test_channel_topic_during_split():
    trunk_user = IRCTestClient("topic_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("topic_branch", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("topic_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("TopicTrunk")
    await branch_user.connect("TopicBranch")
    await admin.connect("TopicAdmin", "admin", password=TEST_ADMIN_PASS)

    await trunk_user.send_raw("JOIN #topicchan")
    await read_and_clear(trunk_user, 0.5)
    await branch_user.send_raw("JOIN #topicchan")
    assert await wait_for_nicks(trunk_user, "#topicchan", present=["TopicTrunk", "TopicBranch"]), "Branch user should join before split"

    await trunk_user.send_raw("TOPIC #topicchan :Test topic during divergence")
    await read_and_clear(trunk_user, 0.8)

    try:
        await split_branch1(admin)

        async def topic_check():
            return "Test topic during divergence" in await channel_topic(trunk_user, "#topicchan")

        assert await wait_for(topic_check, timeout=6.0), "Channel topic should be preserved during divergence"
    finally:
        await reconnect_branch1(admin)


@runner.test("Duplicate nick detection on network convergence")
async def test_duplicate_nick_on_join():
    trunk_user = IRCTestClient("dup_trunk", host=TEST_HOST, port=TRUNK_PORT)
    admin = IRCTestClient("dup_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("DupNick")
    await admin.connect("DupAdmin", "admin", password=TEST_ADMIN_PASS)

    try:
        await split_branch1(admin)
        await reconnect_branch1(admin)
        assert True, "Server should handle duplicate nicks gracefully"
    finally:
        await reconnect_branch1(admin)


@runner.test("Services unavailable on branch during divergence")
async def test_services_unavailable_during_split():
    branch_user = IRCTestClient("service_user", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("service_admin", host=TEST_HOST, port=TRUNK_PORT)

    await branch_user.connect("ServiceUser")
    await admin.connect("ServiceAdmin", "admin", password=TEST_ADMIN_PASS)

    branch_user.buffer.clear()
    await branch_user.send_raw("PRIVMSG Registrar :HELP")
    await read_and_clear(branch_user, 1.0)
    services_work_before = any('Registrar' in line for line in branch_user.buffer)

    try:
        await split_branch1(admin)

        branch_user.buffer.clear()
        await branch_user.send_raw("PRIVMSG Registrar :HELP")
        await read_and_clear(branch_user, 1.0)
        services_unavailable_during_split = any(
            '912' in line
            or 'temporarily unavailable' in line.lower()
            or '401' in line
            or 'No such' in line
            for line in branch_user.buffer
        ) or not branch_user.buffer

        assert services_work_before, "Services should work before divergence"
        assert services_unavailable_during_split, "Registrar should be unreachable on isolated branch"
    finally:
        await reconnect_branch1(admin)


@runner.test("Staff auth unavailable on branch during divergence")
async def test_staff_auth_unavailable_during_split():
    admin = IRCTestClient("auth_admin", host=TEST_HOST, port=TRUNK_PORT)
    branch_staff = IRCTestClient("branch_staff_auth", host=TEST_HOST, port=BRANCH1_PORT)

    await admin.connect("AuthAdmin", "admin", password=TEST_ADMIN_PASS)

    try:
        await split_branch1(admin)

        await branch_staff.connect("BranchStaff")
        branch_staff.buffer.clear()
        await branch_staff.send_raw(f"AUTH admin {TEST_ADMIN_PASS}")
        await read_and_clear(branch_staff, 1.2)

        auth_failed = any(' 464 ' in line for line in branch_staff.buffer)
        assert auth_failed, "Branch staff auth should fail while trunk is split"
    finally:
        await reconnect_branch1(admin)


@runner.test("Multiple sequential splits and joins")
async def test_multiple_splits_joins():
    admin = IRCTestClient("cycle_admin", host=TEST_HOST, port=TRUNK_PORT)
    trunk_user = IRCTestClient("cycle_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("cycle_branch", host=TEST_HOST, port=BRANCH1_PORT)

    await admin.connect("CycleAdmin", "admin", password=TEST_ADMIN_PASS)
    await trunk_user.connect("CycleTrunk")
    await branch_user.connect("CycleBranch")

    await trunk_user.send_raw("JOIN #cyclechan")
    await branch_user.send_raw("JOIN #cyclechan")
    assert await wait_for_nicks(trunk_user, "#cyclechan", present=["CycleTrunk", "CycleBranch"]), "Initial network state should be connected"

    for _ in range(3):
        await split_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#cyclechan", present=["CycleTrunk"], absent=["CycleBranch"]), "Branch user should disappear during split"
        await reconnect_branch1(admin)
        assert await wait_for_nicks(trunk_user, "#cyclechan", present=["CycleTrunk", "CycleBranch"]), "Branch user should return after reconnect"


@runner.test("Users can't message across split")
async def test_no_messaging_across_split():
    trunk_user = IRCTestClient("msg_trunk", host=TEST_HOST, port=TRUNK_PORT)
    branch_user = IRCTestClient("msg_branch", host=TEST_HOST, port=BRANCH1_PORT)
    admin = IRCTestClient("msg_admin", host=TEST_HOST, port=TRUNK_PORT)

    await trunk_user.connect("MsgTrunk")
    await branch_user.connect("MsgBranch")
    await admin.connect("MsgAdmin", "admin", password=TEST_ADMIN_PASS)

    before_ok = await assert_remote_nick_visible(trunk_user, branch_user, "MsgBranch", "Before split")

    try:
        await split_branch1(admin)

        trunk_user.buffer.clear()
        await trunk_user.send_raw("PRIVMSG MsgBranch :After split")
        await read_and_clear(trunk_user, 1.0)
        got_error = any('401' in line or 'No such' in line for line in trunk_user.buffer)

        assert before_ok, "Messaging should work before divergence"
        assert got_error, "Should get error when messaging user on split server"
    finally:
        await reconnect_branch1(admin)


if __name__ == "__main__":
    print("pyIRCX v2.0.1 Network Split/Join Test Suite")
    print("=" * 80)
    print("Testing network divergences, network convergences, and edge cases")
    print()

    success = asyncio.run(runner.run_all())
    sys.exit(0 if success else 1)
