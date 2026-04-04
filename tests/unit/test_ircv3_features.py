#!/usr/bin/env python3
"""
Unit tests for IRCv3 features batch:
- msgid generation
- account-tag
- bot mode (+b)
- labeled-response
- Standard Replies (FAIL/WARN/NOTE)
- CHATHISTORY (timestamp parsing, transcript conversion)
- RENAME (validation)
- UTF8ONLY / BOT ISUPPORT tokens
"""

import pytest
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock, patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from responses import RESPONSES, SERVER_MESSAGES
import modes as modes_module


# =============================================================================
# HELPER: Minimal server and user mocks
# =============================================================================

def make_mock_user(nickname="TestUser", sasl_account=None, modes=None,
                   enabled_caps=None, msg_tags=None):
    """Create a mock User object for testing"""
    user = MagicMock()
    user.nickname = nickname
    user.username = nickname.lower()
    user.realname = f"Real {nickname}"
    user.host = "test.host"
    user.ip = "127.0.0.1"
    user.sasl_account = sasl_account
    user.registered = True
    user.is_virtual = False
    user.is_remote = False
    user.enabled_caps = enabled_caps or set()
    user._msg_tags = msg_tags or {}
    user._label = None
    user._label_batch_id = None
    user._label_sent = False
    user.channels = set()
    user.writer = MagicMock()

    # Mode handling
    _modes = modes or {}
    user.has_mode = lambda m: _modes.get(m, False)
    user.set_mode = lambda m, v: _modes.__setitem__(m, v)
    user.modes = _modes

    # Async send
    user.send = AsyncMock()

    # Staff checks
    user.is_high_staff = lambda: _modes.get('a', False) or _modes.get('o', False)
    user.is_staff = lambda: _modes.get('a', False) or _modes.get('o', False) or _modes.get('g', False)

    def prefix(viewer=None):
        return f"{nickname}!{nickname.lower()}@test.host"
    user.prefix = prefix

    return user


def make_mock_server():
    """Create a minimal mock pyIRCXServer for testing methods"""
    # Import after path setup
    import pyircx
    server = object.__new__(pyircx.pyIRCXServer)
    server.servername = "test.server.local"
    server.servername_short = "test"
    server.channels = {}
    server.channels_lower = {}
    server.users = {}
    server.users_lower = {}
    server.link_manager = None
    server._pending_remote_whois = {}
    server.stats = {'messages_sent': 0}
    # Reset msgid counter for predictable tests
    pyircx.pyIRCXServer._msgid_counter = 0
    return server


def make_mock_channel(name="#test", modes=None, members=None):
    """Create a mock Channel object"""
    channel = MagicMock()
    channel.name = name
    channel.modes = modes or {}
    channel.members = members or {}
    channel.has_member = lambda nick: nick in channel.members
    channel.owners = set()
    channel.hosts = set()
    return channel


# =============================================================================
# ISUPPORT (005) AND NUMERIC TESTS
# =============================================================================

@pytest.mark.unit
class TestISupportTokens:
    """Test that new ISUPPORT tokens are present in 005"""

    def test_utf8only_in_005(self):
        assert "UTF8ONLY" in RESPONSES["005"]

    def test_bot_in_005(self):
        assert "BOT=b" in RESPONSES["005"]

    def test_chathistory_in_005(self):
        assert "CHATHISTORY={max_chathistory}" in RESPONSES["005"]

    def test_335_whoisbot_exists(self):
        assert "335" in RESPONSES
        assert "bot" in RESPONSES["335"].lower()

    def test_stats_bot_users_message(self):
        assert "stats_bot_users" in SERVER_MESSAGES
        assert "{count}" in SERVER_MESSAGES["stats_bot_users"]


@pytest.mark.unit
class TestWebircHostPresentation:
    @pytest.mark.asyncio
    async def test_webirc_updates_host_from_reverse_dns(self):
        server = make_mock_server()
        user = make_mock_user()
        user.registered = False
        user.ip = "127.0.0.1"
        user.host = "localhost"
        user.hostname = "localhost"

        import pyircx
        pyircx.CONFIG.data = {
            "security": {
                "webirc": {
                    "enabled": True,
                    "hosts": {
                        "pyircx-webchat": {
                            "password": "secret",
                            "allowed_ips": ["127.0.0.1"],
                        }
                    },
                }
            }
        }
        server.resolve_hostname = AsyncMock(return_value="resolved.example.test")

        await server.handle_webirc(user, ["secret", "pyircx-webchat", "40.129.129.76", "40.129.129.76"])

        assert user.ip == "40.129.129.76"
        assert user.host == "resolved.example.test"
        assert user.hostname == "resolved.example.test"

    @pytest.mark.asyncio
    async def test_webirc_falls_back_to_ip_when_reverse_dns_fails(self):
        server = make_mock_server()
        user = make_mock_user()
        user.registered = False
        user.ip = "127.0.0.1"
        user.host = "localhost"
        user.hostname = "localhost"

        import pyircx
        pyircx.CONFIG.data = {
            "security": {
                "webirc": {
                    "enabled": True,
                    "hosts": {
                        "pyircx-webchat": {
                            "password": "secret",
                            "allowed_ips": ["127.0.0.1"],
                        }
                    },
                }
            }
        }
        server.resolve_hostname = AsyncMock(return_value="40.129.129.76")

        await server.handle_webirc(user, ["secret", "pyircx-webchat", "40.129.129.76", "40.129.129.76"])

        assert user.ip == "40.129.129.76"
        assert user.host == "40.129.129.76"
        assert user.hostname == "40.129.129.76"




# =============================================================================
# BOT MODE (+b) TESTS
# =============================================================================

@pytest.mark.unit
class TestBotMode:
    """Test bot mode (+b) in modes module"""

    def test_bot_mode_defined(self):
        assert 'b' in modes_module.USER_MODES

    def test_bot_mode_user_settable(self):
        """Bot mode should not be staff-only"""
        desc, staff_only, auto_set = modes_module.USER_MODES['b']
        assert staff_only is False
        assert auto_set is False

    def test_bot_mode_in_modes_str(self):
        assert 'b' in modes_module.USER_MODES_STR

    def test_bot_mode_alphabetical_order(self):
        """USER_MODES_STR should be alphabetically ordered"""
        assert modes_module.USER_MODES_STR == ''.join(sorted(modes_module.USER_MODES_STR))

    def test_is_valid_user_mode_b(self):
        assert modes_module.is_valid_user_mode('b') is True


# =============================================================================
# MSGID GENERATION TESTS
# =============================================================================

@pytest.mark.unit
class TestMsgidGeneration:
    """Test _generate_msgid produces unique, well-formatted IDs"""

    def test_msgid_format(self):
        server = make_mock_server()
        msgid = server._generate_msgid()
        assert msgid.startswith("test-")
        # Should be hex after the prefix
        hex_part = msgid.split('-', 1)[1]
        int(hex_part, 16)  # Should not raise

    def test_msgid_unique(self):
        server = make_mock_server()
        ids = [server._generate_msgid() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_msgid_incrementing(self):
        server = make_mock_server()
        id1 = server._generate_msgid()
        id2 = server._generate_msgid()
        hex1 = int(id1.split('-', 1)[1], 16)
        hex2 = int(id2.split('-', 1)[1], 16)
        assert hex2 == hex1 + 1

    def test_msgid_short_servername(self):
        """servername_short should be max 8 chars"""
        server = make_mock_server()
        server.servername_short = "verylongservername"[:8]
        msgid = server._generate_msgid()
        prefix = msgid.split('-', 1)[0]
        assert len(prefix) <= 8


# =============================================================================
# _build_msg_tags TESTS
# =============================================================================

@pytest.mark.unit
class TestBuildMsgTags:
    """Test unified tag building method"""

    def test_basic_tags_with_msgid_and_account(self):
        server = make_mock_server()
        user = make_mock_user(sasl_account="alice")
        result = server._build_msg_tags(user)
        assert result.startswith("@")
        assert result.endswith(" ")
        assert "msgid=test-" in result
        assert "account=alice" in result

    def test_unauthenticated_account_star(self):
        server = make_mock_server()
        user = make_mock_user(sasl_account=None)
        result = server._build_msg_tags(user)
        assert "account=*" in result

    def test_bot_tag_included_for_bot_users(self):
        server = make_mock_server()
        user = make_mock_user(modes={'b': True})
        result = server._build_msg_tags(user)
        assert ";bot " in result or result.endswith(";bot ")
        # More precise: bot should be a standalone tag
        tags_part = result[1:result.index(' ')]
        tag_list = tags_part.split(';')
        assert "bot" in tag_list

    def test_no_bot_tag_for_non_bot(self):
        server = make_mock_server()
        user = make_mock_user(modes={})
        result = server._build_msg_tags(user)
        tags_part = result[1:result.index(' ')]
        tag_list = tags_part.split(';')
        assert "bot" not in tag_list

    def test_client_tags_included(self):
        server = make_mock_server()
        user = make_mock_user(msg_tags={'+reply': 'abc123', '+typing': None})
        result = server._build_msg_tags(user)
        assert "+reply=abc123" in result

    def test_non_client_tags_excluded(self):
        """Tags without + prefix (server tags from sender) should not be relayed"""
        server = make_mock_server()
        user = make_mock_user(msg_tags={'label': 'xyz', '+reply': 'abc'})
        result = server._build_msg_tags(user)
        assert "label=" not in result
        assert "+reply=abc" in result

    def test_no_msgid_when_disabled(self):
        server = make_mock_server()
        user = make_mock_user()
        result = server._build_msg_tags(user, include_msgid=False)
        assert "msgid=" not in result

    def test_empty_msg_tags_no_client_tags(self):
        """Even with no client tags, should still have msgid and account"""
        server = make_mock_server()
        user = make_mock_user()
        result = server._build_msg_tags(user)
        assert result.startswith("@")
        assert "msgid=" in result
        assert "account=" in result


@pytest.mark.unit
@pytest.mark.asyncio
class TestMysticalEntityBroadcasts:
    """Test admin-issued System/God wildcard messaging."""

    async def test_entity_privmsg_wildcard_broadcasts_to_all_local_users(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        user1 = make_mock_user("UserOne")
        user2 = make_mock_user("UserTwo")
        service = make_mock_user("SystemSvc")
        service.is_virtual = True

        server.users = {
            admin.nickname: admin,
            user1.nickname: user1,
            user2.nickname: user2,
            service.nickname: service,
        }
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "System", "PRIVMSG * hello everyone")

        user1.send.assert_awaited_once_with(":System!System@test.server.local PRIVMSG * :hello everyone")
        user2.send.assert_awaited_once_with(":System!System@test.server.local PRIVMSG * :hello everyone")
        service.send.assert_not_awaited()

    async def test_entity_notice_wildcard_preserves_full_message(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        user1 = make_mock_user("UserOne")

        server.users = {
            admin.nickname: admin,
            user1.nickname: user1,
        }
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "God", "NOTICE * this is a full notice")

        user1.send.assert_awaited_once_with(":God!God@test.server.local NOTICE * :this is a full notice")

    async def test_entity_wildcard_broadcast_propagates_to_links(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        user1 = make_mock_user("UserOne")
        server.users = {
            admin.nickname: admin,
            user1.nickname: user1,
        }
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "System", "PRIVMSG * hello network")

        expected = ":System!System@test.server.local PRIVMSG * :hello network"
        user1.send.assert_awaited_once_with(expected)
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)

    async def test_entity_channel_notice_only_fans_out_locally_once_and_propagates(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        local_member = make_mock_user("LocalUser")
        remote_member = make_mock_user("RemoteUser")
        remote_member.is_remote = True
        channel = make_mock_channel("#ops", members={
            local_member.nickname: local_member,
            remote_member.nickname: remote_member,
        })
        server.channels = {channel.name: channel}
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "God", "NOTICE #ops attention all")

        expected = ":God!God@test.server.local NOTICE #ops :attention all"
        local_member.send.assert_awaited_once_with(expected)
        remote_member.send.assert_not_awaited()
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)

    async def test_entity_kick_propagates_and_updates_channel_state(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        local_member = make_mock_user("LocalUser")
        target = make_mock_user("Victim")
        remote_member = make_mock_user("RemoteUser")
        remote_member.is_remote = True
        target.channels = {"#ops"}
        channel = make_mock_channel("#ops", members={
            local_member.nickname: local_member,
            target.nickname: target,
            remote_member.nickname: remote_member,
        })
        channel.owners.add(target.nickname)
        channel.hosts.add(target.nickname)
        channel.voices.add(target.nickname)
        channel.gagged.add(target.nickname)
        server.channels = {channel.name: channel}
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "System", "KICK #ops Victim rule breach")

        expected = ":System!System@test.server.local KICK #ops Victim :rule breach"
        local_member.send.assert_awaited_once_with(expected)
        target.send.assert_awaited_once_with(expected)
        remote_member.send.assert_not_awaited()
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)
        assert "Victim" not in channel.members
        assert "#ops" not in target.channels
        assert "Victim" not in channel.owners
        assert "Victim" not in channel.hosts
        assert "Victim" not in channel.voices
        assert "Victim" not in channel.gagged

    async def test_entity_kill_local_user_propagates_to_links(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        target = make_mock_user("Victim")
        target.is_virtual = False
        target.has_mode = lambda m: False
        server.users = {target.nickname: target}
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server.quit_user = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._handle_mystical_entity(admin, "God", "KILL Victim judgment")

        expected = ":God!God@test.server.local KILL Victim :judgment"
        target.send.assert_awaited_once_with(expected)
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)
        server.quit_user.assert_awaited_once_with(target)

    async def test_virtual_service_join_helper_notifies_local_members_and_links_once(self):
        server = make_mock_server()
        local_member = make_mock_user("LocalUser")
        remote_member = make_mock_user("RemoteUser")
        remote_member.is_remote = True
        service = make_mock_user("ServiceBot01")
        service.is_virtual = True
        service.channels = set()
        channel = make_mock_channel("#ops", members={
            local_member.nickname: local_member,
            remote_member.nickname: remote_member,
        })
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()

        await server._join_virtual_service_to_channel(service, channel, "#ops")

        join_msg = ":ServiceBot01!servicebot01@test.host JOIN #ops"
        mode_msg = ":test.server.local MODE #ops +q ServiceBot01"
        local_member.send.assert_any_await(join_msg)
        remote_member.send.assert_not_awaited()
        assert channel.members["ServiceBot01"] is service
        assert "ServiceBot01" in channel.owners
        assert "#ops" in service.channels
        assert server.link_manager.broadcast_to_servers.await_args_list[0].args == (join_msg,)
        assert server.link_manager.broadcast_to_servers.await_args_list[1].args == (mode_msg,)

    async def test_entity_invite_uses_virtual_service_join_helper(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        entity = make_mock_user("System", modes={'S': True})
        entity.is_virtual = True
        entity.channels = set()
        local_member = make_mock_user("LocalUser")
        remote_member = make_mock_user("RemoteUser")
        remote_member.is_remote = True
        channel = make_mock_channel("#ops", members={
            admin.nickname: admin,
            local_member.nickname: local_member,
            remote_member.nickname: remote_member,
        })
        server.users = {"System": entity}
        server.servicebots = {}
        server.get_user = MagicMock(return_value=entity)
        server.get_channel = MagicMock(return_value=(channel, "#ops"))
        server.get_reply = MagicMock(return_value=":test.server.local 341 AdminUser System #ops")
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()

        await server.handle_invite(admin, ["System", "#ops"])

        join_msg = ":System!system@test.host JOIN #ops"
        mode_msg = ":test.server.local MODE #ops +q System"
        local_member.send.assert_any_await(join_msg)
        remote_member.send.assert_not_awaited()
        admin.send.assert_any_await(":test.server.local 341 AdminUser System #ops")
        assert channel.members["System"] is entity
        assert "System" in channel.owners
        assert server.link_manager.broadcast_to_servers.await_args_list[0].args == (join_msg,)
        assert server.link_manager.broadcast_to_servers.await_args_list[1].args == (mode_msg,)


@pytest.mark.unit
@pytest.mark.asyncio
class TestCrossServerServiceRouting:
    async def test_service_target_names_cover_dispatcher_and_configured_bots(self):
        server = make_mock_server()
        targets = server._service_target_names()

        assert "god" in targets
        assert "servicebot" in targets
        assert "servicebot01" in targets

    async def test_dispatch_service_target_handles_servicebot_dispatcher(self):
        server = make_mock_server()
        user = make_mock_user("AdminUser")
        server._handle_servicebot_msg = AsyncMock()

        handled = await server._dispatch_service_target(user, "ServiceBot", "HELP")

        assert handled is True
        server._handle_servicebot_msg.assert_awaited_once_with(user, "HELP", "ServiceBot")

    async def test_linked_wildcard_message_fans_out_to_local_users(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        local_user = make_mock_user("LocalUser")
        local_user_2 = make_mock_user("LocalUser2")
        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        service = make_mock_user("ServiceBot01")
        service.is_virtual = True
        manager.irc_server.users = {
            local_user.nickname: local_user,
            local_user_2.nickname: local_user_2,
            remote_user.nickname: remote_user,
            service.nickname: service,
        }

        upstream = MagicMock()
        upstream.name = "branch1.testnet.local"

        line = ":RemoteUser!remote@test.host NOTICE * :network broadcast"
        await manager.handle_prefixed_message(upstream, line)

        local_user.send.assert_awaited_once_with(line)
        local_user_2.send.assert_awaited_once_with(line)
        remote_user.send.assert_not_awaited()
        service.send.assert_not_awaited()
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_linked_servicebot_message_uses_shared_dispatch(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "trunk"
        manager.broadcast_to_servers = AsyncMock()
        manager.irc_server._service_target_names = MagicMock(return_value={"servicebot01"})
        manager.irc_server._dispatch_service_target = AsyncMock(return_value=True)

        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        remote_user.from_server = "branch1.testnet.local"
        remote_user.server = manager.irc_server
        manager.irc_server.users = {remote_user.nickname: remote_user}

        upstream = MagicMock()
        upstream.name = "branch1.testnet.local"
        upstream.add_user = MagicMock()

        await manager.handle_prefixed_message(
            upstream,
            ":RemoteUser!remote@test.host PRIVMSG ServiceBot01 :HELP"
        )

        manager.irc_server._dispatch_service_target.assert_awaited_once_with(
            remote_user,
            "ServiceBot01",
            "HELP",
        )
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_remote_kill_terminates_local_user_on_owning_server(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()
        manager.irc_server.quit_user = AsyncMock()

        local_target = make_mock_user("Victim")
        manager.irc_server.users = {local_target.nickname: local_target}

        upstream = MagicMock()
        upstream.name = "trunk.testnet.local"

        await manager.handle_prefixed_message(
            upstream,
            ":Oper!oper@test.host KILL Victim :Policy violation"
        )

        local_target.send.assert_awaited_once_with(
            ":test.server.local KILL Victim :Policy violation"
        )
        manager.irc_server.quit_user.assert_awaited_once_with(
            local_target, reason='Killed: Policy violation'
        )

    async def test_messenger_push_propagates_to_linked_servers(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        local_user = make_mock_user("UserOne")
        service = make_mock_user("Messenger")
        service.is_virtual = True

        server.users = {
            admin.nickname: admin,
            local_user.nickname: local_user,
            service.nickname: service,
        }
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._messenger_push(admin, "hello network")

        expected = ":Messenger!Messenger@test.server.local PRIVMSG * :[Global] hello network"
        admin.send.assert_awaited_once_with(expected)
        local_user.send.assert_awaited_once_with(expected)
        service.send.assert_not_awaited()
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)

    async def test_newsflash_push_propagates_to_linked_servers(self):
        server = make_mock_server()
        admin = make_mock_user("AdminUser", modes={'a': True})
        local_user = make_mock_user("UserOne")
        service = make_mock_user("NewsFlash")
        service.is_virtual = True

        server.users = {
            admin.nickname: admin,
            local_user.nickname: local_user,
            service.nickname: service,
        }
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()
        server._send_service_msg = AsyncMock()

        await server._newsflash_push(admin, "urgent bulletin")

        expected = ":NewsFlash!NewsFlash@test.server.local NOTICE * :[NEWS] urgent bulletin"
        admin.send.assert_awaited_once_with(expected)
        local_user.send.assert_awaited_once_with(expected)
        service.send.assert_not_awaited()
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(expected)

    async def test_linked_whisper_uses_case_insensitive_target_lookup(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        target_user = make_mock_user("TargetUser")
        channel = make_mock_channel("#ops", members={target_user.nickname: target_user})
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {target_user.nickname: target_user}
        manager.irc_server.users_lower = {target_user.nickname.lower(): target_user.nickname}

        upstream = MagicMock()
        upstream.name = "trunk.testnet.local"

        line = ":Sender!sender@test.host WHISPER #ops targetuser :quiet hello"
        await manager.handle_prefixed_message(upstream, line)

        target_user.send.assert_awaited_once_with(line)
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_linked_whisper_requires_target_membership(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "trunk"
        manager.broadcast_to_servers = AsyncMock()

        target_user = make_mock_user("TargetUser")
        channel = make_mock_channel("#ops", members={})
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {target_user.nickname: target_user}
        manager.irc_server.users_lower = {target_user.nickname.lower(): target_user.nickname}

        upstream = MagicMock()
        upstream.name = "branch1.testnet.local"

        await manager.handle_prefixed_message(
            upstream,
            ":Sender!sender@test.host WHISPER #ops TargetUser :quiet hello"
        )

        target_user.send.assert_not_awaited()
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_linked_invite_uses_case_insensitive_target_lookup(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        target_user = make_mock_user("TargetUser")
        target_user.invited_to = set()
        manager.irc_server.users = {target_user.nickname: target_user}
        manager.irc_server.users_lower = {target_user.nickname.lower(): target_user.nickname}
        manager.irc_server.channels = {}

        upstream = MagicMock()
        upstream.name = "trunk.testnet.local"

        line = ":Oper!oper@test.host INVITE targetuser :#ops"
        await manager.handle_prefixed_message(upstream, line)

        target_user.send.assert_awaited_once_with(line)
        assert "#ops" in target_user.invited_to
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_linked_invite_notifies_local_invite_notify_members(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        target_user = make_mock_user("TargetUser")
        target_user.invited_to = set()
        watcher = make_mock_user("Watcher", enabled_caps={"invite-notify"})
        inviter = make_mock_user("Oper")
        channel = make_mock_channel("#ops", members={
            inviter.nickname: inviter,
            watcher.nickname: watcher,
        })

        manager.irc_server.users = {
            target_user.nickname: target_user,
            watcher.nickname: watcher,
            inviter.nickname: inviter,
        }
        manager.irc_server.users_lower = {
            target_user.nickname.lower(): target_user.nickname,
            watcher.nickname.lower(): watcher.nickname,
            inviter.nickname.lower(): inviter.nickname,
        }
        manager.irc_server.channels = {channel.name: channel}

        await manager.handle_prefixed_message(
            MagicMock(name="upstream"),
            ":Oper!oper@test.host INVITE TargetUser :#ops"
        )

        watcher.send.assert_awaited_once_with(":Oper!oper@test.host INVITE TargetUser #ops")

    async def test_away_notify_only_targets_local_members(self):
        server = make_mock_server()
        away_user = make_mock_user("AwayUser")
        away_user.away_msg = "busy"
        away_user.channels = {"#ops"}
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"away-notify"})
        remote_watcher = make_mock_user("RemoteWatcher", enabled_caps={"away-notify"})
        remote_watcher.is_remote = True
        channel = make_mock_channel("#ops", members={
            away_user.nickname: away_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        })
        server.channels = {channel.name: channel}
        server.users = {
            away_user.nickname: away_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        }

        await server.send_away_notify(away_user)

        local_watcher.send.assert_awaited_once_with(":AwayUser!awayuser@test.host AWAY :busy")
        remote_watcher.send.assert_not_awaited()

    async def test_linked_away_notifies_local_away_notify_members(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        remote_user.channels = {"#ops"}
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"away-notify"})
        channel = make_mock_channel("#ops", members={
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        })
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        }

        await manager.handle_prefixed_message(
            MagicMock(name="upstream"),
            ":RemoteUser!remote@test.host AWAY :stepped out"
        )

        local_watcher.send.assert_awaited_once_with(":RemoteUser!remoteuser@test.host AWAY :stepped out")
        assert remote_user.away_msg == "stepped out"
        manager.broadcast_to_servers.assert_not_awaited()

    async def test_account_notify_only_targets_local_members(self):
        server = make_mock_server()
        account_user = make_mock_user("AccountUser")
        account_user.sasl_account = "AccountUser"
        account_user.channels = {"#ops"}
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"account-notify"})
        remote_watcher = make_mock_user("RemoteWatcher", enabled_caps={"account-notify"})
        remote_watcher.is_remote = True
        channel = make_mock_channel("#ops", members={
            account_user.nickname: account_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        })
        server.channels = {channel.name: channel}
        server.users = {
            account_user.nickname: account_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        }

        await server.send_account_notify(account_user)

        local_watcher.send.assert_awaited_once_with(":AccountUser!accountuser@test.host ACCOUNT AccountUser")
        remote_watcher.send.assert_not_awaited()

    async def test_chghost_notify_only_targets_local_members(self):
        server = make_mock_server()
        changed_user = make_mock_user("ChangedUser")
        changed_user.username = "newident"
        changed_user.host = "new.host"
        changed_user.channels = {"#ops"}
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"chghost"})
        remote_watcher = make_mock_user("RemoteWatcher", enabled_caps={"chghost"})
        remote_watcher.is_remote = True
        channel = make_mock_channel("#ops", members={
            changed_user.nickname: changed_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        })
        server.channels = {channel.name: channel}
        server.users = {
            changed_user.nickname: changed_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        }

        await server.send_chghost_notify(changed_user, "oldident", "old.host")

        local_watcher.send.assert_awaited_once_with(":ChangedUser!oldident@old.host CHGHOST newident new.host")
        remote_watcher.send.assert_not_awaited()

    async def test_linked_account_notifies_local_account_notify_members(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        remote_user.channels = {"#ops"}
        remote_user.sasl_account = None
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"account-notify"})
        channel = make_mock_channel("#ops", members={
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        })
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        }
        manager.irc_server.users_lower = {remote_user.nickname.lower(): remote_user.nickname}

        await manager.handle_prefixed_message(
            MagicMock(name="upstream"),
            ":RemoteUser!remoteuser@test.host ACCOUNT RemoteUser"
        )

        local_watcher.send.assert_awaited_once_with(":RemoteUser!remoteuser@test.host ACCOUNT RemoteUser")
        assert remote_user.sasl_account == "RemoteUser"

    async def test_linked_chghost_notifies_local_chghost_members(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        remote_user.channels = {"#ops"}
        remote_user.username = "oldident"
        remote_user.host = "old.host"
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"chghost"})
        channel = make_mock_channel("#ops", members={
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        })
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        }
        manager.irc_server.users_lower = {remote_user.nickname.lower(): remote_user.nickname}

        await manager.handle_prefixed_message(
            MagicMock(name="upstream"),
            ":RemoteUser!oldident@old.host CHGHOST newident new.host"
        )

        local_watcher.send.assert_awaited_once_with(":RemoteUser!oldident@old.host CHGHOST newident new.host")
        assert remote_user.username == "newident"
        assert remote_user.host == "new.host"

    async def test_setname_notify_only_targets_local_members(self):
        server = make_mock_server()
        changed_user = make_mock_user("ChangedUser")
        changed_user.realname = "New Realname"
        changed_user.channels = {"#ops"}
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"setname"})
        remote_watcher = make_mock_user("RemoteWatcher", enabled_caps={"setname"})
        remote_watcher.is_remote = True
        channel = make_mock_channel("#ops", members={
            changed_user.nickname: changed_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        })
        server.channels = {channel.name: channel}
        server.users = {
            changed_user.nickname: changed_user,
            local_watcher.nickname: local_watcher,
            remote_watcher.nickname: remote_watcher,
        }

        await server.send_setname_notify(changed_user)

        local_watcher.send.assert_awaited_once_with(":ChangedUser!changeduser@test.host SETNAME :New Realname")
        remote_watcher.send.assert_not_awaited()

    async def test_linked_setname_notifies_local_setname_members(self):
        import linking

        manager = object.__new__(linking.ServerLinkManager)
        manager.irc_server = make_mock_server()
        manager.server_role = "branch"
        manager.broadcast_to_servers = AsyncMock()

        remote_user = make_mock_user("RemoteUser")
        remote_user.is_remote = True
        remote_user.channels = {"#ops"}
        remote_user.realname = "Old Name"
        local_watcher = make_mock_user("LocalWatcher", enabled_caps={"setname"})
        channel = make_mock_channel("#ops", members={
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        })
        manager.irc_server.channels = {channel.name: channel}
        manager.irc_server.users = {
            remote_user.nickname: remote_user,
            local_watcher.nickname: local_watcher,
        }
        manager.irc_server.users_lower = {remote_user.nickname.lower(): remote_user.nickname}

        await manager.handle_prefixed_message(
            MagicMock(name="upstream"),
            ":RemoteUser!remoteuser@test.host SETNAME :Updated Name"
        )

        local_watcher.send.assert_awaited_once_with(":RemoteUser!remoteuser@test.host SETNAME :Updated Name")
        assert remote_user.realname == "Updated Name"


# =============================================================================
# STANDARD REPLIES TESTS
# =============================================================================

@pytest.mark.unit
class TestStandardReplies:
    """Test send_fail, send_warn, send_note formatting"""

    @pytest.fixture
    def server(self):
        return make_mock_server()

    @pytest.fixture
    def user(self):
        return make_mock_user()

    @pytest.mark.asyncio
    async def test_send_fail_no_context(self, server, user):
        await server.send_fail(user, "CHATHISTORY", "NEED_MORE_PARAMS",
                               description="Not enough parameters")
        user.send.assert_called_once()
        msg = user.send.call_args[0][0]
        assert msg == ":test.server.local FAIL CHATHISTORY NEED_MORE_PARAMS :Not enough parameters"

    @pytest.mark.asyncio
    async def test_send_fail_with_context(self, server, user):
        await server.send_fail(user, "CHATHISTORY", "INVALID_TARGET", "#nochan",
                               description="No such channel")
        msg = user.send.call_args[0][0]
        assert msg == ":test.server.local FAIL CHATHISTORY INVALID_TARGET #nochan :No such channel"

    @pytest.mark.asyncio
    async def test_send_warn(self, server, user):
        await server.send_warn(user, "NICK", "DEPRECATED", description="Use SETNAME instead")
        msg = user.send.call_args[0][0]
        assert msg == ":test.server.local WARN NICK DEPRECATED :Use SETNAME instead"

    @pytest.mark.asyncio
    async def test_send_note(self, server, user):
        await server.send_note(user, "CHATHISTORY", "NO_RESULTS",
                               description="No messages found")
        msg = user.send.call_args[0][0]
        assert msg == ":test.server.local NOTE CHATHISTORY NO_RESULTS :No messages found"

    @pytest.mark.asyncio
    async def test_send_fail_multiple_context(self, server, user):
        await server.send_fail(user, "RENAME", "INVALID_PARAMS", "#chan", "extra",
                               description="Bad name")
        msg = user.send.call_args[0][0]
        assert "#chan extra" in msg
        assert ":Bad name" in msg


@pytest.mark.unit
@pytest.mark.asyncio
class TestSaslAuthenticateFlow:
    async def test_sasl_continuation_is_not_rate_limited(self):
        server = make_mock_server()
        user = make_mock_user(enabled_caps={"sasl"})
        user.sasl_mechanism = "PLAIN"
        user.sasl_authenticated = False
        user.sasl_buffer = ""
        user.check_rate_limit = MagicMock(return_value=False)
        server.failed_auth_tracker = MagicMock()
        server.failed_auth_tracker.is_locked_out.return_value = False
        server._process_sasl = AsyncMock()
        server.get_reply = MagicMock(side_effect=lambda code, _user, **kwargs: f"{code}:{kwargs.get('message', '')}")
        server.SASL_MECHANISMS = {"PLAIN"}

        await server.handle_authenticate(user, ["YXV0aHppZABhdXRoY2lkAHBhc3M="])

        user.send.assert_not_awaited()
        server._process_sasl.assert_awaited_once_with(user)

    async def test_sasl_start_is_still_rate_limited(self):
        server = make_mock_server()
        user = make_mock_user(enabled_caps={"sasl"})
        user.sasl_mechanism = None
        user.sasl_authenticated = False
        user.check_rate_limit = MagicMock(return_value=False)
        server.failed_auth_tracker = MagicMock()
        server.failed_auth_tracker.is_locked_out.return_value = False
        server.get_reply = MagicMock(side_effect=lambda code, _user, **kwargs: f"{code}:{kwargs.get('message', '')}")
        server.SASL_MECHANISMS = {"PLAIN"}

        await server.handle_authenticate(user, ["PLAIN"])

        user.send.assert_awaited_once()
        assert user.send.await_args.args[0].startswith("904:")


# =============================================================================
# CHATHISTORY TIMESTAMP PARSING TESTS
# =============================================================================

@pytest.mark.unit
class TestChathistoryTimestampParsing:
    """Test _parse_chathistory_ref and _transcript_timestamp"""

    @pytest.fixture
    def server(self):
        return make_mock_server()

    def test_parse_timestamp_iso8601(self, server):
        ref = "timestamp=2024-01-15T10:30:00.000Z"
        result = server._parse_chathistory_ref(ref)
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30

    def test_parse_timestamp_no_millis(self, server):
        ref = "timestamp=2024-06-01T14:00:00Z"
        result = server._parse_chathistory_ref(ref)
        assert result is not None
        assert result.hour == 14

    def test_parse_star_returns_none(self, server):
        assert server._parse_chathistory_ref('*') is None

    def test_parse_msgid_returns_none(self, server):
        """msgid refs not supported"""
        assert server._parse_chathistory_ref('msgid=abc123') is None

    def test_parse_invalid_timestamp(self, server):
        assert server._parse_chathistory_ref('timestamp=not-a-date') is None

    def test_parse_empty_string(self, server):
        assert server._parse_chathistory_ref('') is None

    def test_transcript_timestamp_valid(self, server):
        line = "[2024-01-15 10:30:00] <nick> hello"
        ts = server._transcript_timestamp(line)
        assert ts is not None
        assert ts.year == 2024
        assert ts.hour == 10

    def test_transcript_timestamp_invalid_format(self, server):
        line = "no timestamp here"
        assert server._transcript_timestamp(line) is None

    def test_transcript_timestamp_bad_date(self, server):
        line = "[not-a-date] <nick> hello"
        assert server._transcript_timestamp(line) is None


# =============================================================================
# TRANSCRIPT TO PRIVMSG CONVERSION TESTS
# =============================================================================

@pytest.mark.unit
class TestTranscriptToPrivmsg:
    """Test _transcript_to_privmsg conversion"""

    @pytest.fixture
    def server(self):
        return make_mock_server()

    def test_privmsg_format(self, server):
        line = "[2024-01-15 10:30:00] <alice> Hello world"
        result = server._transcript_to_privmsg(line, "#test")
        assert result is not None
        assert "PRIVMSG #test :Hello world" in result
        assert ":alice!*@*" in result
        assert "msgid=history-" in result
        assert "time=2024-01-15T10:30:00.000Z" in result

    def test_notice_format(self, server):
        line = "[2024-01-15 10:30:00] -bob- Server notice"
        result = server._transcript_to_privmsg(line, "#test")
        assert result is not None
        assert "NOTICE #test :Server notice" in result
        assert ":bob!*@*" in result

    def test_action_format(self, server):
        line = "[2024-01-15 10:30:00] * charlie dances"
        result = server._transcript_to_privmsg(line, "#test")
        assert result is not None
        assert "PRIVMSG #test :\x01ACTION dances\x01" in result
        assert ":charlie!*@*" in result

    def test_join_part_returns_none(self, server):
        """Non-message lines should return None"""
        line = "[2024-01-15 10:30:00] *** alice has joined #test"
        assert server._transcript_to_privmsg(line, "#test") is None

    def test_no_timestamp_returns_none(self, server):
        assert server._transcript_to_privmsg("not a log line", "#test") is None

    def test_empty_line_returns_none(self, server):
        assert server._transcript_to_privmsg("", "#test") is None

    def test_history_msgid_deterministic(self, server):
        """Same line should produce same history msgid"""
        line = "[2024-01-15 10:30:00] <alice> test"
        r1 = server._transcript_to_privmsg(line, "#test")
        r2 = server._transcript_to_privmsg(line, "#test")
        # Extract msgid from both
        for tag in r1.split(' ')[0][1:].split(';'):
            if tag.startswith('msgid='):
                msgid1 = tag
        for tag in r2.split(' ')[0][1:].split(';'):
            if tag.startswith('msgid='):
                msgid2 = tag
        assert msgid1 == msgid2


# =============================================================================
# CHATHISTORY HANDLER TESTS
# =============================================================================

@pytest.mark.unit
class TestChathistoryHandler:
    """Test handle_chathistory validation logic"""

    @pytest.fixture
    def server(self):
        server = make_mock_server()
        # Mock get_channel
        server.get_channel = MagicMock(return_value=(None, None))
        server.get_transcript = MagicMock(return_value=[])
        server.start_batch = AsyncMock(return_value="batch1")
        server.end_batch = AsyncMock()
        server.send_batched = AsyncMock()
        return server

    @pytest.fixture
    def user(self):
        return make_mock_user()

    @pytest.mark.asyncio
    async def test_no_params_sends_fail(self, server, user):
        await server.handle_chathistory(user, [])
        user.send.assert_called_once()
        msg = user.send.call_args[0][0]
        assert "FAIL CHATHISTORY NEED_MORE_PARAMS" in msg

    @pytest.mark.asyncio
    async def test_too_few_params_sends_fail(self, server, user):
        await server.handle_chathistory(user, ["LATEST", "#chan"])
        msg = user.send.call_args[0][0]
        assert "FAIL CHATHISTORY NEED_MORE_PARAMS" in msg

    @pytest.mark.asyncio
    async def test_invalid_subcommand(self, server, user):
        await server.handle_chathistory(user, ["INVALID", "#chan", "10"])
        msg = user.send.call_args[0][0]
        assert "FAIL CHATHISTORY INVALID_PARAMS" in msg
        assert "Unknown subcommand" in msg

    @pytest.mark.asyncio
    async def test_channel_not_found(self, server, user):
        server.get_channel.return_value = (None, None)
        await server.handle_chathistory(user, ["LATEST", "#nochan", "*", "10"])
        msg = user.send.call_args[0][0]
        assert "FAIL CHATHISTORY INVALID_TARGET" in msg
        assert "No such channel" in msg

    @pytest.mark.asyncio
    async def test_not_member(self, server, user):
        channel = make_mock_channel("#test", modes={'y': True})
        channel.has_member = lambda nick: False
        server.get_channel.return_value = (channel, "#test")
        await server.handle_chathistory(user, ["LATEST", "#test", "*", "10"])
        msg = user.send.call_args[0][0]
        assert "not on that channel" in msg

    @pytest.mark.asyncio
    async def test_no_transcript_mode(self, server, user):
        channel = make_mock_channel("#test", modes={'y': False},
                                    members={"TestUser": user})
        server.get_channel.return_value = (channel, "#test")
        await server.handle_chathistory(user, ["LATEST", "#test", "*", "10"])
        msg = user.send.call_args[0][0]
        assert "history enabled" in msg

    @pytest.mark.asyncio
    async def test_between_too_few_params(self, server, user):
        channel = make_mock_channel("#test", modes={'y': True},
                                    members={"TestUser": user})
        server.get_channel.return_value = (channel, "#test")
        # BETWEEN needs 5 params: subcmd target ts1 ts2 limit
        await server.handle_chathistory(user, ["BETWEEN", "#test", "timestamp=2024-01-01T00:00:00Z", "10"])
        msg = user.send.call_args[0][0]
        assert "BETWEEN requires two timestamps" in msg

    @pytest.mark.asyncio
    async def test_latest_returns_batch(self, server, user):
        channel = make_mock_channel("#test", modes={'y': True},
                                    members={"TestUser": user})
        server.get_channel.return_value = (channel, "#test")
        server.get_transcript.return_value = [
            "[2024-01-15 10:30:00] <alice> hello\n",
            "[2024-01-15 10:31:00] <bob> world\n",
        ]

        # Need to patch CONFIG.get for max_chathistory
        with patch('pyircx.CONFIG') as mock_config:
            mock_config.get = MagicMock(return_value=100)
            await server.handle_chathistory(user, ["LATEST", "#test", "*", "10"])

        server.start_batch.assert_called_once()
        server.end_batch.assert_called_once()
        assert server.send_batched.call_count == 2

    @pytest.mark.asyncio
    async def test_limit_clamped_to_max(self, server, user):
        channel = make_mock_channel("#test", modes={'y': True},
                                    members={"TestUser": user})
        server.get_channel.return_value = (channel, "#test")
        # Return 200 lines
        lines = [f"[2024-01-15 10:{i:02d}:00] <alice> msg{i}\n" for i in range(60)]
        server.get_transcript.return_value = lines

        with patch('pyircx.CONFIG') as mock_config:
            mock_config.get = MagicMock(return_value=50)  # max 50
            await server.handle_chathistory(user, ["LATEST", "#test", "*", "999"])

        # Should only send 50 messages (clamped)
        assert server.send_batched.call_count == 50


@pytest.mark.unit
class TestWhoisLinking:
    @pytest.fixture
    def server(self):
        server = make_mock_server()
        server.start_batch = AsyncMock(return_value="batch1")
        server.end_batch = AsyncMock()
        server.send_batched = AsyncMock()
        server.get_reply = MagicMock(
            side_effect=lambda code, recipient, **kwargs: f"reply {code} {kwargs.get('target', '')}"
        )
        return server

    @pytest.fixture
    def user(self):
        user = make_mock_user(enabled_caps={'batch'})
        user.rate_limiter = MagicMock()
        user.rate_limiter.check.return_value = True
        return user

    @pytest.mark.asyncio
    async def test_remote_whois_miss_waits_for_link_reply(self, server, user):
        server.link_manager = MagicMock()
        server.link_manager.enabled = True
        server.link_manager.broadcast_to_servers = AsyncMock()

        timeout_task = MagicMock()
        def fake_create_task(coro):
            coro.close()
            return timeout_task

        with patch('pyircx.asyncio.create_task', side_effect=fake_create_task):
            await server.handle_whois(user, ["RemoteNick"])

        assert server.send_batched.call_count == 0
        assert server.end_batch.call_count == 0
        assert len(server._pending_remote_whois) == 1

        request_id, pending = next(iter(server._pending_remote_whois.items()))
        assert pending['user'] is user
        assert pending['batch_id'] == "batch1"
        assert pending['target_nick'] == "RemoteNick"
        server.link_manager.broadcast_to_servers.assert_awaited_once_with(
            f"WHOISREQ {request_id} {user.nickname} RemoteNick"
        )

    @pytest.mark.asyncio
    async def test_remote_whois_reply_and_done_close_batch(self, server, user):
        timeout_task = MagicMock()
        server._pending_remote_whois["req123"] = {
            'user': user,
            'batch_id': "batch1",
            'target_nick': "RemoteNick",
            'found': False,
            'timeout_task': timeout_task,
        }

        handled = await server.handle_remote_whois_reply(
            "req123", ":test.server.local 311 TestUser RemoteNick ident host * :Real"
        )
        assert handled is True
        server.send_batched.assert_awaited_once_with(
            user,
            "batch1",
            ":test.server.local 311 TestUser RemoteNick ident host * :Real"
        )

        finished = await server.handle_remote_whois_done("req123", found=True)
        assert finished is True
        timeout_task.cancel.assert_called_once()
        server.end_batch.assert_awaited_once_with(user, "batch1")
        assert "req123" not in server._pending_remote_whois

    @pytest.mark.asyncio
    async def test_remote_whois_done_not_found_sends_401_and_318(self, server, user):
        timeout_task = MagicMock()
        server._pending_remote_whois["req404"] = {
            'user': user,
            'batch_id': "batch1",
            'target_nick': "MissingNick",
            'found': False,
            'timeout_task': timeout_task,
        }

        finished = await server.handle_remote_whois_done("req404", found=False)

        assert finished is True
        timeout_task.cancel.assert_called_once()
        assert server.send_batched.await_args_list[0].args == (
            user, "batch1", "reply 401 MissingNick"
        )
        assert server.send_batched.await_args_list[1].args == (
            user, "batch1", "reply 318 MissingNick"
        )
        server.end_batch.assert_awaited_once_with(user, "batch1")


# =============================================================================
# RENAME HANDLER TESTS
# =============================================================================

@pytest.mark.unit
class TestRenameHandler:
    """Test handle_rename validation logic"""

    @pytest.fixture
    def server(self):
        server = make_mock_server()
        server.get_channel = MagicMock(return_value=(None, None))
        server.get_reply = MagicMock(return_value=":test.server.local 403 TestUser #nochan :No such channel")
        return server

    @pytest.fixture
    def admin_user(self):
        return make_mock_user("Admin", modes={'a': True})

    @pytest.fixture
    def normal_user(self):
        return make_mock_user("NormalUser", modes={})

    @pytest.mark.asyncio
    async def test_requires_high_staff(self, server, normal_user):
        await server.handle_rename(normal_user, ["#old", "#new"])
        normal_user.send.assert_called_once()
        # Should get a permission denied reply
        server.get_reply.assert_called()

    @pytest.mark.asyncio
    async def test_too_few_params(self, server, admin_user):
        await server.handle_rename(admin_user, ["#old"])
        admin_user.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalid_new_channel_name(self, server, admin_user):
        await server.handle_rename(admin_user, ["#old", "notachannel"])
        msg = admin_user.send.call_args[0][0]
        assert "FAIL RENAME INVALID_PARAMS" in msg
        assert "Invalid channel name" in msg

    @pytest.mark.asyncio
    async def test_channel_not_found(self, server, admin_user):
        server.get_channel.return_value = (None, None)
        await server.handle_rename(admin_user, ["#old", "#new"])
        admin_user.send.assert_called()

    @pytest.mark.asyncio
    async def test_new_name_already_exists(self, server, admin_user):
        old_channel = make_mock_channel("#old")
        new_channel = make_mock_channel("#new")
        # First call for old channel, second for checking new name
        server.get_channel.side_effect = [
            (old_channel, "#old"),
            (new_channel, "#new"),
        ]
        await server.handle_rename(admin_user, ["#old", "#new"])
        msg = admin_user.send.call_args[0][0]
        assert "FAIL RENAME CHANNEL_NAME_IN_USE" in msg

    @pytest.mark.asyncio
    async def test_successful_rename(self, server, admin_user):
        member = make_mock_user("Member")
        member.channels = {"#old"}
        old_channel = make_mock_channel("#old", members={"Member": member})
        server.get_channel.side_effect = [
            (old_channel, "#old"),  # Find old channel
            (None, None),           # New name not taken
        ]
        server.channels = {"#old": old_channel}
        server.channels_lower = {"#old": "#old"}

        with patch('pyircx.CONFIG') as mock_config:
            mock_config.get = MagicMock(return_value=50)
            await server.handle_rename(admin_user, ["#old", "#new", "Reorganizing"])

        # Channel dict should be updated
        assert "#new" in server.channels
        assert "#old" not in server.channels
        # Channel object should be updated
        assert old_channel.name == "#new"
        # Member should have new channel in their set
        assert "#new" in member.channels
        assert "#old" not in member.channels
        # Member should be notified
        member.send.assert_called()
        rename_msg = member.send.call_args[0][0]
        assert "RENAME #old #new :Reorganizing" in rename_msg

    @pytest.mark.asyncio
    async def test_name_too_long(self, server, admin_user):
        with patch('pyircx.CONFIG') as mock_config:
            mock_config.get = MagicMock(return_value=10)  # max 10 chars
            await server.handle_rename(admin_user, ["#old", "#verylongchannelname"])
        msg = admin_user.send.call_args[0][0]
        assert "Channel name too long" in msg


# =============================================================================
# LABELED-RESPONSE TESTS (user.py send behavior)
# =============================================================================

@pytest.mark.unit
class TestLabeledResponse:
    """Test labeled-response batch tag injection in user.send()"""

    @pytest.fixture
    def user_obj(self):
        """Create a real User object (not mock) for send() testing"""
        from user import User
        import user as user_module
        original_config = user_module.CONFIG

        mock_config = MagicMock()
        def config_get(*args, default=None):
            # Return appropriate defaults based on config key
            if args == ('modes', 'user'):
                return default or 'abgiorsxz'
            if args == ('security', 'flood_messages'):
                return default or 5
            if args == ('security', 'flood_window'):
                return default or 2.0
            if args == ('limits', 'msg_length'):
                return default or 512
            return default
        mock_config.get = config_get
        user_module.CONFIG = mock_config

        u = User(None, None, is_virtual=True)
        u.nickname = "TestUser"
        u.writer = MagicMock()
        u.writer.write = MagicMock()
        u.writer.drain = AsyncMock()
        u.is_virtual = False  # Override so send() doesn't short-circuit
        u.enabled_caps = set()

        yield u

        user_module.CONFIG = original_config

    @pytest.mark.asyncio
    async def test_no_label_no_modification(self, user_obj):
        """Messages without label should pass through unmodified"""
        user_obj._label = None
        user_obj._label_batch_id = None
        await user_obj.send(":server 001 TestUser :Welcome")
        written = user_obj.writer.write.call_args[0][0].decode()
        assert written.strip() == ":server 001 TestUser :Welcome"

    @pytest.mark.asyncio
    async def test_label_batch_id_prepended(self, user_obj):
        """With _label_batch_id set, messages should get @batch= tag"""
        user_obj._label = "mycommand"
        user_obj._label_batch_id = "abc123"
        user_obj._label_sent = False
        await user_obj.send(":server 001 TestUser :Welcome")
        written = user_obj.writer.write.call_args[0][0].decode()
        assert "@batch=abc123" in written
        assert user_obj._label_sent is True

    @pytest.mark.asyncio
    async def test_label_batch_merged_with_existing_tags(self, user_obj):
        """If message already has tags, batch tag is appended"""
        user_obj._label = "mycommand"
        user_obj._label_batch_id = "xyz"
        user_obj._label_sent = False
        await user_obj.send("@msgid=test1 :server PRIVMSG #chan :hello")
        written = user_obj.writer.write.call_args[0][0].decode()
        assert "@msgid=test1;batch=xyz" in written

    @pytest.mark.asyncio
    async def test_label_sent_tracking(self, user_obj):
        """_label_sent should be set True after first send"""
        user_obj._label = "cmd1"
        user_obj._label_batch_id = None  # No batch, just tracking
        user_obj._label_sent = False
        await user_obj.send(":server NOTICE TestUser :hi")
        assert user_obj._label_sent is True


# =============================================================================
# SUPPORTED_CAPS TESTS
# =============================================================================

@pytest.mark.unit
class TestSupportedCaps:
    """Test that new capabilities are in SUPPORTED_CAPS"""

    @pytest.fixture
    def caps(self):
        import pyircx
        return pyircx.pyIRCXServer.SUPPORTED_CAPS

    def test_account_tag_cap(self, caps):
        assert 'account-tag' in caps

    def test_labeled_response_cap(self, caps):
        assert 'labeled-response' in caps

    def test_standard_replies_cap(self, caps):
        assert 'standard-replies' in caps

    def test_chathistory_cap(self, caps):
        assert 'draft/chathistory' in caps

    def test_message_tags_still_present(self, caps):
        assert 'message-tags' in caps

    def test_batch_still_present(self, caps):
        assert 'batch' in caps


# =============================================================================
# COMMAND HANDLERS ROUTING TESTS
# =============================================================================

@pytest.mark.unit
class TestCommandRouting:
    """Test new commands are properly routed"""

    @pytest.fixture
    def handlers(self):
        import pyircx
        return pyircx.pyIRCXServer.COMMAND_HANDLERS

    def test_chathistory_routed(self, handlers):
        assert handlers.get('CHATHISTORY') == 'handle_chathistory'

    def test_rename_routed(self, handlers):
        assert handlers.get('RENAME') == 'handle_rename'

    def test_command_handlers_exist(self, handlers):
        import pyircx
        missing = []
        for cmd, handler_name in handlers.items():
            if not hasattr(pyircx.pyIRCXServer, handler_name):
                missing.append((cmd, handler_name))
        assert not missing, f"Missing handlers: {missing}"

    def test_command_handlers_signature(self, handlers):
        import inspect
        import pyircx
        bad = []
        for cmd, handler_name in handlers.items():
            fn = getattr(pyircx.pyIRCXServer, handler_name, None)
            if fn is None:
                continue
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            # Expect at least: self, user, params (or varargs/kwargs)
            remaining = params[1:]  # skip self
            positional = [
                p for p in remaining
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            ]
            has_var = any(
                p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in remaining
            )
            if len(positional) < 2 and not has_var:
                bad.append((cmd, handler_name, str(sig)))
        assert not bad, f"Handler signature mismatch: {bad}"


# =============================================================================
# SERVICE BOT +b MODE TESTS
# =============================================================================

@pytest.mark.unit
class TestServiceBotMode:
    """Test that service bots get +b mode"""

    def test_create_virtual_service_sets_bot_mode(self):
        server = make_mock_server()
        import pyircx
        import user as user_module

        def config_get(*args, default=None):
            if args == ('modes', 'user'):
                return default or 'abgiorsxz'
            if args == ('security', 'flood_messages'):
                return default or 5
            if args == ('security', 'flood_window'):
                return default or 2.0
            if args == ('services', 'servicebot_max_channels'):
                return default or 10
            return default

        mock_config = MagicMock()
        mock_config.get = config_get
        original_user_config = user_module.CONFIG
        user_module.CONFIG = mock_config

        try:
            with patch('pyircx.CONFIG', mock_config):
                server._create_virtual_service = pyircx.pyIRCXServer._create_virtual_service.__get__(server)
                server.servicebots = {}
                server._create_virtual_service("TestBot", "bot", "Test Bot")
                bot = server.users.get("TestBot")
                assert bot is not None
                assert bot.has_mode('b') is True
                assert bot.has_mode('s') is True
        finally:
            user_module.CONFIG = original_user_config


# =============================================================================
# HELP TEXT TESTS
# =============================================================================

@pytest.mark.unit
class TestIRCv3HelpTopics:
    """Test help topics for new commands"""

    def test_chathistory_help_exists(self):
        from help_text import get_topic_lines
        found, lines = get_topic_lines("CHATHISTORY")
        assert found is True
        assert any("LATEST" in line for line in lines)

    def test_rename_help_exists(self):
        from help_text import get_topic_lines
        found, lines = get_topic_lines("RENAME", is_staff=True)
        assert found is True
        assert any("RENAME" in line for line in lines)

    def test_rename_staff_only(self):
        from help_text import HELP_TOPICS
        assert HELP_TOPICS["RENAME"].get("staff_only") is True

    def test_tagmsg_help_exists(self):
        from help_text import get_topic_lines
        found, lines = get_topic_lines("TAGMSG")
        assert found is True
        assert any("message-tags" in line for line in lines)

    def test_usermodes_mentions_bot(self):
        from help_text import get_topic_lines
        found, lines = get_topic_lines("USERMODES")
        assert found is True
        assert any("+b" in line for line in lines)

    def test_new_topics_in_valid_topics(self):
        from help_text import VALID_TOPICS
        assert "CHATHISTORY" in VALID_TOPICS
        assert "RENAME" in VALID_TOPICS
        assert "TAGMSG" in VALID_TOPICS
