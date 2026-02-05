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
