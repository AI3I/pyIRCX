#!/usr/bin/env python3
"""
Unit tests for validation.py

Tests all validation functions for nicknames, usernames, channels,
messages, passwords, and utility functions.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from validation import (
    validate_nickname,
    validate_username,
    validate_channel_name,
    validate_realname,
    validate_message,
    validate_password,
    validate_staff_level,
    validate_nickname_strict,
    validate_username_strict,
    validate_channel_strict,
    validate_realname_strict,
    validate_message_strict,
    validate_password_strict,
    validate_staff_level_strict,
    validate_reason,
    validate_key,
    validate_raw_command,
    sanitize_ip,
    is_channel,
    is_local_channel,
    is_reserved_service,
    mask_host,
    RESERVED_SERVICES,
)


# =============================================================================
# NICKNAME VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestNicknameValidation:
    """Tests for nickname validation"""

    def test_valid_nicknames(self):
        """Test valid nickname formats"""
        valid_nicks = [
            'John',
            'User123',
            'test_user',
            'Test-User',
            'a',
            'Nick[away]',
            'User{test}',
            'Name\\escaped',
            'Pipe|char',
        ]
        for nick in valid_nicks:
            valid, error = validate_nickname(nick)
            assert valid, f"'{nick}' should be valid, got error: {error}"

    def test_invalid_empty_nickname(self):
        """Test empty nickname is rejected"""
        valid, error = validate_nickname('')
        assert not valid
        assert 'invalid characters' in error

    def test_invalid_nickname_starts_with_digit(self):
        """Test nickname starting with digit is rejected"""
        valid, error = validate_nickname('123user')
        assert not valid
        assert 'invalid characters' in error

    def test_invalid_nickname_with_forbidden_chars(self):
        """Test nicknames with forbidden characters"""
        forbidden = [
            'user name',   # space
            'user.name',   # dot
            'user+name',   # plus
            'user=name',   # equals
            'user#name',   # hash
            'user!name',   # exclamation
            'user@name',   # at
            'user%name',   # percent
            'user&name',   # ampersand
            'user^name',   # caret
            'user$name',   # dollar
            'user~name',   # tilde
            'user:name',   # colon
        ]
        for nick in forbidden:
            valid, error = validate_nickname(nick)
            assert not valid, f"'{nick}' should be invalid"

    def test_invalid_nickname_too_long(self):
        """Test nickname exceeding max length"""
        long_nick = 'a' * 100
        valid, error = validate_nickname(long_nick)
        assert not valid

    def test_invalid_nickname_looks_like_ip(self):
        """Test nickname that looks like IP is rejected"""
        ip_like = ['192.168.1.1', '10.0.0.1', '127.0.0.1']
        for nick in ip_like:
            valid, error = validate_nickname(nick)
            assert not valid, f"'{nick}' should be rejected (looks like IP)"

    def test_reserved_service_names(self):
        """Test reserved service names are rejected"""
        for service in RESERVED_SERVICES:
            valid, error = validate_nickname(service)
            assert not valid, f"'{service}' should be reserved"
            assert 'reserved' in error.lower()

    def test_reserved_service_case_insensitive(self):
        """Test reserved names are case-insensitive"""
        valid, error = validate_nickname('NickServ')
        assert not valid
        valid, error = validate_nickname('SYSTEM')
        assert not valid

    def test_nickname_strict_raises(self):
        """Test strict validation raises ValueError"""
        with pytest.raises(ValueError):
            validate_nickname_strict('')

        with pytest.raises(ValueError):
            validate_nickname_strict('123invalid')

    def test_nickname_strict_returns_value(self):
        """Test strict validation returns valid nickname"""
        result = validate_nickname_strict('ValidNick')
        assert result == 'ValidNick'


# =============================================================================
# USERNAME VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestUsernameValidation:
    """Tests for username validation"""

    def test_valid_usernames(self):
        """Test valid username formats"""
        valid_users = ['john', 'user123', 'test_user', 'a', 'User-Name']
        for user in valid_users:
            valid, error = validate_username(user)
            assert valid, f"'{user}' should be valid"

    def test_invalid_empty_username(self):
        """Test empty username is rejected"""
        valid, error = validate_username('')
        assert not valid

    def test_invalid_username_with_forbidden_chars(self):
        """Test usernames with forbidden characters"""
        forbidden = ['user name', 'user@host', 'user:pass']
        for user in forbidden:
            valid, error = validate_username(user)
            assert not valid, f"'{user}' should be invalid"

    def test_username_strict_raises(self):
        """Test strict validation raises ValueError"""
        with pytest.raises(ValueError):
            validate_username_strict('')

    def test_username_strict_returns_value(self):
        """Test strict validation returns valid username"""
        result = validate_username_strict('validuser')
        assert result == 'validuser'


# =============================================================================
# CHANNEL NAME VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestChannelValidation:
    """Tests for channel name validation"""

    def test_valid_channel_names(self):
        """Test valid channel name formats"""
        valid_channels = [
            '#channel',
            '#Channel123',
            '#test-channel',
            '#test_channel',
            '&local',
            '#a',
        ]
        for chan in valid_channels:
            valid, error = validate_channel_name(chan)
            assert valid, f"'{chan}' should be valid, got: {error}"

    def test_invalid_empty_channel(self):
        """Test empty channel is rejected"""
        valid, error = validate_channel_name('')
        assert not valid

    def test_invalid_channel_no_prefix(self):
        """Test channel without # or & prefix"""
        valid, error = validate_channel_name('channel')
        assert not valid
        assert 'start with' in error.lower()

    def test_invalid_channel_just_prefix(self):
        """Test channel that is just a prefix"""
        valid, error = validate_channel_name('#')
        assert not valid
        valid, error = validate_channel_name('&')
        assert not valid

    def test_invalid_channel_starts_with_digit(self):
        """Test channel name starting with digit after prefix"""
        valid, error = validate_channel_name('#123channel')
        assert not valid

    def test_invalid_channel_with_forbidden_chars(self):
        """Test channels with forbidden characters"""
        forbidden = ['#chan nel', '#chan,nel', '#chan+nel']
        for chan in forbidden:
            valid, error = validate_channel_name(chan)
            assert not valid, f"'{chan}' should be invalid"

    def test_channel_strict_auto_prefix(self):
        """Test strict validation with auto_prefix"""
        result = validate_channel_strict('mychannel', auto_prefix=True)
        assert result == '#mychannel'

    def test_channel_strict_raises(self):
        """Test strict validation raises ValueError"""
        with pytest.raises(ValueError):
            validate_channel_strict('')

    def test_is_channel(self):
        """Test is_channel helper function"""
        assert is_channel('#test')
        assert is_channel('&local')
        assert not is_channel('notchannel')
        assert not is_channel('')

    def test_is_local_channel(self):
        """Test is_local_channel helper function"""
        assert is_local_channel('&local')
        assert not is_local_channel('#global')
        assert not is_local_channel('')


# =============================================================================
# REALNAME VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestRealnameValidation:
    """Tests for realname (GECOS) validation"""

    def test_valid_realnames(self):
        """Test valid realname formats"""
        valid_names = [
            'John Doe',
            'A User',
            'Test User 123',
            'Name with-dashes_and_underscores',
        ]
        for name in valid_names:
            valid, error = validate_realname(name)
            assert valid, f"'{name}' should be valid"

    def test_invalid_empty_realname(self):
        """Test empty realname is rejected"""
        valid, error = validate_realname('')
        assert not valid

    def test_invalid_realname_too_long(self):
        """Test realname exceeding max length"""
        long_name = 'a' * 150
        valid, error = validate_realname(long_name)
        assert not valid

    def test_realname_strips_control_chars(self):
        """Test control characters are handled"""
        # The strict version sanitizes
        result = validate_realname_strict('Test\x00User')
        assert '\x00' not in result


# =============================================================================
# MESSAGE VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestMessageValidation:
    """Tests for message text validation"""

    def test_valid_messages(self):
        """Test valid message formats"""
        valid_msgs = [
            'Hello world',
            'Test message 123',
            'Message with punctuation!?.',
        ]
        for msg in valid_msgs:
            valid, error = validate_message(msg)
            assert valid, f"'{msg}' should be valid"

    def test_invalid_empty_message(self):
        """Test empty message is rejected"""
        valid, error = validate_message('')
        assert not valid

    def test_invalid_message_too_long(self):
        """Test message exceeding max length"""
        long_msg = 'a' * 600
        valid, error = validate_message(long_msg)
        assert not valid

    def test_message_allows_irc_formatting(self):
        """Test IRC formatting codes are allowed"""
        # Bold (0x02), Color (0x03), Reset (0x0F)
        formatted = 'Hello \x02bold\x02 and \x03color'
        valid, error = validate_message(formatted)
        assert valid


# =============================================================================
# PASSWORD VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestPasswordValidation:
    """Tests for password validation"""

    def test_valid_passwords(self):
        """Test valid password formats"""
        valid_passwords = ['password123', 'MyP@ssw0rd!', 'secure-pass_123']
        for pwd in valid_passwords:
            valid, error = validate_password(pwd)
            assert valid, f"'{pwd}' should be valid"

    def test_invalid_empty_password(self):
        """Test empty password is rejected"""
        valid, error = validate_password('')
        assert not valid

    def test_invalid_password_with_spaces(self):
        """Test password with spaces is rejected"""
        valid, error = validate_password('pass word')
        assert not valid
        assert 'space' in error.lower()

    def test_invalid_password_too_long(self):
        """Test password exceeding max length"""
        long_pwd = 'a' * 150
        valid, error = validate_password(long_pwd)
        assert not valid

    def test_password_strict_raises(self):
        """Test strict validation raises ValueError"""
        with pytest.raises(ValueError):
            validate_password_strict('')


# =============================================================================
# STAFF LEVEL VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestStaffLevelValidation:
    """Tests for staff level validation"""

    def test_valid_levels(self):
        """Test valid staff levels"""
        for level in ['ADMIN', 'SYSOP', 'GUIDE', 'USER']:
            valid, error = validate_staff_level(level)
            assert valid, f"'{level}' should be valid"

    def test_invalid_level(self):
        """Test invalid staff level is rejected"""
        valid, error = validate_staff_level('SUPERADMIN')
        assert not valid

    def test_staff_level_strict_raises(self):
        """Test strict validation raises ValueError"""
        with pytest.raises(ValueError):
            validate_staff_level_strict('INVALID')


# =============================================================================
# RAW COMMAND VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
class TestRawCommandValidation:
    """Tests for raw IRC command validation"""

    def test_valid_commands(self):
        """Test valid raw commands"""
        valid_cmds = [
            'PRIVMSG #channel :Hello',
            'JOIN #channel',
            'NICK NewNick',
            'QUIT :Goodbye',
        ]
        for cmd in valid_cmds:
            valid, error = validate_raw_command(cmd)
            assert valid, f"'{cmd}' should be valid"

    def test_invalid_empty_command(self):
        """Test empty command is rejected"""
        valid, error = validate_raw_command('')
        assert not valid

    def test_invalid_command_with_newlines(self):
        """Test commands with newlines are rejected (injection prevention)"""
        valid, error = validate_raw_command('PRIVMSG #test :Hello\r\nQUIT')
        assert not valid

    def test_dangerous_commands_blocked(self):
        """Test dangerous commands are blocked"""
        dangerous = [
            'WEBIRC password gateway host ip',
            'OPER admin password',
            'DIE',
            'RESTART',
            'KILL user :reason',
            'SQUIT server :reason',
            'CONNECT server',
        ]
        for cmd in dangerous:
            valid, error = validate_raw_command(cmd)
            assert not valid, f"'{cmd}' should be blocked"
            assert 'not allowed' in error.lower()


# =============================================================================
# UTILITY FUNCTION TESTS
# =============================================================================

@pytest.mark.unit
class TestUtilityFunctions:
    """Tests for utility validation functions"""

    def test_validate_reason(self):
        """Test reason validation and sanitization"""
        assert validate_reason('Goodbye') == 'Goodbye'
        assert validate_reason('') == ''
        assert validate_reason(None) == ''
        # Long reasons are truncated
        long_reason = 'a' * 300
        result = validate_reason(long_reason)
        assert len(result) <= 200

    def test_validate_key(self):
        """Test channel key validation"""
        assert validate_key('secretkey') == 'secretkey'
        assert validate_key('') == ''
        assert validate_key('key with space') == ''  # spaces not allowed
        assert validate_key(None) == ''

    def test_sanitize_ip_ipv4(self):
        """Test IPv4 address sanitization"""
        assert sanitize_ip('192.168.1.1') == '192.168.1.1'
        assert sanitize_ip('10.0.0.1') == '10.0.0.1'
        assert sanitize_ip('invalid') == '0.0.0.0'
        assert sanitize_ip('') == '0.0.0.0'
        assert sanitize_ip(None) == '0.0.0.0'

    def test_sanitize_ip_ipv6(self):
        """Test IPv6 address sanitization"""
        assert sanitize_ip('::1') == '::1'
        assert sanitize_ip('2001:db8::1') == '2001:db8::1'

    def test_is_reserved_service(self):
        """Test reserved service name detection"""
        assert is_reserved_service('nickserv')
        assert is_reserved_service('NickServ')
        assert is_reserved_service('SYSTEM')
        assert not is_reserved_service('regularuser')


# =============================================================================
# HOST MASKING TESTS
# =============================================================================

@pytest.mark.unit
class TestHostMasking:
    """Tests for host/IP masking function"""

    def test_staff_sees_real_host(self):
        """Test staff viewers see unmasked host"""
        assert mask_host('192.168.1.100', viewer_is_staff=True) == '192.168.1.100'
        assert mask_host('user.example.com', viewer_is_staff=True) == 'user.example.com'

    def test_ipv4_masking(self):
        """Test IPv4 addresses are masked for non-staff"""
        result = mask_host('192.168.1.100', viewer_is_staff=False)
        assert result == '192.168.1.XXX'

    def test_hostname_masking(self):
        """Test hostnames are masked for non-staff"""
        result = mask_host('mypc.example.com', viewer_is_staff=False)
        assert 'example.com' in result
        assert 'mypc' not in result

    def test_single_word_masking(self):
        """Test single word hosts are fully masked"""
        result = mask_host('localhost', viewer_is_staff=False)
        assert 'x' in result.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
