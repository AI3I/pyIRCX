#!/usr/bin/env python3
"""
Unit tests for service_bot.py ServiceBotMonitor class

Tests profanity checking, flood detection, repeat detection,
caps detection, URL spam detection, analyze_message(), and clear_user().
"""

import pytest
import sys
import os
import time
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.fixture
def mock_config():
    """Create a mock CONFIG object for ServiceBotMonitor"""
    config = MagicMock()

    def get_side_effect(*path, default=None):
        config_data = {
            ('servicebot', 'profanity_filter', 'enabled'): True,
            ('servicebot', 'profanity_filter', 'words'): ['badword', 'offensive'],
            ('servicebot', 'profanity_filter', 'patterns'): [r'sp[a@]m'],
            ('servicebot', 'profanity_filter', 'case_sensitive'): False,
            ('servicebot', 'profanity_filter', 'action'): 'warn',
            ('servicebot', 'malicious_detection', 'enabled'): True,
            ('servicebot', 'malicious_detection', 'flood_threshold'): 5,
            ('servicebot', 'malicious_detection', 'flood_window'): 3,
            ('servicebot', 'malicious_detection', 'flood_action'): 'gag',
            ('servicebot', 'malicious_detection', 'repeat_threshold'): 3,
            ('servicebot', 'malicious_detection', 'repeat_window'): 30,
            ('servicebot', 'malicious_detection', 'repeat_action'): 'warn',
            ('servicebot', 'malicious_detection', 'caps_min_length'): 10,
            ('servicebot', 'malicious_detection', 'caps_threshold'): 0.7,
            ('servicebot', 'malicious_detection', 'caps_action'): 'warn',
            ('servicebot', 'malicious_detection', 'url_spam_threshold'): 3,
            ('servicebot', 'malicious_detection', 'url_spam_window'): 10,
            ('servicebot', 'malicious_detection', 'url_spam_action'): 'warn',
        }
        return config_data.get(path, default)

    config.get = get_side_effect
    return config


@pytest.fixture
def monitor(mock_config):
    """Create a ServiceBotMonitor instance with mocked CONFIG"""
    import service_bot
    original_config = service_bot.CONFIG
    service_bot.CONFIG = mock_config

    monitor = service_bot.ServiceBotMonitor()

    yield monitor

    service_bot.CONFIG = original_config


@pytest.fixture
def monitor_no_config():
    """Create a ServiceBotMonitor with CONFIG=None (defaults)"""
    import service_bot
    original_config = service_bot.CONFIG
    service_bot.CONFIG = None

    monitor = service_bot.ServiceBotMonitor()

    yield monitor

    service_bot.CONFIG = original_config


# =============================================================================
# PROFANITY CHECKING TESTS
# =============================================================================

@pytest.mark.unit
class TestProfanityChecking:
    """Tests for check_profanity()"""

    def test_word_match_case_insensitive(self, monitor):
        """Test word match is case-insensitive by default"""
        result, matched = monitor.check_profanity("This contains BADWORD here")
        assert result is True
        assert matched == 'badword'

    def test_word_match_lowercase(self, monitor):
        """Test word match with lowercase input"""
        result, matched = monitor.check_profanity("this has badword in it")
        assert result is True

    def test_word_match_case_sensitive(self, mock_config):
        """Test word match with case_sensitive=True"""
        import service_bot

        def get_case_sensitive(*path, default=None):
            overrides = {
                ('servicebot', 'profanity_filter', 'case_sensitive'): True,
                ('servicebot', 'profanity_filter', 'enabled'): True,
                ('servicebot', 'profanity_filter', 'words'): ['badword'],
                ('servicebot', 'profanity_filter', 'patterns'): [],
                ('servicebot', 'profanity_filter', 'action'): 'warn',
                ('servicebot', 'malicious_detection', 'enabled'): True,
                ('servicebot', 'malicious_detection', 'flood_action'): 'gag',
                ('servicebot', 'malicious_detection', 'repeat_action'): 'warn',
                ('servicebot', 'malicious_detection', 'caps_action'): 'warn',
                ('servicebot', 'malicious_detection', 'url_spam_action'): 'warn',
            }
            return overrides.get(path, default)

        mock_config.get = get_case_sensitive
        original_config = service_bot.CONFIG
        service_bot.CONFIG = mock_config
        try:
            m = service_bot.ServiceBotMonitor()
            # Exact case should match
            result, _ = m.check_profanity("this has badword in it")
            assert result is True
            # Different case should not match
            result, _ = m.check_profanity("this has BADWORD in it")
            assert result is False
        finally:
            service_bot.CONFIG = original_config

    def test_regex_pattern_match(self, monitor):
        """Test regex pattern match"""
        result, matched = monitor.check_profanity("This is sp@m content")
        assert result is True
        assert "pattern:" in matched

    def test_no_match_returns_false_none(self, monitor):
        """Test no match returns (False, None)"""
        result, matched = monitor.check_profanity("This is a clean message")
        assert result is False
        assert matched is None

    def test_disabled_filter_returns_false_none(self, monitor_no_config):
        """Test disabled filter returns (False, None) when config defaults apply"""
        # With CONFIG=None, profanity_words is empty so nothing matches
        result, matched = monitor_no_config.check_profanity("badword here")
        assert result is False
        assert matched is None

    def test_word_boundary_matching(self, monitor):
        """Test word boundary matching (no partial matches)"""
        # "badword" should not match inside "abadwordx" if word boundaries work
        result, _ = monitor.check_profanity("notbadwordy")
        assert result is False

    def test_invalid_regex_patterns_skipped(self, mock_config):
        """Test invalid regex patterns are skipped without error"""
        import service_bot

        def get_invalid_pattern(*path, default=None):
            overrides = {
                ('servicebot', 'profanity_filter', 'enabled'): True,
                ('servicebot', 'profanity_filter', 'words'): [],
                ('servicebot', 'profanity_filter', 'patterns'): ['[invalid(regex', 'valid_pattern'],
                ('servicebot', 'profanity_filter', 'case_sensitive'): False,
                ('servicebot', 'profanity_filter', 'action'): 'warn',
                ('servicebot', 'malicious_detection', 'enabled'): True,
                ('servicebot', 'malicious_detection', 'flood_action'): 'gag',
                ('servicebot', 'malicious_detection', 'repeat_action'): 'warn',
                ('servicebot', 'malicious_detection', 'caps_action'): 'warn',
                ('servicebot', 'malicious_detection', 'url_spam_action'): 'warn',
            }
            return overrides.get(path, default)

        mock_config.get = get_invalid_pattern
        original_config = service_bot.CONFIG
        service_bot.CONFIG = mock_config
        try:
            m = service_bot.ServiceBotMonitor()
            # Should not raise - invalid pattern is skipped
            result, matched = m.check_profanity("contains valid_pattern")
            assert result is True
        finally:
            service_bot.CONFIG = original_config

    def test_cache_invalidation_on_config_change(self, monitor):
        """Test cache invalidation when config signature changes"""
        # First check builds cache
        monitor.check_profanity("test message")
        old_signature = monitor._cache_signature

        # Change the word list (simulates config reload)
        monitor._config_cache['profanity_words'] = ['newbadword']
        monitor._cache_signature = None  # Force rebuild

        monitor.check_profanity("newbadword here")
        assert monitor._cache_signature != old_signature


# =============================================================================
# FLOOD DETECTION TESTS
# =============================================================================

@pytest.mark.unit
class TestFloodDetection:
    """Tests for check_flood()"""

    def test_no_flood_below_threshold(self, monitor):
        """Test no flood when below threshold"""
        for i in range(4):  # threshold is 5
            result = monitor.check_flood("testuser", f"message {i}")
        assert result is False

    def test_flood_triggers_at_threshold(self, monitor):
        """Test flood triggers at threshold"""
        for i in range(4):
            monitor.check_flood("testuser", f"message {i}")
        # 5th message should trigger
        result = monitor.check_flood("testuser", "message 5")
        assert result is True

    def test_window_expiration_clears_history(self, monitor):
        """Test window expiration clears history"""
        # Add messages with old timestamps
        history = monitor._get_user_history("testuser")
        old_time = time.time() - 100  # Well outside window
        for i in range(10):
            history['messages'].append((old_time, f"old message {i}"))

        # New message should not trigger flood (old ones expired)
        result = monitor.check_flood("testuser", "new message")
        assert result is False


# =============================================================================
# REPEAT DETECTION TESTS
# =============================================================================

@pytest.mark.unit
class TestRepeatDetection:
    """Tests for check_repeat()"""

    def test_no_repeat_below_threshold(self, monitor):
        """Test no repeat when below threshold"""
        # Add 2 identical messages (threshold is 3)
        history = monitor._get_user_history("testuser")
        now = time.time()
        history['messages'].append((now, "same message"))
        history['messages'].append((now, "same message"))

        result = monitor.check_repeat("testuser", "same message")
        assert result is False

    def test_repeat_triggers_on_identical_messages(self, monitor):
        """Test repeat triggers on identical messages at threshold"""
        history = monitor._get_user_history("testuser")
        now = time.time()
        history['messages'].append((now, "spam spam"))
        history['messages'].append((now, "spam spam"))
        history['messages'].append((now, "spam spam"))

        result = monitor.check_repeat("testuser", "spam spam")
        assert result is True

    def test_case_insensitive_matching(self, monitor):
        """Test repeat detection is case-insensitive"""
        history = monitor._get_user_history("testuser")
        now = time.time()
        history['messages'].append((now, "SAME MESSAGE"))
        history['messages'].append((now, "same message"))
        history['messages'].append((now, "Same Message"))

        result = monitor.check_repeat("testuser", "same message")
        assert result is True


# =============================================================================
# CAPS DETECTION TESTS
# =============================================================================

@pytest.mark.unit
class TestCapsDetection:
    """Tests for check_caps()"""

    def test_short_messages_ignored(self, monitor):
        """Test short messages (below min_length) are ignored"""
        result = monitor.check_caps("HI THERE")  # Less than 10 alpha chars
        assert result is False

    def test_below_threshold_passes(self, monitor):
        """Test below threshold ratio passes"""
        # Mix of upper and lower, ratio < 0.7
        result = monitor.check_caps("Hello World This Is A Normal Message Here")
        assert result is False

    def test_above_threshold_triggers(self, monitor):
        """Test above threshold ratio triggers"""
        result = monitor.check_caps("THIS IS ALL CAPS AND VERY LONG MESSAGE TEXT")
        assert result is True


# =============================================================================
# URL SPAM DETECTION TESTS
# =============================================================================

@pytest.mark.unit
class TestUrlSpamDetection:
    """Tests for check_url_spam()"""

    def test_no_url_in_message_returns_false(self, monitor):
        """Test no URL in message returns False"""
        result = monitor.check_url_spam("testuser", "This has no links at all")
        assert result is False

    def test_url_below_threshold_passes(self, monitor):
        """Test URL below threshold passes"""
        # First URL message
        result = monitor.check_url_spam("testuser", "Check out https://example.com")
        assert result is False

    def test_url_spam_triggers_at_threshold(self, monitor):
        """Test URL spam triggers at threshold"""
        # Send 3 URL messages (threshold is 3)
        monitor.check_url_spam("spammer", "Visit https://example.com/1")
        monitor.check_url_spam("spammer", "Visit https://example.com/2")
        result = monitor.check_url_spam("spammer", "Visit https://example.com/3")
        assert result is True


# =============================================================================
# analyze_message() TESTS
# =============================================================================

@pytest.mark.unit
class TestAnalyzeMessage:
    """Tests for analyze_message()"""

    def test_returns_empty_list_for_clean_message(self, monitor):
        """Test returns empty list for clean message"""
        violations = monitor.analyze_message("cleanuser", "Hello, how are you today?")
        assert violations == []

    def test_returns_profanity_violation(self, monitor):
        """Test returns profanity violation"""
        violations = monitor.analyze_message("user1", "You are a badword person")
        profanity_violations = [v for v in violations if v[0] == 'profanity']
        assert len(profanity_violations) == 1
        assert profanity_violations[0][1] == 'warn'  # action

    def test_violation_tuples_format(self, monitor):
        """Test violation tuples contain correct (type, action, details)"""
        violations = monitor.analyze_message("user1", "This has badword in it")
        if violations:
            v_type, v_action, v_details = violations[0]
            assert isinstance(v_type, str)
            assert isinstance(v_action, str)
            assert isinstance(v_details, str)


# =============================================================================
# clear_user() TESTS
# =============================================================================

@pytest.mark.unit
class TestClearUser:
    """Tests for clear_user()"""

    def test_removes_user_history(self, monitor):
        """Test removes user history"""
        # Add some history
        monitor._get_user_history("testuser")
        monitor.check_flood("testuser", "message")
        assert "testuser" in monitor.user_history

        # Clear
        monitor.clear_user("testuser")
        assert "testuser" not in monitor.user_history

    def test_clear_nonexistent_user_no_error(self, monitor):
        """Test clearing non-existent user doesn't raise"""
        monitor.clear_user("nonexistent_user_xyz")  # Should not raise


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
