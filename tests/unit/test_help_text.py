#!/usr/bin/env python3
"""
Unit tests for help_text.py

Tests get_topic_lines(), alias resolution, access filtering,
placeholder replacement, and fuzzy matching suggestions.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from help_text import (
    get_topic_lines, get_help_suggestions,
    HELP_TOPICS, TOPIC_ALIASES, VALID_TOPICS
)


# =============================================================================
# BASIC TOPIC RETRIEVAL
# =============================================================================

@pytest.mark.unit
class TestGetTopicLines:
    """Test get_topic_lines() returns lines for known topics"""

    @pytest.mark.parametrize("topic", ["JOIN", "NICK", "MODE", "PART", "TOPIC", "KICK"])
    def test_known_topics_return_lines(self, topic):
        """Test known topics return found=True with non-empty lines"""
        found, lines = get_topic_lines(topic)
        assert found is True
        assert len(lines) > 0

    def test_index_topic(self):
        """Test empty topic returns INDEX"""
        found, lines = get_topic_lines("")
        assert found is True
        assert any("Help Topics" in line for line in lines)

    def test_none_topic_returns_index(self):
        """Test None topic returns INDEX"""
        found, lines = get_topic_lines(None)
        assert found is True

    def test_unknown_topic_returns_not_found(self):
        """Test unknown topic returns found=False and empty lines"""
        found, lines = get_topic_lines("COMPLETELY_INVALID_TOPIC_XYZ")
        assert found is False
        assert lines == []

    def test_case_insensitive(self):
        """Test topic lookup is case-insensitive"""
        found1, lines1 = get_topic_lines("join")
        found2, lines2 = get_topic_lines("JOIN")
        assert found1 is True
        assert found2 is True
        assert lines1 == lines2


# =============================================================================
# ALIAS RESOLUTION
# =============================================================================

@pytest.mark.unit
class TestAliasResolution:
    """Test alias resolution (J->JOIN, MSG->PRIVMSG, 2FA->MFA)"""

    @pytest.mark.parametrize("alias,expected", [
        ("J", "JOIN"),
        ("MSG", "PRIVMSG"),
        ("2FA", "MFA"),
        ("TOTP", "MFA"),
        ("LEAVE", "PART"),
        ("BACK", "AWAY"),
        ("CHANGEPASS", "CHGPASS"),
        ("AUTHENTICATE", "AUTH"),
        ("NICKNAME", "NICK"),
        ("EXIT", "QUIT"),
        ("BYE", "QUIT"),
    ])
    def test_alias_resolves(self, alias, expected):
        """Test alias resolves to the correct topic"""
        found, lines = get_topic_lines(alias, is_staff=True)
        expected_found, expected_lines = get_topic_lines(expected, is_staff=True)
        assert found == expected_found
        assert lines == expected_lines


# =============================================================================
# HELP SUGGESTIONS
# =============================================================================

@pytest.mark.unit
class TestHelpSuggestions:
    """Test get_help_suggestions() fuzzy matching"""

    def test_close_misspelling_returns_suggestions(self):
        """Test close misspellings return suggestions"""
        suggestions = get_help_suggestions("JION")  # close to JOIN
        assert len(suggestions) > 0
        assert "JOIN" in suggestions

    def test_another_misspelling(self):
        """Test another misspelling"""
        suggestions = get_help_suggestions("MOED")  # close to MODE
        assert len(suggestions) > 0
        assert "MODE" in suggestions

    def test_completely_wrong_returns_empty(self):
        """Test completely wrong input returns empty"""
        suggestions = get_help_suggestions("ZZZZZQQQQQ")
        assert suggestions == []


# =============================================================================
# STAFF-ONLY TOPICS
# =============================================================================

@pytest.mark.unit
class TestStaffOnlyTopics:
    """Test staff_only topic access filtering"""

    def test_staff_only_topic_as_non_staff_returns_non_staff_lines(self):
        """Test non-staff gets non_staff_lines for staff_only topics with non_staff_lines"""
        found, lines = get_topic_lines("AUTH", is_staff=False)
        assert found is True
        # Should get the non_staff_lines
        assert any("staff" in line.lower() or "operator" in line.lower() or "guide" in line.lower()
                   for line in lines)

    def test_staff_only_topic_as_staff(self):
        """Test staff gets full lines for staff_only topics"""
        found, lines = get_topic_lines("AUTH", is_staff=True)
        assert found is True
        assert any("AUTH" in line for line in lines)
        # Staff should see more content
        assert len(lines) > 2

    def test_kill_staff_only(self):
        """Test KILL is staff-only"""
        found, lines = get_topic_lines("KILL", is_staff=False)
        assert found is False
        assert lines == []

    def test_kill_as_staff(self):
        """Test KILL accessible to staff"""
        found, lines = get_topic_lines("KILL", is_staff=True)
        assert found is True
        assert len(lines) > 0


# =============================================================================
# ADMIN-ONLY TOPICS
# =============================================================================

@pytest.mark.unit
class TestAdminOnlyTopics:
    """Test admin_only topic access filtering"""

    def test_admin_only_as_non_admin(self):
        """Test non-admin cannot access admin_only topics"""
        found, lines = get_topic_lines("CONNECT", is_staff=True, is_admin=False)
        assert found is False

    def test_admin_only_as_admin(self):
        """Test admin can access admin_only topics"""
        found, lines = get_topic_lines("CONNECT", is_staff=True, is_admin=True)
        assert found is True
        assert len(lines) > 0

    def test_staff_topic_admin_lines(self):
        """Test STAFF topic shows admin_lines only to admins"""
        # Non-admin staff
        found1, lines1 = get_topic_lines("STAFF", is_staff=True, is_admin=False)
        # Admin
        found2, lines2 = get_topic_lines("STAFF", is_staff=True, is_admin=True)
        assert found1 is True
        assert found2 is True
        # Admin should see more lines (admin_lines section)
        assert len(lines2) > len(lines1)


# =============================================================================
# HIGH_STAFF TOPICS
# =============================================================================

@pytest.mark.unit
class TestHighStaffTopics:
    """Test high_staff_only topic access filtering"""

    def test_high_staff_only_as_regular(self):
        """Test high_staff_only topics are hidden from non-high-staff"""
        found, lines = get_topic_lines("PROFANITY", is_staff=True, is_high_staff=False)
        assert found is False

    def test_high_staff_only_as_high_staff(self):
        """Test high_staff_only topics are accessible to high staff"""
        found, lines = get_topic_lines("PROFANITY", is_staff=True, is_high_staff=True)
        assert found is True
        assert len(lines) > 0


# =============================================================================
# PLACEHOLDER REPLACEMENT
# =============================================================================

@pytest.mark.unit
class TestPlaceholderReplacement:
    """Test {nickname} placeholder replacement"""

    def test_nickname_placeholder_replaced(self):
        """Test {nickname} is replaced in output"""
        found, lines = get_topic_lines("MODE", nickname="TestUser")
        assert found is True
        # MODE topic contains {nickname} in examples
        assert any("TestUser" in line for line in lines)
        assert not any("{nickname}" in line for line in lines)

    def test_no_nickname_keeps_placeholder(self):
        """Test without nickname, placeholder stays"""
        found, lines = get_topic_lines("MODE", nickname=None)
        assert found is True
        assert any("{nickname}" in line for line in lines)


# =============================================================================
# DATA STRUCTURE TESTS
# =============================================================================

@pytest.mark.unit
class TestDataStructures:
    """Test VALID_TOPICS and TOPIC_ALIASES structures"""

    def test_valid_topics_populated(self):
        """Test VALID_TOPICS list is populated"""
        assert len(VALID_TOPICS) > 20

    def test_topic_aliases_values_resolve(self):
        """Test TOPIC_ALIASES values all point to valid topics or other aliases"""
        for alias, target in TOPIC_ALIASES.items():
            # Target should be in HELP_TOPICS directly
            assert target in HELP_TOPICS, \
                f"TOPIC_ALIASES['{alias}'] -> '{target}' not found in HELP_TOPICS"

    def test_staff_lines_only_shown_to_staff(self):
        """Test staff_lines are included only when is_staff=True"""
        # INDEX has staff_lines
        _, lines_no_staff = get_topic_lines("INDEX", is_staff=False)
        _, lines_staff = get_topic_lines("INDEX", is_staff=True)
        assert len(lines_staff) > len(lines_no_staff)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
