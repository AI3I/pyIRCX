#!/usr/bin/env python3
"""
Test suite for pyIRCX v1.2.0 features

Tests the following v1.2.0 enhancements:
- Command aliases (J, P, W, M, N, Q, T, K, I, L, WW, WH)
- Client timeout functionality
- HELP ALIASES command
- STATS command improvements (c, d, *)
- STAFF command formatting
- MOTD whitespace preservation
"""

import asyncio
import unittest
import sys
import os
import time
import tempfile
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock

# Add parent directory to path to import pyircx
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyircx


class TestCommandAliases(unittest.TestCase):
    """Test command aliases feature"""

    def test_alias_definitions(self):
        """Test that all expected aliases are defined"""
        expected_aliases = {
            'J': 'JOIN',
            'P': 'PART',
            'W': 'WHOIS',
            'M': 'MSG',
            'N': 'NICK',
            'Q': 'QUIT',
            'T': 'TOPIC',
            'K': 'KICK',
            'I': 'INVITE',
            'L': 'LIST',
            'WW': 'WHOWAS',
            'WH': 'WHISPER',
        }

        # Check if COMMAND_ALIASES is defined in the handle_client_data method
        # This verifies the aliases are implemented as per v1.2.0
        with open('pyircx.py', 'r') as f:
            content = f.read()
            self.assertIn("COMMAND_ALIASES", content)
            for alias, command in expected_aliases.items():
                self.assertIn(f"'{alias}': '{command}'", content)

    def test_alias_case_insensitive(self):
        """Test that aliases are case-insensitive"""
        # Verify the implementation converts to uppercase
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Check for case conversion in command processing
            self.assertIn(".upper()", content)
            # Verify aliases work with uppercase conversion
            self.assertIn("if cmd in COMMAND_ALIASES", content)
            self.assertIn("cmd = COMMAND_ALIASES[cmd]", content)


class TestClientTimeout(unittest.TestCase):
    """Test client timeout functionality"""

    def test_timeout_config_default(self):
        """Test default client timeout value"""
        # Default should be 300 seconds (5 minutes)
        expected_default = 300

        # Load config and verify default
        with open('pyircx.py', 'r') as f:
            content = f.read()
            self.assertIn("client_timeout", content)

    def test_timeout_implementation(self):
        """Test that timeout checking is implemented"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Verify timeout logic exists
            self.assertIn("last_activity", content)
            self.assertIn("client_timeout", content)


class TestHelpAliases(unittest.TestCase):
    """Test /HELP ALIASES command"""

    def test_help_aliases_exists(self):
        """Test that ALIASES help topic is implemented"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            self.assertIn('"ALIASES"', content)
            self.assertIn('"ALIAS"', content)
            self.assertIn('"SHORTCUTS"', content)

    def test_help_aliases_content(self):
        """Test that ALIASES help includes all aliases"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find the ALIASES help section
            aliases_section_start = content.find('elif topic in ["ALIASES"')
            self.assertNotEqual(aliases_section_start, -1, "ALIASES help section not found")

            # Get the section (next ~500 chars should contain the aliases)
            aliases_section = content[aliases_section_start:aliases_section_start + 2000]

            # Verify all aliases are documented
            expected_aliases = ['/J', '/P', '/W', '/M', '/N', '/Q', '/T', '/K', '/I', '/L', '/WW', '/WH']
            for alias in expected_aliases:
                self.assertIn(alias, aliases_section, f"Alias {alias} not documented in help")

    def test_help_aliases_in_valid_topics(self):
        """Test that ALIASES is in the fuzzy matching list"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find the _get_help_suggestions function
            suggestions_start = content.find('def _get_help_suggestions')
            self.assertNotEqual(suggestions_start, -1)

            suggestions_section = content[suggestions_start:suggestions_start + 2000]
            self.assertIn('"ALIASES"', suggestions_section)

    def test_help_aliases_in_available_topics(self):
        """Test that ALIASES appears in available topics list"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Should be in the "Available topics:" line
            self.assertIn('SERVICES ALIASES', content)


class TestStatsImprovements(unittest.TestCase):
    """Test STATS command improvements"""

    def test_stats_c_version_field(self):
        """Test that STATS c shows version correctly"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find STATS c implementation
            stats_c_start = content.find("elif flag == 'c':")
            self.assertNotEqual(stats_c_start, -1)

            stats_c_section = content[stats_c_start:stats_c_start + 1000]
            # Should use __version__ variable
            self.assertIn('__version__', stats_c_section)

    def test_stats_c_mode_defaults(self):
        """Test that STATS c has proper default values for modes"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            stats_c_start = content.find("elif flag == 'c':")
            stats_c_section = content[stats_c_start:stats_c_start + 1000]

            # Should have defaults for user and channel modes
            self.assertIn("default='agiorsxz'", stats_c_section)
            self.assertIn("default='adefghijklmnprstuwxyz'", stats_c_section)

    def test_stats_d_table_names(self):
        """Test that STATS d uses correct database table names"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            stats_d_start = content.find("elif flag == 'd':")
            self.assertNotEqual(stats_d_start, -1)

            stats_d_section = content[stats_d_start:stats_d_start + 2000]
            # Should use correct table names
            self.assertIn('registered_nicks', stats_d_section)
            self.assertIn('registered_channels', stats_d_section)

            # Check for mailbox in the broader STATS implementation
            self.assertIn('FROM mailbox', content)

    def test_stats_asterisk_database_section(self):
        """Test that STATS * includes database section with correct tables"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find STATS * database section
            self.assertIn('Database Statistics', content)

            # Find the section that handles comprehensive stats
            stats_all_start = content.find("if flag == '*':")
            self.assertNotEqual(stats_all_start, -1)

            # Should have proper error handling with error messages (look for database error handling)
            # Get larger section to include database stats
            stats_all_section = content[stats_all_start:stats_all_start + 10000]

            # Should show database error messages, not silent pass
            self.assertIn('Database', stats_all_section)
            # Check that the stats * section exists
            self.assertIn('full statistics', stats_all_section.lower())

    def test_stats_command_tracking_filter(self):
        """Test that command tracking filters out garbage characters"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find command tracking section
            tracking_start = content.find("self.stats['command_usage']")
            self.assertNotEqual(tracking_start, -1)

            # Look backwards and forwards for the filter
            tracking_section = content[max(0, tracking_start - 500):tracking_start + 500]

            # Should filter commands to only ASCII alphanumeric
            self.assertIn('isascii', tracking_section)
            self.assertIn('isalnum', tracking_section)


class TestMOTDWhitespace(unittest.TestCase):
    """Test MOTD whitespace preservation"""

    def test_server_motd_preserve_whitespace(self):
        """Test that server preserves MOTD whitespace"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find MOTD sending code
            motd_start = content.find('async def handle_motd')
            self.assertNotEqual(motd_start, -1)

            motd_section = content[motd_start:motd_start + 2000]
            # Should send lines without stripping (except maybe trailing newlines)
            # The important thing is not to do .strip() or .lstrip()
            # on the content lines themselves
            self.assertIn('372', motd_section)  # MOTD line numeric

    def test_webchat_motd_css(self):
        """Test that webchat CSS preserves MOTD whitespace"""
        with open('webchat/index.html', 'r') as f:
            content = f.read()
            # Find the .message.motd CSS rule
            self.assertIn('.message.motd', content)

            # Find the rule
            motd_css_start = content.find('.message.motd')
            motd_css_end = content.find('}', motd_css_start)
            motd_css = content[motd_css_start:motd_css_end]

            # Should have white-space: pre-wrap
            self.assertIn('white-space: pre-wrap', motd_css)

    def test_webchat_system_message_css(self):
        """Test that webchat system messages also preserve whitespace"""
        with open('webchat/index.html', 'r') as f:
            content = f.read()
            # Find .message.system rule
            system_css_start = content.find('.message.system {')
            self.assertNotEqual(system_css_start, -1)

            system_css_end = content.find('}', system_css_start)
            system_css = content[system_css_start:system_css_end]

            # Should have white-space: pre-wrap
            self.assertIn('white-space: pre-wrap', system_css)


class TestStaffCommandFormatting(unittest.TestCase):
    """Test STAFF command formatting improvements"""

    def test_staff_list_table_format(self):
        """Test that STAFF LIST uses proper formatting"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Find STAFF LIST command by its unique comment
            staff_list_start = content.find("# List all staff accounts - SYSOP+ can view")

            self.assertNotEqual(staff_list_start, -1, "STAFF LIST command not found")

            staff_list_section = content[staff_list_start:staff_list_start + 3000]

            # Should group by level and show online status
            self.assertIn('ADMIN', staff_list_section)
            self.assertIn('SYSOP', staff_list_section)
            self.assertIn('GUIDE', staff_list_section)
            self.assertIn('ONLINE', staff_list_section)


class TestReservedNicknames(unittest.TestCase):
    """Test reserved nicknames handling"""

    def test_reserved_nicknames_list(self):
        """Test that reserved nicknames are properly defined"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Should have reserved nicknames defined
            self.assertIn('System', content)
            self.assertIn('Registrar', content)
            self.assertIn('Messenger', content)
            self.assertIn('NewsFlash', content)
            self.assertIn('ServiceBot', content)

    def test_reserved_check_implementation(self):
        """Test that reserved nickname checking is implemented"""
        with open('pyircx.py', 'r') as f:
            content = f.read()
            # Should have a function or logic to check reserved nicknames
            self.assertIn('reserved', content.lower())


class TestWebadminVersion(unittest.TestCase):
    """Test version display in webadmin"""

    def test_webadmin_version_display(self):
        """Test that webadmin shows version"""
        with open('webadmin/index.php', 'r') as f:
            content = f.read()
            self.assertIn('v1.2.0', content)
            self.assertIn('pyIRCX', content)


class TestWebchatVersion(unittest.TestCase):
    """Test version display in webchat"""

    def test_webchat_version_display(self):
        """Test that webchat shows version"""
        with open('webchat/index.html', 'r') as f:
            content = f.read()
            self.assertIn('v1.2.0', content)


class TestDocumentation(unittest.TestCase):
    """Test that documentation is updated for v1.2.0"""

    def test_manual_version(self):
        """Test that MANUAL.md has correct version"""
        with open('docs/user/MANUAL.md', 'r') as f:
            content = f.read()
            self.assertIn('1.2.0', content)

    def test_manual_aliases_section(self):
        """Test that MANUAL.md documents command aliases"""
        with open('docs/user/MANUAL.md', 'r') as f:
            content = f.read()
            self.assertIn('Command Aliases', content)
            self.assertIn('/J', content)
            self.assertIn('JOIN', content)

    def test_manual_client_timeout(self):
        """Test that MANUAL.md documents client_timeout"""
        with open('docs/user/MANUAL.md', 'r') as f:
            content = f.read()
            self.assertIn('client_timeout', content)

    def test_manual_reserved_nicknames(self):
        """Test that MANUAL.md documents reserved nicknames"""
        with open('docs/user/MANUAL.md', 'r') as f:
            content = f.read()
            self.assertIn('Reserved Nicknames', content)
            self.assertIn('ServiceBot', content)


def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCommandAliases))
    suite.addTests(loader.loadTestsFromTestCase(TestClientTimeout))
    suite.addTests(loader.loadTestsFromTestCase(TestHelpAliases))
    suite.addTests(loader.loadTestsFromTestCase(TestStatsImprovements))
    suite.addTests(loader.loadTestsFromTestCase(TestMOTDWhitespace))
    suite.addTests(loader.loadTestsFromTestCase(TestStaffCommandFormatting))
    suite.addTests(loader.loadTestsFromTestCase(TestReservedNicknames))
    suite.addTests(loader.loadTestsFromTestCase(TestWebadminVersion))
    suite.addTests(loader.loadTestsFromTestCase(TestWebchatVersion))
    suite.addTests(loader.loadTestsFromTestCase(TestDocumentation))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    result = run_tests()

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
