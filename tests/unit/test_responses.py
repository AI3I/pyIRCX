#!/usr/bin/env python3
"""
Unit tests for responses.py

Tests template dictionaries, format placeholders, forbidden characters,
get_log_message() formatting, and wraps validate_responses.py checks.
"""

import pytest
import sys
import os
import re
import string

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import responses


# =============================================================================
# TEMPLATE LOADING TESTS
# =============================================================================

@pytest.mark.unit
class TestTemplateLoading:
    """Test that all template dictionaries load without error"""

    def test_responses_dict_loads(self):
        """Test RESPONSES dict is populated"""
        assert isinstance(responses.RESPONSES, dict)
        assert len(responses.RESPONSES) > 0

    def test_server_messages_dict_loads(self):
        """Test SERVER_MESSAGES dict is populated"""
        assert isinstance(responses.SERVER_MESSAGES, dict)
        assert len(responses.SERVER_MESSAGES) > 0

    def test_log_messages_dict_loads(self):
        """Test LOG_MESSAGES dict is populated"""
        assert isinstance(responses.LOG_MESSAGES, dict)
        assert len(responses.LOG_MESSAGES) > 0

    def test_easter_egg_jokes_loads(self):
        """Test EASTER_EGG_JOKES is a non-empty list of strings"""
        assert isinstance(responses.EASTER_EGG_JOKES, list)
        assert len(responses.EASTER_EGG_JOKES) > 0
        for joke in responses.EASTER_EGG_JOKES:
            assert isinstance(joke, str)

    def test_service_help_loads(self):
        """Test SERVICE_HELP entries are strings or lists of strings"""
        assert hasattr(responses, 'SERVICE_HELP')
        assert isinstance(responses.SERVICE_HELP, dict)
        assert len(responses.SERVICE_HELP) > 0
        for key, value in responses.SERVICE_HELP.items():
            if isinstance(value, list):
                for item in value:
                    assert isinstance(item, str), f"SERVICE_HELP['{key}'] list item is not a string"
            else:
                assert isinstance(value, str), f"SERVICE_HELP['{key}'] is not a string or list"


# =============================================================================
# FORBIDDEN CHARACTER TESTS
# =============================================================================

@pytest.mark.unit
class TestForbiddenCharacters:
    """Test no forbidden characters in any template"""

    def _check_dict_for_forbidden(self, d, dict_name):
        """Helper to check a dict for forbidden chars"""
        errors = []
        for key, value in d.items():
            strings = value if isinstance(value, list) else [value]
            for i, s in enumerate(strings):
                if not isinstance(s, str):
                    continue
                loc = f"{dict_name}['{key}']" + (f"[{i}]" if isinstance(value, list) else "")
                if '\r' in s:
                    errors.append(f"{loc}: contains \\r")
                if '\n' in s:
                    errors.append(f"{loc}: contains \\n")
                if '\0' in s:
                    errors.append(f"{loc}: contains \\0")
        return errors

    def test_responses_no_forbidden_chars(self):
        """Test RESPONSES has no forbidden characters"""
        errors = self._check_dict_for_forbidden(responses.RESPONSES, "RESPONSES")
        assert errors == [], f"Forbidden chars found: {errors}"

    def test_server_messages_no_forbidden_chars(self):
        """Test SERVER_MESSAGES has no forbidden characters"""
        errors = self._check_dict_for_forbidden(responses.SERVER_MESSAGES, "SERVER_MESSAGES")
        assert errors == [], f"Forbidden chars found: {errors}"

    def test_log_messages_no_forbidden_chars(self):
        """Test LOG_MESSAGES has no forbidden characters"""
        errors = self._check_dict_for_forbidden(responses.LOG_MESSAGES, "LOG_MESSAGES")
        assert errors == [], f"Forbidden chars found: {errors}"

    def test_service_help_no_forbidden_chars(self):
        """Test SERVICE_HELP has no forbidden characters"""
        if hasattr(responses, 'SERVICE_HELP'):
            errors = self._check_dict_for_forbidden(responses.SERVICE_HELP, "SERVICE_HELP")
            assert errors == [], f"Forbidden chars found: {errors}"


# =============================================================================
# FORMAT PLACEHOLDER TESTS
# =============================================================================

PLACEHOLDER_PATTERN = re.compile(r'\{([^{}]+)\}')

# Keys that use literal braces in IRC syntax notation
PLAIN_STRING_KEYS = {'usage_register'}


@pytest.mark.unit
class TestFormatPlaceholders:
    """Test all format placeholders are valid Python identifiers"""

    def _check_placeholders(self, d, dict_name, skip_keys=None):
        """Helper to check placeholders in a dict"""
        skip_keys = skip_keys or set()
        errors = []
        for key, value in d.items():
            if key in skip_keys:
                continue
            strings = value if isinstance(value, list) else [value]
            for i, s in enumerate(strings):
                if not isinstance(s, str):
                    continue
                loc = f"{dict_name}['{key}']" + (f"[{i}]" if isinstance(value, list) else "")
                cleaned = s.replace('{{', '').replace('}}', '')
                for match in PLACEHOLDER_PATTERN.finditer(cleaned):
                    placeholder = match.group(1)
                    name = placeholder.split(':')[0].split('!')[0].strip()
                    if not name:
                        continue
                    if not name.isidentifier():
                        errors.append(f"{loc}: invalid placeholder '{{{placeholder}}}'")
        return errors

    def test_responses_placeholders_valid(self):
        """Test RESPONSES placeholders are valid identifiers"""
        errors = self._check_placeholders(responses.RESPONSES, "RESPONSES")
        assert errors == [], f"Invalid placeholders: {errors}"

    def test_server_messages_placeholders_valid(self):
        """Test SERVER_MESSAGES placeholders are valid identifiers"""
        errors = self._check_placeholders(
            responses.SERVER_MESSAGES, "SERVER_MESSAGES", skip_keys=PLAIN_STRING_KEYS
        )
        assert errors == [], f"Invalid placeholders: {errors}"

    def test_log_messages_placeholders_valid(self):
        """Test LOG_MESSAGES placeholders are valid identifiers"""
        errors = self._check_placeholders(responses.LOG_MESSAGES, "LOG_MESSAGES")
        assert errors == [], f"Invalid placeholders: {errors}"


# =============================================================================
# get_log_message() TESTS
# =============================================================================

@pytest.mark.unit
class TestGetLogMessage:
    """Test get_log_message() formatting"""

    def test_formats_correctly_with_kwargs(self):
        """Test get_log_message() formats correctly with kwargs"""
        # Find a key that has a placeholder
        for key, template in responses.LOG_MESSAGES.items():
            if '{' in template and '{{' not in template:
                # Extract placeholder names
                placeholders = PLACEHOLDER_PATTERN.findall(template)
                if placeholders:
                    kwargs = {p.split(':')[0].split('!')[0]: 'test_value' for p in placeholders}
                    result = responses.get_log_message(key, **kwargs)
                    assert 'test_value' in result
                    assert '{' not in result or '{{' in template
                    return
        # If no suitable template found, test still passes (structural issue)

    def test_returns_key_for_undefined_keys(self):
        """Test get_log_message() returns key name for undefined keys"""
        result = responses.get_log_message("completely_nonexistent_key_xyz")
        assert result == "completely_nonexistent_key_xyz"

    def test_handles_missing_format_key(self):
        """Test get_log_message() handles missing format key gracefully"""
        # Find a key with placeholders and call without kwargs
        for key, template in responses.LOG_MESSAGES.items():
            if '{' in template and '{{' not in template:
                result = responses.get_log_message(key)
                # Should return error message containing key name
                assert key in result
                return


# =============================================================================
# DATA INTEGRITY SMOKE TESTS
# =============================================================================

@pytest.mark.unit
class TestDataIntegrity:
    """Smoke tests for data integrity"""

    def test_responses_key_count_nonzero(self):
        """Test RESPONSES has a reasonable number of keys"""
        assert len(responses.RESPONSES) >= 50

    def test_server_messages_key_count_nonzero(self):
        """Test SERVER_MESSAGES has a reasonable number of keys"""
        assert len(responses.SERVER_MESSAGES) >= 50

    def test_log_messages_key_count_nonzero(self):
        """Test LOG_MESSAGES has a reasonable number of keys"""
        assert len(responses.LOG_MESSAGES) >= 20

    def test_all_responses_keys_are_strings(self):
        """Test all RESPONSES keys are strings"""
        for key in responses.RESPONSES:
            assert isinstance(key, str)

    def test_all_server_messages_values_are_strings_or_lists(self):
        """Test all SERVER_MESSAGES values are strings or lists"""
        for key, value in responses.SERVER_MESSAGES.items():
            assert isinstance(value, (str, list)), \
                f"SERVER_MESSAGES['{key}'] is {type(value)}, expected str or list"


# =============================================================================
# VALIDATE_RESPONSES.PY INTEGRATION
# =============================================================================

@pytest.mark.unit
class TestValidateResponsesIntegration:
    """Wrap validate_responses.py checks as pytest test cases"""

    def test_validate_responses_script_passes(self):
        """Test that validate_responses.py main() returns 0 (pass)"""
        # Import and run the validator
        validator_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'validate_responses.py'
        )
        assert os.path.exists(validator_path), "validate_responses.py not found"

        # Save and restore cwd since validate_responses changes it
        original_cwd = os.getcwd()
        try:
            # Load and execute the module
            import importlib.util
            spec = importlib.util.spec_from_file_location("validate_responses", validator_path)
            validator = importlib.util.module_from_spec(spec)

            # Redirect argv to use --quiet
            original_argv = sys.argv
            sys.argv = ['validate_responses.py', '--quiet']
            try:
                spec.loader.exec_module(validator)
                result = validator.main()
            finally:
                sys.argv = original_argv
        finally:
            os.chdir(original_cwd)

        assert result == 0, "validate_responses.py reported errors"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
