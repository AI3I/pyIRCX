#!/usr/bin/env python3
"""
Input Validation for WebChat Gateway
Imports validation logic from centralized validation module
"""

import sys
import os

# Add parent directory to path to import validation module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all validation functions from centralized module
from validation import (
    validate_nickname_strict as validate_nickname,
    validate_username_strict as validate_username,
    validate_realname_strict as validate_realname,
    validate_channel_strict,
    validate_message_strict as validate_message,
    validate_password_strict as validate_password,
    validate_reason,
    validate_key,
    validate_raw_command as _validate_raw_command_tuple,
    sanitize_ip,
    MAX_NICKNAME_LENGTH,
    MAX_USERNAME_LENGTH,
    MAX_REALNAME_LENGTH,
    MAX_CHANNEL_LENGTH,
    MAX_MESSAGE_LENGTH,
    MAX_REASON_LENGTH,
    MAX_PASSWORD_LENGTH
)


def validate_channel(channel):
    """Validate IRC channel name format

    Args:
        channel: Channel name to validate

    Returns:
        str: Validated channel name (with # prefix)

    Raises:
        ValueError: If channel name is invalid
    """
    # Use the strict validator with auto_prefix enabled
    return validate_channel_strict(channel, auto_prefix=True)


def validate_raw_command(command):
    """Validate raw IRC command

    Args:
        command: Raw IRC command string

    Returns:
        str: Validated command

    Raises:
        ValueError: If command is invalid or dangerous
    """
    valid, error = _validate_raw_command_tuple(command)
    if not valid:
        raise ValueError(error)
    return command
