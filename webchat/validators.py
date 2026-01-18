#!/usr/bin/env python3
"""
Input Validation for WebChat Gateway
Validates all user inputs to prevent injection attacks and ensure data integrity
"""

import re


# =============================================================================
# CONSTANTS
# =============================================================================

MAX_NICKNAME_LENGTH = 30
MAX_USERNAME_LENGTH = 30
MAX_REALNAME_LENGTH = 100
MAX_CHANNEL_LENGTH = 50
MAX_MESSAGE_LENGTH = 512
MAX_REASON_LENGTH = 200
MAX_PASSWORD_LENGTH = 100


# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

def validate_nickname(nick):
    """Validate IRC nickname format

    Args:
        nick: Nickname string to validate

    Returns:
        str: Validated nickname

    Raises:
        ValueError: If nickname is invalid

    Rules:
        - Must be 1-30 characters
        - Must start with a letter
        - Can contain: letters, numbers, -, [, ], \\, `, ^, {, }, |
    """
    if not nick:
        raise ValueError("Please provide a nickname")

    if not isinstance(nick, str):
        raise ValueError("Nickname must be text")

    if len(nick) > MAX_NICKNAME_LENGTH:
        raise ValueError(f"Nickname is too long - please use {MAX_NICKNAME_LENGTH} characters or less")

    # IRC nickname rules: must start with letter, can contain letters, numbers, -, _, [, ], \, `, ^, {, }, |
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_\-\[\]\\`^{}|]*$', nick):
        raise ValueError(
            "Nickname must start with a letter and contain only letters, numbers, "
            "and special characters: - _ [ ] \\ ` ^ { } |"
        )

    return nick


def validate_username(username):
    """Validate IRC username format

    Args:
        username: Username string to validate

    Returns:
        str: Validated username

    Raises:
        ValueError: If username is invalid

    Rules:
        - Must be 1-30 characters
        - Can contain: letters, numbers, -, _, .
        - Cannot contain spaces or special characters
    """
    if not username:
        raise ValueError("Please provide a username")

    if not isinstance(username, str):
        raise ValueError("Username must be text")

    if len(username) > MAX_USERNAME_LENGTH:
        raise ValueError(f"Username is too long - please use {MAX_USERNAME_LENGTH} characters or less")

    # Username rules: alphanumeric plus - _ .
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', username):
        raise ValueError(
            "Username can only contain letters, numbers, hyphens, underscores, and periods"
        )

    return username


def validate_realname(realname):
    """Validate IRC realname (GECOS) format

    Args:
        realname: Realname string to validate

    Returns:
        str: Validated and sanitized realname

    Raises:
        ValueError: If realname is invalid

    Rules:
        - Must be 1-100 characters
        - Control characters removed
        - Cannot contain newlines
    """
    if not realname:
        raise ValueError("Please provide your real name")

    if not isinstance(realname, str):
        raise ValueError("Real name must be text")

    if len(realname) > MAX_REALNAME_LENGTH:
        raise ValueError(f"Real name is too long - please use {MAX_REALNAME_LENGTH} characters or less")

    # Remove control characters except space
    realname = re.sub(r'[\x00-\x08\x0B-\x1F\x7F]', '', realname)

    if not realname.strip():
        raise ValueError("Please provide a valid real name")

    return realname


def validate_channel(channel):
    """Validate IRC channel name format

    Args:
        channel: Channel name to validate

    Returns:
        str: Validated channel name (with # prefix)

    Raises:
        ValueError: If channel name is invalid

    Rules:
        - Must be 2-50 characters (including #)
        - Must start with #
        - Cannot contain: spaces, commas, control characters
    """
    if not channel:
        raise ValueError("Please provide a channel name")

    if not isinstance(channel, str):
        raise ValueError("Channel name must be text")

    # Add # if not present
    if not channel.startswith('#'):
        channel = '#' + channel

    if len(channel) > MAX_CHANNEL_LENGTH:
        raise ValueError(f"Channel name is too long - please use {MAX_CHANNEL_LENGTH} characters or less")

    if len(channel) < 2:
        raise ValueError("Channel name is too short - please use at least 1 character after the #")

    # Channel names can't contain spaces, commas, or control characters
    if re.search(r'[\s,\x00-\x1F\x7F]', channel):
        raise ValueError("Channel names cannot contain spaces or commas - please use hyphens or underscores instead")

    return channel


def validate_message(text):
    """Validate and sanitize IRC message text

    Args:
        text: Message text to validate

    Returns:
        str: Validated and sanitized message

    Raises:
        ValueError: If message is invalid

    Rules:
        - Must be 1-512 characters (IRC spec limit)
        - Control characters removed (except formatting codes)
        - Cannot be empty after sanitization
    """
    if not text:
        raise ValueError("Please provide a message to send")

    if not isinstance(text, str):
        raise ValueError("Message must be text")

    if len(text) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message is too long - please keep it under {MAX_MESSAGE_LENGTH} characters")

    # Remove control characters except common IRC formatting codes
    # Keep: 0x02 (bold), 0x03 (color), 0x0F (reset), 0x1D (italic), 0x1F (underline)
    text = re.sub(r'[\x00-\x01\x04-\x08\x0B-\x0E\x10-\x1C\x1E\x7F]', '', text)

    if not text.strip():
        raise ValueError("Please provide a valid message")

    return text


def validate_reason(reason):
    """Validate quit/part reason text

    Args:
        reason: Reason text to validate

    Returns:
        str: Validated and sanitized reason (or empty string if invalid)

    Rules:
        - Maximum 200 characters
        - Control characters removed
        - Returns empty string if validation fails (reason is optional)
    """
    if not reason:
        return ""

    if not isinstance(reason, str):
        return ""

    if len(reason) > MAX_REASON_LENGTH:
        reason = reason[:MAX_REASON_LENGTH]

    # Remove control characters
    reason = re.sub(r'[\x00-\x08\x0B-\x1F\x7F]', '', reason)

    return reason.strip()


def validate_password(password):
    """Validate IRC server password

    Args:
        password: Password string to validate

    Returns:
        str: Validated password

    Raises:
        ValueError: If password is invalid

    Rules:
        - Must be 1-100 characters
        - Cannot contain control characters or spaces
    """
    if not password:
        raise ValueError("Please provide a password")

    if not isinstance(password, str):
        raise ValueError("Password must be text")

    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password is too long - please use {MAX_PASSWORD_LENGTH} characters or less")

    # Passwords can't contain control characters or spaces
    if re.search(r'[\s\x00-\x1F\x7F]', password):
        raise ValueError("Password cannot contain spaces - please use a password without spaces")

    return password


def validate_key(key):
    """Validate IRC channel key (password)

    Args:
        key: Channel key to validate

    Returns:
        str: Validated key (or empty string if invalid)

    Rules:
        - Maximum 50 characters
        - Cannot contain spaces or control characters
        - Returns empty string if validation fails (key is optional)
    """
    if not key:
        return ""

    if not isinstance(key, str):
        return ""

    if len(key) > 50:
        return ""

    # Keys can't contain spaces or control characters
    if re.search(r'[\s\x00-\x1F\x7F]', key):
        return ""

    return key


def validate_raw_command(command):
    """Validate raw IRC command

    Args:
        command: Raw IRC command string

    Returns:
        str: Validated command

    Raises:
        ValueError: If command is invalid or dangerous

    Rules:
        - Must be 1-512 characters
        - Cannot contain newlines or carriage returns
        - Certain dangerous commands are blocked

    Security:
        This function blocks dangerous commands that could be used maliciously.
        Only basic IRC commands are allowed through raw command interface.
    """
    if not command:
        raise ValueError("Please provide a command")

    if not isinstance(command, str):
        raise ValueError("Command must be text")

    command = command.strip()

    if len(command) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"Command is too long - please keep it under {MAX_MESSAGE_LENGTH} characters")

    # Cannot contain newlines or carriage returns (command injection prevention)
    if re.search(r'[\r\n]', command):
        raise ValueError("Invalid command - please use a single-line command")

    # Extract command name (first word, case-insensitive)
    cmd_parts = command.split()
    if not cmd_parts:
        raise ValueError("Please provide a valid command")

    cmd_name = cmd_parts[0].upper()

    # Block dangerous commands that should not be sent via raw interface
    dangerous_commands = [
        'WEBIRC',  # Should only be sent by gateway
        'OPER',    # Server operator commands
        'DIE',     # Server shutdown
        'RESTART', # Server restart
        'KILL',    # Kill user (admin only)
        'SQUIT',   # Server disconnect
        'CONNECT', # Server linking
    ]

    if cmd_name in dangerous_commands:
        raise ValueError(f"Command '{cmd_name}' is not allowed via raw interface")

    return command


def sanitize_ip(ip):
    """Sanitize IP address for logging

    Args:
        ip: IP address string

    Returns:
        str: Sanitized IP address or '0.0.0.0' if invalid

    Rules:
        - Must match IPv4 or IPv6 format
        - Returns '0.0.0.0' for invalid IPs
    """
    if not ip or not isinstance(ip, str):
        return '0.0.0.0'

    # IPv4 format
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 format (simplified - matches most valid IPv6 addresses)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

    if re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip):
        return ip

    return '0.0.0.0'
