#!/usr/bin/env python3
"""
Centralized Input Validation for pyIRCX Server
Consolidates validation logic used across pyircx.py, api_helpers.py, and webchat
"""

import re

from responses import SERVER_MESSAGES

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

# ==============================================================================
# CONSTANTS
# ==============================================================================

# Compiled regex patterns for performance (avoid recompiling in hot paths)
_IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
_HOSTNAME_PATTERN = re.compile(r'^[\w-]+\.[\w.-]+$')

# Nickname/username forbidden characters (includes space)
FORBIDDEN_CHARS = set('.+=#!@%&^$~: ')

# Channel name forbidden characters (similar to nicknames but allows # and &)
CHANNEL_FORBIDDEN_CHARS = set('+=#!@%^$~, ')  # Note: & removed to allow local channels
CHANNEL_PREFIXES = ('#', '&')  # # = global, & = local

# Reserved service names - these are virtual aliases pointing to System
RESERVED_SERVICES = {
    'operserv', 'helpserv', 'infoserv', 'nickserv', 'chanserv', 'memoserv',
    'botserv', 'hostserv', 'statserv', 'global', 'alis', 'services',
    'system', 'registrar', 'messenger', 'newsflash'
}

# Maximum lengths (defaults if CONFIG not available)
MAX_NICKNAME_LENGTH = 30
MAX_USERNAME_LENGTH = 30
MAX_REALNAME_LENGTH = 100
MAX_CHANNEL_LENGTH = 50
MAX_MESSAGE_LENGTH = 512
MAX_REASON_LENGTH = 200
MAX_PASSWORD_LENGTH = 100


# ==============================================================================
# CORE VALIDATION FUNCTIONS (tuple return style for pyircx.py)
# ==============================================================================

def validate_nickname(nick: str, check_reserved=True) -> tuple:
    """
    Validate nickname format. Returns (valid, error_message).
    Called in handle_nick BEFORE assignment - blocks sign-on if invalid.

    Args:
        nick: Nickname string to validate
        check_reserved: If True, check against reserved service names

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    max_len = CONFIG.get('limits', 'max_nick_length', default=30) if CONFIG else MAX_NICKNAME_LENGTH

    if not nick or len(nick) > max_len:
        return False, SERVER_MESSAGES['validate_nick_erroneous']
    if nick[0].isdigit():
        return False, SERVER_MESSAGES['validate_nick_erroneous']
    if any(c in FORBIDDEN_CHARS for c in nick):
        return False, SERVER_MESSAGES['validate_nick_erroneous']
    if _looks_like_ip_or_host(nick):
        return False, SERVER_MESSAGES['validate_nick_erroneous']
    # Check reserved service names (can be disabled for internal use)
    if check_reserved and is_reserved_service(nick):
        return False, SERVER_MESSAGES['validate_nick_reserved']
    return True, ""


def validate_username(username: str) -> tuple:
    """
    Validate username format. Returns (valid, error_message).
    Called in handle_user BEFORE assignment - blocks sign-on if invalid.

    Args:
        username: Username string to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    max_len = CONFIG.get('limits', 'max_user_length', default=30) if CONFIG else MAX_USERNAME_LENGTH

    if not username or len(username) > max_len:
        return False, SERVER_MESSAGES['validate_user_invalid']
    if any(c in FORBIDDEN_CHARS for c in username):
        return False, SERVER_MESSAGES['validate_user_invalid']
    if _looks_like_ip_or_host(username):
        return False, SERVER_MESSAGES['validate_user_invalid']
    return True, ""


def validate_channel_name(name: str) -> tuple:
    """
    Validate channel name format. Returns (valid, error_message).
    Called in handle_join BEFORE creating channel.

    Channel types:
    - # (global): Network-wide channels, persisted across restarts
    - & (local): Server-local channels, not persisted

    Args:
        name: Channel name to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    max_len = CONFIG.get('limits', 'max_channel_length', default=50) if CONFIG else MAX_CHANNEL_LENGTH

    if not name:
        return False, SERVER_MESSAGES['validate_chan_no_name']
    if not is_channel(name):
        return False, SERVER_MESSAGES['validate_chan_bad_prefix']
    if len(name) > max_len:
        return False, SERVER_MESSAGES['validate_chan_too_long'].format(max_len=max_len)

    # Check the part after prefix
    channel_part = name[1:]
    if not channel_part:
        return False, SERVER_MESSAGES['validate_chan_just_prefix']
    if channel_part[0].isdigit():
        return False, SERVER_MESSAGES['validate_chan_starts_digit']
    # Check for forbidden chars (excluding the prefix)
    for c in channel_part:
        if c in CHANNEL_FORBIDDEN_CHARS or ord(c) < 32:
            return False, SERVER_MESSAGES['validate_chan_invalid_chars']
    if _looks_like_ip_or_host(channel_part):
        return False, SERVER_MESSAGES['validate_chan_looks_like_host']

    return True, ""


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def _looks_like_ip_or_host(s: str) -> bool:
    """Check if string looks like IP address or hostname (IPv4 or IPv6)"""
    # Also check using ipaddress module for robust IPv6 detection
    if ':' in s:
        try:
            import ipaddress
            ipaddress.ip_address(s)
            return True
        except ValueError:
            pass
    return bool(_IPV4_PATTERN.match(s) or _IPV6_PATTERN.match(s) or _HOSTNAME_PATTERN.match(s))


def is_channel(name: str) -> bool:
    """Check if a name is a channel (starts with # or &)"""
    return bool(name) and name[0] in CHANNEL_PREFIXES


def mask_host(host_or_ip: str, viewer_is_staff: bool) -> str:
    """
    Mask host/IP for privacy. Staff see real host, non-staff see masked.

    IPv4: 192.168.100.45 → 192.168.100.XXX (mask last octet)
    IPv6: 2001:db8:85a3:1234:5678:90ab:cdef:1234 → 2001:db8:85a3:1234:XXXX:XXXX:XXXX:XXXX
    Hostname: user-pc.example.com → xxxxxxx.example.com (mask first component)
    """
    if viewer_is_staff:
        return host_or_ip

    # IPv4: mask last octet
    if _IPV4_PATTERN.match(host_or_ip):
        parts = host_or_ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"

    # IPv6: mask last 4 segments (interface identifier)
    if ':' in host_or_ip:
        try:
            import ipaddress
            ip = ipaddress.ip_address(host_or_ip)
            if isinstance(ip, ipaddress.IPv6Address):
                parts = host_or_ip.split(':')
                # Handle compressed notation (::)
                if '::' in host_or_ip:
                    # Expand it first for simpler handling
                    expanded = ip.exploded
                    parts = expanded.split(':')
                # Keep first 4 segments (network), mask last 4 (interface ID)
                if len(parts) >= 8:
                    return ':'.join(parts[:4]) + ':XXXX:XXXX:XXXX:XXXX'
                elif len(parts) >= 4:
                    return ':'.join(parts[:4]) + ':XXXX:XXXX:XXXX:XXXX'
                else:
                    # Short address, mask what we can
                    return ':'.join(parts[:max(1, len(parts)//2)]) + '::XXXX'
        except (ValueError, ImportError):
            pass

    # Hostname: mask first component with equal number of X's
    if '.' in host_or_ip:
        parts = host_or_ip.split('.')
        first_component = parts[0]
        masked_component = 'x' * len(first_component)
        return masked_component + '.' + '.'.join(parts[1:])

    # Single word hostname or unknown format - mask completely
    return 'x' * len(host_or_ip) if host_or_ip else 'xxxx'


def is_local_channel(name: str) -> bool:
    """Check if a channel is local (starts with &)"""
    return bool(name) and name.startswith('&')


def is_reserved_service(name: str) -> bool:
    """Check if a nickname is a reserved service name"""
    return name.lower() in RESERVED_SERVICES


# ==============================================================================
# ADDITIONAL VALIDATION FUNCTIONS (for webchat and API)
# ==============================================================================

def validate_realname(realname: str) -> tuple:
    """
    Validate IRC realname (GECOS) format. Returns (valid, error_message).

    Args:
        realname: Realname string to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not realname:
        return False, SERVER_MESSAGES['validate_realname_empty']

    if not isinstance(realname, str):
        return False, SERVER_MESSAGES['validate_realname_not_text']

    if len(realname) > MAX_REALNAME_LENGTH:
        return False, SERVER_MESSAGES['validate_realname_too_long'].format(max_len=MAX_REALNAME_LENGTH)

    # Remove control characters except space
    sanitized = re.sub(r'[\x00-\x08\x0B-\x1F\x7F]', '', realname)

    if not sanitized.strip():
        return False, SERVER_MESSAGES['validate_realname_invalid']

    return True, ""


def validate_message(text: str) -> tuple:
    """
    Validate IRC message text. Returns (valid, error_message).

    Args:
        text: Message text to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not text:
        return False, SERVER_MESSAGES['validate_msg_empty']

    if not isinstance(text, str):
        return False, SERVER_MESSAGES['validate_msg_not_text']

    if len(text) > MAX_MESSAGE_LENGTH:
        return False, SERVER_MESSAGES['validate_msg_too_long'].format(max_len=MAX_MESSAGE_LENGTH)

    # Remove control characters except common IRC formatting codes and CTCP
    # Keep: 0x01 (CTCP), 0x02 (bold), 0x03 (color), 0x0F (reset), 0x1D (italic), 0x1F (underline)
    sanitized = re.sub(r'[\x00\x04-\x08\x0B-\x0E\x10-\x1C\x1E\x7F]', '', text)

    if not sanitized.strip():
        return False, SERVER_MESSAGES['validate_msg_invalid']

    return True, ""


def validate_password(password: str) -> tuple:
    """
    Validate IRC server password. Returns (valid, error_message).

    Args:
        password: Password string to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not password:
        return False, SERVER_MESSAGES['validate_pass_empty']

    if not isinstance(password, str):
        return False, SERVER_MESSAGES['validate_pass_not_text']

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, SERVER_MESSAGES['validate_pass_too_long'].format(max_len=MAX_PASSWORD_LENGTH)

    # Passwords can't contain control characters or spaces
    if re.search(r'[\s\x00-\x1F\x7F]', password):
        return False, SERVER_MESSAGES['validate_pass_has_spaces']

    return True, ""


def validate_staff_level(level: str) -> tuple:
    """
    Validate staff privilege level. Returns (valid, error_message).

    Args:
        level: Staff level string

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    valid_levels = ['ADMIN', 'SYSOP', 'GUIDE', 'USER']
    if level not in valid_levels:
        return False, SERVER_MESSAGES['validate_staff_level_invalid'].format(level=level, valid_levels=', '.join(valid_levels))
    return True, ""


# ==============================================================================
# EXCEPTION-RAISING WRAPPERS (for api_helpers and webchat compatibility)
# ==============================================================================

def validate_nickname_strict(nick: str) -> str:
    """
    Validate nickname and raise ValueError if invalid.
    Used by API and webchat that expect exceptions.

    Args:
        nick: Nickname string to validate

    Returns:
        str: Validated nickname

    Raises:
        ValueError: If nickname is invalid
    """
    valid, error = validate_nickname(nick)
    if not valid:
        raise ValueError(error)
    return nick


def validate_username_strict(username: str) -> str:
    """
    Validate username and raise ValueError if invalid.
    Used by API and webchat that expect exceptions.

    Args:
        username: Username string to validate

    Returns:
        str: Validated username

    Raises:
        ValueError: If username is invalid
    """
    valid, error = validate_username(username)
    if not valid:
        raise ValueError(error)
    return username


def validate_channel_strict(channel: str, auto_prefix: bool = False) -> str:
    """
    Validate channel name and raise ValueError if invalid.
    Used by API and webchat that expect exceptions.

    Args:
        channel: Channel name to validate
        auto_prefix: If True, automatically add # prefix if missing

    Returns:
        str: Validated channel name (with prefix)

    Raises:
        ValueError: If channel name is invalid
    """
    # Auto-add # prefix if requested and missing
    if auto_prefix and not channel.startswith(CHANNEL_PREFIXES):
        channel = '#' + channel

    valid, error = validate_channel_name(channel)
    if not valid:
        raise ValueError(error)
    return channel


def validate_realname_strict(realname: str) -> str:
    """
    Validate realname and raise ValueError if invalid.
    Returns sanitized realname with control characters removed.

    Args:
        realname: Realname string to validate

    Returns:
        str: Validated and sanitized realname

    Raises:
        ValueError: If realname is invalid
    """
    valid, error = validate_realname(realname)
    if not valid:
        raise ValueError(error)

    # Return sanitized version
    return re.sub(r'[\x00-\x08\x0B-\x1F\x7F]', '', realname)


def validate_message_strict(text: str) -> str:
    """
    Validate message text and raise ValueError if invalid.
    Returns sanitized message with control characters removed.

    Args:
        text: Message text to validate

    Returns:
        str: Validated and sanitized message

    Raises:
        ValueError: If message is invalid
    """
    valid, error = validate_message(text)
    if not valid:
        raise ValueError(error)

    # Return sanitized version
    return re.sub(r'[\x00\x04-\x08\x0B-\x0E\x10-\x1C\x1E\x7F]', '', text)


def validate_password_strict(password: str) -> str:
    """
    Validate password and raise ValueError if invalid.

    Args:
        password: Password string to validate

    Returns:
        str: Validated password

    Raises:
        ValueError: If password is invalid
    """
    valid, error = validate_password(password)
    if not valid:
        raise ValueError(error)
    return password


def validate_staff_level_strict(level: str) -> None:
    """
    Validate staff level and raise ValueError if invalid.

    Args:
        level: Staff level string

    Raises:
        ValueError: If level is invalid
    """
    valid, error = validate_staff_level(level)
    if not valid:
        raise ValueError(error)


# ==============================================================================
# SANITIZATION FUNCTIONS
# ==============================================================================

def validate_reason(reason: str) -> str:
    """
    Validate quit/part reason text.
    Returns sanitized reason or empty string if invalid (reason is optional).

    Args:
        reason: Reason text to validate

    Returns:
        str: Validated and sanitized reason (or empty string if invalid)
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


def validate_key(key: str) -> str:
    """
    Validate IRC channel key (password).
    Returns validated key or empty string if invalid (key is optional).

    Args:
        key: Channel key to validate

    Returns:
        str: Validated key (or empty string if invalid)
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


def validate_regex_pattern(pattern: str, max_length: int = 200) -> tuple:
    """
    Validate a regex pattern for safety (ReDoS protection).
    Returns (valid, error_message).

    Checks for:
    - Maximum length
    - Basic syntax validity
    - Potentially dangerous patterns (excessive backtracking)

    Args:
        pattern: Regex pattern to validate
        max_length: Maximum allowed pattern length

    Returns:
        tuple: (bool, str) - (is_valid, error_message or None)
    """
    if not pattern:
        return False, SERVER_MESSAGES['validate_pattern_empty']

    if len(pattern) > max_length:
        return False, SERVER_MESSAGES['validate_pattern_too_long'].format(max_len=max_length)

    # Check for basic syntax validity
    try:
        re.compile(pattern)
    except re.error as e:
        return False, SERVER_MESSAGES['validate_pattern_bad_regex'].format(error=e)

    # Check for potentially dangerous patterns that could cause ReDoS
    # These are patterns with nested quantifiers or long repetitions
    dangerous_patterns = [
        r'\(\?[^)]*\+[^)]*\+',  # Nested + quantifiers
        r'\(\?[^)]*\*[^)]*\*',  # Nested * quantifiers
        r'\(\?[^)]*\{[^}]*\}[^)]*\{',  # Nested {} quantifiers
        r'(\.\*){3,}',  # Too many .* in sequence
        r'(\.\+){3,}',  # Too many .+ in sequence
        r'\([^)]*\)\{[0-9]{3,}',  # Large repetition counts
        r'\([^)]*\)\{[0-9]+,[0-9]{4,}\}',  # Very large max repetition
    ]

    for dangerous in dangerous_patterns:
        if re.search(dangerous, pattern, re.IGNORECASE):
            return False, SERVER_MESSAGES['validate_pattern_dangerous']

    # Count quantifiers - too many could be problematic
    quantifier_count = len(re.findall(r'[\*\+\?]|\{[0-9,]+\}', pattern))
    if quantifier_count > 10:
        return False, SERVER_MESSAGES['validate_pattern_too_many_quantifiers']

    # Check for excessive alternation
    alternation_count = pattern.count('|')
    if alternation_count > 20:
        return False, SERVER_MESSAGES['validate_pattern_too_many_alternations']

    return True, None


def validate_raw_command(command: str) -> tuple:
    """
    Validate raw IRC command with dangerous command blocking.
    Returns (valid, error_message).

    Args:
        command: Raw IRC command string

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not command:
        return False, SERVER_MESSAGES['validate_cmd_empty']

    if not isinstance(command, str):
        return False, SERVER_MESSAGES['validate_cmd_not_text']

    command = command.strip()

    if len(command) > MAX_MESSAGE_LENGTH:
        return False, SERVER_MESSAGES['validate_cmd_too_long'].format(max_len=MAX_MESSAGE_LENGTH)

    # Cannot contain newlines or carriage returns (command injection prevention)
    if re.search(r'[\r\n]', command):
        return False, SERVER_MESSAGES['validate_cmd_multiline']

    # Extract command name (first word, case-insensitive)
    cmd_parts = command.split()
    if not cmd_parts:
        return False, SERVER_MESSAGES['validate_cmd_invalid']

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
        return False, SERVER_MESSAGES['validate_cmd_blocked'].format(cmd_name=cmd_name)

    return True, ""


def sanitize_ip(ip: str) -> str:
    """
    Sanitize IP address for logging.
    Returns sanitized IP address or '0.0.0.0' if invalid.

    Args:
        ip: IP address string

    Returns:
        str: Sanitized IP address or '0.0.0.0' if invalid
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
