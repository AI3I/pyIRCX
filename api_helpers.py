#!/usr/bin/env python3
"""
API Helper Functions for pyIRCX
Provides error handling, validation, and IRC command utilities
"""

import functools
import logging
import sqlite3
import socket
import re

logger = logging.getLogger(__name__)


# =============================================================================
# ERROR HANDLING
# =============================================================================

def api_error_handler(func):
    """Decorator for consistent API error handling

    Wraps functions to provide standardized error responses and logging.
    All exceptions are caught and converted to error dictionaries.

    Returns:
        dict: Always includes 'success' key (True/False)
              On error, includes 'error' and 'error_type' keys

    Usage:
        @api_error_handler
        def my_function():
            # ... your code ...
            return {"data": result}  # success=True added automatically
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)

            # Ensure result is a dict
            if not isinstance(result, dict):
                result = {"data": result}

            # Ensure success key exists
            if 'success' not in result:
                result['success'] = True

            return result

        except sqlite3.IntegrityError as e:
            logger.error(f"{func.__name__} IntegrityError: {e}")
            return {
                'success': False,
                'error': f"Database integrity error: {str(e)}",
                'error_type': 'integrity'
            }

        except sqlite3.OperationalError as e:
            logger.error(f"{func.__name__} OperationalError: {e}")
            return {
                'success': False,
                'error': f"Database operational error: {str(e)}",
                'error_type': 'operational'
            }

        except ValueError as e:
            logger.error(f"{func.__name__} ValueError: {e}")
            return {
                'success': False,
                'error': str(e),
                'error_type': 'validation'
            }

        except socket.timeout:
            logger.error(f"{func.__name__} socket timeout")
            return {
                'success': False,
                'error': 'Connection timeout',
                'error_type': 'timeout'
            }

        except ConnectionRefusedError:
            logger.error(f"{func.__name__} connection refused")
            return {
                'success': False,
                'error': 'Connection refused - server may not be running',
                'error_type': 'connection'
            }

        except Exception as e:
            logger.error(f"{func.__name__} error: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'error_type': 'unknown'
            }

    return wrapper


# =============================================================================
# INPUT VALIDATION
# =============================================================================

def validate_access_type(access_type):
    """Validate ACCESS command type

    Args:
        access_type: String like 'GRANT', 'DENY', 'OWNER', 'HOST', 'VOICE'

    Raises:
        ValueError: If access_type is invalid
    """
    valid_types = ['GRANT', 'DENY', 'OWNER', 'HOST', 'VOICE']
    if access_type not in valid_types:
        raise ValueError(
            f"Invalid access_type: '{access_type}'. "
            f"Must be one of: {', '.join(valid_types)}"
        )


def validate_pattern(pattern, min_length=1, max_length=255):
    """Validate hostmask/nickname pattern

    Args:
        pattern: Pattern string (e.g., "nick!*@*.com")
        min_length: Minimum allowed length
        max_length: Maximum allowed length

    Raises:
        ValueError: If pattern is invalid
    """
    if not pattern:
        raise ValueError("Pattern cannot be empty")

    if not isinstance(pattern, str):
        raise ValueError("Pattern must be a string")

    if len(pattern) < min_length:
        raise ValueError(f"Pattern must be at least {min_length} characters")

    if len(pattern) > max_length:
        raise ValueError(f"Pattern must not exceed {max_length} characters")


def validate_timeout(timeout):
    """Validate timeout value

    Args:
        timeout: Timeout in seconds (integer)

    Raises:
        ValueError: If timeout is invalid
    """
    if not isinstance(timeout, int):
        raise ValueError("Timeout must be an integer")

    if timeout < 0:
        raise ValueError("Timeout cannot be negative")


def validate_nickname(nickname):
    """Validate IRC nickname

    Args:
        nickname: IRC nickname string

    Raises:
        ValueError: If nickname is invalid
    """
    if not nickname:
        raise ValueError("Nickname cannot be empty")

    if not isinstance(nickname, str):
        raise ValueError("Nickname must be a string")

    if len(nickname) > 30:
        raise ValueError("Nickname must not exceed 30 characters")

    # IRC nickname rules: must start with letter, can contain letters, numbers, -, [, ], \, `, ^, {, }, |
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9\-\[\]\\`^{}|]*$', nickname):
        raise ValueError(
            "Invalid nickname format. Must start with a letter and "
            "contain only letters, numbers, and: - [ ] \\ ` ^ { } |"
        )


def validate_channel_name(channel):
    """Validate IRC channel name

    Args:
        channel: Channel name (with or without # prefix)

    Returns:
        str: Normalized channel name (with # prefix)

    Raises:
        ValueError: If channel name is invalid
    """
    if not channel:
        raise ValueError("Channel name cannot be empty")

    if not isinstance(channel, str):
        raise ValueError("Channel name must be a string")

    # Add # if not present
    if not channel.startswith('#'):
        channel = '#' + channel

    if len(channel) > 50:
        raise ValueError("Channel name must not exceed 50 characters")

    # Channel names can't contain spaces, commas, or control characters
    if re.search(r'[\s,\x00-\x1F]', channel):
        raise ValueError("Channel name contains invalid characters")

    return channel


def validate_staff_level(level):
    """Validate staff privilege level

    Args:
        level: Staff level string

    Raises:
        ValueError: If level is invalid
    """
    valid_levels = ['ADMIN', 'SYSOP', 'GUIDE', 'USER']
    if level not in valid_levels:
        raise ValueError(
            f"Invalid staff level: '{level}'. "
            f"Must be one of: {', '.join(valid_levels)}"
        )


# =============================================================================
# IRC COMMAND SENDER
# =============================================================================

def send_irc_command(command, description="IRC command", server_status_func=None):
    """Send a raw IRC command to the server

    Unified helper for sending IRC commands via socket connection.
    Handles connection, error handling, and response retrieval.

    Args:
        command: IRC command string (e.g., "KILL User :reason")
        description: Human-readable description for logging
        server_status_func: Function that returns server status dict
                           If None, attempts local connection to 127.0.0.1:6667

    Returns:
        dict: {
            'success': bool,
            'response': str,  # IRC server response
            'error': str      # Error message if success=False
        }

    Example:
        result = send_irc_command("KILL BadUser :Banned", "Kill user")
        if result['success']:
            print(f"Command sent: {result['response']}")
        else:
            print(f"Error: {result['error']}")
    """
    try:
        # Determine server connection details
        if server_status_func:
            status = server_status_func()
            if not status.get('running'):
                return {
                    'success': False,
                    'error': 'IRC server not running',
                    'response': ''
                }
            host = status.get('host', '127.0.0.1')
            port = status.get('port', 6667)
        else:
            # Default connection
            host = '127.0.0.1'
            port = 6667

        # Create and configure socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        # Connect to IRC server
        sock.connect((host, port))
        logger.debug(f"Connected to IRC server {host}:{port}")

        # Send command
        command_bytes = f"{command}\r\n".encode('utf-8')
        sock.send(command_bytes)
        logger.info(f"{description}: {command}")

        # Receive response
        response = sock.recv(4096).decode('utf-8', errors='ignore')

        # Clean up
        sock.close()

        return {
            'success': True,
            'response': response.strip(),
            'error': ''
        }

    except socket.timeout:
        logger.error(f"{description} - socket timeout")
        return {
            'success': False,
            'error': 'Connection timeout',
            'response': ''
        }

    except ConnectionRefusedError:
        logger.error(f"{description} - connection refused")
        return {
            'success': False,
            'error': 'Connection refused - server may not be running',
            'response': ''
        }

    except Exception as e:
        logger.error(f"{description} error: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'response': ''
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def dict_factory(cursor, row):
    """Convert database row to dictionary

    Args:
        cursor: sqlite3 cursor
        row: Database row tuple

    Returns:
        dict: Row as dictionary with column names as keys
    """
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def sanitize_sql_pattern(pattern):
    """Sanitize a pattern for SQL LIKE queries

    Args:
        pattern: Pattern string that may contain SQL wildcards

    Returns:
        str: Sanitized pattern safe for SQL LIKE
    """
    # Escape SQL LIKE wildcards
    pattern = pattern.replace('%', '\\%')
    pattern = pattern.replace('_', '\\_')
    return pattern
