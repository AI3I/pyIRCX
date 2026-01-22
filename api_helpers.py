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
import time
from collections import defaultdict
from datetime import datetime, timedelta

from responses import get_log_message

logger = logging.getLogger(__name__)


# =============================================================================
# RATE LIMITING
# =============================================================================

# Global rate limit storage
_rate_limits = defaultdict(list)

def rate_limit(calls_per_minute=10):
    """Decorator to rate limit function calls

    Prevents brute force attacks by limiting the number of calls per minute
    for a given function and username combination.

    Args:
        calls_per_minute: Maximum number of calls allowed per minute (default: 10)

    Usage:
        @rate_limit(calls_per_minute=5)
        @api_error_handler
        def test_staff_login(username, password):
            # ... function code ...

    Returns:
        Wrapped function that enforces rate limiting

    Raises:
        ValueError: If rate limit is exceeded
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create a unique key based on function name and first argument (usually username)
            key = f"{func.__name__}:{args[0] if args else 'global'}"
            now = datetime.now()
            minute_ago = now - timedelta(minutes=1)

            # Clean old entries (older than 1 minute)
            _rate_limits[key] = [ts for ts in _rate_limits[key] if ts > minute_ago]

            # Check if rate limit exceeded
            if len(_rate_limits[key]) >= calls_per_minute:
                logger.warning(get_log_message("rate_limit_exceeded", key=key))
                raise ValueError(f"Too many attempts - please try again in a moment")

            # Record this call
            _rate_limits[key].append(now)

            return func(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# CACHING
# =============================================================================

def timed_cache(seconds=60):
    """Decorator to cache function results for a specified duration

    Reduces disk I/O for frequently called read-only functions by caching
    their results for a specified number of seconds.

    Args:
        seconds: Cache duration in seconds (default: 60)

    Usage:
        @timed_cache(seconds=60)
        @api_error_handler
        def get_server_config():
            # ... function code ...

    Returns:
        Wrapped function that caches results

    Note:
        - Only use for read-only functions that return the same data
        - Cache is cleared after the specified duration
        - Different arguments create separate cache entries
    """
    def decorator(func):
        cache = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function args
            cache_key = (args, tuple(sorted(kwargs.items())))
            now = time.time()

            # Check if cached result exists and is still valid
            if cache_key in cache:
                result, timestamp = cache[cache_key]
                if now - timestamp < seconds:
                    logger.debug(get_log_message("cache_hit", func=func.__name__))
                    return result

            # Cache miss or expired - call function
            logger.debug(get_log_message("cache_miss", func=func.__name__))
            result = func(*args, **kwargs)
            cache[cache_key] = (result, now)

            return result

        return wrapper
    return decorator


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
            logger.error(get_log_message("api_integrity_error", func=func.__name__, error=e))
            return {
                'success': False,
                'error': f"Database integrity error: {str(e)}",
                'error_type': 'integrity'
            }

        except sqlite3.OperationalError as e:
            logger.error(get_log_message("api_operational_error", func=func.__name__, error=e))
            return {
                'success': False,
                'error': f"Database operational error: {str(e)}",
                'error_type': 'operational'
            }

        except ValueError as e:
            logger.error(get_log_message("api_value_error", func=func.__name__, error=e))
            return {
                'success': False,
                'error': str(e),
                'error_type': 'validation'
            }

        except socket.timeout:
            logger.error(get_log_message("api_socket_timeout", func=func.__name__))
            return {
                'success': False,
                'error': 'Connection timeout',
                'error_type': 'timeout'
            }

        except ConnectionRefusedError:
            logger.error(get_log_message("api_connection_refused", func=func.__name__))
            return {
                'success': False,
                'error': 'Connection refused - server may not be running',
                'error_type': 'connection'
            }

        except Exception as e:
            logger.error(get_log_message("api_generic_error", func=func.__name__, error=e), exc_info=True)
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
        raise ValueError("Please provide a pattern (e.g., nick!*@*.com)")

    if not isinstance(pattern, str):
        raise ValueError("Pattern must be a text string")

    if len(pattern) < min_length:
        raise ValueError(f"Pattern must be at least {min_length} character(s) long")

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


# Import validation functions from centralized validation module
from validation import (
    validate_nickname_strict as validate_nickname,
    validate_channel_strict,
    validate_staff_level_strict
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
    # Use the strict validator with auto_prefix enabled
    return validate_channel_strict(channel, auto_prefix=True)


def validate_staff_level(level):
    """Validate staff privilege level

    Args:
        level: Staff level string

    Raises:
        ValueError: If level is invalid
    """
    validate_staff_level_strict(level)


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
        logger.debug(get_log_message("api_connected", host=host, port=port))

        # Send command
        command_bytes = f"{command}\r\n".encode('utf-8')
        sock.send(command_bytes)
        logger.info(get_log_message("api_command", description=description, command=command))

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
        logger.error(get_log_message("api_socket_timeout_cmd", description=description))
        return {
            'success': False,
            'error': 'Connection timeout',
            'response': ''
        }

    except ConnectionRefusedError:
        logger.error(get_log_message("api_connection_refused_cmd", description=description))
        return {
            'success': False,
            'error': 'Connection refused - server may not be running',
            'response': ''
        }

    except Exception as e:
        logger.error(get_log_message("api_error_cmd", description=description, error=e), exc_info=True)
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
