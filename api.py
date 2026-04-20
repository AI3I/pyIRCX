#!/usr/bin/env python3
"""
pyIRCX Management API
Provides comprehensive data access and management for web administration
"""

import sqlite3
import json
import sys
import os
import time
import re
import hashlib
import socket
import subprocess
from pathlib import Path
from datetime import datetime
import logging

# Import connection pool and helpers
import db_pool
from api_helpers import (
    api_error_handler,
    rate_limit,
    timed_cache,
    validate_access_type,
    validate_pattern,
    validate_timeout,
    validate_nickname,
    validate_channel_name,
    validate_staff_level
)
from responses import get_log_message, SERVER_MESSAGES

# Setup logging
logger = logging.getLogger(__name__)

# Default paths - check system install location first, then local checkout
# System installation paths (from install.sh)
SYSTEM_CONFIG = "/etc/pyircx/pyircx_config.json"
SYSTEM_INSTALL = "/opt/pyircx"
PROJECT_ROOT = Path(__file__).resolve().parent
PROJECT_CONFIG = PROJECT_ROOT / "pyircx_config.json"

# User installation paths (legacy manual installations)
USER_CONFIG = os.path.expanduser("~/pyIRCX/pyircx_config.json")
USER_INSTALL = os.path.expanduser("~/pyIRCX")

ENV_CONFIG = os.environ.get("PYIRCX_CONFIG")
ENV_DB = os.environ.get("PYIRCX_DB")
ENV_LOG = os.environ.get("PYIRCX_LOG")
ENV_STATUS = os.environ.get("PYIRCX_STATUS")

# Determine which installation is active
if ENV_CONFIG:
    DEFAULT_CONFIG = ENV_CONFIG
    DEFAULT_DB = ENV_DB or str(PROJECT_ROOT / "pyircx.db")
    DEFAULT_LOG = ENV_LOG or str(PROJECT_ROOT / "pyircx.log")
    DEFAULT_STATUS = ENV_STATUS or str(PROJECT_ROOT / "pyircx_status.json")
elif os.path.exists(SYSTEM_CONFIG):
    # System installation detected
    DEFAULT_CONFIG = SYSTEM_CONFIG
    DEFAULT_DB = os.path.join(SYSTEM_INSTALL, "pyircx.db")
    DEFAULT_LOG = os.path.join(SYSTEM_INSTALL, "pyircx.log")
    DEFAULT_STATUS = os.path.join(SYSTEM_INSTALL, "pyircx_status.json")
elif PROJECT_CONFIG.exists():
    # Running from a source checkout
    DEFAULT_CONFIG = str(PROJECT_CONFIG)
    DEFAULT_DB = str(PROJECT_ROOT / "pyircx.db")
    DEFAULT_LOG = str(PROJECT_ROOT / "pyircx.log")
    DEFAULT_STATUS = str(PROJECT_ROOT / "pyircx_status.json")
else:
    # Fall back to legacy user installation
    DEFAULT_CONFIG = USER_CONFIG
    DEFAULT_DB = os.path.join(USER_INSTALL, "pyircx.db")
    DEFAULT_LOG = os.path.join(USER_INSTALL, "pyircx.log")
    DEFAULT_STATUS = os.path.join(USER_INSTALL, "pyircx_status.json")


def _get_bcrypt():
    """Import bcrypt only when password operations are needed."""
    try:
        import bcrypt
    except ImportError as e:
        raise RuntimeError("bcrypt is required for password operations") from e
    return bcrypt


def _hash_password(password):
    bcrypt = _get_bcrypt()
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def _check_password(password, password_hash):
    bcrypt = _get_bcrypt()
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def ensure_db_pool(pool_size=10):
    """Initialize the shared DB pool on first use."""
    if db_pool.get_pool_stats() is not None:
        return True
    return init_db_pool(pool_size=pool_size)

def load_config():
    """Load pyIRCX configuration"""
    with open(DEFAULT_CONFIG, 'r') as f:
        return json.load(f)

def save_config(config):
    """Save pyIRCX configuration"""
    with open(DEFAULT_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    return config


def invalidate_config_caches():
    """Clear cached config-derived API responses after writes."""
    for func in (get_motd, get_server_config, get_full_config, get_newsflash_settings):
        cache_clear = getattr(func, 'cache_clear', None)
        if callable(cache_clear):
            cache_clear()

@timed_cache(seconds=60)
@api_error_handler
def get_motd():
    """Get MOTD (Message of the Day) from configuration (cached for 60 seconds)"""
    config = load_config()
    if 'server' in config and 'motd' in config['server']:
        motd = config['server']['motd']
        # Return as array of lines
        if isinstance(motd, str):
            return {"motd": [motd]}
        return {"motd": motd}
    # Return empty MOTD if not configured (default should be in config file)
    return {"motd": []}

@api_error_handler
def set_motd(motd_lines):
    """Set MOTD (Message of the Day) in configuration"""
    config = load_config()
    if 'server' not in config:
        config['server'] = {}

    # Parse motd_lines - can be JSON array or newline-separated string
    if isinstance(motd_lines, str):
        try:
            # Try to parse as JSON first
            parsed = json.loads(motd_lines)
            if isinstance(parsed, list):
                motd_lines = parsed
            else:
                # Split on newlines (preserve empty lines for spacing)
                motd_lines = [line.rstrip() for line in motd_lines.split('\n')]
        except json.JSONDecodeError:
            # Not JSON, split on newlines (preserve empty lines for spacing)
            motd_lines = [line.rstrip() for line in motd_lines.split('\n')]

    config['server']['motd'] = motd_lines
    save_config(config)
    invalidate_config_caches()
    return {"success": True}

def get_db_path():
    """Get database path from config or use default"""
    config = load_config()
    if 'database' in config and 'path' in config['database']:
        db_path = config['database']['path']
        # Handle relative paths
        if not os.path.isabs(db_path):
            if os.path.abspath(DEFAULT_CONFIG) == os.path.abspath(SYSTEM_CONFIG):
                db_path = os.path.normpath(os.path.join(SYSTEM_INSTALL, db_path))
            else:
                config_dir = os.path.dirname(os.path.abspath(DEFAULT_CONFIG))
                db_path = os.path.normpath(os.path.join(config_dir, db_path))
        return db_path
    return DEFAULT_DB

def get_admin_queue_path():
    """Get admin command queue path based on installation type"""
    if os.path.exists(SYSTEM_CONFIG):
        return os.path.join(SYSTEM_INSTALL, "admin_commands.queue")
    elif PROJECT_CONFIG.exists():
        return str(PROJECT_ROOT / "admin_commands.queue")
    else:
        return os.path.join(USER_INSTALL, "admin_commands.queue")

def write_admin_command(command_string, success_message):
    """Write a command to the admin command queue file

    Args:
        command_string: Command string to write (e.g., "KILL_CHANNEL:#test")
        success_message: Success message to return

    Returns:
        dict with success/error status
    """
    try:
        cmd_file = get_admin_queue_path()
        with open(cmd_file, 'a') as f:
            f.write(f"{command_string}\n")
        return {"success": True, "message": success_message}
    except Exception as e:
        return {"error": SERVER_MESSAGES['api_admin_command_write_failed'].format(error=e)}


def init_db_pool(pool_size=10):
    """Initialize the database connection pool

    Args:
        pool_size: Number of connections to maintain in pool (default: 10)

    Returns:
        bool: True if initialized successfully, False otherwise
    """
    try:
        db_path = get_db_path()
        db_pool.init_pool(db_path, pool_size=pool_size)
        logger.info(get_log_message("api_pool_initialized", path=db_path, pool_size=pool_size))
        return True
    except Exception as e:
        logger.error(get_log_message("api_pool_init_failed", error=e))
        return False

# ============================================================================
# HEALTH CHECK
# ============================================================================

@api_error_handler
def health_check():
    """Health check endpoint for monitoring systems

    Returns:
        dict: Health status including database, status file, and pool stats
    """
    health = {
        'healthy': True,
        'checks': {},
        'timestamp': int(time.time())
    }

    # Check 1: Database connectivity
    try:
        ensure_db_pool()
        with db_pool.get_connection(timeout=2.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health['checks']['database'] = {'status': 'ok', 'message': SERVER_MESSAGES['api_health_db_ok']}
    except Exception as e:
        health['checks']['database'] = {'status': 'error', 'message': str(e)}
        health['healthy'] = False

    # Check 2: Status file freshness
    try:
        if os.path.exists(DEFAULT_STATUS):
            with open(DEFAULT_STATUS, 'r') as f:
                status = json.load(f)
            age = time.time() - status.get('timestamp', 0)
            if age < 60:
                health['checks']['status_file'] = {'status': 'ok', 'message': SERVER_MESSAGES['api_health_status_fresh'].format(age=int(age))}
            elif age < 300:
                health['checks']['status_file'] = {'status': 'warning', 'message': SERVER_MESSAGES['api_health_status_stale'].format(age=int(age))}
            else:
                health['checks']['status_file'] = {'status': 'error', 'message': SERVER_MESSAGES['api_health_status_very_stale'].format(age=int(age))}
                health['healthy'] = False
        else:
            health['checks']['status_file'] = {'status': 'warning', 'message': SERVER_MESSAGES['api_health_status_not_found']}
    except Exception as e:
        health['checks']['status_file'] = {'status': 'error', 'message': str(e)}

    # Check 3: Connection pool stats
    try:
        pool_stats = db_pool.get_pool_stats()
        if pool_stats:
            health['checks']['connection_pool'] = {
                'status': 'ok',
                'pool_size': pool_stats['pool_size'],
                'available': pool_stats['available'],
                'in_use': pool_stats['in_use']
            }
        else:
            health['checks']['connection_pool'] = {'status': 'error', 'message': SERVER_MESSAGES['api_health_pool_not_initialized']}
            health['healthy'] = False
    except Exception as e:
        health['checks']['connection_pool'] = {'status': 'error', 'message': str(e)}

    return health


# ============================================================================
# REAL-TIME STATUS
# ============================================================================

@api_error_handler
def get_realtime_status():
    """Get real-time connected users and active channels from status dump"""
    if not os.path.exists(DEFAULT_STATUS):
        return {"error": SERVER_MESSAGES['api_status_not_found']}

    with open(DEFAULT_STATUS, 'r') as f:
        status = json.load(f)

    # Calculate age of status
    age = time.time() - status.get('timestamp', 0)
    status['status_age'] = age

    return status

@api_error_handler
def get_services_list():
    """Get list of network services and ServiceBots with their status"""
    config = load_config()

    # Define core services (always present when server is running)
    core_services = [
        {
            "nickname": "System",
            "type": "Core Service",
            "description": "Network Services",
            "is_servicebot": False,
            "channels": ["#System"]
        },
        {
            "nickname": "Registrar",
            "type": "Core Service",
            "description": "Registration Services (nickname and channel registration)",
            "is_servicebot": False,
            "channels": ["#System"]
        },
        {
            "nickname": "Messenger",
            "type": "Core Service",
            "description": "Message Services (mailbox and private messaging)",
            "is_servicebot": False,
            "channels": ["#System"]
        },
        {
            "nickname": "NewsFlash",
            "type": "Core Service",
            "description": "News Broadcast Services (rotating and push messages)",
            "is_servicebot": False,
            "channels": ["#System"]
        }
    ]

    # Get ServiceBot configuration
    servicebot_count = config.get('services', {}).get('servicebot_count', 10)
    servicebot_max_channels = config.get('services', {}).get('servicebot_max_channels', 10)

    # Create ServiceBot entries
    servicebots = []
    for i in range(1, servicebot_count + 1):
        bot_name = f"ServiceBot{i:02d}"
        servicebots.append({
            "nickname": bot_name,
            "type": "ServiceBot",
            "description": f"Service Bot #{i} (channel monitoring and moderation)",
            "is_servicebot": True,
            "max_channels": servicebot_max_channels,
            "channels": []  # Will be populated from status if available
        })

    # Try to get real-time channel information from status file
    if os.path.exists(DEFAULT_STATUS):
        try:
            with open(DEFAULT_STATUS, 'r') as f:
                status = json.load(f)

            # Update service channel lists from status file services data
            all_services = core_services + servicebots
            for service_status in status.get('services', []):
                service_nick = service_status.get('nickname')
                service_channels = service_status.get('channels', [])

                # Find matching service in our list and update its channels
                for service in all_services:
                    if service['nickname'] == service_nick:
                        service['channels'] = service_channels
                        break

            # Add timestamp for freshness
            return {
                "services": all_services,
                "servicebot_count": servicebot_count,
                "servicebot_enabled": config.get('servicebot', {}).get('enabled', True),
                "timestamp": status.get('timestamp', 0),
                "server_running": True
            }
        except Exception:
            # If status file can't be read, still return service list
            pass

    # Return services list even if status file not available
    return {
        "services": core_services + servicebots,
        "servicebot_count": servicebot_count,
        "servicebot_enabled": config.get('servicebot', {}).get('enabled', True),
        "server_running": False
    }

# ============================================================================
# IRC SERVER COMMUNICATION
# ============================================================================

@api_error_handler
def send_irc_kill_channel(channel_name):
    """Kill a channel by writing to pyircx admin command queue

    Args:
        channel_name: Channel to kill (e.g. '#pyIRCX')

    Returns:
        dict with success/error status
    """
    validate_channel_name(channel_name)
    return write_admin_command(
        f"KILL_CHANNEL:{channel_name}",
        SERVER_MESSAGES['api_channel_reset'].format(channel=channel_name)
    )

@api_error_handler
def send_irc_kill_user(nickname, reason=None):
    """Kill a user connection by writing to pyircx admin command queue

    Args:
        nickname: Nickname to kill
        reason: Kill reason (optional)

    Returns:
        dict with success/error status
    """
    validate_nickname(nickname)
    if not reason:
        reason = SERVER_MESSAGES['api_kill_default_reason']
    if len(reason) > 500:
        raise ValueError(SERVER_MESSAGES['api_reason_required'])
    return write_admin_command(
        f"KILL_USER:{nickname}:{reason}",
        SERVER_MESSAGES['api_kill_success'].format(nickname=nickname)
    )

@api_error_handler
def send_irc_ban_user(nickname, reason=None, duration=3600):
    """Ban a user by writing to pyircx admin command queue

    Args:
        nickname: Nickname to ban
        reason: Ban reason (optional)
        duration: Ban duration in seconds (default: 1 hour)

    Returns:
        dict with success/error status
    """
    validate_nickname(nickname)
    if not isinstance(duration, int) or duration < 0:
        raise ValueError(SERVER_MESSAGES['api_ban_duration_invalid'])
    if not reason:
        reason = SERVER_MESSAGES['api_ban_default_reason']
    if len(reason) > 500:
        raise ValueError(SERVER_MESSAGES['api_reason_required'])
    return write_admin_command(
        f"BAN_USER:{nickname}:{duration}:{reason}",
        SERVER_MESSAGES['api_ban_success'].format(nickname=nickname, duration=duration)
    )

@api_error_handler
def send_irc_lock_channel(channel_name, owner="System"):
    """Lock a channel (register + set auth-only) by writing to pyircx admin command queue

    Args:
        channel_name: Channel to lock (e.g. '#channel')
        owner: Owner for the channel (staff username or registered nickname)

    Returns:
        dict with success/error status
    """
    validate_channel_name(channel_name)
    if not owner or len(owner) > 30:
        raise ValueError(SERVER_MESSAGES['api_owner_name_required'])
    return write_admin_command(
        f"LOCK_CHANNEL:{channel_name}:{owner}",
        SERVER_MESSAGES['api_lock_channel_success'].format(channel_name=channel_name, owner=owner)
    )

@api_error_handler
def set_channel_mode(channel_name, mode_string):
    """Set channel mode via admin command queue

    Args:
        channel_name: Channel name (e.g., #channel)
        mode_string: Mode string (e.g., "+z" or "-z")

    Returns:
        dict with success/error status
    """
    validate_channel_name(channel_name)
    if not mode_string or len(mode_string) > 50:
        raise ValueError(SERVER_MESSAGES['api_mode_string_required'])
    if not re.match(r'^[+-][a-zA-Z]+$', mode_string):
        raise ValueError(SERVER_MESSAGES['api_mode_string_invalid_format'])
    return write_admin_command(
        f"SET_CHANNEL_MODE:{channel_name}:{mode_string}",
        SERVER_MESSAGES['api_set_mode_success'].format(mode_string=mode_string, channel_name=channel_name)
    )

@api_error_handler
def set_channel_topic(channel_name, topic):
    """Set channel topic via admin command queue

    Args:
        channel_name: Channel name (e.g., #channel)
        topic: New topic (empty string to clear)

    Returns:
        dict with success/error status
    """
    validate_channel_name(channel_name)
    if topic and len(topic) > 500:
        raise ValueError(SERVER_MESSAGES['api_topic_too_long'])
    return write_admin_command(
        f"SET_CHANNEL_TOPIC:{channel_name}:{topic}",
        SERVER_MESSAGES['api_set_topic_success'].format(channel_name=channel_name)
    )

@api_error_handler
def apply_channel_modes_live(channel_name, modes):
    """Apply channel modes by killing channel to force reload from database

    Args:
        channel_name: Channel name (e.g., #channel)
        modes: Mode string (e.g., "nt" or "*" to clear)

    Returns:
        dict with success/error status
    """
    # Kill channel to force reload from database with new modes
    return send_irc_kill_channel(channel_name)

@api_error_handler
def apply_channel_props_live(channel_name, topic=None, onjoin=None, onpart=None,
                             memberkey=None, hostkey=None, ownerkey=None):
    """Apply channel PROP settings by killing channel to force reload from database

    Args:
        channel_name: Channel name
        topic: Channel topic (or "*" to clear)
        onjoin: On-join message (or "*" to clear)
        onpart: On-part message (or "*" to clear)
        memberkey: Member key (or "*" to clear)
        hostkey: Host key (or "*" to clear)
        ownerkey: Owner key (or "*" to clear)

    Returns:
        dict with success/error status
    """
    # Kill channel to force reload from database with new properties
    return send_irc_kill_channel(channel_name)

# ============================================================================
# DATABASE STATISTICS
# ============================================================================

@api_error_handler
def get_server_stats():
    """Get server statistics from database and runtime status"""
    db_path = get_db_path()

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        stats = {}

        # Count staff users
        cursor.execute("SELECT COUNT(*) as count, level FROM users GROUP BY level")
        staff_counts = {}
        total_staff = 0
        for row in cursor.fetchall():
            staff_counts[row['level']] = row['count']
            total_staff += row['count']

        stats['staff'] = {
            'total': total_staff,
            'by_level': staff_counts
        }

        # Count registered nicknames
        cursor.execute("SELECT COUNT(*) as count FROM registered_nicks")
        stats['registered_nicks'] = cursor.fetchone()['count']

        # Count registered channels
        cursor.execute("SELECT COUNT(*) as count FROM registered_channels")
        stats['registered_channels'] = cursor.fetchone()['count']

        # Count server access entries (bans) - exclude expired
        now = int(time.time())
        cursor.execute("""
            SELECT COUNT(*) as count, type
            FROM server_access
            WHERE timeout = 0 OR timeout > ?
            GROUP BY type
        """, (now,))
        access_counts = {}
        for row in cursor.fetchall():
            access_counts[row['type']] = row['count']
        stats['server_access'] = access_counts

        # Count unread messages
        cursor.execute("SELECT COUNT(*) as count FROM mailbox WHERE read = 0")
        stats['unread_mailbox'] = cursor.fetchone()['count']

        # Count newsflash items
        cursor.execute("SELECT COUNT(*) as count FROM newsflash")
        stats['newsflash_count'] = cursor.fetchone()['count']

        # Count memos
        cursor.execute("SELECT COUNT(*) as count FROM memos WHERE read = 0")
        stats['unread_memos'] = cursor.fetchone()['count']

    # Read runtime status from JSON file (after db context)
    status_file = os.path.join(os.path.dirname(db_path), 'pyircx_status.json')
    if os.path.exists(status_file):
        try:
            with open(status_file, 'r') as f:
                runtime_status = json.load(f)

            stats['connected_users'] = len(runtime_status.get('connected_users', []))
            stats['active_channels'] = len(runtime_status.get('active_channels', []))
            stats['linked_servers'] = len(runtime_status.get('linked_servers', []))

            # Calculate uptime if timestamp is available
            if 'timestamp' in runtime_status:
                stats['status_timestamp'] = runtime_status['timestamp']

            # Get boot time from config or status
            if 'boot_time' in runtime_status:
                stats['boot_time'] = runtime_status['boot_time']
                stats['uptime_seconds'] = int(time.time() - runtime_status['boot_time'])

            # Get peak users if available
            if 'peak_users' in runtime_status:
                stats['peak_users'] = runtime_status['peak_users']

            stats['server_running'] = True
        except (json.JSONDecodeError, IOError) as e:
            # Status file exists but couldn't be read
            stats['server_running'] = False
            stats['connected_users'] = 0
            stats['active_channels'] = 0
            stats['linked_servers'] = 0
    else:
        # No status file = server not running
        stats['server_running'] = False
        stats['connected_users'] = 0
        stats['active_channels'] = 0
        stats['linked_servers'] = 0

    return stats

# ============================================================================
# SERVER ACCESS MANAGEMENT
# ============================================================================

@api_error_handler
def get_server_access_list():
    """Get all server access rules (bans)"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT type, pattern, set_by, set_at, timeout, reason
            FROM server_access
            ORDER BY set_at DESC
        """)

        rules = []
        current_time = int(time.time())
        for row in cursor.fetchall():
            timeout = row['timeout'] if row['timeout'] else 0
            expired = timeout > 0 and current_time > timeout

            rules.append({
                'type': row['type'],
                'pattern': row['pattern'],
                'set_by': row['set_by'],
                'set_at': row['set_at'],
                'timeout': timeout,
                'reason': row['reason'],
                'expired': expired
            })

        return rules

@api_error_handler
def add_server_access(access_type, pattern, set_by, reason, timeout=0):
    """Add a server access rule (ban)

    Args:
        timeout: Duration in minutes (0 = permanent), will be converted to absolute timestamp
    """
    # Validate inputs
    validate_access_type(access_type)
    validate_pattern(pattern)
    validate_timeout(timeout)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        set_at = int(time.time())

        # Convert duration in minutes to absolute timestamp
        # 0 means permanent (no expiry)
        duration_minutes = int(timeout) if timeout else 0
        if duration_minutes > 0:
            timeout_val = set_at + (duration_minutes * 60)
        else:
            timeout_val = 0

        cursor.execute("""
            INSERT INTO server_access (type, pattern, set_by, set_at, timeout, reason)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (access_type, pattern, set_by, set_at, timeout_val, reason))

        return {"success": True, "message": SERVER_MESSAGES['api_server_access_added'].format(access_type=access_type, pattern=pattern)}

@api_error_handler
def remove_server_access(access_type, pattern):
    """Remove a server access rule"""
    # Validate inputs
    validate_access_type(access_type)
    validate_pattern(pattern)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM server_access WHERE type = ? AND pattern = ?
        """, (access_type, pattern))

        rows_affected = cursor.rowcount

        if rows_affected > 0:
            return {"success": True, "message": SERVER_MESSAGES['api_server_access_removed'].format(access_type=access_type, pattern=pattern)}
        else:
            return {"error": SERVER_MESSAGES['api_server_access_not_found'].format(pattern=pattern)}

# ============================================================================
# NEWSFLASH MANAGEMENT
# ============================================================================

@api_error_handler
def get_newsflash_list():
    """Get all NewsFlash messages"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, message, priority, created_by, created_at
            FROM newsflash
            ORDER BY priority DESC, created_at DESC
        """)

        newsflash = []
        for row in cursor.fetchall():
            newsflash.append({
                'id': row['id'],
                'message': row['message'],
                'priority': row['priority'],
                'created_by': row['created_by'],
                'created_at': row['created_at']
            })

        return newsflash

@api_error_handler
def add_newsflash(message, created_by, priority=0):
    """Add a NewsFlash message"""
    # Validate inputs
    if not message or len(message) > 500:
        raise ValueError(SERVER_MESSAGES['api_newsflash_message_required'])
    if priority < 0 or priority > 10:
        raise ValueError(SERVER_MESSAGES['api_newsflash_priority_invalid'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        created_at = int(time.time())

        cursor.execute("""
            INSERT INTO newsflash (message, created_by, created_at, priority)
            VALUES (?, ?, ?, ?)
        """, (message, created_by, created_at, priority))

        return {"success": True, "message": SERVER_MESSAGES['api_newsflash_added']}

@api_error_handler
def delete_newsflash(msg_id):
    """Delete a NewsFlash message"""
    # Validate input
    if not msg_id or int(msg_id) < 1:
        raise ValueError(SERVER_MESSAGES['api_newsflash_id_invalid'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM newsflash WHERE id = ?", (int(msg_id),))

        rows_affected = cursor.rowcount

        if rows_affected > 0:
            return {"success": True, "message": SERVER_MESSAGES['api_newsflash_deleted']}
        else:
            return {"error": SERVER_MESSAGES['api_newsflash_not_found'].format(msg_id=msg_id)}

# ============================================================================
# MAILBOX VIEWING
# ============================================================================

@api_error_handler
def get_mailbox_messages(limit=50):
    """Get recent mailbox messages"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT m.id, m.sender_nick, m.message, m.sent_at, m.read,
                   rn.nickname as recipient
            FROM mailbox m
            LEFT JOIN registered_nicks rn ON m.recipient_uuid = rn.uuid
            ORDER BY m.sent_at DESC
            LIMIT ?
        """, (limit,))

        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row['id'],
                'sender': row['sender_nick'],
                'recipient': row['recipient'] if row['recipient'] else 'Unknown',
                'message': row['message'],
                'sent_at': row['sent_at'],
                'read': bool(row['read'])
            })

        return messages

@api_error_handler
def send_mailbox_message(sender_nick, recipient_nick, message):
    """Send a mailbox message to a registered nickname

    Args:
        sender_nick: Sender's nickname
        recipient_nick: Recipient's registered nickname
        message: Message content

    Returns:
        dict with success/error status
    """
    # Validate inputs
    if not sender_nick or len(sender_nick) > 30:
        raise ValueError(SERVER_MESSAGES['api_sender_nick_required'])
    if not message or len(message) > 500:
        raise ValueError(SERVER_MESSAGES['api_newsflash_message_required'])
    validate_nickname(recipient_nick)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Look up recipient's UUID in registered_nicks
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (recipient_nick,))
        recipient_row = cursor.fetchone()

        if not recipient_row:
            # Auto-create registered_nicks entry for recipient
            # This allows sending messages to any nickname via webadmin
            import uuid as uuid_mod
            recipient_uuid = str(uuid_mod.uuid4())
            now = int(time.time())

            cursor.execute("""
                INSERT INTO registered_nicks (uuid, nickname, password_hash, registered_at, last_seen, registered_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (recipient_uuid, recipient_nick, "", now, now, "AUTO (mailbox)"))
            logger.info(get_log_message("api_auto_nick_mailbox", nickname=recipient_nick, sender=sender_nick))
        else:
            recipient_uuid = recipient_row[0]
        sent_at = int(time.time())

        # Insert message
        cursor.execute("""
            INSERT INTO mailbox (sender_nick, recipient_uuid, message, sent_at, read)
            VALUES (?, ?, ?, ?, 0)
        """, (sender_nick, recipient_uuid, message, sent_at))

        return {"success": True, "message": SERVER_MESSAGES['api_mailbox_sent'].format(recipient_nick=recipient_nick)}

@api_error_handler
def delete_mailbox_message(message_id):
    """Delete a mailbox message by ID"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if message exists
        cursor.execute("SELECT id FROM mailbox WHERE id = ?", (message_id,))
        if not cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_mailbox_not_found'].format(message_id=message_id)}

        # Delete the message
        cursor.execute("DELETE FROM mailbox WHERE id = ?", (message_id,))

        return {"success": True, "message": SERVER_MESSAGES['api_mailbox_deleted'].format(message_id=message_id)}

# ============================================================================
# SEARCH FUNCTIONS
# ============================================================================

@api_error_handler
def search_registered_nicks(query):
    """Search registered nicknames"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT nickname, registered_at, last_seen, mfa_enabled, email
            FROM registered_nicks
            WHERE nickname LIKE ?
            ORDER BY nickname
            LIMIT 50
        """, (f"%{query}%",))

        results = []
        for row in cursor.fetchall():
            results.append({
                'nickname': row['nickname'],
                'registered_at': row['registered_at'],
                'last_seen': row['last_seen'],
                'mfa_enabled': bool(row['mfa_enabled']),
                'email': row['email'] if row['email'] else 'Not set'
            })

        return results

@api_error_handler
def search_channels(query):
    """Search registered channels from registered_channels table"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Search registered_channels table
        cursor.execute("""
            SELECT channel_name, registered_at, last_used,
                   (SELECT nickname FROM registered_nicks WHERE uuid = registered_channels.owner_uuid) as owner
            FROM registered_channels
            WHERE channel_name LIKE ?
            ORDER BY channel_name
            LIMIT 50
        """, (f"%{query}%",))

        results = []
        for row in cursor.fetchall():
            # Use indices instead of keys to avoid issues with UNION
            results.append({
                'name': row[0],  # channel_name
                'registered_at': row[1],  # registered_at
                'last_used': row[2],  # last_used
                'owner': row[3] if row[3] else 'Unknown'  # owner
            })

        return results


# ============================================================================
# EXISTING FUNCTIONS (keeping for compatibility)
# ============================================================================

@api_error_handler
def get_recent_registrations(limit=10):
    """Get recently registered nicknames"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT nickname, registered_at, last_seen, mfa_enabled
            FROM registered_nicks
            ORDER BY registered_at DESC
            LIMIT ?
        """, (limit,))

        registrations = []
        for row in cursor.fetchall():
            registrations.append({
                'nickname': row['nickname'],
                'registered_at': row['registered_at'],
                'last_seen': row['last_seen'] if row['last_seen'] else None,
                'mfa_enabled': bool(row['mfa_enabled'])
            })

        return registrations

@api_error_handler
def get_registered_channels(limit=50):
    """Get registered channels"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT rc.channel_name, rc.registered_at, rc.last_used,
                   (SELECT nickname FROM registered_nicks WHERE uuid = rc.owner_uuid) as owner
            FROM registered_channels rc
            ORDER BY rc.registered_at DESC
            LIMIT ?
        """, (limit,))

        channels = []
        for row in cursor.fetchall():
            channels.append({
                'name': row[0],  # channel_name
                'owner': row[3] if row[3] else 'Unknown',  # owner from subquery
                'registered_at': row[1],  # registered_at
                'last_used': row[2] if row[2] else row[1]  # last_used or registered_at
            })

        return channels

@api_error_handler
def get_staff_list():
    """Get list of staff users (optimized: 2 queries instead of N+1)"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Query 1: Get all staff members
        cursor.execute("""
            SELECT username, level, created_at, last_login, registered_nick, email, realname, force_realname
            FROM users
            ORDER BY
                CASE level
                    WHEN 'sysadmin' THEN 1
                    WHEN 'SYSOP' THEN 1
                    WHEN 'admin' THEN 2
                    WHEN 'ADMIN' THEN 2
                    WHEN 'guide' THEN 3
                    WHEN 'GUIDE' THEN 3
                    ELSE 4
                END,
                username
        """)
        staff_rows = cursor.fetchall()

        # Query 2: Get all owned nicknames in one query
        cursor.execute("""
            SELECT registered_by, nickname
            FROM registered_nicks
            WHERE registered_by IS NOT NULL
            ORDER BY registered_by, registered_at DESC
        """)

        # Build lookup dict: username -> [nicknames]
        owned_nicks_map = {}
        for row in cursor.fetchall():
            registered_by = row['registered_by']
            if registered_by not in owned_nicks_map:
                owned_nicks_map[registered_by] = []
            owned_nicks_map[registered_by].append(row['nickname'])

        # Combine results
        staff = []
        for row in staff_rows:
            username = row['username']
            staff.append({
                'username': username,
                'level': row['level'],
                'created_at': row['created_at'],
                'last_login': row['last_login'],
                'owned_nicknames': owned_nicks_map.get(username, []),
                'email': row['email'],
                'realname': row['realname'],
                'force_realname': bool(row['force_realname'])
            })

        return staff

# ============================================================================
# STAFF MANAGEMENT
# ============================================================================

@api_error_handler
def add_staff(username, password, level, realname=None, email=None, force_realname=False):
    """Add a new staff member"""
    # Validate inputs
    validate_staff_level(level)
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        raise ValueError(SERVER_MESSAGES['api_username_invalid_format'])
    if len(password) < 8:
        raise ValueError(SERVER_MESSAGES['api_password_too_short'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_staff_already_exists'].format(username=username)}

        # Hash password (same method as pyircx.py uses)
        password_hash = _hash_password(password)

        # Insert new staff member
        cursor.execute("""
            INSERT INTO users (username, password_hash, level, realname, email, force_realname)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, password_hash, level, realname, email, 1 if force_realname else 0))

        return {"success": True, "message": SERVER_MESSAGES['api_staff_added'].format(username=username, level=level)}

@api_error_handler
def delete_staff(username):
    """Delete a staff member"""
    # Validate input
    if not username or len(username) < 3:
        raise ValueError(SERVER_MESSAGES['api_username_too_short'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_staff_not_found'].format(username=username)}

        # Delete staff member
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))

        return {"success": True, "message": SERVER_MESSAGES['api_staff_deleted'].format(username=username)}

@api_error_handler
def change_staff_password(username, new_password):
    """Change a staff member's password"""
    # Validate inputs
    if not username or len(username) < 3:
        raise ValueError(SERVER_MESSAGES['api_username_too_short'])
    if len(new_password) < 8:
        raise ValueError(SERVER_MESSAGES['api_password_too_short'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_staff_not_found'].format(username=username)}

        # Hash password
        password_hash = _hash_password(new_password)

        # Update password
        cursor.execute("""
            UPDATE users SET password_hash = ? WHERE username = ?
        """, (password_hash, username))

        return {"success": True, "message": SERVER_MESSAGES['api_staff_password_changed'].format(username=username)}

@api_error_handler
def change_staff_level(username, new_level):
    """Change a staff member's privilege level"""
    # Validate inputs
    if not username or len(username) < 3:
        raise ValueError(SERVER_MESSAGES['api_username_too_short'])
    validate_staff_level(new_level)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_staff_not_found'].format(username=username)}

        # Update level
        cursor.execute("""
            UPDATE users SET level = ? WHERE username = ?
        """, (new_level, username))

        return {"success": True, "message": SERVER_MESSAGES['api_staff_level_changed'].format(username=username, new_level=new_level)}

@api_error_handler
def update_staff_profile(username, realname=None, email=None, force_realname=None):
    """Update staff member's profile information (realname and email)"""
    # Validate input
    if not username or len(username) < 3:
        raise ValueError(SERVER_MESSAGES['api_username_too_short'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_staff_not_found'].format(username=username)}

        # Update profile fields
        cursor.execute("""
            UPDATE users SET realname = ?, email = ?, force_realname = ?
            WHERE username = ?
        """, (realname, email, 1 if force_realname else 0, username))

        return {"success": True, "message": SERVER_MESSAGES['api_staff_profile_updated'].format(username=username)}


@timed_cache(seconds=60)
@api_error_handler
def get_server_config():
    """Get server configuration (cached for 60 seconds)"""
    config = load_config()

    # Return safe config info (no sensitive data)
    safe_config = {}

    if 'server' in config:
        safe_config['server'] = {
            'name': config['server'].get('name', 'Unknown'),
            'network': config['server'].get('network', 'Unknown')
        }

    if 'network' in config:
        safe_config['port'] = config['network'].get('listen_ports', [])

    if 'ssl' in config:
        safe_config['ssl_enabled'] = config['ssl'].get('enabled', False)
        if config['ssl'].get('enabled'):
            safe_config['ssl_port'] = config['ssl'].get('ports', [])

    return safe_config

@timed_cache(seconds=30)
@api_error_handler
def get_full_config():
    """Get full configuration for editing (cached for 30 seconds)"""
    return load_config()

@api_error_handler
def get_config():
    """Get raw configuration wrapped in an API response."""
    return {"config": load_config()}

@api_error_handler
def set_config(config_json):
    """Set configuration from JSON string"""
    config = json.loads(config_json)
    save_config(config)
    invalidate_config_caches()
    return {"success": True}

# ============================================================================
# LOG FUNCTIONS
# ============================================================================

@api_error_handler
def get_logs(lines=100, level_filter=None, search=None):
    """Get server logs from journalctl (systemd) or log file"""
    # Try to get logs from journalctl (systemd journal) first
    cmd = ['journalctl', '-u', 'pyircx.service', '-n', str(lines), '--no-pager', '--output=short-iso']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout:
            log_lines = result.stdout.strip().split('\n')

            # Apply filters
            if level_filter:
                log_lines = [line for line in log_lines if f"[{level_filter}]" in line]

            if search:
                log_lines = [line for line in log_lines if search.lower() in line.lower()]

            return {
                'logs': '\n'.join(log_lines),
                'line_count': len(log_lines),
                'source': 'journalctl'
            }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # Fall back to file

    # Fallback to log file if journalctl not available
    if not os.path.exists(DEFAULT_LOG):
        return {"error": SERVER_MESSAGES['api_logs_unavailable']}

    with open(DEFAULT_LOG, 'r') as f:
        log_lines = f.readlines()

    # Get last N lines
    log_lines = log_lines[-lines:]

    # Apply filters
    if level_filter:
        log_lines = [line for line in log_lines if f"[{level_filter}]" in line]

    if search:
        log_lines = [line for line in log_lines if search.lower() in line.lower()]

    return {
        'logs': ''.join(log_lines),
        'line_count': len(log_lines),
        'source': 'file'
    }


@api_error_handler
def get_connection_sessions(limit=250, search=None):
    """Get persisted client connection sessions for the WebAdmin log view."""
    limit = max(1, min(int(limit or 250), 1000))
    search = (search or '').strip()

    query = """
        SELECT nickname, username, realname, ip_address, host,
               logon_time, logout_time, duration, reason
        FROM connection_sessions
    """
    params = []
    if search:
        pattern = f"%{search.lower()}%"
        query += """
            WHERE lower(nickname) LIKE ?
               OR lower(username) LIKE ?
               OR lower(COALESCE(realname, '')) LIKE ?
               OR lower(COALESCE(ip_address, '')) LIKE ?
               OR lower(COALESCE(host, '')) LIKE ?
               OR lower(COALESCE(reason, '')) LIKE ?
        """
        params.extend([pattern] * 6)
    query += " ORDER BY logon_time DESC, id DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    sessions = []
    for row in rows:
        sessions.append({
            "nickname": row["nickname"],
            "username": row["username"],
            "realname": row["realname"] or "",
            "ip_address": row["ip_address"] or "",
            "host": row["host"] or "",
            "logon_time": row["logon_time"],
            "logout_time": row["logout_time"],
            "duration": row["duration"],
            "reason": row["reason"] or "",
        })

    return {
        "sessions": sessions,
        "count": len(sessions),
        "limit": limit,
    }


def _run_systemctl(*args):
    """Run systemctl safely and return completed process."""
    return subprocess.run(
        ['systemctl', *args],
        capture_output=True,
        text=True,
        timeout=10
    )


@api_error_handler
def get_service_status():
    """Return pyIRCX service status."""
    try:
        result = _run_systemctl('is-active', 'pyircx.service')
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {'status': 'unavailable'}

    status = (result.stdout or result.stderr).strip() or 'unknown'
    return {'status': status}


@api_error_handler
def control_service(action):
    """Control the pyIRCX systemd service."""
    if action not in {'start', 'stop', 'restart', 'reload', 'status'}:
        raise ValueError('Invalid service action')

    if action == 'status':
        return get_service_status()

    try:
        result = _run_systemctl(action, 'pyircx.service')
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {'error': 'Service control unavailable'}

    if result.returncode == 0:
        return {'success': True, 'message': f'Service {action} successful'}

    message = (result.stderr or result.stdout).strip()
    return {'error': f'Failed to control service: {message}'}

# ============================================================================
# NEWSFLASH SETTINGS
# ============================================================================

@timed_cache(seconds=60)
@api_error_handler
def get_newsflash_settings():
    """Get NewsFlash broadcast settings (cached for 60 seconds)"""
    config = load_config()
    newsflash = config.get('newsflash', {})
    return {
        'on_connect': newsflash.get('on_connect', False),
        'periodic_enabled': newsflash.get('periodic_enabled', False),
        'periodic_interval': newsflash.get('periodic_interval', 30)
    }

@api_error_handler
def set_newsflash_settings(on_connect, periodic_enabled, periodic_interval):
    """Set NewsFlash broadcast settings"""
    config = load_config()
    if 'newsflash' not in config:
        config['newsflash'] = {}

    config['newsflash']['on_connect'] = on_connect == 'true' or on_connect == True
    config['newsflash']['periodic_enabled'] = periodic_enabled == 'true' or periodic_enabled == True
    config['newsflash']['periodic_interval'] = int(periodic_interval)

    save_config(config)
    invalidate_config_caches()
    return {"success": True, "message": SERVER_MESSAGES['api_newsflash_settings_updated']}

# ============================================================================
# NICKNAME AND CHANNEL REGISTRATION
# ============================================================================

@api_error_handler
def register_nickname(nickname, password, email=None):
    """Register a new nickname"""
    # Validate inputs
    validate_nickname(nickname)
    if len(password) < 8:
        raise ValueError(SERVER_MESSAGES['api_password_too_short'])
    if email and email != '*':
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError(SERVER_MESSAGES['api_email_invalid'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if nickname already exists
        cursor.execute("SELECT nickname FROM registered_nicks WHERE nickname = ?", (nickname,))
        if cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_nickname_already_registered'].format(nickname=nickname)}

        # Generate UUID and hash password
        import uuid
        nick_uuid = str(uuid.uuid4())
        password_hash = _hash_password(password)
        now = int(time.time())

        # Set email (None if '*' was provided)
        email_val = email if email and email != '*' else None

        # Insert new nickname
        cursor.execute("""
            INSERT INTO registered_nicks (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (nick_uuid, nickname, password_hash, email_val, now, now, "API Admin"))

        return {"success": True, "message": SERVER_MESSAGES['api_nickname_registered'].format(nickname=nickname)}

# Reserved service names (from pyircx.py)
RESERVED_SERVICES = {
    'operserv', 'helpserv', 'infoserv', 'nickserv', 'chanserv', 'memoserv',
    'botserv', 'hostserv', 'statserv', 'global', 'alis', 'services',
    'system', 'registrar', 'messenger', 'newsflash'
}

@api_error_handler
def register_channel(channel_name, owner_nickname, topic=None, modes=None, onjoin=None, onpart=None,
                     memberkey=None, hostkey=None, ownerkey=None, description=None):
    """Register a new channel (simplified to match actual database schema)"""
    # Validate channel name
    validate_channel_name(channel_name)

    with db_pool.get_connection() as conn:
        import uuid as uuid_mod
        cursor = conn.cursor()

        # Check if channel already exists
        cursor.execute("SELECT channel_name FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        if cursor.fetchone():
            return {"error": SERVER_MESSAGES['api_channel_already_registered'].format(channel_name=channel_name)}

        # Get owner's UUID from registered_nicks
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (owner_nickname,))
        owner_row = cursor.fetchone()

        if not owner_row:
            # Check if this is a reserved service name
            if owner_nickname.lower() in ['system', 'registrar', 'messenger', 'newsflash', 'services']:
                service_name_mapping = {
                    'system': 'System', 'registrar': 'Registrar', 'messenger': 'Messenger',
                    'newsflash': 'NewsFlash', 'services': 'Services'
                }
                proper_name = service_name_mapping.get(owner_nickname.lower(), owner_nickname.title())

                # Auto-create registered_nicks entry for service
                service_uuid = str(uuid_mod.uuid4())
                now_temp = int(time.time())

                cursor.execute("""
                    INSERT INTO registered_nicks (uuid, nickname, password_hash, registered_at, last_seen, registered_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (service_uuid, proper_name, "", now_temp, now_temp, "AUTO (service account)"))
                logger.info(get_log_message("api_auto_service_account", name=proper_name, channel=channel_name))

                owner_uuid = service_uuid
            else:
                return {"error": SERVER_MESSAGES['api_channel_owner_not_found'].format(owner_nickname=owner_nickname)}
        else:
            owner_uuid = owner_row[0]

        # Insert new channel using correct schema
        chan_uuid = str(uuid_mod.uuid4())
        now = int(time.time())

        cursor.execute("""
            INSERT INTO registered_channels
            (uuid, channel_name, owner_uuid, registered_at, last_used, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (chan_uuid, channel_name, owner_uuid, now, now, description or ""))

        return {"success": True, "message": SERVER_MESSAGES['api_channel_registered'].format(channel_name=channel_name, owner_nickname=owner_nickname)}


@api_error_handler
def unregister_nickname(nickname):
    """Unregister a nickname"""
    # Validate input
    validate_nickname(nickname)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()

        if not nick_row:
            return {"error": SERVER_MESSAGES['api_nickname_not_registered'].format(nickname=nickname)}

        nick_uuid = nick_row[0]

        # Check if this nickname owns any channels
        cursor.execute("SELECT COUNT(*) as count FROM registered_channels WHERE owner_uuid = ?", (nick_uuid,))
        channel_count = cursor.fetchone()[0]

        if channel_count > 0:
            return {"error": SERVER_MESSAGES['api_nickname_owns_channels'].format(nickname=nickname, channel_count=channel_count)}

        # Delete the nickname
        cursor.execute("DELETE FROM registered_nicks WHERE uuid = ?", (nick_uuid,))

        return {"success": True, "message": SERVER_MESSAGES['api_nickname_unregistered'].format(nickname=nickname)}

@api_error_handler
def edit_nickname(nickname, new_password=None, new_email=None):
    """Edit a registered nickname's password and/or email"""
    # Validate inputs
    validate_nickname(nickname)
    if not new_password and new_email is None:
        raise ValueError(SERVER_MESSAGES['api_nickname_no_changes'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()

        if not nick_row:
            return {"error": SERVER_MESSAGES['api_nickname_not_registered'].format(nickname=nickname)}

        nick_uuid = nick_row[0]
        updates = []
        params = []

        # Update password if provided
        if new_password:
            if len(new_password) < 8:
                raise ValueError(SERVER_MESSAGES['api_password_too_short'])
            password_hash = _hash_password(new_password)
            updates.append("password_hash = ?")
            params.append(password_hash)

        # Update email if provided (empty string means clear email)
        if new_email is not None:
            if new_email == "" or new_email == "*":
                updates.append("email = NULL")
            else:
                # Validate email
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
                    raise ValueError(SERVER_MESSAGES['api_email_invalid'])
                updates.append("email = ?")
                params.append(new_email)

        # Build and execute UPDATE query
        params.append(nick_uuid)
        query = f"UPDATE registered_nicks SET {', '.join(updates)} WHERE uuid = ?"
        cursor.execute(query, params)

        changes = []
        if new_password:
            changes.append("password")
        if new_email is not None:
            changes.append("email")

        return {"success": True, "message": SERVER_MESSAGES['api_nickname_updated'].format(changes=' and '.join(changes), nickname=nickname)}

@api_error_handler
def reset_mfa(nickname):
    """Reset MFA for a nickname (admin function)"""
    # Validate input
    validate_nickname(nickname)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()

        if not nick_row:
            return {"error": SERVER_MESSAGES['api_nickname_not_registered'].format(nickname=nickname)}

        # Reset MFA
        cursor.execute(
            "UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE LOWER(nickname) = LOWER(?)",
            (nickname,)
        )

        return {"success": True, "message": SERVER_MESSAGES['api_mfa_disabled'].format(nickname=nickname)}

@rate_limit(calls_per_minute=5)
@api_error_handler
def test_identify(nickname, password):
    """Test if a nickname/password combination is valid (rate limited: 5 attempts/minute)"""
    # Validate inputs
    validate_nickname(nickname)
    if not password:
        raise ValueError(SERVER_MESSAGES['api_password_required'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Get password hash
        cursor.execute(
            "SELECT password_hash, mfa_enabled FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)",
            (nickname,)
        )
        row = cursor.fetchone()

        if not row:
            return {"success": False, "message": SERVER_MESSAGES['api_identify_nickname_not_registered']}

        password_hash, mfa_enabled = row

        # Verify password
        if _check_password(password, password_hash):
            if mfa_enabled:
                return {"success": True, "message": SERVER_MESSAGES['api_identify_mfa_required'], "mfa_required": True}
            else:
                return {"success": True, "message": SERVER_MESSAGES['api_identify_success'], "mfa_required": False}
        else:
            return {"success": False, "message": SERVER_MESSAGES['api_identify_password_incorrect']}

@rate_limit(calls_per_minute=5)
@api_error_handler
def test_staff_login(username, password):
    """Test if a staff username/password combination is valid (rate limited: 5 attempts/minute)"""
    # Validate inputs
    if not username or not password:
        raise ValueError(SERVER_MESSAGES['api_login_credentials_required'])

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Get password hash and level
        cursor.execute(
            "SELECT password_hash, level FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            return {"success": False, "message": SERVER_MESSAGES['api_staff_login_not_found']}

        password_hash, level = row

        # Verify password
        if _check_password(password, password_hash):
            return {"success": True, "message": SERVER_MESSAGES['api_login_success_with_level'].format(level=level), "level": level}
        else:
            return {"success": False, "message": SERVER_MESSAGES['api_staff_login_password_incorrect']}

@api_error_handler
def test_staff_login_stdin(username):
    """Test if a staff username/password combination is valid (password from stdin)"""
    # Read password from stdin (more secure for web interface)
    password = sys.stdin.read().strip()

    # Use the existing test_staff_login function
    return test_staff_login(username, password)


def _read_stdin_json():
    """Read a JSON payload from stdin for secret-bearing API commands."""
    raw = sys.stdin.read()
    if not raw:
        raise ValueError("Missing stdin payload")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid stdin payload: {exc}") from exc


def add_staff_stdin(username, level, realname=None, email=None, force_realname=False):
    """Add a staff member with password provided via stdin JSON."""
    payload = _read_stdin_json()
    return add_staff(username, payload.get('password', ''), level, realname, email, force_realname)


def change_staff_password_stdin(username):
    """Change a staff password with the new password provided via stdin JSON."""
    payload = _read_stdin_json()
    return change_staff_password(username, payload.get('password', ''))


def register_nickname_stdin(nickname, email=None):
    """Register a nickname with password provided via stdin JSON."""
    payload = _read_stdin_json()
    return register_nickname(nickname, payload.get('password', ''), email)


def edit_nickname_stdin(nickname, new_email=None):
    """Edit a nickname with optional password provided via stdin JSON."""
    payload = _read_stdin_json()
    password = payload.get('password', '')
    new_password = password if password else None
    return edit_nickname(nickname, new_password, new_email)

@api_error_handler
def get_staff_details(username):
    """Get detailed staff information including owned nicknames"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Get staff details
        cursor.execute(
            "SELECT username, level, created_at, last_login, email, realname, force_realname FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            return {"error": SERVER_MESSAGES['api_staff_account_not_found'].format(username=username)}

        # Get all nicknames registered by this staff member
        cursor.execute(
            "SELECT nickname FROM registered_nicks WHERE registered_by = ? ORDER BY registered_at DESC",
            (username,)
        )
        owned_nicknames = [r['nickname'] for r in cursor.fetchall()]

        details = {
            "username": row['username'],
            "level": row['level'],
            "created_at": row['created_at'],
            "last_login": row['last_login'],
            "owned_nicknames": owned_nicknames,
            "email": row['email'],
            "realname": row['realname'],
            "force_realname": bool(row['force_realname'])
        }

        return {"success": True, "staff": details}

@api_error_handler
def unregister_channel(channel_name):
    """Unregister a channel"""
    # Validate input
    validate_channel_name(channel_name)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if channel exists
        cursor.execute("SELECT uuid FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        chan_row = cursor.fetchone()

        if not chan_row:
            return {"error": SERVER_MESSAGES['api_channel_not_registered'].format(channel_name=channel_name)}

        # Delete the channel
        cursor.execute("DELETE FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))

        return {"success": True, "message": SERVER_MESSAGES['api_channel_unregistered'].format(channel_name=channel_name)}

@api_error_handler
def edit_channel(channel_name, new_owner=None, new_description=None, new_topic=None, new_modes=None,
                 new_onjoin=None, new_onpart=None, new_memberkey=None, new_hostkey=None, new_ownerkey=None, new_voicekey=None, new_userlimit=None):
    """Edit a registered channel's properties by updating registered_channels table"""
    # Validate input
    validate_channel_name(channel_name)

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Load channel data from registered_channels (JSON format in properties column)
        cursor.execute("SELECT properties, owner_uuid, description FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if not row:
            return {"error": SERVER_MESSAGES['api_channel_not_registered'].format(channel_name=channel_name)}

        # Parse JSON properties (may be None for newly registered channels)
        channel_data = json.loads(row[0]) if row[0] else {}
        current_owner_uuid = row[1]
        current_description = row[2]
        changes = []
        owner_uuid_changed = False
        new_owner_uuid = current_owner_uuid
        new_description_val = current_description

        # Update owner (requires looking up new owner's UUID)
        if new_owner:
            cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (new_owner,))
            owner_row = cursor.fetchone()
            if owner_row:
                new_owner_uuid = owner_row[0]
                owner_uuid_changed = True
                # Also update owners list in properties
                channel_data['owners'] = [new_owner]
                changes.append("owner")
            else:
                return {"error": SERVER_MESSAGES['api_owner_not_found'].format(new_owner=new_owner)}

        # Update description
        if new_description is not None:
            new_description_val = "" if new_description == "*" else new_description
            changes.append("description")

        # Update topic
        if new_topic is not None:
            channel_data['topic'] = "" if new_topic == "*" else new_topic
            changes.append("topic")

        # Update modes
        if new_modes is not None:
            if new_modes == "*":
                channel_data['modes'] = {"n": True, "t": True}
            else:
                mode_dict = {}
                for mode_char in new_modes:
                    mode_dict[mode_char] = True
                channel_data['modes'] = mode_dict
            changes.append("modes")

        # Update ONJOIN
        if new_onjoin is not None:
            channel_data['onjoin'] = None if new_onjoin == "*" else new_onjoin
            changes.append("onjoin")

        # Update ONPART
        if new_onpart is not None:
            channel_data['onpart'] = None if new_onpart == "*" else new_onpart
            changes.append("onpart")

        # Update MEMBERKEY
        if new_memberkey is not None:
            channel_data['key'] = None if new_memberkey == "*" else new_memberkey
            changes.append("memberkey")

        # Update HOSTKEY
        if new_hostkey is not None:
            channel_data['host_key'] = None if new_hostkey == "*" else new_hostkey
            changes.append("hostkey")

        # Update OWNERKEY
        if new_ownerkey is not None:
            channel_data['owner_key'] = None if new_ownerkey == "*" else new_ownerkey
            changes.append("ownerkey")

        # Update VOICEKEY
        if new_voicekey is not None:
            channel_data['voice_key'] = None if new_voicekey == "*" else new_voicekey
            changes.append("voicekey")

        # Update USERLIMIT
        if new_userlimit is not None:
            if new_userlimit == "*" or new_userlimit == "" or new_userlimit == "0":
                channel_data['user_limit'] = None
                # Remove +l mode if clearing limit
                if 'modes' in channel_data and isinstance(channel_data['modes'], dict):
                    channel_data['modes'].pop('l', None)
            else:
                try:
                    limit_val = int(new_userlimit)
                    if limit_val > 0:
                        channel_data['user_limit'] = limit_val
                        # Add +l mode when setting limit
                        if 'modes' not in channel_data:
                            channel_data['modes'] = {}
                        channel_data['modes']['l'] = True
                except (ValueError, TypeError):
                    pass  # Invalid limit value, skip
            changes.append("userlimit")

        if not changes:
            return {"error": SERVER_MESSAGES['api_channel_no_changes']}

        # Save back to registered_channels
        cursor.execute("""UPDATE registered_channels
                         SET properties = ?, owner_uuid = ?, description = ?, last_used = ?
                         WHERE LOWER(channel_name) = LOWER(?)""",
                      (json.dumps(channel_data), new_owner_uuid, new_description_val, int(time.time()), channel_name))

    # Kill channel to force reload from database (outside transaction)
    kill_result = send_irc_kill_channel(channel_name)

    if kill_result.get("success"):
        message = SERVER_MESSAGES['api_channel_updated_reload'].format(changes=', '.join(changes), channel_name=channel_name)
    else:
        message = SERVER_MESSAGES['api_channel_updated'].format(changes=', '.join(changes), channel_name=channel_name)

    return {"success": True, "message": message}

@api_error_handler
def get_registered_nicks_paginated(limit=50, offset=0):
    """Get registered nicknames with pagination"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM registered_nicks")
        total = cursor.fetchone()['count']

        # Get paginated results
        cursor.execute("""
            SELECT uuid, nickname, registered_at, last_seen, mfa_enabled, email, registered_by, mfa_secret
            FROM registered_nicks
            ORDER BY registered_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        nicknames = []
        for row in cursor.fetchall():
            nicknames.append({
                'uuid': row['uuid'],
                'nickname': row['nickname'],
                'registered_at': row['registered_at'],
                'last_seen': row['last_seen'] if row['last_seen'] else None,
                'mfa_enabled': bool(row['mfa_enabled']),
                'mfa_secret': row['mfa_secret'] if row['mfa_secret'] else None,
                'email': row['email'] if row['email'] else 'Not set',
                'registered_by': row['registered_by'] if row['registered_by'] else 'Unknown'
            })

        return {"data": nicknames, "total": total}

@api_error_handler
def get_registered_channels_paginated(limit=50, offset=0):
    """Get registered channels with pagination"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM registered_channels")
        total = cursor.fetchone()['count']

        # Get paginated results
        cursor.execute("""
            SELECT
                rc.channel_name,
                rc.registered_at,
                rc.last_used,
                (SELECT nickname FROM registered_nicks WHERE uuid = rc.owner_uuid) as owner
            FROM registered_channels rc
            ORDER BY rc.channel_name
            LIMIT ? OFFSET ?
        """, (limit, offset))

        channels = []
        for row in cursor.fetchall():
            channels.append({
                'name': row[0],  # channel_name
                'owner': row[3] if row[3] else 'Unknown',  # owner from subquery
                'registered_at': row[1],  # registered_at
                'last_used': row[2] if row[2] else row[1]  # last_used or registered_at
            })

        return {"data": channels, "total": total}


@api_error_handler
def get_channel_details(channel_name):
    """Get detailed channel information for editing"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Load from registered_channels
        cursor.execute("SELECT properties FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if not row:
            return {"error": SERVER_MESSAGES['api_channel_not_found'].format(channel_name=channel_name)}

        # Parse JSON properties (may be None for newly registered channels)
        channel_data = json.loads(row[0]) if row[0] else {}

        # Extract relevant fields
        details = {
            "name": channel_name,
            "topic": channel_data.get("topic", ""),
            "onjoin": channel_data.get("onjoin") or "",
            "onpart": channel_data.get("onpart") or "",
            "memberkey": channel_data.get("key") or "",
            "hostkey": channel_data.get("host_key") or "",
            "ownerkey": channel_data.get("owner_key") or "",
            "modes": channel_data.get("modes", {}),
            "owners": channel_data.get("owners", []),
            "user_limit": channel_data.get("user_limit") or 0
        }

        return {"success": True, "channel": details}

@api_error_handler
def get_channel_access(channel_name):
    """Get ACCESS lists for a channel"""
    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check in registered_channels table (JSON properties)
        cursor.execute("SELECT properties FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if row and row[0]:
            data = json.loads(row[0])
            access_list = data.get('access_list', {
                'OWNER': [],
                'HOST': [],
                'VOICE': [],
                'GRANT': [],
                'DENY': []
            })
        else:
            # Channel not registered or no properties yet, return empty lists
            access_list = {
                'OWNER': [],
                'HOST': [],
                'VOICE': [],
                'GRANT': [],
                'DENY': []
            }

        return {"access_list": access_list}

@api_error_handler
def set_channel_access(channel_name, access_list_json):
    """Set ACCESS lists for a channel"""
    # Validate inputs
    validate_channel_name(channel_name)
    if not access_list_json:
        raise ValueError(SERVER_MESSAGES['api_access_list_required'])

    try:
        access_list = json.loads(access_list_json)
    except json.JSONDecodeError as e:
        raise ValueError(SERVER_MESSAGES['api_json_invalid'].format(error=e))

    with db_pool.get_connection() as conn:
        cursor = conn.cursor()

        # Check if channel exists in registered_channels
        cursor.execute("SELECT properties FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if row:
            # Update existing entry - parse properties (may be None)
            data = json.loads(row[0]) if row[0] else {}
            data['access_list'] = access_list
            cursor.execute("UPDATE registered_channels SET properties = ?, last_used = ? WHERE LOWER(channel_name) = LOWER(?)",
                         (json.dumps(data), int(time.time()), channel_name))
        else:
            # Channel not registered - cannot set ACCESS on unregistered channel
            return {"error": SERVER_MESSAGES['api_channel_not_registered_for_access'].format(channel_name=channel_name)}

    # Kill channel to force reload from database (outside transaction)
    send_irc_kill_channel(channel_name)

    return {"success": True, "message": SERVER_MESSAGES['api_channel_access_updated'].format(channel_name=channel_name)}

# ============================================================================
# MAIN COMMAND DISPATCHER
# ============================================================================

def main():
    """Main entry point for API calls"""
    if len(sys.argv) < 2:
        print(json.dumps({"error": SERVER_MESSAGES['api_no_command']}))
        sys.exit(1)

    command = sys.argv[1]
    result = None

    db_commands = {
        "health", "health-check", "stats", "server-access-list", "add-server-access",
        "remove-server-access", "newsflash-list", "add-newsflash", "delete-newsflash",
        "newsflash-settings", "set-newsflash-settings", "mailbox-list", "send-mailbox-message",
        "delete-mailbox-message", "search-nicknames", "search-channels", "add-staff",
        "delete-staff", "change-staff-password", "change-staff-level", "update-staff-profile",
        "register-nick", "register-channel", "unregister-nick", "unregister-channel",
        "edit-nick", "reset-mfa", "test-identify", "test-staff-login", "test-staff-login-stdin",
        "get-staff-details", "edit-channel", "list-nicknames-paginated", "list-channels-paginated",
        "get-channel-access", "get-channel-details", "set-channel-access", "recent-registrations",
        "channels", "staff", "services", "list-services", "config", "get-config",
        "full-config", "set-config", "get-motd", "set-motd"
    }

    if command in db_commands:
        ensure_db_pool()

    # Health check
    if command == "health" or command == "health-check":
        result = health_check()

    # Real-time status
    elif command == "realtime-status":
        result = get_realtime_status()

    # Statistics
    elif command == "stats":
        result = get_server_stats()

    # Server access management
    elif command == "server-access-list":
        result = get_server_access_list()
    elif command == "add-server-access":
        if len(sys.argv) < 6:
            result = {"error": SERVER_MESSAGES['api_usage_add_server_access']}
        else:
            timeout = int(sys.argv[6]) if len(sys.argv) > 6 else 0
            result = add_server_access(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], timeout)
    elif command == "remove-server-access":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_remove_server_access']}
        else:
            result = remove_server_access(sys.argv[2], sys.argv[3])

    # Newsflash management
    elif command == "newsflash-list":
        result = get_newsflash_list()
    elif command == "add-newsflash":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_add_newsflash']}
        else:
            priority = int(sys.argv[4]) if len(sys.argv) > 4 else 0
            result = add_newsflash(sys.argv[2], sys.argv[3], priority)
    elif command == "delete-newsflash":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_delete_newsflash']}
        else:
            result = delete_newsflash(sys.argv[2])
    elif command == "newsflash-settings":
        result = get_newsflash_settings()
    elif command == "set-newsflash-settings":
        if len(sys.argv) < 5:
            result = {"error": SERVER_MESSAGES['api_usage_set_newsflash_settings']}
        else:
            result = set_newsflash_settings(sys.argv[2], sys.argv[3], sys.argv[4])

    # Mailbox
    elif command == "mailbox-list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        result = get_mailbox_messages(limit)
    elif command == "send-mailbox-message":
        if len(sys.argv) < 5:
            result = {"error": SERVER_MESSAGES['api_usage_send_mailbox_message']}
        else:
            result = send_mailbox_message(sys.argv[2], sys.argv[3], sys.argv[4])
    elif command == "delete-mailbox-message":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_delete_mailbox_message']}
        else:
            result = delete_mailbox_message(sys.argv[2])

    # Search
    elif command == "search-nicknames":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_search_nicknames']}
        else:
            result = search_registered_nicks(sys.argv[2])
    elif command == "search-channels":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_search_channels']}
        else:
            result = search_channels(sys.argv[2])

    # Configuration
    elif command == "config":
        result = get_server_config()
    elif command == "get-config":
        result = get_config()
    elif command == "full-config":
        result = get_full_config()
    elif command == "set-config":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_set_config']}
        else:
            result = set_config(sys.argv[2])

    # MOTD
    elif command == "get-motd":
        result = get_motd()
    elif command == "set-motd":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_set_motd']}
        else:
            result = set_motd(sys.argv[2])

    # Logs
    elif command == "logs":
        lines = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        level = sys.argv[3] if len(sys.argv) > 3 else None
        search_term = sys.argv[4] if len(sys.argv) > 4 else None
        result = get_logs(lines, level, search_term)
    elif command == "connection-sessions":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 250
        search_term = sys.argv[3] if len(sys.argv) > 3 else None
        result = get_connection_sessions(limit, search_term)
    elif command == "service-status":
        result = get_service_status()
    elif command == "service-control":
        if len(sys.argv) < 3:
            result = {"error": "Invalid service action"}
        else:
            result = control_service(sys.argv[2])

    # Staff management
    elif command == "add-staff":
        if len(sys.argv) < 5:
            result = {"error": SERVER_MESSAGES['api_usage_add_staff']}
        else:
            realname = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
            email = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None
            force_realname = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] == '1' else False
            result = add_staff(sys.argv[2], sys.argv[3], sys.argv[4], realname, email, force_realname)
    elif command == "add-staff-stdin":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_add_staff']}
        else:
            realname = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
            email = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
            force_realname = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] == '1' else False
            result = add_staff_stdin(sys.argv[2], sys.argv[3], realname, email, force_realname)
    elif command == "delete-staff":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_delete_staff']}
        else:
            result = delete_staff(sys.argv[2])
    elif command == "change-staff-password":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_change_staff_password']}
        else:
            result = change_staff_password(sys.argv[2], sys.argv[3])
    elif command == "change-staff-password-stdin":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_change_staff_password']}
        else:
            result = change_staff_password_stdin(sys.argv[2])
    elif command == "change-staff-level":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_change_staff_level']}
        else:
            result = change_staff_level(sys.argv[2], sys.argv[3])
    elif command == "update-staff-profile":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_update_staff_profile']}
        else:
            realname = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
            email = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
            force_realname = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] == '1' else False
            result = update_staff_profile(sys.argv[2], realname, email, force_realname)

    # Nickname and channel registration
    elif command == "register-nick":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_register_nick']}
        else:
            email = sys.argv[4] if len(sys.argv) > 4 else None
            result = register_nickname(sys.argv[2], sys.argv[3], email)
    elif command == "register-nick-stdin":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_register_nick']}
        else:
            email = sys.argv[3] if len(sys.argv) > 3 else None
            result = register_nickname_stdin(sys.argv[2], email)
    elif command == "register-channel":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_register_channel']}
        else:
            result = register_channel(sys.argv[2], sys.argv[3])
    elif command == "unregister-nick":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_unregister_nick']}
        else:
            result = unregister_nickname(sys.argv[2])
    elif command == "unregister-channel":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_unregister_channel']}
        else:
            result = unregister_channel(sys.argv[2])
    elif command == "edit-nick":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_edit_nick']}
        else:
            new_password = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
            new_email = sys.argv[4] if len(sys.argv) > 4 else None
            result = edit_nickname(sys.argv[2], new_password, new_email)
    elif command == "edit-nick-stdin":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_edit_nick']}
        else:
            new_email = sys.argv[3] if len(sys.argv) > 3 else None
            result = edit_nickname_stdin(sys.argv[2], new_email)
    elif command == "reset-mfa":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_reset_mfa']}
        else:
            result = reset_mfa(sys.argv[2])
    elif command == "test-identify":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_test_identify']}
        else:
            result = test_identify(sys.argv[2], sys.argv[3])
    elif command == "test-staff-login":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_test_staff_login']}
        else:
            result = test_staff_login(sys.argv[2], sys.argv[3])
    elif command == "test-staff-login-stdin":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_test_staff_login_stdin']}
        else:
            result = test_staff_login_stdin(sys.argv[2])
    elif command == "get-staff-details":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_get_staff_details']}
        else:
            result = get_staff_details(sys.argv[2])
    elif command == "edit-channel":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_edit_channel']}
        else:
            new_owner = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
            new_description = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
            new_topic = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
            new_modes = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None
            new_onjoin = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else None
            new_onpart = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] else None
            new_memberkey = sys.argv[9] if len(sys.argv) > 9 and sys.argv[9] else None
            new_hostkey = sys.argv[10] if len(sys.argv) > 10 and sys.argv[10] else None
            new_ownerkey = sys.argv[11] if len(sys.argv) > 11 and sys.argv[11] else None
            new_voicekey = sys.argv[12] if len(sys.argv) > 12 and sys.argv[12] else None
            new_userlimit = sys.argv[13] if len(sys.argv) > 13 and sys.argv[13] else None
            result = edit_channel(sys.argv[2], new_owner, new_description, new_topic, new_modes,
                                new_onjoin, new_onpart, new_memberkey, new_hostkey, new_ownerkey, new_voicekey, new_userlimit)
    elif command == "list-nicknames-paginated":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        result = get_registered_nicks_paginated(limit, offset)
    elif command == "list-channels-paginated":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        result = get_registered_channels_paginated(limit, offset)
    elif command == "get-channel-access":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_get_channel_access']}
        else:
            result = get_channel_access(sys.argv[2])
    elif command == "get-channel-details":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_get_channel_details']}
        else:
            result = get_channel_details(sys.argv[2])
    elif command == "set-channel-access":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_set_channel_access']}
        else:
            result = set_channel_access(sys.argv[2], sys.argv[3])

    # Legacy commands
    elif command == "recent-registrations":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        result = get_recent_registrations(limit)
    elif command == "channels":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        result = get_registered_channels(limit)
    elif command == "staff":
        result = get_staff_list()
    elif command == "services" or command == "list-services":
        result = get_services_list()
    elif command == "kill-user":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_kill_user']}
        else:
            nickname = sys.argv[2]
            reason = sys.argv[3] if len(sys.argv) > 3 else SERVER_MESSAGES['api_kill_default_reason']
            result = send_irc_kill_user(nickname, reason)
    elif command == "ban-user":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_ban_user']}
        else:
            nickname = sys.argv[2]
            duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
            reason = sys.argv[4] if len(sys.argv) > 4 else SERVER_MESSAGES['api_ban_default_reason']
            result = send_irc_ban_user(nickname, reason, duration)
    elif command == "kill-channel":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_kill_channel']}
        else:

            channel = sys.argv[2]
            result = send_irc_kill_channel(channel)
    elif command == "lock-channel":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_lock_channel']}
        else:
            channel = sys.argv[2]
            owner = sys.argv[3] if len(sys.argv) > 3 else "System"
            result = send_irc_lock_channel(channel, owner)

    elif command == "set-channel-mode":
        if len(sys.argv) < 4:
            result = {"error": SERVER_MESSAGES['api_usage_set_channel_mode']}
        else:
            channel = sys.argv[2]
            mode_string = sys.argv[3]
            result = set_channel_mode(channel, mode_string)

    elif command == "set-channel-topic":
        if len(sys.argv) < 3:
            result = {"error": SERVER_MESSAGES['api_usage_set_channel_topic']}
        else:
            channel = sys.argv[2]
            topic = sys.argv[3] if len(sys.argv) > 3 else ""
            result = set_channel_topic(channel, topic)


    else:
        result = {"error": SERVER_MESSAGES['api_unknown_command'].format(command=command)}

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
