#!/usr/bin/env python3
"""
pyIRCX Management API
Provides comprehensive data access and management for web administration

Copyright (C) 2026 John D. Lewis

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sqlite3
import json
import sys
import os
import time
import re
import hashlib
import bcrypt
import socket
from pathlib import Path
from datetime import datetime
import logging

# Import connection pool and helpers
import db_pool
from api_helpers import (
    api_error_handler,
    validate_access_type,
    validate_pattern,
    validate_timeout,
    validate_nickname,
    validate_channel_name,
    validate_staff_level
)

# Setup logging
logger = logging.getLogger(__name__)

# Default paths - check system install location first, then user home
# System installation paths (from install.sh)
SYSTEM_CONFIG = "/etc/pyircx/pyircx_config.json"
SYSTEM_INSTALL = "/opt/pyircx"

# User installation paths (for manual/development installations)
USER_CONFIG = os.path.expanduser("~/pyIRCX/pyircx_config.json")
USER_INSTALL = os.path.expanduser("~/pyIRCX")

# Determine which installation is active
if os.path.exists(SYSTEM_CONFIG):
    # System installation detected
    DEFAULT_CONFIG = SYSTEM_CONFIG
    DEFAULT_DB = os.path.join(SYSTEM_INSTALL, "pyircx.db")
    DEFAULT_LOG = os.path.join(SYSTEM_INSTALL, "pyircx.log")
    DEFAULT_STATUS = os.path.join(SYSTEM_INSTALL, "pyircx_status.json")
else:
    # Fall back to user installation
    DEFAULT_CONFIG = USER_CONFIG
    DEFAULT_DB = os.path.join(USER_INSTALL, "pyircx.db")
    DEFAULT_LOG = os.path.join(USER_INSTALL, "pyircx.log")
    DEFAULT_STATUS = os.path.join(USER_INSTALL, "pyircx_status.json")

def load_config():
    """Load pyIRCX configuration"""
    try:
        with open(DEFAULT_CONFIG, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {}

def save_config(config):
    """Save pyIRCX configuration"""
    try:
        with open(DEFAULT_CONFIG, 'w') as f:
            json.dump(config, f, indent=2)
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}

def get_motd():
    """Get MOTD (Message of the Day) from configuration"""
    try:
        config = load_config()
        if 'server' in config and 'motd' in config['server']:
            motd = config['server']['motd']
            # Return as array of lines
            if isinstance(motd, str):
                return {"motd": [motd]}
            return {"motd": motd}
        # Return empty MOTD if not configured (default should be in config file)
        return {"motd": []}
    except Exception as e:
        return {"error": str(e)}

def set_motd(motd_lines):
    """Set MOTD (Message of the Day) in configuration"""
    try:
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
        return save_config(config)
    except Exception as e:
        return {"error": str(e)}

def get_db_path():
    """Get database path from config or use default"""
    config = load_config()
    if 'database' in config and 'path' in config['database']:
        db_path = config['database']['path']
        # Handle relative paths
        if not os.path.isabs(db_path):
            # Use the appropriate base directory
            if os.path.exists(SYSTEM_CONFIG):
                db_path = os.path.join(SYSTEM_INSTALL, db_path)
            else:
                db_path = os.path.join(USER_INSTALL, db_path)
        return db_path
    return DEFAULT_DB


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
        logger.info(f"Database connection pool initialized: {db_path} (pool_size={pool_size})")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database pool: {e}")
        return False


# Initialize pool on module import
try:
    init_db_pool()
except Exception as e:
    # If pool init fails, log but don't crash - will fall back to direct connections
    logger.warning(f"Connection pool initialization failed: {e}")


# ============================================================================
# REAL-TIME STATUS
# ============================================================================

def get_realtime_status():
    """Get real-time connected users and active channels from status dump"""
    try:
        if not os.path.exists(DEFAULT_STATUS):
            return {"error": "Status file not found. Server may not be running."}

        with open(DEFAULT_STATUS, 'r') as f:
            status = json.load(f)

        # Calculate age of status
        age = time.time() - status.get('timestamp', 0)
        status['status_age'] = age

        return status

    except Exception as e:
        return {"error": str(e)}

def get_services_list():
    """Get list of network services and ServiceBots with their status"""
    try:
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

                # Update service channel lists based on active channels
                all_services = core_services + servicebots
                for channel_data in status.get('active_channels', []):
                    channel_name = channel_data.get('name')
                    members = channel_data.get('members', [])

                    # Check if any services are in this channel
                    for service in all_services:
                        # Note: status file only shows real users, not virtual ones
                        # So we can't get actual service presence, only maintain the default lists
                        pass

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

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# IRC SERVER COMMUNICATION
# ============================================================================

def send_irc_kill_channel(channel_name):
    """Kill a channel by writing to pyircx admin command queue
    
    Args:
        channel_name: Channel to kill (e.g. '#pyIRCX')
        
    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'
        
        # Append command to queue file
        with open(cmd_file, 'a') as f:
            f.write(f"KILL_CHANNEL:{channel_name}\n")
        
        return {"success": True, "message": f"Channel {channel_name} will be reset"}

    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

def send_irc_kill_user(nickname, reason="Killed by administrator"):
    """Kill a user connection by writing to pyircx admin command queue

    Args:
        nickname: Nickname to kill
        reason: Kill reason (optional)

    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'

        # Append command to queue file
        with open(cmd_file, 'a') as f:
            f.write(f"KILL_USER:{nickname}:{reason}\n")

        return {"success": True, "message": f"User {nickname} will be disconnected"}

    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

def send_irc_ban_user(nickname, reason="Banned by administrator", duration=3600):
    """Ban a user (K-Line) by writing to pyircx admin command queue

    Args:
        nickname: Nickname to ban
        reason: Ban reason (optional)
        duration: Ban duration in seconds (default: 1 hour)

    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'

        # Append command to queue file - format: BAN_USER:nickname:duration:reason
        with open(cmd_file, 'a') as f:
            f.write(f"BAN_USER:{nickname}:{duration}:{reason}\n")

        return {"success": True, "message": f"User {nickname} will be banned for {duration} seconds"}

    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

def send_irc_lock_channel(channel_name, owner="System"):
    """Lock a channel (register + set auth-only) by writing to pyircx admin command queue

    Args:
        channel_name: Channel to lock (e.g. '#channel')
        owner: Owner for the channel (staff username or registered nickname)

    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'

        # Append command to queue file - format: LOCK_CHANNEL:channel:owner
        with open(cmd_file, 'a') as f:
            f.write(f"LOCK_CHANNEL:{channel_name}:{owner}\n")

        return {"success": True, "message": f"Channel {channel_name} will be locked and registered to {owner}"}

    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

def set_channel_mode(channel_name, mode_string):
    """Set channel mode via admin command queue
    
    Args:
        channel_name: Channel name (e.g., #channel)
        mode_string: Mode string (e.g., "+z" or "-z")
    
    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'
        with open(cmd_file, 'a') as f:
            f.write(f"SET_CHANNEL_MODE:{channel_name}:{mode_string}\n")
        return {"success": True, "message": f"Mode {mode_string} will be set on {channel_name}"}
    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

def set_channel_topic(channel_name, topic):
    """Set channel topic via admin command queue
    
    Args:
        channel_name: Channel name (e.g., #channel)
        topic: New topic (empty string to clear)
    
    Returns:
        dict with success/error status
    """
    try:
        cmd_file = '/opt/pyircx/admin_commands.queue'
        with open(cmd_file, 'a') as f:
            f.write(f"SET_CHANNEL_TOPIC:{channel_name}:{topic}\n")
        return {"success": True, "message": f"Topic will be set on {channel_name}"}
    except Exception as e:
        return {"error": f"Failed to write admin command: {str(e)}"}

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

def get_server_stats():
    """Get server statistics from database and runtime status"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}. The database is created when pyIRCX starts for the first time. Please start the service: systemctl start pyircx"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        # Count server access entries (bans/glines) - exclude expired
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

        conn.close()

        # Read runtime status from JSON file
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

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# BAN/GLINE MANAGEMENT
# ============================================================================

def get_server_access_list():
    """Get all server access rules (bans/glines)"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return rules

    except Exception as e:
        return {"error": str(e)}

def add_server_access(access_type, pattern, set_by, reason, timeout=0):
    """Add a server access rule (ban/gline)
    
    Args:
        timeout: Duration in minutes (0 = permanent), will be converted to absolute timestamp
    """
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
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

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Added {access_type} for {pattern}"}

    except Exception as e:
        return {"error": str(e)}

def remove_server_access(access_type, pattern):
    """Remove a server access rule"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM server_access WHERE type = ? AND pattern = ?
        """, (access_type, pattern))

        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()

        if rows_affected > 0:
            return {"success": True, "message": f"Removed {access_type} for {pattern}"}
        else:
            return {"error": "Rule not found"}

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# NEWSFLASH MANAGEMENT
# ============================================================================

def get_newsflash_list():
    """Get all newsflash messages"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return newsflash

    except Exception as e:
        return {"error": str(e)}

def add_newsflash(message, created_by, priority=0):
    """Add a newsflash message"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        created_at = int(time.time())

        cursor.execute("""
            INSERT INTO newsflash (message, created_by, created_at, priority)
            VALUES (?, ?, ?, ?)
        """, (message, created_by, created_at, priority))

        conn.commit()
        conn.close()

        return {"success": True, "message": "NewsFlash added"}

    except Exception as e:
        return {"error": str(e)}

def delete_newsflash(msg_id):
    """Delete a newsflash message"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM newsflash WHERE id = ?", (int(msg_id),))

        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()

        if rows_affected > 0:
            return {"success": True, "message": "NewsFlash deleted"}
        else:
            return {"error": "NewsFlash not found"}

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# MAILBOX VIEWING
# ============================================================================

def get_mailbox_messages(limit=50):
    """Get recent mailbox messages"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return messages

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# SEARCH FUNCTIONS
# ============================================================================

def search_registered_nicks(query):
    """Search registered nicknames"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return results

    except Exception as e:
        return {"error": str(e)}

def search_channels(query):
    """Search registered channels from registered_channels table"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return results

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# EXISTING FUNCTIONS (keeping for compatibility)
# ============================================================================

def get_recent_registrations(limit=10):
    """Get recently registered nicknames"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return registrations

    except Exception as e:
        return {"error": str(e)}

def get_registered_channels(limit=50):
    """Get registered channels"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return channels

    except Exception as e:
        return {"error": str(e)}

def get_staff_list():
    """Get list of staff users"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

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

        staff = []
        for row in cursor.fetchall():
            username = row['username']
            
            # Get all nicknames owned by this staff member
            cursor.execute(
                "SELECT nickname FROM registered_nicks WHERE registered_by = ? ORDER BY registered_at DESC",
                (username,)
            )
            owned_nicknames = [r['nickname'] for r in cursor.fetchall()]
            
            staff.append({
                'username': username,
                'level': row['level'],
                'created_at': row['created_at'],
                'last_login': row['last_login'],
                'owned_nicknames': owned_nicknames,
                'email': row['email'],
                'realname': row['realname'],
                'force_realname': bool(row['force_realname'])
            })

        conn.close()
        return staff

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# STAFF MANAGEMENT
# ============================================================================

def add_staff(username, password, level, realname=None, email=None, force_realname=False):
    """Add a new staff member"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    # Validate level
    if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
        return {"error": "Invalid staff level. Must be ADMIN, SYSOP, or GUIDE"}

    # Validate username
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return {"error": "Username must be 3-20 characters (letters, numbers, _, -)"}

    # Validate password strength
    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return {"error": f"Staff member '{username}' already exists"}

        # Hash password (same method as pyircx.py uses)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert new staff member
        cursor.execute("""
            INSERT INTO users (username, password_hash, level, realname, email, force_realname)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, password_hash, level, realname, email, 1 if force_realname else 0))

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Staff member '{username}' added as {level}"}

    except Exception as e:
        return {"error": str(e)}

def delete_staff(username):
    """Delete a staff member"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            conn.close()
            return {"error": f"Staff member '{username}' not found"}

        # Delete staff member
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))

        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()

        if rows_affected > 0:
            return {"success": True, "message": f"Staff member '{username}' deleted"}
        else:
            return {"error": "Failed to delete staff member"}

    except Exception as e:
        return {"error": str(e)}

def change_staff_password(username, new_password):
    """Change a staff member's password"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    # Validate password strength
    if len(new_password) < 8:
        return {"error": "Password must be at least 8 characters"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            conn.close()
            return {"error": f"Staff member '{username}' not found"}

        # Hash password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update password
        cursor.execute("""
            UPDATE users SET password_hash = ? WHERE username = ?
        """, (password_hash, username))

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Password changed for '{username}'"}

    except Exception as e:
        return {"error": str(e)}

def change_staff_level(username, new_level):
    """Change a staff member's privilege level"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    # Validate level
    if new_level not in ['ADMIN', 'SYSOP', 'GUIDE']:
        return {"error": "Invalid staff level. Must be ADMIN, SYSOP, or GUIDE"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            conn.close()
            return {"error": f"Staff member '{username}' not found"}

        # Update level
        cursor.execute("""
            UPDATE users SET level = ? WHERE username = ?
        """, (new_level, username))

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Level changed for '{username}' to {new_level}"}

    except Exception as e:
        return {"error": str(e)}

def update_staff_profile(username, realname=None, email=None, force_realname=None):
    """Update staff member's profile information (realname and email)"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            conn.close()
            return {"error": f"Staff member '{username}' not found"}

        # Update profile fields
        cursor.execute("""
            UPDATE users SET realname = ?, email = ?, force_realname = ?
            WHERE username = ?
        """, (realname, email, 1 if force_realname else 0, username))

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Profile updated for '{username}'"}

    except Exception as e:
        return {"error": str(e)}


def get_server_config():
    """Get server configuration"""
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

def get_full_config():
    """Get full configuration for editing"""
    return load_config()

def set_config(config_json):
    """Set configuration from JSON string"""
    try:
        config = json.loads(config_json)
        return save_config(config)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {str(e)}"}

# ============================================================================
# LOG FUNCTIONS
# ============================================================================

def get_logs(lines=100, level_filter=None, search=None):
    """Get server logs from journalctl (systemd) or log file"""
    try:
        # Try to get logs from journalctl (systemd journal) first
        import subprocess
        
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
            return {"error": "No logs available (journalctl failed and log file not found)"}

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

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# NEWSFLASH SETTINGS
# ============================================================================

def get_newsflash_settings():
    """Get newsflash broadcast settings"""
    config = load_config()
    newsflash = config.get('newsflash', {})
    return {
        'on_connect': newsflash.get('on_connect', False),
        'periodic_enabled': newsflash.get('periodic_enabled', False),
        'periodic_interval': newsflash.get('periodic_interval', 30)
    }

def set_newsflash_settings(on_connect, periodic_enabled, periodic_interval):
    """Set newsflash broadcast settings"""
    try:
        config = load_config()
        if 'newsflash' not in config:
            config['newsflash'] = {}
        
        config['newsflash']['on_connect'] = on_connect == 'true' or on_connect == True
        config['newsflash']['periodic_enabled'] = periodic_enabled == 'true' or periodic_enabled == True
        config['newsflash']['periodic_interval'] = int(periodic_interval)
        
        result = save_config(config)
        if 'error' in result:
            return result
        return {"success": True, "message": "NewsFlash settings updated"}
    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# NICKNAME AND CHANNEL REGISTRATION
# ============================================================================

def register_nickname(nickname, password, email=None):
    """Register a new nickname"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    # Validate nickname
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_\-\[\]\\`\^\{\}]{0,29}$', nickname):
        return {"error": "Invalid nickname format. Must start with a letter and be 1-30 characters."}

    # Validate password strength
    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}

    # Validate email if provided
    if email and email != '*':
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return {"error": "Invalid email address"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if nickname already exists
        cursor.execute("SELECT nickname FROM registered_nicks WHERE nickname = ?", (nickname,))
        if cursor.fetchone():
            conn.close()
            return {"error": f"Nickname '{nickname}' is already registered"}

        # Generate UUID and hash password
        import uuid
        nick_uuid = str(uuid.uuid4())
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        now = int(time.time())

        # Set email (None if '*' was provided)
        email_val = email if email and email != '*' else None

        # Insert new nickname
        cursor.execute("""
            INSERT INTO registered_nicks (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (nick_uuid, nickname, password_hash, email_val, now, now, "API Admin"))

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Nickname '{nickname}' registered successfully"}

    except Exception as e:
        return {"error": str(e)}

# Reserved service names (from pyircx.py)
RESERVED_SERVICES = {
    'operserv', 'helpserv', 'infoserv', 'nickserv', 'chanserv', 'memoserv',
    'botserv', 'hostserv', 'statserv', 'global', 'alis', 'services',
    'system', 'registrar', 'messenger', 'newsflash'
}

def register_channel(channel_name, owner_nickname, topic=None, modes=None, onjoin=None, onpart=None,
                     memberkey=None, hostkey=None, ownerkey=None, description=None):
    """Register a new channel (simplified to match actual database schema)"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    # Validate channel name
    if not re.match(r'^[#&][a-zA-Z0-9_\-]+$', channel_name):
        return {"error": "Invalid channel name. Must start with # or & and contain only letters, numbers, _, -"}

    try:
        import uuid as uuid_mod
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if channel already exists
        cursor.execute("SELECT channel_name FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        if cursor.fetchone():
            conn.close()
            return {"error": f"Channel '{channel_name}' is already registered"}

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

                owner_uuid = service_uuid
            else:
                conn.close()
                return {"error": f"Owner '{owner_nickname}' not found. Valid options: registered nickname, staff username (ADMIN/SYSOP/GUIDE), or service name (System, Registrar, Messenger, NickServ, ChanServ, etc.)"}
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

        conn.commit()
        conn.close()

        return {"success": True, "message": f"Channel '{channel_name}' registered successfully to {owner_nickname}"}

    except Exception as e:
        return {"error": str(e)}


def unregister_nickname(nickname):
    """Unregister a nickname"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()

        if not nick_row:
            conn.close()
            return {"error": f"Nickname '{nickname}' is not registered"}

        nick_uuid = nick_row[0]

        # Check if this nickname owns any channels
        cursor.execute("SELECT COUNT(*) as count FROM registered_channels WHERE owner_uuid = ?", (nick_uuid,))
        channel_count = cursor.fetchone()[0]

        if channel_count > 0:
            conn.close()
            return {"error": f"Cannot unregister '{nickname}': owns {channel_count} registered channel(s). Unregister channels first."}

        # Delete the nickname
        cursor.execute("DELETE FROM registered_nicks WHERE uuid = ?", (nick_uuid,))
        conn.commit()
        conn.close()

        return {"success": True, "message": f"Nickname '{nickname}' has been unregistered"}

    except Exception as e:
        return {"error": str(e)}

def edit_nickname(nickname, new_password=None, new_email=None):
    """Edit a registered nickname's password and/or email"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    if not new_password and new_email is None:
        return {"error": "No changes specified. Provide new_password and/or new_email."}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()

        if not nick_row:
            conn.close()
            return {"error": f"Nickname '{nickname}' is not registered"}

        nick_uuid = nick_row[0]
        updates = []
        params = []

        # Update password if provided
        if new_password:
            if len(new_password) < 8:
                conn.close()
                return {"error": "Password must be at least 8 characters"}
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            updates.append("password_hash = ?")
            params.append(password_hash)

        # Update email if provided (empty string means clear email)
        if new_email is not None:
            if new_email == "" or new_email == "*":
                updates.append("email = NULL")
            else:
                # Validate email
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
                    conn.close()
                    return {"error": "Invalid email address"}
                updates.append("email = ?")
                params.append(new_email)

        # Build and execute UPDATE query
        params.append(nick_uuid)
        query = f"UPDATE registered_nicks SET {', '.join(updates)} WHERE uuid = ?"
        cursor.execute(query, params)

        conn.commit()
        conn.close()

        changes = []
        if new_password:
            changes.append("password")
        if new_email is not None:
            changes.append("email")

        return {"success": True, "message": f"Updated {' and '.join(changes)} for nickname '{nickname}'"}

    except Exception as e:
        return {"error": str(e)}

def reset_mfa(nickname):
    """Reset MFA for a nickname (admin function)"""
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if nickname exists
        cursor.execute("SELECT uuid FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        nick_row = cursor.fetchone()
        
        if not nick_row:
            conn.close()
            return {"error": f"Nickname '{nickname}' is not registered"}
        
        # Reset MFA
        cursor.execute(
            "UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE LOWER(nickname) = LOWER(?)",
            (nickname,)
        )
        conn.commit()
        conn.close()
        
        return {"success": True, "message": f"MFA disabled for '{nickname}'"}
    
    except Exception as e:
        return {"error": str(e)}

def test_identify(nickname, password):
    """Test if a nickname/password combination is valid"""
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get password hash
        cursor.execute(
            "SELECT password_hash, mfa_enabled FROM registered_nicks WHERE LOWER(nickname) = LOWER(?)",
            (nickname,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"success": False, "message": "Nickname not registered"}
        
        password_hash, mfa_enabled = row
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            if mfa_enabled:
                return {"success": True, "message": "Password correct (MFA required for login)", "mfa_required": True}
            else:
                return {"success": True, "message": "Password correct (authentication would succeed)", "mfa_required": False}
        else:
            return {"success": False, "message": "Password incorrect"}
    
    except Exception as e:
        return {"error": str(e)}

def test_staff_login(username, password):
    """Test if a staff username/password combination is valid"""
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get password hash and level
        cursor.execute(
            "SELECT password_hash, level FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"success": False, "message": "Staff account not found"}
        
        password_hash, level = row
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return {"success": True, "message": f"Password correct (Level: {level})", "level": level}
        else:
            return {"success": False, "message": "Password incorrect"}
    
    except Exception as e:
        return {"error": str(e)}

def test_staff_login_stdin(username):
    """Test if a staff username/password combination is valid (password from stdin)"""
    # Read password from stdin (more secure for web interface)
    password = sys.stdin.read().strip()

    # Use the existing test_staff_login function
    return test_staff_login(username, password)

def get_staff_details(username):
    """Get detailed staff information including owned nicknames"""
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get staff details
        cursor.execute(
            "SELECT username, level, created_at, last_login, email, realname, force_realname FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return {"error": f"Staff account '{username}' not found"}
        
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
        
        conn.close()
        return {"success": True, "staff": details}
        
    except Exception as e:
        return {"error": str(e)}

def unregister_channel(channel_name):
    """Unregister a channel"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if channel exists
        cursor.execute("SELECT uuid FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        chan_row = cursor.fetchone()

        if not chan_row:
            conn.close()
            return {"error": f"Channel '{channel_name}' is not registered"}

        # Delete the channel
        cursor.execute("DELETE FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        conn.commit()
        conn.close()

        return {"success": True, "message": f"Channel '{channel_name}' has been unregistered"}

    except Exception as e:
        return {"error": str(e)}

def edit_channel(channel_name, new_owner=None, new_description=None, new_topic=None, new_modes=None,
                 new_onjoin=None, new_onpart=None, new_memberkey=None, new_hostkey=None, new_ownerkey=None, new_voicekey=None, new_userlimit=None):
    """Edit a registered channel's properties by updating registered_channels table"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Load channel data from registered_channels (JSON format in properties column)
        cursor.execute("SELECT properties, owner_uuid, description FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return {"error": f"Channel '{channel_name}' is not registered"}

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
                conn.close()
                return {"error": f"Owner nickname '{new_owner}' not found"}

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
            conn.close()
            return {"error": "No changes were made"}

        # Save back to registered_channels
        cursor.execute("""UPDATE registered_channels
                         SET properties = ?, owner_uuid = ?, description = ?, last_used = ?
                         WHERE LOWER(channel_name) = LOWER(?)""",
                      (json.dumps(channel_data), new_owner_uuid, new_description_val, int(time.time()), channel_name))

        conn.commit()
        conn.close()

        # Kill channel to force reload from database
        kill_result = send_irc_kill_channel(channel_name)

        message = f"Updated {', '.join(changes)} for channel '{channel_name}'"
        if kill_result.get("success"):
            message += " (channel will reload)"

        return {"success": True, "message": message}

    except Exception as e:
        return {"error": f"Failed to update channel: {str(e)}"}

def get_registered_nicks_paginated(limit=50, offset=0):
    """Get registered nicknames with pagination"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return {"data": nicknames, "total": total}

    except Exception as e:
        return {"error": str(e)}

def get_registered_channels_paginated(limit=50, offset=0):
    """Get registered channels with pagination"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
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

        conn.close()
        return {"data": channels, "total": total}

    except Exception as e:
        return {"error": str(e)}


def get_channel_details(channel_name):
    """Get detailed channel information for editing"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Load from registered_channels
        cursor.execute("SELECT properties FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return {"error": f"Channel '{channel_name}' not found"}

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

        conn.close()
        return {"success": True, "channel": details}

    except Exception as e:
        return {"error": str(e)}

def get_channel_access(channel_name):
    """Get ACCESS lists for a channel"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
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

        conn.close()
        return {"access_list": access_list}

    except Exception as e:
        return {"error": str(e)}

def set_channel_access(channel_name, access_list_json):
    """Set ACCESS lists for a channel"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        access_list = json.loads(access_list_json)

        conn = sqlite3.connect(db_path)
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
            conn.close()
            return {"error": f"Channel '{channel_name}' is not registered. Register it first."}

        conn.commit()
        conn.close()

        # Kill channel to force reload from database
        send_irc_kill_channel(channel_name)

        return {"success": True, "message": f"ACCESS lists updated for {channel_name}"}

    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# MAIN COMMAND DISPATCHER
# ============================================================================

def main():
    """Main entry point for API calls"""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command specified"}))
        sys.exit(1)

    command = sys.argv[1]
    result = None

    # Real-time status
    if command == "realtime-status":
        result = get_realtime_status()

    # Statistics
    elif command == "stats":
        result = get_server_stats()

    # Ban/Gline management
    elif command == "server-access-list":
        result = get_server_access_list()
    elif command == "add-server-access":
        if len(sys.argv) < 6:
            result = {"error": "Usage: add-server-access <type> <pattern> <set_by> <reason> [timeout]"}
        else:
            timeout = int(sys.argv[6]) if len(sys.argv) > 6 else 0
            result = add_server_access(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], timeout)
    elif command == "remove-server-access":
        if len(sys.argv) < 4:
            result = {"error": "Usage: remove-server-access <type> <pattern>"}
        else:
            result = remove_server_access(sys.argv[2], sys.argv[3])

    # Newsflash management
    elif command == "newsflash-list":
        result = get_newsflash_list()
    elif command == "add-newsflash":
        if len(sys.argv) < 4:
            result = {"error": "Usage: add-newsflash <message> <created_by> [priority]"}
        else:
            priority = int(sys.argv[4]) if len(sys.argv) > 4 else 0
            result = add_newsflash(sys.argv[2], sys.argv[3], priority)
    elif command == "delete-newsflash":
        if len(sys.argv) < 3:
            result = {"error": "Usage: delete-newsflash <id>"}
        else:
            result = delete_newsflash(sys.argv[2])
    elif command == "newsflash-settings":
        result = get_newsflash_settings()
    elif command == "set-newsflash-settings":
        if len(sys.argv) < 5:
            result = {"error": "Usage: set-newsflash-settings <on_connect> <periodic_enabled> <periodic_interval>"}
        else:
            result = set_newsflash_settings(sys.argv[2], sys.argv[3], sys.argv[4])

    # Mailbox
    elif command == "mailbox-list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        result = get_mailbox_messages(limit)
    elif command == "send-mailbox-message":
        if len(sys.argv) < 5:
            result = {"error": "Usage: send-mailbox-message <sender> <recipient> <message>"}
        else:
            result = send_mailbox_message(sys.argv[2], sys.argv[3], sys.argv[4])

    # Search
    elif command == "search-nicks":
        if len(sys.argv) < 3:
            result = {"error": "Usage: search-nicks <query>"}
        else:
            result = search_registered_nicks(sys.argv[2])
    elif command == "search-channels":
        if len(sys.argv) < 3:
            result = {"error": "Usage: search-channels <query>"}
        else:
            result = search_channels(sys.argv[2])

    # Configuration
    elif command == "config":
        result = get_server_config()
    elif command == "get-config":
        result = {"config": load_config()}
    elif command == "full-config":
        result = get_full_config()
    elif command == "set-config":
        if len(sys.argv) < 3:
            result = {"error": "Usage: set-config <json>"}
        else:
            result = set_config(sys.argv[2])

    # MOTD
    elif command == "get-motd":
        result = get_motd()
    elif command == "set-motd":
        if len(sys.argv) < 3:
            result = {"error": "Usage: set-motd <motd_lines>"}
        else:
            result = set_motd(sys.argv[2])

    # Logs
    elif command == "logs":
        lines = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        level = sys.argv[3] if len(sys.argv) > 3 else None
        search_term = sys.argv[4] if len(sys.argv) > 4 else None
        result = get_logs(lines, level, search_term)

    # Staff management
    elif command == "add-staff":
        if len(sys.argv) < 5:
            result = {"error": "Usage: add-staff <username> <password> <level> [realname] [email] [force_realname]"}
        else:
            realname = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
            email = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None
            force_realname = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] == '1' else False
            result = add_staff(sys.argv[2], sys.argv[3], sys.argv[4], realname, email, force_realname)
    elif command == "delete-staff":
        if len(sys.argv) < 3:
            result = {"error": "Usage: delete-staff <username>"}
        else:
            result = delete_staff(sys.argv[2])
    elif command == "change-staff-password":
        if len(sys.argv) < 4:
            result = {"error": "Usage: change-staff-password <username> <new_password>"}
        else:
            result = change_staff_password(sys.argv[2], sys.argv[3])
    elif command == "change-staff-level":
        if len(sys.argv) < 4:
            result = {"error": "Usage: change-staff-level <username> <new_level>"}
        else:
            result = change_staff_level(sys.argv[2], sys.argv[3])
    elif command == "update-staff-profile":
        if len(sys.argv) < 4:
            result = {"error": "Usage: update-staff-profile <username> <realname> <email> <force_realname>"}
        else:
            realname = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
            email = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
            force_realname = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] == '1' else False
            result = update_staff_profile(sys.argv[2], realname, email, force_realname)

    # Nickname and channel registration
    elif command == "register-nick":
        if len(sys.argv) < 4:
            result = {"error": "Usage: register-nick <nickname> <password> [email]"}
        else:
            email = sys.argv[4] if len(sys.argv) > 4 else None
            result = register_nickname(sys.argv[2], sys.argv[3], email)
    elif command == "register-channel":
        if len(sys.argv) < 4:
            result = {"error": "Usage: register-channel <channel_name> <owner_nickname>"}
        else:
            result = register_channel(sys.argv[2], sys.argv[3])
    elif command == "unregister-nick":
        if len(sys.argv) < 3:
            result = {"error": "Usage: unregister-nick <nickname>"}
        else:
            result = unregister_nickname(sys.argv[2])
    elif command == "unregister-channel":
        if len(sys.argv) < 3:
            result = {"error": "Usage: unregister-channel <channel_name>"}
        else:
            result = unregister_channel(sys.argv[2])
    elif command == "edit-nick":
        if len(sys.argv) < 3:
            result = {"error": "Usage: edit-nick <nickname> <new_password> [new_email]"}
        else:
            new_password = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
            new_email = sys.argv[4] if len(sys.argv) > 4 else None
            result = edit_nickname(sys.argv[2], new_password, new_email)
    elif command == "reset-mfa":
        if len(sys.argv) < 3:
            result = {"error": "Usage: reset-mfa <nickname>"}
        else:
            result = reset_mfa(sys.argv[2])
    elif command == "test-identify":
        if len(sys.argv) < 4:
            result = {"error": "Usage: test-identify <nickname> <password>"}
        else:
            result = test_identify(sys.argv[2], sys.argv[3])
    elif command == "test-staff-login":
        if len(sys.argv) < 4:
            result = {"error": "Usage: test-staff-login <username> <password>"}
        else:
            result = test_staff_login(sys.argv[2], sys.argv[3])
    elif command == "test-staff-login-stdin":
        if len(sys.argv) < 3:
            result = {"error": "Usage: test-staff-login-stdin <username> (password from stdin)"}
        else:
            result = test_staff_login_stdin(sys.argv[2])
    elif command == "get-staff-details":
        if len(sys.argv) < 3:
            result = {"error": "Usage: get-staff-details <username>"}
        else:
            result = get_staff_details(sys.argv[2])
    elif command == "edit-channel":
        if len(sys.argv) < 3:
            result = {"error": "Usage: edit-channel <channel_name> <new_owner> [new_description] [new_topic] [new_modes] [new_onjoin] [new_onpart] [new_memberkey] [new_hostkey] [new_ownerkey] [new_voicekey]"}
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
    elif command == "list-nicks-paginated":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        result = get_registered_nicks_paginated(limit, offset)
    elif command == "list-channels-paginated":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        result = get_registered_channels_paginated(limit, offset)
    elif command == "get-channel-access":
        if len(sys.argv) < 3:
            result = {"error": "Usage: get-channel-access <channel_name>"}
        else:
            result = get_channel_access(sys.argv[2])
    elif command == "get-channel-details":
        if len(sys.argv) < 3:
            result = {"error": "Usage: get-channel-details <channel_name>"}
        else:
            result = get_channel_details(sys.argv[2])
    elif command == "set-channel-access":
        if len(sys.argv) < 4:
            result = {"error": "Usage: set-channel-access <channel_name> <access_list_json>"}
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
            result = {"error": "Usage: kill-user <nickname> [reason]"}
        else:
            nickname = sys.argv[2]
            reason = sys.argv[3] if len(sys.argv) > 3 else "Killed by administrator"
            result = send_irc_kill_user(nickname, reason)
    elif command == "ban-user":
        if len(sys.argv) < 3:
            result = {"error": "Usage: ban-user <nickname> [duration] [reason]"}
        else:
            nickname = sys.argv[2]
            duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
            reason = sys.argv[4] if len(sys.argv) > 4 else "Banned by administrator"
            result = send_irc_ban_user(nickname, reason, duration)
    elif command == "kill-channel":
        if len(sys.argv) < 3:
            result = {"error": "Usage: kill-channel <channel>"}
        else:

            channel = sys.argv[2]
            result = send_irc_kill_channel(channel)
    elif command == "lock-channel":
        if len(sys.argv) < 3:
            result = {"error": "Usage: lock-channel <channel> [owner]"}
        else:
            channel = sys.argv[2]
            owner = sys.argv[3] if len(sys.argv) > 3 else "System"
            result = send_irc_lock_channel(channel, owner)

    elif command == "set-channel-mode":
        if len(sys.argv) < 4:
            result = {"error": "Usage: set-channel-mode <channel> <mode_string>"}
        else:
            channel = sys.argv[2]
            mode_string = sys.argv[3]
            result = set_channel_mode(channel, mode_string)

    elif command == "set-channel-topic":
        if len(sys.argv) < 3:
            result = {"error": "Usage: set-channel-topic <channel> [topic]"}
        else:
            channel = sys.argv[2]
            topic = sys.argv[3] if len(sys.argv) > 3 else ""
            result = set_channel_topic(channel, topic)


    else:
        result = {"error": f"Unknown command: {command}"}

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
