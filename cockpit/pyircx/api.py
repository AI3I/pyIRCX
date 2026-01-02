#!/usr/bin/env python3
"""
pyIRCX Management API
Provides comprehensive data access and management for Cockpit web interface
"""

import sqlite3
import json
import sys
import os
import time
import re
import hashlib
from pathlib import Path
from datetime import datetime

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

# ============================================================================
# DATABASE STATISTICS
# ============================================================================

def get_server_stats():
    """Get server statistics from database"""
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

        # Count server access entries (bans/glines)
        cursor.execute("SELECT COUNT(*) as count, type FROM server_access GROUP BY type")
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
    """Add a server access rule (ban/gline)"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        set_at = int(time.time())
        timeout_val = int(timeout) if timeout else 0

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
    """Search registered channels"""
    db_path = get_db_path()

    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT rc.channel_name, rc.registered_at, rc.last_used, rn.nickname as owner
            FROM registered_channels rc
            LEFT JOIN registered_nicks rn ON rc.owner_uuid = rn.uuid
            WHERE rc.channel_name LIKE ?
            ORDER BY rc.channel_name
            LIMIT 50
        """, (f"%{query}%",))

        results = []
        for row in cursor.fetchall():
            results.append({
                'name': row['channel_name'],
                'owner': row['owner'] if row['owner'] else 'Unknown',
                'registered_at': row['registered_at'],
                'last_used': row['last_used']
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
            SELECT rc.channel_name, rc.registered_at, rc.last_used, rn.nickname as owner
            FROM registered_channels rc
            LEFT JOIN registered_nicks rn ON rc.owner_uuid = rn.uuid
            ORDER BY rc.last_used DESC
            LIMIT ?
        """, (limit,))

        channels = []
        for row in cursor.fetchall():
            channels.append({
                'name': row['channel_name'],
                'owner': row['owner'] if row['owner'] else 'Unknown',
                'registered_at': row['registered_at'],
                'last_used': row['last_used'] if row['last_used'] else None
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
            SELECT username, level
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
            staff.append({
                'username': row['username'],
                'level': row['level']
            })

        conn.close()
        return staff

    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# STAFF MANAGEMENT
# ============================================================================

def add_staff(username, password, level):
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
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Insert new staff member
        cursor.execute("""
            INSERT INTO users (username, password, level)
            VALUES (?, ?, ?)
        """, (username, password_hash, level))

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
        password_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        # Update password
        cursor.execute("""
            UPDATE users SET password = ? WHERE username = ?
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
    """Get server logs with optional filtering"""
    try:
        if not os.path.exists(DEFAULT_LOG):
            return {"error": "Log file not found"}

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
            'line_count': len(log_lines)
        }

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

    # Mailbox
    elif command == "mailbox-list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        result = get_mailbox_messages(limit)

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
    elif command == "full-config":
        result = get_full_config()
    elif command == "set-config":
        if len(sys.argv) < 3:
            result = {"error": "Usage: set-config <json>"}
        else:
            result = set_config(sys.argv[2])

    # Logs
    elif command == "logs":
        lines = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        level = sys.argv[3] if len(sys.argv) > 3 else None
        search_term = sys.argv[4] if len(sys.argv) > 4 else None
        result = get_logs(lines, level, search_term)

    # Staff management
    elif command == "add-staff":
        if len(sys.argv) < 5:
            result = {"error": "Usage: add-staff <username> <password> <level>"}
        else:
            result = add_staff(sys.argv[2], sys.argv[3], sys.argv[4])
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

    # Legacy commands
    elif command == "recent-registrations":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        result = get_recent_registrations(limit)
    elif command == "channels":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        result = get_registered_channels(limit)
    elif command == "staff":
        result = get_staff_list()

    else:
        result = {"error": f"Unknown command: {command}"}

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
