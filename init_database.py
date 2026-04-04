#!/usr/bin/env python3
"""
Database Initialization Script for pyIRCX

Creates a new database with all required tables and default staff accounts (admin/sysop/guide).
Can be used for:
- Fresh installation
- Database repair/regeneration
- Testing environments

IMPORTANT: This script creates tables matching the exact schema expected by pyircx.py.
Do NOT modify the table schemas without also updating pyircx.py.

Usage:
    python3 init_database.py [database_path] [--admin-username USERNAME] [--admin-password PASSWORD]

Examples:
    python3 init_database.py pyircx.db
    python3 init_database.py /opt/pyircx/pyircx.db
    python3 init_database.py pyircx.db --admin-username admin --admin-password secretpass
"""

import sys
import os
import sqlite3
import bcrypt
import argparse
from datetime import datetime

# Default admin credentials (must be replaced before production use)
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "__CHANGE_ME__"

def create_database(db_path, admin_username=None, admin_password=None):
    """Create pyIRCX database with all required tables"""

    print(f"Creating database: {db_path}")

    # Remove existing database if present
    if os.path.exists(db_path):
        backup_path = f"{db_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"Existing database found, backing up to: {backup_path}")
        os.rename(db_path, backup_path)

    # Connect and create database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("Creating tables...")

    # Staff accounts (local server administration)
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT,
        level TEXT,
        created_at INTEGER DEFAULT 0,
        last_login INTEGER DEFAULT 0,
        registered_nick TEXT,
        email TEXT,
        realname TEXT,
        force_realname INTEGER DEFAULT 0,
        mfa_enabled INTEGER DEFAULT 0,
        mfa_secret TEXT
    )""")
    print("✓ users table (staff accounts)")

    # Registered nicknames
    cursor.execute("""CREATE TABLE IF NOT EXISTS registered_nicks (
        uuid TEXT PRIMARY KEY,
        nickname TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        registered_at INTEGER,
        last_seen INTEGER,
        mfa_enabled INTEGER DEFAULT 0,
        mfa_secret TEXT,
        registered_by TEXT
    )""")
    print("✓ registered_nicks table")

    # Registered channels
    cursor.execute("""CREATE TABLE IF NOT EXISTS registered_channels (
        uuid TEXT PRIMARY KEY,
        channel_name TEXT UNIQUE NOT NULL,
        owner_uuid TEXT,
        registered_at INTEGER,
        last_used INTEGER,
        topic TEXT DEFAULT '',
        modes TEXT DEFAULT '',
        onjoin TEXT DEFAULT '',
        onpart TEXT DEFAULT '',
        account_data TEXT DEFAULT '{}',
        ownerkey TEXT,
        description TEXT DEFAULT '',
        properties TEXT DEFAULT '{}'
    )""")
    print("✓ registered_channels table")

    # Server access (ban/allow lists)
    cursor.execute("""CREATE TABLE IF NOT EXISTS server_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        set_by TEXT NOT NULL,
        set_at INTEGER NOT NULL,
        reason TEXT,
        timeout INTEGER DEFAULT 0,
        UNIQUE(type, pattern)
    )""")
    print("✓ server_access table")

    # Mailbox (offline messages)
    cursor.execute("""CREATE TABLE IF NOT EXISTS mailbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_uuid TEXT NOT NULL,
        sender_nick TEXT NOT NULL,
        message TEXT NOT NULL,
        sent_at INTEGER NOT NULL,
        read INTEGER DEFAULT 0
    )""")
    print("✓ mailbox table")

    # NewsFlash announcements
    cursor.execute("""CREATE TABLE IF NOT EXISTS newsflash (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_by TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        priority INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1
    )""")
    print("✓ newsflash table")

    # Memos
    cursor.execute("""CREATE TABLE IF NOT EXISTS memos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_uuid TEXT NOT NULL,
        sender_nick TEXT NOT NULL,
        subject TEXT,
        message TEXT NOT NULL,
        sent_at INTEGER NOT NULL,
        read INTEGER DEFAULT 0,
        priority INTEGER DEFAULT 0
    )""")
    print("✓ memos table")

    # Channel access lists
    cursor.execute("""CREATE TABLE IF NOT EXISTS channel_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_uuid TEXT NOT NULL,
        user_uuid TEXT NOT NULL,
        level TEXT NOT NULL,
        set_by TEXT NOT NULL,
        set_at INTEGER NOT NULL,
        timeout INTEGER DEFAULT 0,
        UNIQUE(channel_uuid, user_uuid, level)
    )""")
    print("✓ channel_access table")

    # User audit log
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        nickname TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT
    )""")
    print("✓ user_audit_log table")

    # ServiceBot tracking
    cursor.execute("""CREATE TABLE IF NOT EXISTS servicebot_tracking (
        bot_nickname TEXT PRIMARY KEY,
        assigned_channels TEXT DEFAULT '',
        last_activity INTEGER,
        message_count INTEGER DEFAULT 0
    )""")
    print("✓ servicebot_tracking table")

    # Create indexes for performance
    print("Creating indexes...")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_uuid)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_memos_recipient ON memos(recipient_uuid)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_access_channel ON channel_access(channel_uuid)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_audit_nickname ON user_audit_log(nickname)")
    print("✓ Indexes created")

    # Create default staff accounts (ADMIN, SYSOP, GUIDE)
    admin_user = admin_username or DEFAULT_ADMIN_USER
    admin_pass = admin_password or DEFAULT_ADMIN_PASS

    print(f"\nCreating default staff accounts...")

    import uuid
    timestamp = int(datetime.now().timestamp())

    # Define default staff accounts
    staff_accounts = [
        {'username': admin_user, 'level': 'ADMIN', 'password': admin_pass},
        {'username': 'sysop', 'level': 'SYSOP', 'password': admin_pass},
        {'username': 'guide', 'level': 'GUIDE', 'password': admin_pass},
    ]

    for account in staff_accounts:
        hashed = bcrypt.hashpw(account['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute("""INSERT INTO users (username, password_hash, level, created_at, last_login)
                          VALUES (?, ?, ?, ?, 0)""",
                       (account['username'], hashed, account['level'], timestamp))

        print(f"✓ {account['level']:<6} account: {account['username']}")

    print(f"\nDefault password for all accounts: {admin_pass}")
    if admin_pass == DEFAULT_ADMIN_PASS:
        print(f"⚠ WARNING: Using default password! Change immediately!")

    conn.commit()
    conn.close()

    # Set proper permissions (660 for group access)
    os.chmod(db_path, 0o660)
    print(f"\n✓ Database created successfully: {db_path}")
    print(f"  Size: {os.path.getsize(db_path)} bytes")
    print(f"  Permissions: {oct(os.stat(db_path).st_mode)[-3:]}")

    return True

def main():
    parser = argparse.ArgumentParser(
        description='Initialize pyIRCX database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s pyircx.db
  %(prog)s /opt/pyircx/pyircx.db
  %(prog)s pyircx.db --admin-username sysadmin --admin-password MySecretPass123

Post-installation:
  1. Change the admin password immediately:
       python3 api.py change-staff-password admin YourNewPassword

  2. Or login to IRC and use:
       /QUOTE PASS admin:<current-password>
       /STAFF PASS admin YourNewPassword

  3. Set ownership (if running as root):
       chown pyircx:pyircx /opt/pyircx/pyircx.db
       chmod 660 /opt/pyircx/pyircx.db
        """
    )

    parser.add_argument('database',
                        help='Path to database file (e.g., pyircx.db or /opt/pyircx/pyircx.db)')
    parser.add_argument('--admin-username',
                        default=DEFAULT_ADMIN_USER,
                        help=f'Admin username (default: {DEFAULT_ADMIN_USER})')
    parser.add_argument('--admin-password',
                        default=DEFAULT_ADMIN_PASS,
                        help=f'Admin password (default: {DEFAULT_ADMIN_PASS})')
    parser.add_argument('--force', '-f',
                        action='store_true',
                        help='Force overwrite existing database without backup')

    args = parser.parse_args()

    # Validate database path
    db_path = os.path.abspath(args.database)
    db_dir = os.path.dirname(db_path)

    if not os.path.exists(db_dir):
        print(f"Error: Directory does not exist: {db_dir}")
        print(f"Create it first: mkdir -p {db_dir}")
        return 1

    if not os.access(db_dir, os.W_OK):
        print(f"Error: No write permission for directory: {db_dir}")
        print(f"Try running as root: sudo {' '.join(sys.argv)}")
        return 1

    # Check if database exists
    if os.path.exists(db_path) and not args.force:
        print(f"Database already exists: {db_path}")
        print(f"Size: {os.path.getsize(db_path)} bytes")
        print(f"\nOptions:")
        print(f"  1. Use --force to overwrite (creates backup)")
        print(f"  2. Delete manually and re-run")
        print(f"  3. Use repair.sh to fix existing database")
        return 1

    try:
        create_database(db_path, args.admin_username, args.admin_password)
        print("\n" + "=" * 60)
        print("DATABASE INITIALIZATION COMPLETE")
        print("=" * 60)
        print(f"\nNext steps:")
        print(f"  1. Set ownership: chown pyircx:pyircx {db_path}")
        print(f"  2. Set permissions: chmod 660 {db_path}")
        print(f"  3. Start pyIRCX: systemctl start pyircx")
        print(f"  4. Change admin password!")
        return 0
    except Exception as e:
        print(f"\nError creating database: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
