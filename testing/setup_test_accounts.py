#!/usr/bin/env python3
"""
Setup Test Accounts for pyIRCX Testing

Creates staff accounts in the database for testing:
- admin/testpass (ADMIN)
- sysop/testpass (SYSOP)
- guide/testpass (GUIDE)

Usage:
    python3 testing/setup_test_accounts.py [--db /path/to/pyircx.db]

Copyright (C) 2026 John D. Lewis
Licensed under GPL v3+
"""

import sqlite3
import hashlib
import argparse
import os
import sys
import time


def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def setup_test_accounts(db_path: str):
    """Create test staff accounts in database"""

    # Check if database exists
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        print("Please create the database first or specify correct path with --db")
        return False

    print(f"📂 Opening database: {db_path}")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verify users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("❌ Users table not found in database")
            print("Database may not be initialized properly")
            return False

        current_time = int(time.time())

        # Test accounts to create
        accounts = [
            ('admin', 'testpass', 'ADMIN', 'Test Admin Account'),
            ('sysop', 'testpass', 'SYSOP', 'Test Sysop Account'),
            ('guide', 'testpass', 'GUIDE', 'Test Guide Account'),
        ]

        print("\n🔧 Creating/updating test accounts...")

        for username, password, level, realname in accounts:
            password_hash = hash_password(password)

            # Check if account exists
            cursor.execute("SELECT username, level FROM users WHERE username = ?", (username,))
            existing = cursor.fetchone()

            if existing:
                # Update existing account
                cursor.execute("""
                    UPDATE users
                    SET password_hash = ?, level = ?, realname = ?, last_login = ?
                    WHERE username = ?
                """, (password_hash, level, realname, current_time, username))
                print(f"  ✓ Updated {username} ({level})")
            else:
                # Insert new account
                cursor.execute("""
                    INSERT INTO users (username, password_hash, level, created_at, last_login, realname)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, password_hash, level, current_time, current_time, realname))
                print(f"  ✓ Created {username} ({level})")

        conn.commit()

        # Verify accounts
        print("\n✅ Verification:")
        cursor.execute("SELECT username, level FROM users WHERE username IN ('admin', 'sysop', 'guide')")
        for row in cursor.fetchall():
            print(f"  ✓ {row[0]}: {row[1]}")

        conn.close()

        print("\n" + "="*60)
        print("Test accounts ready!")
        print("="*60)
        print("\nCredentials:")
        print("  admin/testpass  (ADMIN)")
        print("  sysop/testpass  (SYSOP)")
        print("  guide/testpass  (GUIDE)")
        print("\nAuthentication in tests:")
        print("  PASS testpass")
        print("  NICK admin")
        print("  USER admin 0 * :Test Admin")
        print("  (Will auto-auth if PASS matches)")
        print("\nOr after connecting:")
        print("  IDENTIFY admin testpass")
        print("="*60)

        return True

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(description='Setup test accounts for pyIRCX testing')
    parser.add_argument('--db', default='/opt/pyircx/pyircx.db',
                       help='Path to pyIRCX database (default: /opt/pyircx/pyircx.db)')

    args = parser.parse_args()

    print("="*60)
    print("pyIRCX Test Account Setup")
    print("="*60)

    success = setup_test_accounts(args.db)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
