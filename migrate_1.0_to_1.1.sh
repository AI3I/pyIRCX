#!/bin/bash
#
# pyIRCX Database Migration Script
# Version 1.0.x to 1.1.0
#
# This script adds new columns required for v1.1.0:
# - users table: email, realname, force_realname
# - server_access table: timeout
#
# Copyright (C) 2026 pyIRCX Project
# Licensed under GNU GPL v3

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root or with sudo"
    echo "Usage: sudo $0"
    exit 1
fi

echo "========================================="
echo "pyIRCX Database Migration: 1.0.x → 1.1.0"
echo "========================================="
echo ""

# Database path
DB_PATH="/opt/pyircx/pyircx.db"

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database not found at $DB_PATH"
    echo "Please ensure pyIRCX is installed."
    exit 1
fi

# Backup database first
BACKUP_PATH="${DB_PATH}.backup-$(date +%Y%m%d-%H%M%S)"
echo "Creating backup: $BACKUP_PATH"
cp "$DB_PATH" "$BACKUP_PATH"
echo "✓ Backup created"
echo ""

# Function to check if column exists
column_exists() {
    local table=$1
    local column=$2
    sqlite3 "$DB_PATH" "PRAGMA table_info($table);" | grep -q "|$column|"
}

echo "Checking current database schema..."
echo ""

# Check and add columns to users table
echo "Updating 'users' table..."

if column_exists "users" "created_at"; then
    echo "  - Column 'created_at' already exists"
else
    echo "  - Adding column 'created_at'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN created_at INTEGER;"
    echo "    ✓ Added"
fi

if column_exists "users" "last_login"; then
    echo "  - Column 'last_login' already exists"
else
    echo "  - Adding column 'last_login'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN last_login INTEGER;"
    echo "    ✓ Added"
fi

if column_exists "users" "registered_nick"; then
    echo "  - Column 'registered_nick' already exists"
else
    echo "  - Adding column 'registered_nick'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN registered_nick TEXT;"
    echo "    ✓ Added"
fi

if column_exists "users" "email"; then
    echo "  - Column 'email' already exists"
else
    echo "  - Adding column 'email'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN email TEXT;"
    echo "    ✓ Added"
fi

if column_exists "users" "realname"; then
    echo "  - Column 'realname' already exists"
else
    echo "  - Adding column 'realname'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN realname TEXT;"
    echo "    ✓ Added"
fi

if column_exists "users" "force_realname"; then
    echo "  - Column 'force_realname' already exists"
else
    echo "  - Adding column 'force_realname'"
    sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN force_realname INTEGER DEFAULT 0;"
    echo "    ✓ Added"
fi

echo ""

# Check and add columns to server_access table
echo "Updating 'server_access' table..."

if column_exists "server_access" "timeout"; then
    echo "  - Column 'timeout' already exists"
else
    echo "  - Adding column 'timeout'"
    sqlite3 "$DB_PATH" "ALTER TABLE server_access ADD COLUMN timeout INTEGER DEFAULT 0;"
    echo "    ✓ Added"
fi

echo ""
echo "========================================="
echo "Migration completed successfully!"
echo "========================================="
echo ""
echo "Database backup saved to:"
echo "  $BACKUP_PATH"
echo ""
echo "New features in v1.1.0:"
echo "  - Staff profiles (email, real name)"
echo "  - Access control expiration"
echo "  - Web Administration Panel"
echo ""
echo "To complete the upgrade:"
echo "  1. Restart pyIRCX service: systemctl restart pyircx.service"
echo "  2. Access web admin at: http://your-server/pyircx-admin/"
echo "  3. Set staff passwords: python3 /opt/pyircx/api.py change-staff-password <user> <pass>"
echo ""
