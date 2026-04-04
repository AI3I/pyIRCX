#!/usr/bin/env python3
"""
Unit tests for init_database.py.
"""

import sqlite3

from init_database import create_database


def test_create_database_honors_custom_admin_username(tmp_path):
    db_path = tmp_path / "init.db"

    create_database(str(db_path), admin_username="atlasadmin", admin_password="SecretPass123!")

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT username, level FROM users ORDER BY level, username").fetchall()
    conn.close()

    assert ("atlasadmin", "ADMIN") in rows
    assert ("admin", "ADMIN") not in rows
    assert ("sysop", "SYSOP") in rows
    assert ("guide", "GUIDE") in rows
