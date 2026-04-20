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
    session_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'connection_sessions'"
    ).fetchone()
    session_indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_connection_sessions_%'"
        ).fetchall()
    }
    conn.close()

    assert ("atlasadmin", "ADMIN") in rows
    assert ("admin", "ADMIN") not in rows
    assert ("sysop", "SYSOP") in rows
    assert ("guide", "GUIDE") in rows
    assert session_table == ("connection_sessions",)
    assert {
        "idx_connection_sessions_logon",
        "idx_connection_sessions_nick",
        "idx_connection_sessions_user",
        "idx_connection_sessions_ip",
    }.issubset(session_indexes)
