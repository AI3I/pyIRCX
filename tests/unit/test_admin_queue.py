#!/usr/bin/env python3
"""Tests for WebAdmin command queue processing."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

import api
import pyircx


def create_registration_schema(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE registered_nicks (
                uuid TEXT PRIMARY KEY,
                nickname TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                registered_at INTEGER,
                last_seen INTEGER,
                mfa_enabled INTEGER DEFAULT 0,
                mfa_secret TEXT,
                registered_by TEXT
            );

            CREATE TABLE registered_channels (
                uuid TEXT PRIMARY KEY,
                channel_name TEXT UNIQUE NOT NULL,
                owner_uuid TEXT,
                registered_at INTEGER,
                last_used INTEGER,
                description TEXT,
                properties TEXT
            );
        """)


class FakeMember:
    is_virtual = False

    def __init__(self, nickname, channel):
        self.nickname = nickname
        self.channels = {channel}
        self.sent = []

    def prefix(self):
        return f"{self.nickname}!user@example.test"

    async def send(self, message):
        self.sent.append(message)


class FakeServer:
    def __init__(self, db_pool, channel=None):
        self.db_pool = db_pool
        self.system_nick = "System"
        self.users = {}
        self.server_bans = {}
        self.channels = {}
        self.channels_lower = {}
        if channel:
            self.channels[channel.name] = channel
            self.channels_lower[channel.name.lower()] = channel.name

    def get_channel(self, channel_name):
        actual = self.channels_lower.get(channel_name.lower())
        if not actual:
            return None, channel_name
        return self.channels[actual], actual


class AsyncCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        return False

    async def fetchone(self):
        return self.cursor.fetchone()


class AsyncExecute:
    def __init__(self, conn, query, params):
        self.conn = conn
        self.query = query
        self.params = params
        self.cursor = None

    async def _run(self):
        if self.cursor is None:
            self.cursor = self.conn.execute(self.query, self.params)
        return AsyncCursor(self.cursor)

    def __await__(self):
        return self._run().__await__()

    async def __aenter__(self):
        return await self._run()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.cursor:
            self.cursor.close()
        return False


class AsyncSqliteConnection:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, query, params=()):
        return AsyncExecute(self.conn, query, params)

    async def commit(self):
        self.conn.commit()


class AsyncConnectionContext:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return AsyncSqliteConnection(self.conn)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
        return False


class FakeDbPool:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)

    def connection(self):
        return AsyncConnectionContext(self.conn)

    def close(self):
        self.conn.close()


@pytest.mark.unit
def test_api_writes_admin_queue_to_env_path(tmp_path, monkeypatch):
    queue_path = tmp_path / "admin_commands.queue"
    monkeypatch.setenv("PYIRCX_ADMIN_QUEUE", str(queue_path))

    result = api.write_admin_command("KILL_CHANNEL:#test", "queued")

    assert result == {"success": True, "message": "queued"}
    assert queue_path.read_text(encoding="utf-8") == "KILL_CHANNEL:#test\n"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_server_claims_admin_queue_and_processes_remaining_after_error(tmp_path, monkeypatch):
    queue_path = tmp_path / "admin_commands.queue"
    queue_path.write_text("BROKEN:first\nKILL_CHANNEL:#Live\n", encoding="utf-8")
    monkeypatch.setenv("PYIRCX_ADMIN_QUEUE", str(queue_path))

    member = FakeMember("Alice", "#Live")
    channel = SimpleNamespace(name="#Live", members={"Alice": member})
    manager = pyircx.ServerManager()
    manager.server = FakeServer(db_pool=None, channel=channel)

    async def failing_process(line):
        if line.startswith("BROKEN"):
            raise RuntimeError("expected test failure")
        await pyircx.ServerManager._process_admin_command(manager, line)

    manager._process_admin_command = failing_process

    await manager.check_admin_commands()

    assert not queue_path.exists()
    assert not (tmp_path / "admin_commands.queue.processing").exists()
    assert "#Live" not in manager.server.channels
    assert member.channels == set()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_server_replays_existing_processing_queue_after_restart(tmp_path, monkeypatch):
    queue_path = tmp_path / "admin_commands.queue"
    processing_path = tmp_path / "admin_commands.queue.processing"
    processing_path.write_text("KILL_CHANNEL:#Live\n", encoding="utf-8")
    monkeypatch.setenv("PYIRCX_ADMIN_QUEUE", str(queue_path))

    member = FakeMember("Alice", "#Live")
    channel = SimpleNamespace(name="#Live", members={"Alice": member})
    manager = pyircx.ServerManager()
    manager.server = FakeServer(db_pool=None, channel=channel)

    await manager.check_admin_commands()

    assert not processing_path.exists()
    assert "#Live" not in manager.server.channels
    assert member.channels == set()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_lock_channel_uses_async_pool_and_current_schema(tmp_path):
    db_path = tmp_path / "pyircx.db"
    create_registration_schema(db_path)

    db_pool = FakeDbPool(db_path)

    member = FakeMember("Alice", "#Ops")
    channel = pyircx.Channel("#Ops")
    channel.members["Alice"] = member
    channel.topic = "Current topic"

    manager = pyircx.ServerManager()
    manager.server = FakeServer(db_pool=db_pool, channel=channel)

    await manager._admin_lock_channel("#Ops", "System")
    db_pool.close()

    with sqlite3.connect(db_path) as conn:
        owner = conn.execute(
            "SELECT uuid FROM registered_nicks WHERE nickname = ?",
            ("System",)
        ).fetchone()
        row = conn.execute("""
            SELECT channel_name, owner_uuid, properties
              FROM registered_channels
             WHERE channel_name = ?
        """, ("#Ops",)).fetchone()

    assert owner is not None
    assert row[0] == "#Ops"
    assert row[1] == owner[0]
    properties = json.loads(row[2])
    assert properties["topic"] == "Current topic"
    assert properties["owners"] == ["System"]
    assert properties["modes"]["r"] is True
    assert properties["modes"]["a"] is True
    assert properties["modes"]["z"] is True
    assert "#Ops" not in manager.server.channels
    assert member.channels == set()
