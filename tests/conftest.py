#!/usr/bin/env python3
"""
pytest configuration and shared fixtures for pyIRCX tests
"""

import pytest
import tempfile
import os
import sys
import sqlite3
import asyncio
import inspect
import json
import types

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _install_import_stub(module_name, **attrs):
    """Install a minimal stub for optional runtime dependencies in tests."""
    try:
        __import__(module_name)
    except ImportError:
        stub = types.ModuleType(module_name)
        for key, value in attrs.items():
            setattr(stub, key, value)
        sys.modules[module_name] = stub


_install_import_stub(
    "bcrypt",
    gensalt=lambda *args, **kwargs: b"stub-salt",
    hashpw=lambda password, salt: password if isinstance(password, bytes) else str(password).encode("utf-8"),
    checkpw=lambda password, hashed: (
        password if isinstance(password, bytes) else str(password).encode("utf-8")
    ) == hashed,
)
_install_import_stub("pyotp", random_base32=lambda *args, **kwargs: "A" * 32, TOTP=lambda *args, **kwargs: None)
_install_import_stub("aiosqlite", connect=None)


def pytest_configure(config):
    """Register local markers used by the suite."""
    config.addinivalue_line("markers", "asyncio: run test in an asyncio event loop")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Run asyncio-marked coroutine tests without external plugins."""
    if "asyncio" not in pyfuncitem.keywords:
        return None

    test_func = pyfuncitem.obj
    if not inspect.iscoroutinefunction(test_func):
        return None

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        kwargs = {
            name: pyfuncitem.funcargs[name]
            for name in pyfuncitem._fixtureinfo.argnames
        }
        loop.run_until_complete(test_func(**kwargs))
    finally:
        asyncio.set_event_loop(None)
        loop.close()
    return True


# =============================================================================
# DATABASE FIXTURES
# =============================================================================

@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing

    Yields:
        str: Path to temporary database file
    """
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)

    # Initialize with schema (matches init_database.py)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        -- Users table (staff accounts)
        CREATE TABLE IF NOT EXISTS users (
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
        );

        -- Registered nicknames
        CREATE TABLE IF NOT EXISTS registered_nicks (
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

        -- Registered channels
        CREATE TABLE IF NOT EXISTS registered_channels (
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
        );

        -- Server access (ban/allow lists)
        CREATE TABLE IF NOT EXISTS server_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            set_by TEXT NOT NULL,
            set_at INTEGER NOT NULL,
            reason TEXT,
            timeout INTEGER DEFAULT 0,
            UNIQUE(type, pattern)
        );

        -- Mailbox (offline messages)
        CREATE TABLE IF NOT EXISTS mailbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_uuid TEXT NOT NULL,
            sender_nick TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            read INTEGER DEFAULT 0
        );

        -- NewsFlash announcements
        CREATE TABLE IF NOT EXISTS newsflash (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_by TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            priority INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        );

        -- Memos
        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_uuid TEXT NOT NULL,
            sender_nick TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            read INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0
        );

        -- Channel access lists
        CREATE TABLE IF NOT EXISTS channel_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_uuid TEXT NOT NULL,
            user_uuid TEXT NOT NULL,
            level TEXT NOT NULL,
            set_by TEXT NOT NULL,
            set_at INTEGER NOT NULL,
            timeout INTEGER DEFAULT 0,
            UNIQUE(channel_uuid, user_uuid, level)
        );

        -- User audit log
        CREATE TABLE IF NOT EXISTS user_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            nickname TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT
        );

        -- ServiceBot tracking
        CREATE TABLE IF NOT EXISTS servicebot_tracking (
            bot_nickname TEXT PRIMARY KEY,
            assigned_channels TEXT DEFAULT '',
            last_activity INTEGER,
            message_count INTEGER DEFAULT 0
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_uuid);
        CREATE INDEX IF NOT EXISTS idx_memos_recipient ON memos(recipient_uuid);
        CREATE INDEX IF NOT EXISTS idx_channel_access_channel ON channel_access(channel_uuid);
        CREATE INDEX IF NOT EXISTS idx_user_audit_nickname ON user_audit_log(nickname);
    """)
    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def db_connection(temp_db):
    """Create a database connection for testing

    Args:
        temp_db: Path to temporary database

    Yields:
        sqlite3.Connection: Database connection
    """
    conn = sqlite3.connect(temp_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# =============================================================================
# CONFIGURATION FIXTURES
# =============================================================================

@pytest.fixture
def temp_config():
    """Create a temporary config file for testing

    Yields:
        str: Path to temporary config file
    """
    import json

    fd, config_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)

    config = {
        "server": {
            "name": "test.server.local",
            "network": "TestNet",
            "motd": ["Welcome to the test server"]
        },
        "network": {
            "listen_ports": [6667]
        },
        "database": {
            "path": "test.db"
        },
        "limits": {
            "max_nick_length": 30,
            "max_user_length": 30,
            "max_channel_length": 50,
            "max_users": 1000
        },
        "security": {
            "flood_messages": 5,
            "flood_window": 2.0
        },
        "services": {
            "enabled": True
        },
        "servicebot": {
            "enabled": True
        }
    }

    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)

    yield config_path

    # Cleanup
    try:
        os.unlink(config_path)
    except OSError:
        pass


@pytest.fixture
def api_module():
    """Import api.py with a temporary checkout-local config path."""
    import importlib

    module = importlib.import_module("api")
    original_config = module.DEFAULT_CONFIG
    original_db = module.DEFAULT_DB
    original_log = module.DEFAULT_LOG
    original_status = module.DEFAULT_STATUS

    fd, config_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({"server": {"name": "Test", "network": "TestNet"}}, f)

    module.DEFAULT_CONFIG = config_path
    module.DEFAULT_DB = os.path.join(tempfile.gettempdir(), "pyircx-test.db")
    module.DEFAULT_LOG = os.path.join(tempfile.gettempdir(), "pyircx-test.log")
    module.DEFAULT_STATUS = os.path.join(tempfile.gettempdir(), "pyircx-test-status.json")

    yield module

    module.DEFAULT_CONFIG = original_config
    module.DEFAULT_DB = original_db
    module.DEFAULT_LOG = original_log
    module.DEFAULT_STATUS = original_status
    try:
        os.unlink(config_path)
    except OSError:
        pass


# =============================================================================
# MOCK FIXTURES
# =============================================================================

@pytest.fixture
def mock_db_pool(temp_db, monkeypatch):
    """Mock the db_pool module to use a temporary database

    Args:
        temp_db: Path to temporary database
        monkeypatch: pytest monkeypatch fixture
    """
    import db_pool

    # Initialize pool with temp database
    db_pool.init_pool(temp_db, pool_size=2)

    yield db_pool

    # Cleanup
    db_pool.close_pool()


# =============================================================================
# SAMPLE DATA FIXTURES
# =============================================================================

@pytest.fixture
def sample_staff(db_connection):
    """Create sample staff accounts for testing

    Args:
        db_connection: Database connection

    Returns:
        dict: Staff account details
    """
    import bcrypt
    import time

    cursor = db_connection.cursor()
    now = int(time.time())

    staff = {
        'admin': {
            'username': 'testadmin',
            'password': 'adminpass123',
            'level': 'ADMIN'
        },
        'sysop': {
            'username': 'testsysop',
            'password': 'sysoppass123',
            'level': 'SYSOP'
        },
        'guide': {
            'username': 'testguide',
            'password': 'guidepass123',
            'level': 'GUIDE'
        }
    }

    for key, data in staff.items():
        password_hash = bcrypt.hashpw(
            data['password'].encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        cursor.execute("""
            INSERT INTO users (username, password_hash, level, created_at)
            VALUES (?, ?, ?, ?)
        """, (data['username'], password_hash, data['level'], now))

    db_connection.commit()
    return staff


@pytest.fixture
def sample_nicks(db_connection):
    """Create sample registered nicknames for testing

    Args:
        db_connection: Database connection

    Returns:
        list: List of registered nickname details
    """
    import bcrypt
    import uuid
    import time

    cursor = db_connection.cursor()
    now = int(time.time())

    nicks = [
        {'nickname': 'TestUser1', 'email': 'test1@example.com'},
        {'nickname': 'TestUser2', 'email': 'test2@example.com'},
        {'nickname': 'TestUser3', 'email': None},
    ]

    for nick_data in nicks:
        nick_uuid = str(uuid.uuid4())
        password_hash = bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode('utf-8')

        cursor.execute("""
            INSERT INTO registered_nicks
            (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (nick_uuid, nick_data['nickname'], password_hash,
              nick_data['email'], now, now, 'test'))

        nick_data['uuid'] = nick_uuid

    db_connection.commit()
    return nicks


@pytest.fixture
def sample_channels(db_connection, sample_nicks):
    """Create sample registered channels for testing

    Args:
        db_connection: Database connection
        sample_nicks: Sample nicknames fixture

    Returns:
        list: List of registered channel details
    """
    import uuid
    import time
    import json

    cursor = db_connection.cursor()
    now = int(time.time())

    channels = [
        {'name': '#TestChannel1', 'owner_idx': 0},
        {'name': '#TestChannel2', 'owner_idx': 1},
    ]

    for chan_data in channels:
        chan_uuid = str(uuid.uuid4())
        owner_uuid = sample_nicks[chan_data['owner_idx']]['uuid']

        cursor.execute("""
            INSERT INTO registered_channels
            (uuid, channel_name, owner_uuid, registered_at, last_used, properties)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (chan_uuid, chan_data['name'], owner_uuid, now, now, json.dumps({})))

        chan_data['uuid'] = chan_uuid
        chan_data['owner_uuid'] = owner_uuid

    db_connection.commit()
    return channels


# =============================================================================
# UTILITY FIXTURES
# =============================================================================

@pytest.fixture
def capture_logs(caplog):
    """Capture log output for assertions

    Args:
        caplog: pytest caplog fixture

    Yields:
        caplog: Configured log capture
    """
    import logging
    caplog.set_level(logging.DEBUG)
    yield caplog
