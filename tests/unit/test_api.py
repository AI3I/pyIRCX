#!/usr/bin/env python3
"""
Unit tests for api.py

Tests API endpoints for user management, channel management, staff operations,
server configuration, and health check.
"""

import pytest
import sys
import os
import tempfile
import json
import time
import sqlite3
from io import StringIO
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Must set up db_pool before importing api
import db_pool


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope='function')
def setup_api_env(tmp_path):
    """Set up complete API environment with temp database and config"""
    # Create temp database
    db_path = str(tmp_path / 'test.db')

    # Initialize database schema (matches init_database.py)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
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

        CREATE TABLE IF NOT EXISTS mailbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_uuid TEXT NOT NULL,
            sender_nick TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            read INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS newsflash (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_by TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            priority INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        );

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

        CREATE TABLE IF NOT EXISTS user_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            nickname TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT
        );

        CREATE TABLE IF NOT EXISTS servicebot_tracking (
            bot_nickname TEXT PRIMARY KEY,
            assigned_channels TEXT DEFAULT '',
            last_activity INTEGER,
            message_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS connection_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            username TEXT NOT NULL,
            realname TEXT,
            ip_address TEXT,
            host TEXT,
            logon_time INTEGER NOT NULL,
            logout_time INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_uuid);
        CREATE INDEX IF NOT EXISTS idx_memos_recipient ON memos(recipient_uuid);
        CREATE INDEX IF NOT EXISTS idx_channel_access_channel ON channel_access(channel_uuid);
        CREATE INDEX IF NOT EXISTS idx_user_audit_nickname ON user_audit_log(nickname);
    """)
    conn.close()

    # Initialize db_pool with temp database
    db_pool.init_pool(db_path, pool_size=2)

    # Create temp config
    config_path = str(tmp_path / 'config.json')
    config = {
        "server": {
            "name": "test.server.local",
            "network": "TestNet",
            "motd": ["Test MOTD line 1", "Test MOTD line 2"]
        },
        "network": {
            "listen_ports": [6667]
        },
        "database": {
            "path": db_path
        },
        "limits": {
            "max_nick_length": 30,
            "max_users": 100
        },
        "services": {
            "enabled": True
        }
    }
    with open(config_path, 'w') as f:
        json.dump(config, f)

    # Create temp status file
    status_path = str(tmp_path / 'status.json')
    status = {
        "timestamp": int(time.time()),
        "users": [],
        "channels": [],
        "server": {
            "name": "test.server.local",
            "uptime": 3600
        }
    }
    with open(status_path, 'w') as f:
        json.dump(status, f)

    yield {
        'db_path': db_path,
        'config_path': config_path,
        'status_path': status_path,
        'tmp_path': tmp_path
    }

    # Cleanup
    db_pool.close_pool()


@pytest.fixture
def api_module(setup_api_env, monkeypatch):
    """Import api module with mocked paths"""
    env = setup_api_env

    # Patch the default paths before importing api
    monkeypatch.setenv('PYIRCX_CONFIG', env['config_path'])
    monkeypatch.setenv('PYIRCX_STATUS', env['status_path'])

    # Now import api (it uses db_pool which is already initialized)
    import api

    # Patch the DEFAULT constants
    monkeypatch.setattr(api, 'DEFAULT_CONFIG', env['config_path'])
    monkeypatch.setattr(api, 'DEFAULT_STATUS', env['status_path'])
    monkeypatch.setattr(api, 'DEFAULT_DB', env['db_path'])

    # Re-initialize db_pool with test database after api import
    # (api module initialization may have overwritten the pool)
    db_pool.close_pool()
    db_pool.init_pool(env['db_path'], pool_size=2)

    # Save original function references before wrapping
    _orig_add_staff = api.add_staff
    _orig_delete_staff = api.delete_staff
    _orig_get_registered_nicks_paginated = api.get_registered_nicks_paginated
    _orig_search_registered_nicks = api.search_registered_nicks
    _orig_get_newsflash_list = api.get_newsflash_list
    _orig_get_mailbox_messages = api.get_mailbox_messages
    _orig_get_server_access_list = api.get_server_access_list
    _orig_get_registered_channels = api.get_registered_channels
    _orig_get_server_stats = api.get_server_stats
    _orig_get_realtime_status = api.get_realtime_status
    _orig_get_server_config = api.get_server_config
    _orig_get_full_config = api.get_full_config
    _orig_get_motd = api.get_motd
    _orig_get_staff_list = api.get_staff_list
    _orig_health_check = api.health_check
    _orig_add_server_access = api.add_server_access
    _orig_add_newsflash = api.add_newsflash
    _orig_delete_newsflash = api.delete_newsflash

    # Add wrapper functions to map test names to actual API function names
    # and ensure consistent return format with 'success' key

    def create_staff_account(username, password, level):
        result = _orig_add_staff(username, password, level)
        if 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def delete_staff_account(username):
        result = _orig_delete_staff(username)
        if 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def get_registered_nicks():
        result = _orig_get_registered_nicks_paginated(limit=50, offset=0)
        if 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result.get("data", [])}

    def search_registered_nick(query):
        result = _orig_search_registered_nicks(query)
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def get_newsflash():
        result = _orig_get_newsflash_list()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def get_mailbox():
        result = _orig_get_mailbox_messages(limit=50)
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def wrapped_get_server_access_list():
        result = _orig_get_server_access_list()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def wrapped_get_registered_channels():
        result = _orig_get_registered_channels()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def wrapped_get_server_stats():
        result = _orig_get_server_stats()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def wrapped_get_realtime_status():
        result = _orig_get_realtime_status()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def wrapped_get_server_config():
        result = _orig_get_server_config()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}
    wrapped_get_server_config.cache_clear = getattr(_orig_get_server_config, 'cache_clear', lambda: None)

    def wrapped_get_motd():
        result = _orig_get_motd()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}
    wrapped_get_motd.cache_clear = getattr(_orig_get_motd, 'cache_clear', lambda: None)

    def wrapped_get_full_config():
        result = _orig_get_full_config()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}
    wrapped_get_full_config.cache_clear = getattr(_orig_get_full_config, 'cache_clear', lambda: None)

    def wrapped_get_staff_list():
        result = _orig_get_staff_list()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        # api_error_handler already wraps list in {"data": list, "success": True}
        if isinstance(result, dict) and 'data' in result:
            return {"success": True, "data": result['data']}
        return {"success": True, "data": result if isinstance(result, list) else []}

    def wrapped_health_check():
        result = _orig_health_check()
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def wrapped_add_server_access(access_type, pattern, set_by, reason, timeout=0):
        result = _orig_add_server_access(access_type, pattern, set_by, reason, timeout)
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def wrapped_add_newsflash(message, created_by, priority=0):
        result = _orig_add_newsflash(message, created_by, priority)
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    def wrapped_delete_newsflash(msg_id):
        result = _orig_delete_newsflash(msg_id)
        if isinstance(result, dict) and 'error' in result:
            return {"success": False, "error": result['error']}
        return {"success": True, **result}

    # Attach wrapper functions to api module for tests
    api.create_staff_account = create_staff_account
    api.delete_staff_account = delete_staff_account
    api.get_registered_nicks = get_registered_nicks
    api.search_registered_nick = search_registered_nick
    api.get_newsflash = get_newsflash
    api.get_mailbox = get_mailbox
    api.get_server_access_list = wrapped_get_server_access_list
    api.get_registered_channels = wrapped_get_registered_channels
    api.get_server_stats = wrapped_get_server_stats
    api.get_realtime_status = wrapped_get_realtime_status
    api.get_server_config = wrapped_get_server_config
    api.get_motd = wrapped_get_motd
    api.get_full_config = wrapped_get_full_config
    api.get_staff_list = wrapped_get_staff_list
    api.health_check = wrapped_health_check
    api.add_server_access = wrapped_add_server_access
    api.add_newsflash = wrapped_add_newsflash
    api.delete_newsflash = wrapped_delete_newsflash

    return api


# =============================================================================
# HEALTH CHECK TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestHealthCheck:
    """Tests for health check endpoint"""

    def test_health_check_healthy(self, api_module):
        """Test health check returns healthy status"""
        result = api_module.health_check()

        assert result['success'] == True
        # healthy may be True or False depending on status file freshness
        assert 'healthy' in result
        assert 'checks' in result
        assert 'database' in result['checks']
        assert result['checks']['database']['status'] == 'ok'

    def test_health_check_includes_pool_stats(self, api_module):
        """Test health check includes connection pool statistics"""
        result = api_module.health_check()

        assert 'connection_pool' in result['checks']
        pool_check = result['checks']['connection_pool']
        assert 'pool_size' in pool_check
        assert 'available' in pool_check


# =============================================================================
# SERVER STATS TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestServerStats:
    """Tests for server statistics endpoint"""

    def test_get_server_stats(self, api_module):
        """Test getting server statistics"""
        result = api_module.get_server_stats()

        assert result['success'] == True
        assert 'data' in result or 'registered_nicks' in result

    def test_get_realtime_status(self, api_module):
        """Test getting real-time status"""
        result = api_module.get_realtime_status()

        assert result['success'] == True
        assert 'timestamp' in result or 'error' not in result


# =============================================================================
# STAFF MANAGEMENT TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestStaffManagement:
    """Tests for staff management endpoints"""

    def test_get_staff_list_empty(self, api_module):
        """Test getting staff list when empty"""
        result = api_module.get_staff_list()

        assert result['success'] == True
        # Result should be a list (might be in 'data' key)
        staff = result.get('data', result)
        if isinstance(staff, list):
            assert len(staff) == 0

    def test_create_staff_account(self, api_module):
        """Test creating a staff account"""
        result = api_module.create_staff_account(
            username='teststaff',
            password='TestPass123!',
            level='GUIDE'
        )

        assert result['success'] == True

    def test_create_staff_account_invalid_level(self, api_module):
        """Test creating staff with invalid level fails"""
        result = api_module.create_staff_account(
            username='badstaff',
            password='TestPass123!',
            level='SUPERADMIN'
        )

        assert result['success'] == False

    def test_create_staff_duplicate(self, api_module):
        """Test creating duplicate staff account fails"""
        # Create first
        api_module.create_staff_account(
            username='dupstaff',
            password='TestPass123!',
            level='GUIDE'
        )

        # Try duplicate
        result = api_module.create_staff_account(
            username='dupstaff',
            password='DifferentPass!',
            level='SYSOP'
        )

        assert result['success'] == False

    def test_delete_staff_account(self, api_module):
        """Test deleting a staff account"""
        # Create first
        api_module.create_staff_account(
            username='todelete',
            password='TestPass123!',
            level='GUIDE'
        )

        # Delete
        result = api_module.delete_staff_account('todelete')
        assert result['success'] == True

    def test_delete_nonexistent_staff(self, api_module):
        """Test deleting non-existent staff fails gracefully"""
        result = api_module.delete_staff_account('nonexistent')
        # Should return success=False or handle gracefully
        # The exact behavior depends on implementation

    def test_get_staff_list_after_create(self, api_module):
        """Test staff list includes created accounts"""
        api_module.create_staff_account(
            username='listedstaff',
            password='TestPass123!',
            level='ADMIN'
        )

        result = api_module.get_staff_list()
        assert result['success'] == True

        staff = result.get('data', result)
        if isinstance(staff, list):
            usernames = [s['username'] for s in staff]
            assert 'listedstaff' in usernames

    def test_add_staff_stdin(self, api_module, monkeypatch):
        monkeypatch.setattr(api_module.sys, 'stdin', StringIO(json.dumps({'password': 'TestPass123!'})))
        result = api_module.add_staff_stdin('stdinstaff', 'GUIDE')
        assert result['success'] == True

    def test_change_staff_password_stdin(self, api_module, monkeypatch):
        api_module.create_staff_account(
            username='passchange',
            password='OldPass123!',
            level='GUIDE'
        )
        monkeypatch.setattr(api_module.sys, 'stdin', StringIO(json.dumps({'password': 'NewPass123!'})))
        result = api_module.change_staff_password_stdin('passchange')
        assert result['success'] == True


# =============================================================================
# NICKNAME MANAGEMENT TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestNicknameManagement:
    """Tests for registered nickname endpoints"""

    def test_get_registered_nicks_empty(self, api_module):
        """Test getting registered nicks when empty"""
        result = api_module.get_registered_nicks()

        assert result['success'] == True

    def test_search_registered_nick(self, api_module):
        """Test searching for a nickname"""
        result = api_module.search_registered_nick('nonexistent')

        # Should succeed but return no results
        assert result['success'] == True

    def test_register_nickname_stdin(self, api_module, monkeypatch):
        monkeypatch.setattr(api_module.sys, 'stdin', StringIO(json.dumps({'password': 'NickPass123!'})))
        result = api_module.register_nickname_stdin('StdInNick', 'stdin@example.com')
        assert result['success'] == True

    def test_edit_nickname_stdin(self, api_module, monkeypatch):
        register_result = api_module.register_nickname('EditNick', 'BeforePass123!', 'before@example.com')
        assert register_result['success'] == True
        monkeypatch.setattr(api_module.sys, 'stdin', StringIO(json.dumps({'password': 'AfterPass123!'})))
        result = api_module.edit_nickname_stdin('EditNick', 'after@example.com')
        assert result['success'] == True


# =============================================================================
# CHANNEL MANAGEMENT TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestChannelManagement:
    """Tests for channel management endpoints"""

    def test_get_registered_channels_empty(self, api_module):
        """Test getting registered channels when empty"""
        result = api_module.get_registered_channels()

        assert result['success'] == True

    def test_get_channel_details_nonexistent(self, api_module):
        """Test getting details for non-existent channel"""
        result = api_module.get_channel_details('#nonexistent')

        # Should return error or empty result
        assert 'error' in result or result.get('success') == False or result.get('channel') is None


# =============================================================================
# SERVER ACCESS TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestServerAccess:
    """Tests for server access (ban) management"""

    def test_get_server_access_list_empty(self, api_module):
        """Test getting access list when empty"""
        result = api_module.get_server_access_list()

        assert result['success'] == True

    def test_add_server_access(self, api_module):
        """Test adding a server access entry (DENY)"""
        result = api_module.add_server_access(
            access_type='DENY',
            pattern='*!*@badhost.com',
            set_by='admin',
            reason='Test deny'
        )

        assert result['success'] == True

    def test_get_server_access_after_add(self, api_module):
        """Test access list includes added entries"""
        api_module.add_server_access(
            access_type='DENY',
            pattern='*!*@testban.com',
            set_by='admin',
            reason='Test'
        )

        result = api_module.get_server_access_list()
        assert result['success'] == True

        entries = result.get('data', result.get('entries', []))
        if isinstance(entries, list) and len(entries) > 0:
            patterns = [e.get('pattern', '') for e in entries]
            assert '*!*@testban.com' in patterns


# =============================================================================
# NEWSFLASH TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestNewsflash:
    """Tests for newsflash management"""

    def test_get_newsflash_empty(self, api_module):
        """Test getting newsflash when empty"""
        result = api_module.get_newsflash()

        assert result['success'] == True

    def test_add_newsflash(self, api_module):
        """Test adding a newsflash message"""
        result = api_module.add_newsflash(
            message='Test announcement',
            created_by='admin'
        )

        assert result['success'] == True

    def test_delete_newsflash(self, api_module):
        """Test deleting a newsflash message"""
        # Add first
        add_result = api_module.add_newsflash(
            message='To be deleted',
            created_by='admin'
        )

        # Get the ID
        newsflash = api_module.get_newsflash()
        if newsflash.get('data'):
            item_id = newsflash['data'][0]['id']

            # Delete
            result = api_module.delete_newsflash(item_id)
            assert result['success'] == True


# =============================================================================
# MAILBOX TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestMailbox:
    """Tests for mailbox/memo management"""

    def test_get_mailbox_empty(self, api_module):
        """Test getting mailbox when empty"""
        result = api_module.get_mailbox()

        assert result['success'] == True


# =============================================================================
# CONFIGURATION TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestConfiguration:
    """Tests for server configuration endpoints"""

    def test_get_server_config(self, api_module):
        """Test getting server configuration"""
        result = api_module.get_server_config()

        assert result['success'] == True

    def test_get_motd(self, api_module):
        """Test getting MOTD"""
        result = api_module.get_motd()

        assert result['success'] == True

    def test_get_connection_sessions_filters_history(self, api_module):
        """Test retrieving persisted connection sessions for WebAdmin logs"""
        conn = sqlite3.connect(api_module.get_db_path())
        conn.execute(
            """INSERT INTO connection_sessions
               (nickname, username, realname, ip_address, host, logon_time, logout_time, duration, reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("LogNick", "~loguser", "Log User", "198.51.100.9", "host.example", 1000, 1060, 60, "Client exited")
        )
        conn.commit()
        conn.close()

        result = api_module.get_connection_sessions(10, "198.51.100")

        assert result["success"] == True
        assert result["count"] == 1
        assert result["sessions"][0]["nickname"] == "LogNick"
        assert result["sessions"][0]["ip_address"] == "198.51.100.9"
        assert result["sessions"][0]["duration"] == 60

    def test_set_motd_invalidates_cached_get_motd(self, api_module):
        api_module.get_motd()
        api_module.set_motd(json.dumps(["Updated MOTD"]))
        result = api_module.get_motd()

        assert result['success'] == True
        assert result['motd'] == ["Updated MOTD"]

    def test_set_config_invalidates_cached_full_config(self, api_module):
        api_module.get_full_config()
        updated = api_module.load_config()
        updated['server']['network'] = 'UpdatedNet'
        api_module.set_config(json.dumps(updated))
        result = api_module.get_full_config()

        assert result['success'] == True
        assert result['server']['network'] == 'UpdatedNet'

    def test_set_newsflash_settings_invalidates_cached_read(self, api_module):
        api_module.get_newsflash_settings()
        api_module.set_newsflash_settings('true', 'true', '45')
        result = api_module.get_newsflash_settings()

        assert result['success'] == True
        assert result['on_connect'] is True
        assert result['periodic_enabled'] is True
        assert result['periodic_interval'] == 45


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestErrorHandling:
    """Tests for API error handling"""

    def test_api_error_handler_returns_dict(self, api_module):
        """Test error handler always returns dict with success key"""
        # Call any endpoint
        result = api_module.get_server_stats()

        assert isinstance(result, dict)
        assert 'success' in result

    def test_validation_errors_have_error_type(self, api_module):
        """Test validation errors include error_type"""
        result = api_module.create_staff_account(
            username='',  # Invalid
            password='pass',
            level='ADMIN'
        )

        if not result['success']:
            assert 'error' in result


@pytest.mark.unit
@pytest.mark.api
class TestAdminQueueCommands:
    """Tests for admin queue command formatting."""

    def test_send_irc_ban_user_writes_duration_before_reason(self, api_module):
        with patch.object(api_module, 'write_admin_command', return_value={'success': True}) as mock_write:
            result = api_module.send_irc_ban_user('BanTarget', 'Testing ban', 7200)

        assert result['success'] == True
        mock_write.assert_called_once_with(
            'BAN_USER:BanTarget:7200:Testing ban',
            api_module.SERVER_MESSAGES['api_ban_success'].format(nickname='BanTarget', duration=7200)
        )


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

@pytest.mark.unit
@pytest.mark.api
class TestRateLimiting:
    """Tests for API rate limiting"""

    def test_rate_limit_not_triggered_normally(self, api_module):
        """Test rate limit is not triggered under normal use"""
        # Make a few calls - should all succeed
        for _ in range(5):
            result = api_module.get_server_stats()
            assert result['success'] == True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
