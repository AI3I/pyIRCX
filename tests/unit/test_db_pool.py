#!/usr/bin/env python3
"""
Unit tests for db_pool.py

Tests connection pooling functionality including pool initialization,
connection management, error handling, and statistics.
"""

import pytest
import sys
import os
import tempfile
import threading
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import db_pool
from db_pool import ConnectionPool


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def temp_db_path():
    """Create a temporary database file"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def pool(temp_db_path):
    """Create a connection pool for testing"""
    p = ConnectionPool(temp_db_path, pool_size=3)
    yield p
    p.close_all()


# =============================================================================
# CONNECTION POOL INITIALIZATION TESTS
# =============================================================================

@pytest.mark.unit
class TestPoolInitialization:
    """Tests for connection pool initialization"""

    def test_pool_creates_connections(self, temp_db_path):
        """Test pool creates specified number of connections"""
        pool = ConnectionPool(temp_db_path, pool_size=5)
        stats = pool.get_stats()

        assert stats['pool_size'] == 5
        assert stats['available'] == 5
        assert stats['in_use'] == 0
        assert stats['initialized'] == True

        pool.close_all()

    def test_pool_default_size(self, temp_db_path):
        """Test pool uses default size of 10"""
        pool = ConnectionPool(temp_db_path)
        stats = pool.get_stats()

        assert stats['pool_size'] == 10

        pool.close_all()

    def test_pool_stores_db_path(self, temp_db_path):
        """Test pool stores database path"""
        pool = ConnectionPool(temp_db_path, pool_size=2)
        stats = pool.get_stats()

        assert stats['db_path'] == temp_db_path

        pool.close_all()

    def test_pool_invalid_db_path(self):
        """Test pool handles invalid database path"""
        # Should still work - SQLite creates the file
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'subdir', 'test.db')
            # This may fail if parent dir doesn't exist
            # depending on SQLite behavior


# =============================================================================
# CONNECTION ACQUISITION TESTS
# =============================================================================

@pytest.mark.unit
class TestConnectionAcquisition:
    """Tests for getting connections from pool"""

    def test_get_connection_basic(self, pool):
        """Test basic connection acquisition"""
        with pool.get_connection() as conn:
            assert conn is not None
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1

    def test_get_connection_updates_stats(self, pool):
        """Test connection acquisition updates statistics"""
        initial_stats = pool.get_stats()
        assert initial_stats['available'] == 3
        assert initial_stats['in_use'] == 0

        with pool.get_connection() as conn:
            during_stats = pool.get_stats()
            assert during_stats['available'] == 2
            assert during_stats['in_use'] == 1

        after_stats = pool.get_stats()
        assert after_stats['available'] == 3
        assert after_stats['in_use'] == 0

    def test_get_multiple_connections(self, pool):
        """Test acquiring multiple connections"""
        with pool.get_connection() as conn1:
            with pool.get_connection() as conn2:
                # Both should be valid
                conn1.execute("SELECT 1")
                conn2.execute("SELECT 2")

                stats = pool.get_stats()
                assert stats['in_use'] == 2

    def test_connection_returned_on_exception(self, pool):
        """Test connection is returned to pool on exception"""
        initial_available = pool.get_stats()['available']

        try:
            with pool.get_connection() as conn:
                raise ValueError("Test exception")
        except ValueError:
            pass

        after_stats = pool.get_stats()
        assert after_stats['available'] == initial_available

    def test_connection_timeout(self, temp_db_path):
        """Test connection acquisition timeout when pool exhausted"""
        # Create pool with 1 connection
        pool = ConnectionPool(temp_db_path, pool_size=1)

        with pool.get_connection() as conn1:
            # Pool now exhausted - should timeout
            with pytest.raises(RuntimeError) as exc_info:
                with pool.get_connection(timeout=0.5) as conn2:
                    pass

            assert 'No database connection available' in str(exc_info.value)

        pool.close_all()


# =============================================================================
# TRANSACTION TESTS
# =============================================================================

@pytest.mark.unit
class TestTransactions:
    """Tests for transaction handling"""

    def test_auto_commit_on_success(self, pool):
        """Test transactions are committed on successful exit"""
        with pool.get_connection() as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO test (value) VALUES ('test')")

        # Verify data persisted
        with pool.get_connection() as conn:
            cursor = conn.execute("SELECT value FROM test")
            result = cursor.fetchone()
            assert result[0] == 'test'

    def test_auto_rollback_on_exception(self, pool):
        """Test transactions are rolled back on exception"""
        with pool.get_connection() as conn:
            conn.execute("CREATE TABLE test2 (id INTEGER PRIMARY KEY, value TEXT)")

        try:
            with pool.get_connection() as conn:
                conn.execute("INSERT INTO test2 (value) VALUES ('should_rollback')")
                raise ValueError("Trigger rollback")
        except ValueError:
            pass

        # Verify data was rolled back
        with pool.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM test2")
            result = cursor.fetchone()
            assert result[0] == 0


# =============================================================================
# POOL CLOSE TESTS
# =============================================================================

@pytest.mark.unit
class TestPoolClose:
    """Tests for pool shutdown"""

    def test_close_all_connections(self, temp_db_path):
        """Test all connections are closed"""
        pool = ConnectionPool(temp_db_path, pool_size=5)

        assert pool.get_stats()['available'] == 5

        pool.close_all()

        assert pool.get_stats()['initialized'] == False
        assert pool.get_stats()['available'] == 0

    def test_pool_not_usable_after_close(self, temp_db_path):
        """Test pool raises error after close"""
        pool = ConnectionPool(temp_db_path, pool_size=2)
        pool.close_all()

        with pytest.raises(RuntimeError):
            with pool.get_connection() as conn:
                pass


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

@pytest.mark.unit
class TestThreadSafety:
    """Tests for thread-safe pool operations"""

    def test_concurrent_connections(self, temp_db_path):
        """Test pool handles concurrent access"""
        pool = ConnectionPool(temp_db_path, pool_size=5)
        results = []
        errors = []

        def worker(thread_id):
            try:
                with pool.get_connection() as conn:
                    time.sleep(0.1)  # Simulate work
                    cursor = conn.execute("SELECT ?", (thread_id,))
                    result = cursor.fetchone()[0]
                    results.append(result)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        pool.close_all()

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10


# =============================================================================
# GLOBAL POOL FUNCTION TESTS
# =============================================================================

@pytest.mark.unit
class TestGlobalPoolFunctions:
    """Tests for module-level pool functions"""

    def test_init_pool(self, temp_db_path):
        """Test global pool initialization"""
        pool = db_pool.init_pool(temp_db_path, pool_size=3)

        assert pool is not None
        stats = db_pool.get_pool_stats()
        assert stats['pool_size'] == 3

        db_pool.close_pool()

    def test_get_connection_global(self, temp_db_path):
        """Test getting connection from global pool"""
        db_pool.init_pool(temp_db_path, pool_size=2)

        with db_pool.get_connection() as conn:
            cursor = conn.execute("SELECT 1")
            assert cursor.fetchone()[0] == 1

        db_pool.close_pool()

    def test_get_connection_without_init(self):
        """Test getting connection without initialization raises error"""
        # Ensure pool is closed
        db_pool.close_pool()

        with pytest.raises(RuntimeError) as exc_info:
            with db_pool.get_connection() as conn:
                pass

        assert 'not initialized' in str(exc_info.value)

    def test_close_pool(self, temp_db_path):
        """Test global pool close"""
        db_pool.init_pool(temp_db_path, pool_size=2)
        db_pool.close_pool()

        stats = db_pool.get_pool_stats()
        assert stats is None

    def test_reinit_pool(self, temp_db_path):
        """Test reinitializing global pool"""
        db_pool.init_pool(temp_db_path, pool_size=2)
        db_pool.init_pool(temp_db_path, pool_size=5)  # Should close old, create new

        stats = db_pool.get_pool_stats()
        assert stats['pool_size'] == 5

        db_pool.close_pool()


# =============================================================================
# CONNECTION CONFIGURATION TESTS
# =============================================================================

@pytest.mark.unit
class TestConnectionConfiguration:
    """Tests for connection configuration settings"""

    def test_row_factory_enabled(self, pool):
        """Test connections have Row factory enabled"""
        with pool.get_connection() as conn:
            conn.execute("CREATE TABLE test_row (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO test_row VALUES (1, 'test')")

            cursor = conn.execute("SELECT * FROM test_row")
            row = cursor.fetchone()

            # Row factory should allow dict-like access
            assert row['id'] == 1
            assert row['name'] == 'test'

    def test_foreign_keys_enabled(self, pool):
        """Test foreign keys are enabled"""
        with pool.get_connection() as conn:
            cursor = conn.execute("PRAGMA foreign_keys")
            result = cursor.fetchone()
            assert result[0] == 1  # 1 = enabled

    def test_wal_mode_enabled(self, pool):
        """Test WAL journal mode is enabled"""
        with pool.get_connection() as conn:
            cursor = conn.execute("PRAGMA journal_mode")
            result = cursor.fetchone()
            assert result[0].lower() == 'wal'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
