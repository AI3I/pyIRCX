#!/usr/bin/env python3
"""
Database Connection Pool for pyIRCX
Provides thread-safe connection pooling for SQLite operations

Copyright (C) 2026 John D. Lewis

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sqlite3
import threading
import logging
from contextlib import contextmanager
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class ConnectionPool:
    """Thread-safe SQLite connection pool

    Manages a pool of reusable database connections to avoid
    the overhead of repeatedly opening/closing connections.

    Usage:
        pool = ConnectionPool('/path/to/db.sqlite', pool_size=10)

        with pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            results = cursor.fetchall()
    """

    def __init__(self, db_path, pool_size=10):
        """Initialize connection pool

        Args:
            db_path: Path to SQLite database file
            pool_size: Number of connections to maintain in pool
        """
        self.db_path = db_path
        self.pool_size = pool_size
        self.pool = Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        self._initialized = False

        logger.info(f"Initializing connection pool: {db_path} (size: {pool_size})")

        # Create initial pool of connections
        for i in range(pool_size):
            try:
                conn = self._create_connection()
                self.pool.put(conn)
                logger.debug(f"Created connection {i+1}/{pool_size}")
            except Exception as e:
                logger.error(f"Failed to create connection {i+1}: {e}")
                raise

        self._initialized = True
        logger.info(f"Connection pool initialized with {pool_size} connections")

    def _create_connection(self):
        """Create a new database connection with standard settings"""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,  # Allow connection sharing across threads
            timeout=30.0  # Wait up to 30s for locks
        )
        conn.row_factory = sqlite3.Row  # Enable dict-like row access

        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")

        # Set journal mode for better concurrency
        conn.execute("PRAGMA journal_mode = WAL")

        return conn

    @contextmanager
    def get_connection(self, timeout=5.0):
        """Get a connection from the pool (context manager)

        Args:
            timeout: Seconds to wait for an available connection

        Yields:
            sqlite3.Connection: Database connection

        Raises:
            Empty: If no connection available within timeout

        Usage:
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users")
        """
        if not self._initialized:
            raise RuntimeError("Connection pool not initialized")

        conn = None
        try:
            # Get connection from pool
            try:
                conn = self.pool.get(timeout=timeout)
            except Empty:
                logger.error(f"Connection pool exhausted (timeout={timeout}s)")
                raise RuntimeError(f"No database connection available (pool size: {self.pool_size})")

            # Yield connection to caller
            yield conn

            # Commit any pending transactions on success
            conn.commit()

        except Exception as e:
            # Rollback on error
            if conn is not None:
                try:
                    conn.rollback()
                    logger.debug("Transaction rolled back due to error")
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")
            raise

        finally:
            # Always return connection to pool
            if conn is not None:
                try:
                    self.pool.put(conn, block=False)
                except Exception as e:
                    logger.error(f"Failed to return connection to pool: {e}")
                    # Try to create a replacement connection
                    try:
                        new_conn = self._create_connection()
                        self.pool.put(new_conn, block=False)
                        logger.info("Created replacement connection")
                    except Exception as create_error:
                        logger.error(f"Failed to create replacement connection: {create_error}")

    def close_all(self):
        """Close all connections in the pool

        Should be called during shutdown to cleanly close all connections.
        """
        logger.info("Closing all connections in pool")
        closed_count = 0

        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
                closed_count += 1
            except Empty:
                break
            except Exception as e:
                logger.error(f"Error closing connection: {e}")

        logger.info(f"Closed {closed_count} connections")
        self._initialized = False

    def get_stats(self):
        """Get connection pool statistics

        Returns:
            dict: Pool statistics including size and available connections
        """
        return {
            'pool_size': self.pool_size,
            'available': self.pool.qsize(),
            'in_use': self.pool_size - self.pool.qsize(),
            'initialized': self._initialized,
            'db_path': self.db_path
        }


# Global connection pool instance
_pool = None
_pool_lock = threading.Lock()


def init_pool(db_path, pool_size=10):
    """Initialize the global connection pool

    Args:
        db_path: Path to SQLite database file
        pool_size: Number of connections to maintain

    Returns:
        ConnectionPool: The initialized pool
    """
    global _pool

    with _pool_lock:
        if _pool is not None:
            logger.warning("Connection pool already initialized, closing existing pool")
            _pool.close_all()

        _pool = ConnectionPool(db_path, pool_size)
        return _pool


def get_connection(timeout=5.0):
    """Get a connection from the global pool

    Args:
        timeout: Seconds to wait for available connection

    Returns:
        Context manager yielding a database connection

    Raises:
        RuntimeError: If pool not initialized

    Usage:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
    """
    if _pool is None:
        raise RuntimeError("Connection pool not initialized. Call init_pool() first.")

    return _pool.get_connection(timeout=timeout)


def close_pool():
    """Close the global connection pool"""
    global _pool

    with _pool_lock:
        if _pool is not None:
            _pool.close_all()
            _pool = None


def get_pool_stats():
    """Get statistics about the global connection pool

    Returns:
        dict: Pool statistics or None if not initialized
    """
    if _pool is None:
        return None
    return _pool.get_stats()


# Cleanup on module unload
import atexit
atexit.register(close_pool)
