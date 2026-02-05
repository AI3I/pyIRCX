#!/usr/bin/env python3
"""
Database utilities for pyIRCX Server

This module contains:
- DatabasePool: Async SQLite connection pooling
- Password hashing/verification utilities using bcrypt
"""

import asyncio
import logging
import os
import sqlite3

import aiosqlite
import bcrypt

from responses import get_log_message

logger = logging.getLogger('pyIRCX')
USE_THREADS = os.environ.get("PYIRCX_NO_THREADS") != "1"


async def run_blocking(func, *args, **kwargs):
    if USE_THREADS:
        return await asyncio.to_thread(func, *args, **kwargs)
    return func(*args, **kwargs)


class DatabasePool:
    """Simple async SQLite connection pool"""

    def __init__(self, db_path, pool_size=5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = asyncio.Queue(maxsize=pool_size)
        self._initialized = False
        self._lock = asyncio.Lock()
        self._sync = os.environ.get("PYIRCX_SYNC_DB") == "1"
        self._connect_timeout = float(os.environ.get("PYIRCX_ASYNC_DB_TIMEOUT", "5"))

    async def initialize(self):
        """Initialize the connection pool"""
        async with self._lock:
            if self._initialized:
                return
            use_sync = self._sync
            for _ in range(self.pool_size):
                if use_sync:
                    conn = await run_blocking(
                        sqlite3.connect,
                        self.db_path,
                        check_same_thread=False
                    )
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys = ON")
                    await self._pool.put(SyncConnection(conn))
                    continue

                try:
                    conn = await asyncio.wait_for(
                        aiosqlite.connect(self.db_path),
                        timeout=self._connect_timeout
                    )
                except Exception as e:
                    logger.warning(
                        "aiosqlite connect failed or timed out; "
                        "falling back to sqlite3 for this process: %s",
                        e
                    )
                    use_sync = True
                    # Drain any partially created async connections
                    while not self._pool.empty():
                        existing = await self._pool.get()
                        try:
                            await existing.close()
                        except Exception:
                            pass
                    conn = await run_blocking(
                        sqlite3.connect,
                        self.db_path,
                        check_same_thread=False
                    )
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys = ON")
                    await self._pool.put(SyncConnection(conn))
                else:
                    await self._pool.put(conn)
            self._initialized = True
            logger.info(get_log_message("db_async_pool_ready", size=self.pool_size))

    async def acquire(self):
        """Get a connection from the pool with queue monitoring"""
        if not self._initialized:
            await self.initialize()
        # Log warning if pool is saturated
        if self._pool.qsize() == 0:
            logger.warning(get_log_message("db_async_pool_exhausted", size=self.pool_size))
        return await self._pool.get()

    async def release(self, conn):
        """Return a connection to the pool"""
        await self._pool.put(conn)

    async def close(self):
        """Close all connections in the pool"""
        async with self._lock:
            while not self._pool.empty():
                conn = await self._pool.get()
                await conn.close()
            self._initialized = False

    async def execute(self, query, params=None):
        """Execute a query and return results"""
        conn = await self.acquire()
        try:
            async with conn.execute(query, params or ()) as cursor:
                return await cursor.fetchall()
        finally:
            await self.release(conn)

    async def execute_one(self, query, params=None):
        """Execute a query and return first result"""
        conn = await self.acquire()
        try:
            async with conn.execute(query, params or ()) as cursor:
                return await cursor.fetchone()
        finally:
            await self.release(conn)

    async def execute_write(self, query, params=None):
        """Execute a write query with commit"""
        conn = await self.acquire()
        try:
            await conn.execute(query, params or ())
            await conn.commit()
        finally:
            await self.release(conn)

    def connection(self):
        """Async context manager for getting a pooled connection.

        Usage:
            async with db_pool.connection() as conn:
                async with conn.execute("SELECT * FROM users") as cursor:
                    rows = await cursor.fetchall()

        The connection is automatically returned to the pool when the context exits.
        """
        return _PooledConnection(self)


class _PooledConnection:
    """Async context manager for pooled database connections."""

    def __init__(self, pool):
        self.pool = pool
        self.conn = None

    async def __aenter__(self):
        self.conn = await self.pool.acquire()
        return self.conn

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            await self.pool.release(self.conn)
        return False


class SyncExecute:
    """Awaitable + async context manager for sqlite3 execute."""

    def __init__(self, conn, query, params):
        self._conn = conn
        self._query = query
        self._params = params
        self._cursor = None
        self._executed = False

    async def _run(self):
        if not self._executed:
            cursor = await run_blocking(self._conn.execute, self._query, self._params)
            self._cursor = SyncCursor(cursor)
            self._executed = True
        return self._cursor

    def __await__(self):
        return self._run().__await__()

    async def __aenter__(self):
        return await self._run()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._cursor:
            await self._cursor.close()
        return False


class SyncCursor:
    """Async wrapper for sqlite3.Cursor."""

    def __init__(self, cursor):
        self._cursor = cursor

    async def fetchone(self):
        return await run_blocking(self._cursor.fetchone)

    async def fetchall(self):
        return await run_blocking(self._cursor.fetchall)

    async def close(self):
        await run_blocking(self._cursor.close)

    def __aiter__(self):
        return self

    async def __anext__(self):
        row = await run_blocking(self._cursor.fetchone)
        if row is None:
            raise StopAsyncIteration
        return row


class SyncConnection:
    """Async-compatible wrapper for sqlite3.Connection."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, query, params=()):
        return SyncExecute(self._conn, query, params)

    async def commit(self):
        await run_blocking(self._conn.commit)

    async def close(self):
        await run_blocking(self._conn.close)


async def check_password_async(password: str, password_hash: str) -> bool:
    """Non-blocking bcrypt password check using executor"""
    loop = asyncio.get_event_loop()
    try:
        if USE_THREADS:
            return await loop.run_in_executor(
                None,
                bcrypt.checkpw,
                password.encode(),
                password_hash.encode()
            )
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


async def hash_password_async(password: str) -> str:
    """Non-blocking bcrypt password hashing using executor"""
    loop = asyncio.get_event_loop()
    if USE_THREADS:
        salt = await loop.run_in_executor(None, bcrypt.gensalt)
        hashed = await loop.run_in_executor(
            None,
            bcrypt.hashpw,
            password.encode(),
            salt
        )
    else:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()
