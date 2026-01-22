#!/usr/bin/env python3
"""
Database utilities for pyIRCX Server

This module contains:
- DatabasePool: Async SQLite connection pooling
- Password hashing/verification utilities using bcrypt
"""

import asyncio
import logging

import aiosqlite
import bcrypt

from responses import get_log_message

logger = logging.getLogger('pyIRCX')


class DatabasePool:
    """Simple async SQLite connection pool"""

    def __init__(self, db_path, pool_size=5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = asyncio.Queue(maxsize=pool_size)
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize the connection pool"""
        async with self._lock:
            if self._initialized:
                return
            for _ in range(self.pool_size):
                conn = await aiosqlite.connect(self.db_path)
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


async def check_password_async(password: str, password_hash: str) -> bool:
    """Non-blocking bcrypt password check using executor"""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None,
            bcrypt.checkpw,
            password.encode(),
            password_hash.encode()
        )
    except Exception:
        return False


async def hash_password_async(password: str) -> str:
    """Non-blocking bcrypt password hashing using executor"""
    loop = asyncio.get_event_loop()
    salt = await loop.run_in_executor(None, bcrypt.gensalt)
    hashed = await loop.run_in_executor(
        None,
        bcrypt.hashpw,
        password.encode(),
        salt
    )
    return hashed.decode()
