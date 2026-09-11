#!/usr/bin/env python3
"""Tests for server link password authentication."""

import bcrypt
import pytest

from linking import ServerLinkManager


def make_manager(password):
    manager = ServerLinkManager.__new__(ServerLinkManager)
    manager.links_config = [{'name': 'hub.example.test', 'password': password}]
    return manager


@pytest.mark.unit
@pytest.mark.asyncio
async def test_bcrypt_link_password_authenticates():
    hashed = bcrypt.hashpw(b"s3cret", bcrypt.gensalt(rounds=4)).decode()
    if not hashed.startswith("$2"):
        pytest.skip("real bcrypt not installed (conftest stub in use)")
    manager = make_manager(hashed)

    assert await manager.authenticate_server('hub.example.test', 's3cret') is True
    assert await manager.authenticate_server('hub.example.test', 'wrong') is False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_plaintext_link_password_authenticates():
    manager = make_manager('s3cret')

    assert await manager.authenticate_server('hub.example.test', 's3cret') is True
    assert await manager.authenticate_server('hub.example.test', 'wrong') is False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_unknown_link_is_rejected():
    manager = make_manager('s3cret')

    assert await manager.authenticate_server('other.example.test', 's3cret') is False
