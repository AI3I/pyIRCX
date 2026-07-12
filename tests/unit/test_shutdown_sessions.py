from collections import deque
from types import SimpleNamespace

import pytest


def make_server():
    import pyircx

    server = object.__new__(pyircx.pyIRCXServer)
    server.users = {}
    server.session_history = deque(maxlen=100)
    server.db_pool = object()
    server.max_connection_sessions = 100
    server.connection_session_retention_days = 0
    server.debug_mode = True
    return server


def make_user(nick="Alice"):
    return SimpleNamespace(
        nickname=nick,
        username="alice",
        realname="Alice Example",
        ip="192.0.2.10",
        host="client.example",
        signon_time=100,
        registered=True,
        disconnected=False,
        is_virtual=False,
        is_remote=False,
    )


@pytest.mark.asyncio
async def test_shutdown_persists_active_sessions_once(monkeypatch):
    server = make_server()
    user = make_user()
    server.users[user.nickname] = user
    persisted = []

    async def fake_persist(entry):
        persisted.append(entry)

    monkeypatch.setattr(server, "_record_persistent_session_history", fake_persist)
    monkeypatch.setattr("pyircx.time.time", lambda: 200)

    assert await server.persist_active_connection_sessions("Server shutting down") == 1
    assert await server.persist_active_connection_sessions("Server shutting down") == 0

    assert len(persisted) == 1
    assert persisted[0]["nick"] == "Alice"
    assert persisted[0]["logout_time"] == 200
    assert persisted[0]["duration"] == 100
    assert persisted[0]["reason"] == "Server shutting down"
