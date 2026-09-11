#!/usr/bin/env python3
"""Tests for initial modes applied by the IRCX CREATE command."""

import pytest

import pyircx


def make_server():
    server = object.__new__(pyircx.pyIRCXServer)
    server.servername = "irc.example.test"
    server.max_users_per_channel = 100
    server.get_reply = lambda code, user, **kwargs: f":{server.servername} {code} {user.nickname} {kwargs}"
    return server


class FakeUser:
    nickname = "Alice"

    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(message)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_cannot_set_registered_or_locked_modes():
    server = make_server()
    user = FakeUser()
    channel = pyircx.Channel("#new")

    await server._apply_create_modes(channel, user, "+ntrz", [])

    assert channel.modes['n'] is True
    assert channel.modes['t'] is True
    assert channel.modes['r'] is False
    assert channel.modes['z'] is False
    assert sum(" 696 " in line for line in user.sent) == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_applies_parameter_modes():
    server = make_server()
    user = FakeUser()
    channel = pyircx.Channel("#new")

    await server._apply_create_modes(channel, user, "+kl", ["secret", "500"])

    assert channel.key == "secret"
    assert channel.user_limit == 100
    assert user.sent == []
