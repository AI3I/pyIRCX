#!/usr/bin/env python3
"""Tests for DNSBL lookup response handling."""

import logging

import pytest

import security


class FakeConfig:
    def __init__(self, data):
        self.data = data

    def get(self, *keys, default=None):
        value = self.data
        for key in keys:
            if not isinstance(value, dict) or key not in value:
                return default
            value = value[key]
        return value


class FakeResolverLoop:
    def __init__(self, response):
        self.response = response
        self.queries = []

    async def getaddrinfo(self, query, port, family=0):
        self.queries.append((query, port, family))
        return [(family, None, None, None, (self.response, 0))]


@pytest.fixture
def dnsbl_config(monkeypatch):
    config = FakeConfig({
        "security": {
            "dnsbl": {
                "enabled": True,
                "lists": ["xbl.spamhaus.org"],
                "timeout": 0.1,
                "cache_ttl": 3600,
                "whitelist": [],
            }
        }
    })
    monkeypatch.setattr(security, "CONFIG", config)
    return config


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dnsbl_policy_response_warns_without_listing(monkeypatch, caplog, dnsbl_config):
    resolver = FakeResolverLoop("127.255.255.254")
    monkeypatch.setattr(security.asyncio, "get_running_loop", lambda: resolver)

    checker = security.DNSBLChecker()
    with caplog.at_level(logging.WARNING, logger="pyIRCX"):
        is_listed, listed_on = await checker.check_ip("66.132.172.203")

    assert is_listed is False
    assert listed_on == []
    assert "policy response 127.255.255.254" in caplog.text
    assert resolver.queries[0][0] == "203.172.132.66.xbl.spamhaus.org"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dnsbl_normal_loopback_response_lists_ip(monkeypatch, dnsbl_config):
    resolver = FakeResolverLoop("127.0.0.2")
    monkeypatch.setattr(security.asyncio, "get_running_loop", lambda: resolver)

    checker = security.DNSBLChecker()
    is_listed, listed_on = await checker.check_ip("66.132.172.203")

    assert is_listed is True
    assert listed_on == ["xbl.spamhaus.org"]
