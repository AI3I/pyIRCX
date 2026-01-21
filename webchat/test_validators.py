#!/usr/bin/env python3
"""
Test script for webchat validators
"""

import sys
from validators import (
    validate_nickname, validate_username, validate_realname,
    validate_channel, validate_message, validate_reason,
    validate_password, validate_key, validate_raw_command, sanitize_ip
)


def test_nickname():
    """Test nickname validation"""
    print("Testing nickname validation...")

    # Valid nicknames
    assert validate_nickname("Alice") == "Alice"
    assert validate_nickname("Bob123") == "Bob123"
    assert validate_nickname("User[IRC]") == "User[IRC]"

    # Invalid nicknames
    try:
        validate_nickname("123Invalid")  # Starts with number
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Erroneous nickname" in str(e) or "Invalid" in str(e)

    try:
        validate_nickname("Invalid Nick")  # Contains space
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Erroneous nickname" in str(e) or "Invalid" in str(e)

    print("✓ Nickname validation passed")


def test_channel():
    """Test channel validation"""
    print("Testing channel validation...")

    # Valid channels
    assert validate_channel("#test") == "#test"
    assert validate_channel("test") == "#test"  # Adds # automatically
    assert validate_channel("#Test-Channel") == "#Test-Channel"

    # Invalid channels
    try:
        validate_channel("#test channel")  # Contains space
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "cannot contain spaces" in str(e) or "invalid characters" in str(e)

    print("✓ Channel validation passed")


def test_message():
    """Test message validation"""
    print("Testing message validation...")

    # Valid messages
    assert validate_message("Hello world") == "Hello world"
    assert validate_message("Test 123") == "Test 123"

    # Message too long
    try:
        validate_message("x" * 513)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "too long" in str(e) or "under 512" in str(e)

    print("✓ Message validation passed")


def test_raw_command():
    """Test raw command validation"""
    print("Testing raw command validation...")

    # Valid commands
    assert validate_raw_command("PRIVMSG #test :Hello") == "PRIVMSG #test :Hello"
    assert validate_raw_command("JOIN #channel") == "JOIN #channel"

    # Dangerous commands
    try:
        validate_raw_command("WEBIRC password gateway ip ip")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "not allowed" in str(e)

    try:
        validate_raw_command("KILL user reason")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "not allowed" in str(e)

    # Command injection
    try:
        validate_raw_command("PRIVMSG #test :Hello\r\nKILL user")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "single-line" in str(e) or "Invalid command" in str(e)

    print("✓ Raw command validation passed")


def test_ip_sanitization():
    """Test IP sanitization"""
    print("Testing IP sanitization...")

    # Valid IPv4
    assert sanitize_ip("192.168.1.1") == "192.168.1.1"
    assert sanitize_ip("10.0.0.1") == "10.0.0.1"

    # Invalid IPs
    assert sanitize_ip("not.an.ip") == "0.0.0.0"
    assert sanitize_ip("") == "0.0.0.0"
    assert sanitize_ip(None) == "0.0.0.0"

    print("✓ IP sanitization passed")


def main():
    """Run all tests"""
    print("=" * 60)
    print("WebChat Validators Test Suite")
    print("=" * 60)
    print()

    try:
        test_nickname()
        test_channel()
        test_message()
        test_raw_command()
        test_ip_sanitization()

        print()
        print("=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print()
        print("=" * 60)
        print(f"✗ Test failed: {e}")
        print("=" * 60)
        return 1

    except Exception as e:
        print()
        print("=" * 60)
        print(f"✗ Unexpected error: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
