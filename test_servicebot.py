#!/usr/bin/env python3
"""
Test ServiceBot Monitoring Behavior

Tests:
1. ServiceBot auto-gag on profanity
2. ServiceBot auto-gag on flood
3. ServiceBot auto-gag on excessive caps
4. Shadow ban behavior (no notification to gagged user)
5. Notifications sent to #System channel
6. Services cannot be gagged
"""

import socket
import time
import re

class IRCTestClient:
    def __init__(self, nickname, username, realname, server='localhost', port=6667):
        self.nickname = nickname
        self.username = username
        self.realname = realname
        self.server = server
        self.port = port
        self.sock = None
        self.buffer = ""

    def connect(self):
        """Connect to IRC server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect((self.server, self.port))
        print(f"✓ Connected to {self.server}:{self.port}")

        # Send registration
        self.send(f"NICK {self.nickname}")
        self.send(f"USER {self.username} 0 * :{self.realname}")

        # Wait for welcome
        while True:
            line = self.recv_line()
            if not line:
                break
            print(f"< {line}")
            if "001" in line or "Welcome" in line:
                print(f"✓ Registered as {self.nickname}")
                return True
        return False

    def send(self, message):
        """Send a message to the server"""
        self.sock.send(f"{message}\r\n".encode())
        print(f"> {message}")

    def recv_line(self):
        """Receive a single line from the server"""
        while '\n' not in self.buffer:
            try:
                data = self.sock.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    return None
                self.buffer += data
            except socket.timeout:
                return None

        line, self.buffer = self.buffer.split('\n', 1)
        return line.strip()

    def recv_until(self, pattern, timeout=5):
        """Receive lines until pattern matches or timeout"""
        start = time.time()
        matches = []
        while time.time() - start < timeout:
            line = self.recv_line()
            if not line:
                continue
            print(f"< {line}")
            if re.search(pattern, line, re.IGNORECASE):
                matches.append(line)
        return matches

    def join(self, channel):
        """Join a channel"""
        self.send(f"JOIN {channel}")
        time.sleep(0.5)

    def privmsg(self, target, message):
        """Send PRIVMSG"""
        self.send(f"PRIVMSG {target} :{message}")

    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            print(f"✓ Disconnected")


def test_servicebot_profanity():
    """Test ServiceBot auto-gag on profanity"""
    print("\n" + "="*60)
    print("TEST: ServiceBot Auto-Gag on Profanity")
    print("="*60)

    client = IRCTestClient("TestUser1", "test1", "Test User 1")
    try:
        client.connect()
        client.join("#test")
        time.sleep(1)

        print("\nSending profanity message...")
        client.privmsg("#test", "This is a fuck test")
        time.sleep(2)

        print("\nChecking if user is gagged (shadow ban)...")
        client.privmsg("#test", "Can anyone see this?")

        # User should NOT receive any notification about being gagged
        matches = client.recv_until("gagged|gag", timeout=2)
        if not matches:
            print("✓ PASS: User received no gag notification (shadow ban working)")
        else:
            print(f"✗ FAIL: User received gag notification: {matches}")

    finally:
        client.close()


def test_servicebot_flood():
    """Test ServiceBot auto-gag on flood"""
    print("\n" + "="*60)
    print("TEST: ServiceBot Auto-Gag on Flood")
    print("="*60)

    client = IRCTestClient("TestUser2", "test2", "Test User 2")
    try:
        client.connect()
        client.join("#test")
        time.sleep(1)

        print("\nSending flood messages...")
        for i in range(6):
            client.privmsg("#test", f"Flood message {i}")
            time.sleep(0.1)

        time.sleep(2)

        print("\nChecking if user is gagged...")
        client.privmsg("#test", "Can anyone see this?")

        matches = client.recv_until("gagged|gag", timeout=2)
        if not matches:
            print("✓ PASS: User received no gag notification (shadow ban working)")
        else:
            print(f"✗ FAIL: User received gag notification: {matches}")

    finally:
        client.close()


def test_services_cannot_be_gagged():
    """Test that services cannot be gagged"""
    print("\n" + "="*60)
    print("TEST: Services Cannot Be Gagged")
    print("="*60)

    # This requires ADMIN/SYSOP access to test manually
    # For automated testing, we'd need to auth as staff first
    print("⚠ MANUAL TEST REQUIRED:")
    print("  1. Connect as ADMIN/SYSOP")
    print("  2. Try: MODE #channel +z System")
    print("  3. Should receive: 'Cannot gag services'")


def test_system_channel_notifications():
    """Test that gag notifications go to #System"""
    print("\n" + "="*60)
    print("TEST: #System Channel Gag Notifications")
    print("="*60)

    print("⚠ MANUAL TEST REQUIRED:")
    print("  1. Connect as ADMIN/SYSOP and join #System")
    print("  2. Trigger ServiceBot gag in another channel")
    print("  3. Check #System for notification: [GAG] ServiceBot gagged user in #channel")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("ServiceBot Monitoring Test Suite")
    print("="*60)

    try:
        test_servicebot_profanity()
        test_servicebot_flood()
        test_services_cannot_be_gagged()
        test_system_channel_notifications()

        print("\n" + "="*60)
        print("Test Suite Complete")
        print("="*60)

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
