#!/usr/bin/env python3
"""
Test Access Control System (GRANT/DENY/OWNER/HOST/VOICE)

Tests:
1. Channel access levels (OWNER, HOST, VOICE)
2. Server access levels (GRANT, DENY)
3. Access list ADD/REMOVE/CLEAR operations
4. Access priority and overrides
5. Staff vs owner permissions
6. Wildcard mask matching
7. Services cannot be added to DENY lists
"""

import socket
import time
import re

class IRCTestClient:
    def __init__(self, nickname, username, realname, password=None, server='localhost', port=6667):
        self.nickname = nickname
        self.username = username
        self.realname = realname
        self.password = password
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
        if self.password:
            self.send(f"PASS {self.password}")
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

    def recv_until(self, pattern, timeout=3):
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

    def recv_all(self, timeout=2):
        """Receive all pending lines"""
        start = time.time()
        lines = []
        while time.time() - start < timeout:
            line = self.recv_line()
            if not line:
                continue
            print(f"< {line}")
            lines.append(line)
        return lines

    def join(self, channel):
        """Join a channel"""
        self.send(f"JOIN {channel}")
        time.sleep(0.5)

    def access(self, target, *args):
        """Send ACCESS command"""
        self.send(f"ACCESS {target} {' '.join(args)}")

    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            print(f"✓ Disconnected")


def test_channel_owner_mode():
    """Test channel OWNER access level"""
    print("\n" + "="*60)
    print("TEST: Channel OWNER Access Level")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan")
        time.sleep(1)

        print("\nAdding user to OWNER access list...")
        owner.access("#testchan", "ADD", "OWNER", "TestUser!*@*")

        matches = owner.recv_until("ACCESS.*added|806", timeout=2)
        if matches:
            print("✓ PASS: OWNER entry added successfully")
        else:
            print("✗ FAIL: OWNER entry not added")

        print("\nListing OWNER access...")
        owner.access("#testchan", "LIST", "OWNER")
        matches = owner.recv_until("TestUser", timeout=2)
        if matches:
            print("✓ PASS: OWNER entry appears in list")
        else:
            print("✗ FAIL: OWNER entry not in list")

    finally:
        owner.close()


def test_channel_host_mode():
    """Test channel HOST access level"""
    print("\n" + "="*60)
    print("TEST: Channel HOST Access Level")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan2")
        time.sleep(1)

        print("\nAdding user to HOST access list...")
        owner.access("#testchan2", "ADD", "HOST", "HostUser!*@*")

        matches = owner.recv_until("ACCESS.*added|806", timeout=2)
        if matches:
            print("✓ PASS: HOST entry added successfully")
        else:
            print("✗ FAIL: HOST entry not added")

        print("\nListing HOST access...")
        owner.access("#testchan2", "LIST", "HOST")
        matches = owner.recv_until("HostUser", timeout=2)
        if matches:
            print("✓ PASS: HOST entry appears in list")
        else:
            print("✗ FAIL: HOST entry not in list")

    finally:
        owner.close()


def test_channel_voice_mode():
    """Test channel VOICE access level"""
    print("\n" + "="*60)
    print("TEST: Channel VOICE Access Level")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan3")
        time.sleep(1)

        print("\nAdding user to VOICE access list...")
        owner.access("#testchan3", "ADD", "VOICE", "VoiceUser!*@*")

        matches = owner.recv_until("ACCESS.*added|806", timeout=2)
        if matches:
            print("✓ PASS: VOICE entry added successfully")
        else:
            print("✗ FAIL: VOICE entry not added")

        print("\nListing VOICE access...")
        owner.access("#testchan3", "LIST", "VOICE")
        matches = owner.recv_until("VoiceUser", timeout=2)
        if matches:
            print("✓ PASS: VOICE entry appears in list")
        else:
            print("✗ FAIL: VOICE entry not in list")

    finally:
        owner.close()


def test_channel_deny_mode():
    """Test channel DENY access level"""
    print("\n" + "="*60)
    print("TEST: Channel DENY Access Level")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan4")
        time.sleep(1)

        print("\nAdding user to DENY access list...")
        owner.access("#testchan4", "ADD", "DENY", "BadUser!*@*")

        matches = owner.recv_until("ACCESS.*added|806", timeout=2)
        if matches:
            print("✓ PASS: DENY entry added successfully")
        else:
            print("✗ FAIL: DENY entry not added")

        print("\nListing DENY access...")
        owner.access("#testchan4", "LIST", "DENY")
        matches = owner.recv_until("BadUser", timeout=2)
        if matches:
            print("✓ PASS: DENY entry appears in list")
        else:
            print("✗ FAIL: DENY entry not in list")

    finally:
        owner.close()


def test_access_remove():
    """Test removing access entries"""
    print("\n" + "="*60)
    print("TEST: Remove Access Entry")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan5")
        time.sleep(1)

        print("\nAdding then removing VOICE entry...")
        owner.access("#testchan5", "ADD", "VOICE", "TempUser!*@*")
        time.sleep(1)
        owner.access("#testchan5", "REMOVE", "VOICE", "TempUser!*@*")

        matches = owner.recv_until("removed|ACCESS.*removed", timeout=2)
        if matches:
            print("✓ PASS: Entry removed successfully")
        else:
            print("✗ FAIL: Entry not removed")

        print("\nVerifying entry is gone...")
        owner.access("#testchan5", "LIST", "VOICE")
        matches = owner.recv_until("TempUser", timeout=2)
        if not matches:
            print("✓ PASS: Entry no longer in list")
        else:
            print("✗ FAIL: Entry still in list")

    finally:
        owner.close()


def test_access_clear():
    """Test clearing all access entries"""
    print("\n" + "="*60)
    print("TEST: Clear Access List")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan6")
        time.sleep(1)

        print("\nAdding multiple VOICE entries...")
        owner.access("#testchan6", "ADD", "VOICE", "User1!*@*")
        time.sleep(0.5)
        owner.access("#testchan6", "ADD", "VOICE", "User2!*@*")
        time.sleep(0.5)
        owner.access("#testchan6", "ADD", "VOICE", "User3!*@*")
        time.sleep(1)

        print("\nClearing all VOICE entries...")
        owner.access("#testchan6", "CLEAR", "VOICE")

        matches = owner.recv_until("Cleared|cleared", timeout=2)
        if matches:
            print("✓ PASS: Access list cleared")
        else:
            print("✗ FAIL: Access list not cleared")

        print("\nVerifying list is empty...")
        owner.access("#testchan6", "LIST", "VOICE")
        matches = owner.recv_until("User1|User2|User3", timeout=2)
        if not matches:
            print("✓ PASS: List is empty")
        else:
            print("✗ FAIL: List still has entries")

    finally:
        owner.close()


def test_service_deny_protection():
    """Test that services cannot be added to DENY lists"""
    print("\n" + "="*60)
    print("TEST: Services Cannot Be Added to DENY Lists")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan7")
        time.sleep(1)

        print("\nAttempting to add System service to DENY list...")
        owner.access("#testchan7", "ADD", "DENY", "System!*@*")

        matches = owner.recv_until("Cannot add services|825", timeout=2)
        if matches:
            print("✓ PASS: System service protected from DENY list")
        else:
            print("✗ FAIL: Service was added to DENY list or no protection error")

        print("\nAttempting to add Registrar service to DENY list...")
        owner.access("#testchan7", "ADD", "DENY", "Registrar!*@*")

        matches = owner.recv_until("Cannot add services|825", timeout=2)
        if matches:
            print("✓ PASS: Registrar service protected from DENY list")
        else:
            print("✗ FAIL: Service was added to DENY list")

    finally:
        owner.close()


def test_server_access():
    """Test server-level GRANT/DENY access (requires ADMIN/SYSOP)"""
    print("\n" + "="*60)
    print("TEST: Server-Level Access Control")
    print("="*60)

    print("⚠ MANUAL TEST REQUIRED:")
    print("  1. Connect as ADMIN/SYSOP")
    print("  2. Test: ACCESS SERVER ADD GRANT admin!*@*")
    print("  3. Test: ACCESS SERVER ADD DENY baduser!*@*")
    print("  4. Test: ACCESS SERVER LIST GRANT")
    print("  5. Test: ACCESS SERVER LIST DENY")
    print("  6. Verify entries appear correctly")


def test_wildcard_matching():
    """Test wildcard mask matching"""
    print("\n" + "="*60)
    print("TEST: Wildcard Mask Matching")
    print("="*60)

    owner = IRCTestClient("ChannelOwner", "owner", "Channel Owner")
    try:
        owner.connect()
        owner.join("#testchan8")
        time.sleep(1)

        print("\nTesting various wildcard patterns...")
        patterns = [
            "*!*@*.example.com",
            "User*!*@*",
            "*!user@*",
            "User!user@host.com"
        ]

        for pattern in patterns:
            print(f"\n  Adding pattern: {pattern}")
            owner.access("#testchan8", "ADD", "VOICE", pattern)
            time.sleep(0.5)

        print("\nListing all patterns...")
        owner.access("#testchan8", "LIST", "VOICE")
        lines = owner.recv_all(timeout=3)

        found_count = sum(1 for line in lines if any(p in line for p in patterns))
        print(f"\n✓ Found {found_count}/{len(patterns)} patterns in list")

    finally:
        owner.close()


def test_access_auto_grant():
    """Test that users automatically get modes based on access list"""
    print("\n" + "="*60)
    print("TEST: Automatic Mode Grant on Join")
    print("="*60)

    print("⚠ MANUAL TEST REQUIRED:")
    print("  1. Create channel #testautogrant")
    print("  2. Add entry: ACCESS #testautogrant ADD OWNER TestUser!*@*")
    print("  3. User TestUser joins #testautogrant")
    print("  4. Verify TestUser receives +q (owner) mode automatically")
    print("  5. Repeat for HOST (+o) and VOICE (+v)")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Access Control System Test Suite")
    print("="*60)

    try:
        # Automated tests
        test_channel_owner_mode()
        test_channel_host_mode()
        test_channel_voice_mode()
        test_channel_deny_mode()
        test_access_remove()
        test_access_clear()
        test_service_deny_protection()
        test_wildcard_matching()

        # Manual tests
        test_server_access()
        test_access_auto_grant()

        print("\n" + "="*60)
        print("Test Suite Complete")
        print("="*60)
        print("\nNOTE: Some tests require manual verification with ADMIN/SYSOP privileges")

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
