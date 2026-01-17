#!/usr/bin/env python3
"""
Comprehensive Multi-Branch Testing for pyIRCX
Tests cross-server communication with trunk + 2 branches
"""

import socket
import time
import sys

def send_line(sock, line):
    """Send a line to the server"""
    print(f">>> {line}")
    sock.sendall((line + "\r\n").encode('utf-8'))
    time.sleep(0.1)  # Small delay to allow server processing

def recv_lines(sock, timeout=2.0):
    """Receive lines from server with timeout"""
    sock.settimeout(timeout)
    lines = []
    try:
        while True:
            data = sock.recv(4096).decode('utf-8', errors='replace')
            if not data:
                break
            for line in data.split('\r\n'):
                if line.strip():
                    print(f"<<< {line}")
                    lines.append(line)
    except socket.timeout:
        pass
    return lines

def wait_for_pattern(sock, pattern, timeout=5.0):
    """Wait for a specific pattern in server responses"""
    start = time.time()
    while time.time() - start < timeout:
        lines = recv_lines(sock, timeout=0.5)
        for line in lines:
            if pattern in line:
                return True, lines
    return False, []

def connect_user(host, port, nickname, username, realname):
    """Connect and register a user"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    send_line(sock, f"NICK {nickname}")
    send_line(sock, f"USER {username} {username} localhost :{realname}")

    # Wait for welcome message (001)
    found, lines = wait_for_pattern(sock, "001")
    if not found:
        print(f"✗ Failed to register {nickname}")
        return None
    print(f"✓ {nickname} registered on {host}:{port}")
    return sock

def test_cross_server_messaging():
    """Test PRIVMSG between users on different servers"""
    print("\n" + "="*80)
    print("TEST: Cross-Server User-to-User Messaging")
    print("="*80)

    # Connect users to different servers
    trunk_user = connect_user('127.0.0.1', 6667, 'trunkuser', 'trunk', 'Trunk User')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1user', 'branch1', 'Branch1 User')
    branch2_user = connect_user('127.0.0.1', 6669, 'branch2user', 'branch2', 'Branch2 User')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return False

    time.sleep(1)  # Allow nick bursts to propagate

    # Test 1: Branch1 → Branch2 (via trunk)
    print("\n--- Test 1: branch1user sends PRIVMSG to branch2user ---")
    send_line(branch1_user, "PRIVMSG branch2user :Hello from branch1!")
    found, lines = wait_for_pattern(branch2_user, "Hello from branch1!", timeout=3.0)
    if found:
        print("✓ Message delivered from branch1 to branch2")
    else:
        print("✗ Message NOT delivered from branch1 to branch2")
        return False

    # Test 2: Branch2 → Trunk (direct)
    print("\n--- Test 2: branch2user sends PRIVMSG to trunkuser ---")
    send_line(branch2_user, "PRIVMSG trunkuser :Hello from branch2!")
    found, lines = wait_for_pattern(trunk_user, "Hello from branch2!", timeout=3.0)
    if found:
        print("✓ Message delivered from branch2 to trunk")
    else:
        print("✗ Message NOT delivered from branch2 to trunk")
        return False

    # Test 3: Trunk → Branch1 (direct)
    print("\n--- Test 3: trunkuser sends PRIVMSG to branch1user ---")
    send_line(trunk_user, "PRIVMSG branch1user :Hello from trunk!")
    found, lines = wait_for_pattern(branch1_user, "Hello from trunk!", timeout=3.0)
    if found:
        print("✓ Message delivered from trunk to branch1")
    else:
        print("✗ Message NOT delivered from trunk to branch1")
        return False

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    print("\n✓ All cross-server messaging tests passed!")
    return True

def test_cross_server_channels():
    """Test channel operations across servers"""
    print("\n" + "="*80)
    print("TEST: Cross-Server Channel Operations")
    print("="*80)

    # Connect users to different servers
    trunk_user = connect_user('127.0.0.1', 6667, 'trunkchan', 'trunk', 'Trunk Chan')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1chan', 'branch1', 'Branch1 Chan')
    branch2_user = connect_user('127.0.0.1', 6669, 'branch2chan', 'branch2', 'Branch2 Chan')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return False

    time.sleep(1)  # Allow nick bursts to propagate

    # Test 1: All users join same channel
    print("\n--- Test 1: All users join #testchan ---")
    send_line(trunk_user, "JOIN #testchan")
    recv_lines(trunk_user, timeout=0.5)

    send_line(branch1_user, "JOIN #testchan")
    # Branch1 user should see trunk user already in channel
    found, lines = wait_for_pattern(branch1_user, "353", timeout=2.0)  # NAMES list
    has_trunk = any('trunkchan' in line for line in lines)
    if has_trunk:
        print("✓ Branch1 user sees trunk user in #testchan")
    else:
        print("✗ Branch1 user does NOT see trunk user in #testchan")
        return False

    send_line(branch2_user, "JOIN #testchan")
    # Branch2 user should see both trunk and branch1 users
    found, lines = wait_for_pattern(branch2_user, "353", timeout=2.0)
    has_trunk = any('trunkchan' in line for line in lines)
    has_branch1 = any('branch1chan' in line for line in lines)
    if has_trunk and has_branch1:
        print("✓ Branch2 user sees both trunk and branch1 users in #testchan")
    else:
        print("✗ Branch2 user does NOT see all users in #testchan")
        return False

    time.sleep(0.5)

    # Test 2: Cross-server channel messaging
    print("\n--- Test 2: Cross-server channel messaging ---")
    send_line(branch1_user, "PRIVMSG #testchan :Hello from branch1!")

    # Trunk user should see the message
    found_trunk, lines = wait_for_pattern(trunk_user, "Hello from branch1!", timeout=2.0)
    # Branch2 user should see the message
    found_branch2, lines = wait_for_pattern(branch2_user, "Hello from branch1!", timeout=2.0)

    if found_trunk and found_branch2:
        print("✓ Channel message propagated to all servers")
    else:
        if not found_trunk:
            print("✗ Trunk user did NOT receive channel message")
        if not found_branch2:
            print("✗ Branch2 user did NOT receive channel message")
        return False

    # Test 3: PART propagation
    print("\n--- Test 3: PART propagation ---")
    send_line(branch1_user, "PART #testchan")

    # Trunk and Branch2 users should see the PART
    found_trunk, lines = wait_for_pattern(trunk_user, "branch1chan", timeout=2.0)
    found_branch2, lines = wait_for_pattern(branch2_user, "branch1chan", timeout=2.0)

    has_part_trunk = any('PART' in line for line in lines)
    if found_trunk and has_part_trunk:
        print("✓ PART propagated to trunk")
    else:
        print("✗ PART NOT propagated to trunk")
        return False

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    print("\n✓ All cross-server channel tests passed!")
    return True

def test_quit_propagation():
    """Test QUIT propagation across servers"""
    print("\n" + "="*80)
    print("TEST: QUIT Propagation")
    print("="*80)

    # Connect users
    trunk_user = connect_user('127.0.0.1', 6667, 'trunkquit', 'trunk', 'Trunk Quit')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1quit', 'branch1', 'Branch1 Quit')

    if not all([trunk_user, branch1_user]):
        print("✗ Failed to connect users")
        return False

    time.sleep(1)

    # Both join a channel
    send_line(trunk_user, "JOIN #quitchan")
    recv_lines(trunk_user, timeout=0.5)
    send_line(branch1_user, "JOIN #quitchan")
    recv_lines(branch1_user, timeout=0.5)
    time.sleep(0.5)

    # Branch1 user quits
    print("\n--- branch1quit QUITs ---")
    send_line(branch1_user, "QUIT")
    branch1_user.close()

    # Trunk user should see the QUIT
    found, lines = wait_for_pattern(trunk_user, "QUIT", timeout=2.0)
    has_branch1 = any('branch1quit' in line for line in lines)

    if found and has_branch1:
        print("✓ QUIT propagated from branch to trunk")
    else:
        print("✗ QUIT NOT propagated from branch to trunk")
        return False

    trunk_user.close()

    print("\n✓ QUIT propagation test passed!")
    return True

def main():
    """Run all tests"""
    print("="*80)
    print("pyIRCX Multi-Branch Integration Tests")
    print("="*80)
    print("\nEnsure trunk + 2 branches are running:")
    print("  Trunk:   127.0.0.1:6667")
    print("  Branch1: 127.0.0.1:6668")
    print("  Branch2: 127.0.0.1:6669")
    print("\nStarting tests in 3 seconds...")
    time.sleep(3)

    results = []

    # Run all tests
    try:
        results.append(("Cross-Server Messaging", test_cross_server_messaging()))
        time.sleep(1)
        results.append(("Cross-Server Channels", test_cross_server_channels()))
        time.sleep(1)
        results.append(("QUIT Propagation", test_quit_propagation()))
    except Exception as e:
        print(f"\n✗ Test suite error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    passed = 0
    failed = 0
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\nTotal: {passed} passed, {failed} failed")
    print("="*80)

    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
