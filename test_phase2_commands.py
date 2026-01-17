#!/usr/bin/env python3
"""
Phase 2 Command Testing for pyIRCX Server Linking
Tests TOPIC, KICK, INVITE, MODE, and other cross-server commands
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
    original_timeout = sock.gettimeout()
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
    finally:
        # Restore original timeout
        sock.settimeout(original_timeout if original_timeout is not None else 5.0)
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

def test_topic_propagation():
    """Test TOPIC propagation across servers"""
    print("\n" + "="*80)
    print("TEST: TOPIC Propagation Across Server Links")
    print("="*80)

    # Connect users to different servers
    trunk_user = connect_user('127.0.0.1', 6667, 'trunktopic', 'trunk', 'Trunk Topic')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1topic', 'branch1', 'Branch1 Topic')
    branch2_user = connect_user('127.0.0.1', 6669, 'branch2topic', 'branch2', 'Branch2 Topic')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return False

    time.sleep(1)  # Allow nick bursts to propagate

    # All users join #topicchan
    print("\n--- All users join #topicchan ---")
    send_line(trunk_user, "JOIN #topicchan")
    recv_lines(trunk_user, timeout=0.5)

    send_line(branch1_user, "JOIN #topicchan")
    recv_lines(branch1_user, timeout=0.5)

    send_line(branch2_user, "JOIN #topicchan")
    recv_lines(branch2_user, timeout=0.5)

    time.sleep(0.5)

    # Clear any pending messages
    recv_lines(trunk_user, timeout=0.2)
    recv_lines(branch1_user, timeout=0.2)
    recv_lines(branch2_user, timeout=0.2)

    # Trunk user grants operator status to branch1 user (needed for +t mode)
    print("\n--- Granting operator status to branch1topic ---")
    send_line(trunk_user, "MODE #topicchan +o branch1topic")
    time.sleep(0.5)

    # Clear MODE responses
    recv_lines(trunk_user, timeout=0.2)
    recv_lines(branch1_user, timeout=0.2)
    recv_lines(branch2_user, timeout=0.2)

    # Test 1: Branch1 user sets TOPIC
    print("\n--- Test 1: branch1topic sets TOPIC ---")
    send_line(branch1_user, "TOPIC #topicchan :This is the new topic!")

    # Give time for cross-server propagation
    time.sleep(1.0)

    # All users should see the TOPIC change
    found_trunk, lines_trunk = wait_for_pattern(trunk_user, "This is the new topic!", timeout=3.0)
    found_branch2, lines_branch2 = wait_for_pattern(branch2_user, "This is the new topic!", timeout=3.0)

    # Verify TOPIC messages contain correct syntax
    has_topic_trunk = any('TOPIC #topicchan' in line for line in lines_trunk)
    has_topic_branch2 = any('TOPIC #topicchan' in line for line in lines_branch2)

    if found_trunk and has_topic_trunk:
        print("✓ TOPIC propagated to trunk server")
    else:
        print("✗ TOPIC NOT propagated to trunk server")
        return False

    if found_branch2 and has_topic_branch2:
        print("✓ TOPIC propagated to branch2 server")
    else:
        print("✗ TOPIC NOT propagated to branch2 server")
        return False

    time.sleep(0.5)

    # Clear buffers
    recv_lines(trunk_user, timeout=0.2)
    recv_lines(branch1_user, timeout=0.2)
    recv_lines(branch2_user, timeout=0.2)

    # Test 2: Trunk user changes TOPIC
    print("\n--- Test 2: trunktopic changes TOPIC ---")
    send_line(trunk_user, "TOPIC #topicchan :Changed by trunk user")

    # Give time for cross-server propagation
    time.sleep(1.0)

    # Branch users should see the new TOPIC
    found_branch1, lines_branch1 = wait_for_pattern(branch1_user, "Changed by trunk user", timeout=3.0)
    found_branch2, lines_branch2 = wait_for_pattern(branch2_user, "Changed by trunk user", timeout=3.0)

    has_topic_branch1 = any('TOPIC #topicchan' in line for line in lines_branch1)
    has_topic_branch2 = any('TOPIC #topicchan' in line for line in lines_branch2)

    if found_branch1 and has_topic_branch1:
        print("✓ TOPIC from trunk propagated to branch1")
    else:
        print("✗ TOPIC from trunk NOT propagated to branch1")
        return False

    if found_branch2 and has_topic_branch2:
        print("✓ TOPIC from trunk propagated to branch2")
    else:
        print("✗ TOPIC from trunk NOT propagated to branch2")
        return False

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    print("\n✓ TOPIC propagation test passed!")
    return True

def test_kick_propagation():
    """Test KICK propagation across servers"""
    print("\n" + "="*80)
    print("TEST: KICK Propagation Across Server Links")
    print("="*80)

    # Connect users to different servers
    trunk_user = connect_user('127.0.0.1', 6667, 'trunkkick', 'trunk', 'Trunk Kick')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1kick', 'branch1', 'Branch1 Kick')
    branch2_user = connect_user('127.0.0.1', 6669, 'branch2kick', 'branch2', 'Branch2 Kick')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return False

    time.sleep(1)  # Allow nick bursts to propagate

    # All users join #kickchan
    print("\n--- All users join #kickchan ---")
    send_line(trunk_user, "JOIN #kickchan")
    recv_lines(trunk_user, timeout=0.5)

    send_line(branch1_user, "JOIN #kickchan")
    recv_lines(branch1_user, timeout=0.5)

    send_line(branch2_user, "JOIN #kickchan")
    recv_lines(branch2_user, timeout=0.5)

    time.sleep(1)  # Wait for all JOINs to propagate

    # Clear buffers
    recv_lines(trunk_user, timeout=0.2)
    recv_lines(branch1_user, timeout=0.2)
    recv_lines(branch2_user, timeout=0.2)

    # Test: Trunk user (owner) kicks branch1 user
    print("\n--- Test: trunkkick (owner) kicks branch1kick ---")
    send_line(trunk_user, "KICK #kickchan branch1kick :Test kick reason")

    time.sleep(1.0)  # Give time for propagation

    # Branch2 user should see the KICK
    found_branch2, lines_branch2 = wait_for_pattern(branch2_user, "KICK", timeout=2.0)
    has_kick = any('branch1kick' in line and 'Test kick reason' in line for line in lines_branch2)

    if found_branch2 and has_kick:
        print("✓ KICK propagated to branch2 server")
    else:
        print("✗ KICK NOT propagated to branch2 server")
        return False

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    print("\n✓ KICK propagation test passed!")
    return True

def test_invite_propagation():
    """Test INVITE propagation across servers"""
    print("\n" + "="*80)
    print("TEST: INVITE Propagation Across Server Links")
    print("="*80)

    # Connect users to different servers
    trunk_user = connect_user('127.0.0.1', 6667, 'trunkinvite', 'trunk', 'Trunk Invite')
    branch1_user = connect_user('127.0.0.1', 6668, 'branch1invite', 'branch1', 'Branch1 Invite')
    branch2_user = connect_user('127.0.0.1', 6669, 'branch2invite', 'branch2', 'Branch2 Invite')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return False

    time.sleep(1)  # Allow nick bursts to propagate

    # Only trunk user joins #invitechan initially
    print("\n--- Trunk user creates invite-only channel #invitechan ---")
    send_line(trunk_user, "JOIN #invitechan")
    recv_lines(trunk_user, timeout=0.5)

    # Set invite-only mode
    send_line(trunk_user, "MODE #invitechan +i")
    recv_lines(trunk_user, timeout=0.5)

    time.sleep(0.5)

    # Clear buffers
    recv_lines(trunk_user, timeout=0.2)
    recv_lines(branch1_user, timeout=0.2)
    recv_lines(branch2_user, timeout=0.2)

    # Test: Trunk user invites branch1 user
    print("\n--- Test: trunkinvite invites branch1invite to #invitechan ---")
    send_line(trunk_user, "INVITE branch1invite #invitechan")

    time.sleep(1.0)  # Give time for propagation

    # Branch1 user should receive the INVITE
    found_branch1, lines_branch1 = wait_for_pattern(branch1_user, "INVITE", timeout=2.0)
    has_invite = any('branch1invite' in line and 'invitechan' in line for line in lines_branch1)

    if found_branch1 and has_invite:
        print("✓ INVITE propagated to branch1 user")
    else:
        print("✗ INVITE NOT propagated to branch1 user")
        return False

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    print("\n✓ INVITE propagation test passed!")
    return True

def main():
    """Run all Phase 2 tests"""
    print("="*80)
    print("pyIRCX Phase 2 Command Tests")
    print("="*80)
    print("\nEnsure trunk + 2 branches are running:")
    print("  Trunk:   127.0.0.1:6667")
    print("  Branch1: 127.0.0.1:6668")
    print("  Branch2: 127.0.0.1:6669")
    print("\nStarting tests in 3 seconds...")
    time.sleep(3)

    results = []

    # Run tests
    try:
        results.append(("TOPIC Propagation", test_topic_propagation()))
        time.sleep(1)
        results.append(("KICK Propagation", test_kick_propagation()))
        time.sleep(1)
        results.append(("INVITE Propagation", test_invite_propagation()))
    except Exception as e:
        print(f"\n✗ Test suite error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Summary
    print("\n" + "="*80)
    print("PHASE 2 TEST SUMMARY")
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
