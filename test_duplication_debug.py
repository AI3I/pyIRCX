#!/usr/bin/env python3
"""
Minimal test to debug message duplication.
Sends ONE channel message and tracks what each user sees.
"""

import socket
import time

def connect_and_register(host, port, nick, user, realname):
    """Connect to server and register"""
    s = socket.socket()
    s.connect((host, port))
    # Drain initial MOTD
    s.settimeout(0.5)
    try:
        while True:
            s.recv(4096)
    except socket.timeout:
        pass

    # Register
    s.send(f"NICK {nick}\r\nUSER {user} {user} {user} :{realname}\r\n".encode())
    s.settimeout(2.0)
    data = s.recv(8192).decode('utf-8', errors='replace')
    if '001' not in data:
        print(f"ERROR: {nick} failed to register")
        print(data)
        return None
    print(f"✓ {nick} registered on {host}:{port}")
    return s

def join_channel(sock, nick, channel):
    """Join a channel and wait for confirmation"""
    sock.send(f"JOIN {channel}\r\n".encode())
    sock.settimeout(1.0)
    data = sock.recv(8192).decode('utf-8', errors='replace')
    if '366' in data:  # End of NAMES
        print(f"✓ {nick} joined {channel}")
        return True
    print(f"✗ {nick} failed to join {channel}")
    return False

def send_message(sock, target, text):
    """Send a PRIVMSG"""
    sock.send(f"PRIVMSG {target} :{text}\r\n".encode())
    print(f">>> Sent: PRIVMSG {target} :{text}")

def receive_all(sock, timeout=1.0):
    """Receive all available data"""
    sock.settimeout(timeout)
    messages = []
    try:
        while True:
            data = sock.recv(4096).decode('utf-8', errors='replace')
            if not data:
                break
            for line in data.split('\r\n'):
                if line.strip():
                    messages.append(line)
    except socket.timeout:
        pass
    return messages

def main():
    print("="*80)
    print("DUPLICATION DEBUG TEST")
    print("="*80)
    print("\nConnecting users...")

    # Connect 3 users to 3 different servers
    trunk_user = connect_and_register('127.0.0.1', 6667, 'trunkchan', 'trunk', 'Trunk User')
    branch1_user = connect_and_register('127.0.0.1', 6668, 'branch1chan', 'branch1', 'Branch1 User')
    branch2_user = connect_and_register('127.0.0.1', 6669, 'branch2chan', 'branch2', 'Branch2 User')

    if not all([trunk_user, branch1_user, branch2_user]):
        print("✗ Failed to connect all users")
        return 1

    time.sleep(1)  # Allow NICK bursts to propagate

    print("\nJoining #testchan...")
    join_channel(trunk_user, 'trunkchan', '#testchan')
    time.sleep(0.3)
    join_channel(branch1_user, 'branch1chan', '#testchan')
    time.sleep(0.3)
    join_channel(branch2_user, 'branch2chan', '#testchan')
    time.sleep(0.5)

    # Clear any pending JOIN messages
    receive_all(trunk_user, timeout=0.3)
    receive_all(branch1_user, timeout=0.3)
    receive_all(branch2_user, timeout=0.3)

    print("\n" + "="*80)
    print("SENDING TEST MESSAGE FROM BRANCH1")
    print("="*80)

    send_message(branch1_user, '#testchan', 'UNIQUE_TEST_MESSAGE_12345')
    time.sleep(0.5)

    # Collect what each user received
    trunk_msgs = receive_all(trunk_user)
    branch1_msgs = receive_all(branch1_user)
    branch2_msgs = receive_all(branch2_user)

    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)

    # Filter for PRIVMSG lines
    trunk_privmsgs = [m for m in trunk_msgs if 'PRIVMSG' in m and 'UNIQUE_TEST_MESSAGE' in m]
    branch1_privmsgs = [m for m in branch1_msgs if 'PRIVMSG' in m and 'UNIQUE_TEST_MESSAGE' in m]
    branch2_privmsgs = [m for m in branch2_msgs if 'PRIVMSG' in m and 'UNIQUE_TEST_MESSAGE' in m]

    print(f"\nTrunk user (trunkchan) received {len(trunk_privmsgs)} PRIVMSG(s):")
    for i, msg in enumerate(trunk_privmsgs, 1):
        print(f"  {i}. {msg}")

    print(f"\nBranch1 user (branch1chan - SENDER) received {len(branch1_privmsgs)} PRIVMSG(s):")
    for i, msg in enumerate(branch1_privmsgs, 1):
        print(f"  {i}. {msg}")

    print(f"\nBranch2 user (branch2chan) received {len(branch2_privmsgs)} PRIVMSG(s):")
    for i, msg in enumerate(branch2_privmsgs, 1):
        print(f"  {i}. {msg}")

    print("\n" + "="*80)
    print("ANALYSIS")
    print("="*80)

    # Expected: Each user should see the message ONCE
    # Trunk: 1x (from branch1 via link)
    # Branch1 sender: 0x (sender shouldn't see own message with current code)
    # Branch2: 1x (from trunk forwarding)

    issues = []
    if len(trunk_privmsgs) != 1:
        issues.append(f"Trunk received {len(trunk_privmsgs)} instead of 1")
    if len(branch1_privmsgs) > 0:
        issues.append(f"Sender (branch1) received {len(branch1_privmsgs)} (echo issue)")
    if len(branch2_privmsgs) != 1:
        issues.append(f"Branch2 received {len(branch2_privmsgs)} instead of 1")

    if issues:
        print("✗ ISSUES FOUND:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("✓ All users received correct number of messages")

    # Cleanup
    trunk_user.close()
    branch1_user.close()
    branch2_user.close()

    return 0 if not issues else 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
