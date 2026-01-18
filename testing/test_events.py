#!/usr/bin/env python3
"""Test EVENT command and event notifications"""
import socket
import time

def test_events():
    # Connect as admin
    admin_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    admin_sock.connect(('127.0.0.1', 6667))

    def send(sock, msg):
        sock.send(f"{msg}\r\n".encode())
        time.sleep(0.15)

    def recv(sock):
        try:
            data = sock.recv(8192).decode('utf-8', errors='ignore')
            return data
        except:
            return ""

    # Register admin
    send(admin_sock, "NICK EventAdmin")
    send(admin_sock, "USER eventadmin 0 * :Event Admin")
    time.sleep(0.5)
    recv(admin_sock)

    # Authenticate as admin
    send(admin_sock, "PRIVMSG Registrar :IDENTIFY admin password")
    time.sleep(0.5)
    recv(admin_sock)

    print("=== Testing EVENT ADD ===")
    send(admin_sock, "EVENT ADD MEMBER")
    time.sleep(0.3)
    data = recv(admin_sock)
    if "806" in data:
        print("✓ EVENT ADD MEMBER successful")
    else:
        print("✗ EVENT ADD failed")
        print(data)

    print("\n=== Testing EVENT LIST ===")
    send(admin_sock, "EVENT LIST")
    time.sleep(0.3)
    data = recv(admin_sock)
    if "808" in data and "MEMBER" in data and "810" in data:
        print("✓ EVENT LIST shows MEMBER subscription")
    else:
        print("✗ EVENT LIST failed")
        print(data)

    print("\n=== Testing MEMBER/JOIN event ===")
    # Connect another user and join a channel
    user_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_sock.connect(('127.0.0.1', 6667))

    send(user_sock, "NICK TestUser1")
    send(user_sock, "USER testuser1 0 * :Test User")
    time.sleep(0.5)
    recv(user_sock)

    send(user_sock, "JOIN #eventtest")
    time.sleep(0.5)
    recv(user_sock)

    # Check if admin received EVENT
    data = recv(admin_sock)
    if "EVENT" in data and "MEMBER" in data and "JOIN" in data and "#eventtest" in data:
        print("✓ Received MEMBER/JOIN event")
        print(f"  Event: {[line for line in data.split('\\r\\n') if 'EVENT' in line][0]}")
    else:
        print("✗ No MEMBER/JOIN event received")
        print(data)

    print("\n=== Testing MEMBER/PART event ===")
    send(user_sock, "PART #eventtest")
    time.sleep(0.5)
    recv(user_sock)

    data = recv(admin_sock)
    if "EVENT" in data and "MEMBER" in data and "PART" in data:
        print("✓ Received MEMBER/PART event")
    else:
        print("✗ No MEMBER/PART event received")

    print("\n=== Testing EVENT DELETE ===")
    send(admin_sock, "EVENT DELETE MEMBER *!*@*")
    time.sleep(0.3)
    data = recv(admin_sock)
    if "807" in data:
        print("✓ EVENT DELETE successful")
    else:
        print("✗ EVENT DELETE failed")

    print("\n=== Testing EVENT LIST after DELETE ===")
    send(admin_sock, "EVENT LIST")
    time.sleep(0.3)
    data = recv(admin_sock)
    if "808" in data and "810" in data and "MEMBER" not in data:
        print("✓ EVENT LIST shows no subscriptions")
    else:
        print("✗ EVENT LIST still shows subscriptions")
        print(data)

    user_sock.close()
    admin_sock.close()

if __name__ == '__main__':
    test_events()
