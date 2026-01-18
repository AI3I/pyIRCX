#!/usr/bin/env python3
"""Quick manual test of System/God"""
import socket
import time

def test_system_god():
    # Connect to IRC
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6667))

    def send(msg):
        print(f">>> {msg}")
        sock.send(f"{msg}\r\n".encode())
        time.sleep(0.2)

    def recv():
        try:
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            for line in data.split('\r\n'):
                if line:
                    print(f"<<< {line}")
            return data
        except:
            return ""

    # Register
    send("NICK TestAdmin")
    send("USER testadmin 0 * :Test Admin")
    time.sleep(0.5)
    recv()

    # Try to authenticate as admin
    send("PRIVMSG Registrar :IDENTIFY admin password")
    time.sleep(0.5)
    data = recv()

    print("\n=== Testing non-admin random response ===")
    send("PRIVMSG System :Hello!")
    time.sleep(0.3)
    recv()

    sock.close()

if __name__ == '__main__':
    test_system_god()
