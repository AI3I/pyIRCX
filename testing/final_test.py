#!/usr/bin/env python3
"""Final test - verify capitalization for both System and God"""
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 6667))

def send(msg):
    sock.send(f"{msg}\r\n".encode())
    time.sleep(0.15)

def recv():
    try:
        data = sock.recv(4096).decode('utf-8', errors='ignore')
        lines = [line for line in data.split('\r\n') if line and 'NOTICE' in line and ('System' in line or 'God' in line)]
        for line in lines:
            print(line)
        return lines
    except:
        return []

# Register
send("NICK CapTest")
send("USER captest 0 * :Cap Test")
time.sleep(0.5)
recv()

# Test lowercase "system"
print("\n=== Testing lowercase 'system' ===")
send("PRIVMSG system :test")
time.sleep(0.3)
recv()

# Test lowercase "god"
print("\n=== Testing lowercase 'god' ===")
send("PRIVMSG god :test")
time.sleep(0.3)
recv()

# Test mixed case "SyStEm"
print("\n=== Testing mixed case 'SyStEm' ===")
send("PRIVMSG SyStEm :test")
time.sleep(0.3)
recv()

sock.close()
print("\n✓ All responses should show proper capitalization (System/God)")
