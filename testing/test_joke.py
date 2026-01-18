#!/usr/bin/env python3
"""Test the JOKE command"""
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
        return data
    except:
        return ""

# Register
send("NICK JokeTester")
send("USER joketester 0 * :Joke Tester")
time.sleep(0.5)
recv()

print("Testing JOKE command - requesting 5 jokes:\n")
for i in range(5):
    send("JOKE")
    time.sleep(0.3)
    data = recv()
    # Extract just the joke from the NOTICE
    for line in data.split('\r\n'):
        if 'NOTICE' in line and ':' in line:
            # Get the part after the last ':'
            joke = line.split(':', 2)[-1]
            print(f"{i+1}. {joke}")

sock.close()
