#!/usr/bin/env python3
"""
Test script for trunk/branch setup with staff authentication
Tests various scenarios and checks error message clarity
"""

import socket
import time
import sys

def send_line(sock, line):
    """Send a line to the IRC server"""
    print(f">>> {line}")
    sock.sendall(f"{line}\r\n".encode('utf-8'))
    time.sleep(0.1)

def recv_lines(sock, timeout=1.0):
    """Receive lines from the IRC server"""
    sock.settimeout(timeout)
    lines = []
    try:
        while True:
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            if not data:
                break
            for line in data.split('\r\n'):
                if line.strip():
                    lines.append(line.strip())
                    print(f"<<< {line.strip()}")
    except socket.timeout:
        pass
    return lines

def test_branch_staff_auth_success():
    """Test successful staff authentication on branch server"""
    print("\n" + "="*80)
    print("TEST 1: Staff authentication SUCCESS on branch server")
    print("="*80)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6668))  # Branch server

    # Read welcome
    recv_lines(sock, 0.5)

    # Authenticate with PASS (default admin password is 'changeme')
    send_line(sock, "PASS changeme")
    send_line(sock, "NICK testadmin")
    send_line(sock, "USER testadmin testadmin localhost :Test Admin")

    # Wait for response
    lines = recv_lines(sock, 2.0)

    # Check for success indicators
    success = False
    for line in lines:
        if 'MODE testadmin' in line and '+o' in line:
            print("\n✓ Staff authentication successful - received +o mode")
            success = True
        if '001' in line or 'Welcome' in line:
            print("✓ Registration complete")

    if not success:
        print("\n✗ FAILED: Did not receive staff modes")
        return False

    sock.close()
    return True

def test_branch_staff_auth_failure():
    """Test failed staff authentication on branch server"""
    print("\n" + "="*80)
    print("TEST 2: Staff authentication FAILURE on branch server")
    print("="*80)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6668))  # Branch server

    # Read welcome
    recv_lines(sock, 0.5)

    # Authenticate with wrong password
    send_line(sock, "PASS wrongpassword")
    send_line(sock, "NICK testuser")
    send_line(sock, "USER testuser testuser localhost :Test User")

    # Wait for response
    lines = recv_lines(sock, 2.0)

    # Check that we DON'T get staff modes
    got_staff_mode = False
    got_registration = False

    for line in lines:
        if 'MODE testuser' in line and '+o' in line:
            print("\n✗ FAILED: Received staff modes with wrong password!")
            got_staff_mode = True
        if '001' in line or 'Welcome' in line:
            print("✓ Registration complete (as normal user)")
            got_registration = True

    if not got_staff_mode and got_registration:
        print("\n✓ Staff authentication properly rejected")
        sock.close()
        return True

    sock.close()
    return False

def test_branch_service_routing():
    """Test service message routing from branch to trunk"""
    print("\n" + "="*80)
    print("TEST 3: Service message routing from branch to trunk")
    print("="*80)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6668))  # Branch server

    # Read welcome
    recv_lines(sock, 0.5)

    # Connect as normal user
    send_line(sock, "NICK servicetest")
    send_line(sock, "USER servicetest servicetest localhost :Service Test")

    # Wait for registration
    recv_lines(sock, 1.0)

    # Try to message Registrar
    send_line(sock, "PRIVMSG Registrar :HELP")

    # Wait for response
    lines = recv_lines(sock, 2.0)

    # Check for service response
    success = False
    for line in lines:
        if 'Registrar' in line and ('NOTICE' in line or 'PRIVMSG' in line):
            print("\n✓ Received response from Registrar service")
            success = True

    if not success:
        print("\n✗ FAILED: No response from Registrar service")
        return False

    sock.close()
    return True

def test_trunk_direct_connection():
    """Test connecting directly to trunk server"""
    print("\n" + "="*80)
    print("TEST 4: Direct connection to trunk server")
    print("="*80)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6667))  # Trunk server

    # Read welcome
    recv_lines(sock, 0.5)

    # Connect as normal user
    send_line(sock, "NICK trunktest")
    send_line(sock, "USER trunktest trunktest localhost :Trunk Test")

    # Wait for registration
    lines = recv_lines(sock, 1.0)

    success = False
    for line in lines:
        if '001' in line or 'Welcome' in line:
            print("✓ Successfully connected to trunk server")
            success = True

    # Try to message Registrar (should work locally)
    send_line(sock, "PRIVMSG Registrar :HELP")
    lines = recv_lines(sock, 2.0)

    for line in lines:
        if 'Registrar' in line:
            print("✓ Registrar service responding on trunk")

    sock.close()
    return success

def main():
    """Run all tests"""
    print("="*80)
    print("pyIRCX Trunk/Branch Authentication and Service Routing Tests")
    print("="*80)

    results = []

    # Run tests
    results.append(("Staff Auth Success", test_branch_staff_auth_success()))
    time.sleep(0.5)

    results.append(("Staff Auth Failure", test_branch_staff_auth_failure()))
    time.sleep(0.5)

    results.append(("Service Routing", test_branch_service_routing()))
    time.sleep(0.5)

    results.append(("Trunk Direct Connect", test_trunk_direct_connection()))

    # Print summary
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
