#!/usr/bin/env python3
"""
Test System and God mystical entity functionality
"""
import asyncio
import socket
import time

class SimpleIRCClient:
    def __init__(self, host='127.0.0.1', port=6667):
        self.host = host
        self.port = port
        self.sock = None
        self.buffer = []

    async def connect(self):
        """Connect to IRC server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.setblocking(False)

    async def send(self, msg):
        """Send message to server"""
        self.sock.send(f"{msg}\r\n".encode())
        await asyncio.sleep(0.1)

    async def recv(self):
        """Receive messages from server"""
        try:
            data = self.sock.recv(4096).decode('utf-8', errors='ignore')
            lines = data.split('\r\n')
            self.buffer.extend([line for line in lines if line])
            return lines
        except BlockingIOError:
            return []

    async def login(self, nick, password=None):
        """Login to IRC server"""
        await self.send(f"NICK {nick}")
        await self.send(f"USER {nick} 0 * :{nick}")

        # Wait for registration to complete
        await asyncio.sleep(0.5)
        await self.recv()

        if password:
            await self.send(f"PRIVMSG Registrar :IDENTIFY {password}")
            # Wait for authentication to complete
            await asyncio.sleep(0.5)
            await self.recv()

    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()

async def test_random_responses():
    """Test that non-admins get random funny responses"""
    print("\n=== Testing Random Responses (Non-Admin) ===")

    client = SimpleIRCClient()
    await client.connect()
    await client.login("TestUser")

    # Clear buffer
    client.buffer = []

    # Send message to God
    print("Sending message to God...")
    await client.send("PRIVMSG God :Hello God!")
    await asyncio.sleep(0.3)
    await client.recv()

    # Check for response
    god_responses = [line for line in client.buffer if 'God!' in line and 'NOTICE' in line]
    if god_responses:
        print(f"✓ God responded: {god_responses[0]}")
    else:
        print("✗ No response from God")
        print(f"Buffer: {client.buffer}")

    # Clear buffer
    client.buffer = []

    # Send message to System
    print("\nSending message to System...")
    await client.send("PRIVMSG System :Hello System!")
    await asyncio.sleep(0.3)
    await client.recv()

    # Check for response
    system_responses = [line for line in client.buffer if 'System!' in line and 'NOTICE' in line]
    if system_responses:
        print(f"✓ System responded: {system_responses[0]}")
    else:
        print("✗ No response from System")
        print(f"Buffer: {client.buffer}")

    client.close()

async def test_admin_help():
    """Test that admins can get HELP from System/God"""
    print("\n=== Testing Admin HELP ===")

    client = SimpleIRCClient()
    await client.connect()
    await client.login("AdminTest", "password")
    # Authenticate as admin
    await client.send("PRIVMSG Registrar :IDENTIFY admin password")

    # Clear buffer
    client.buffer = []

    # Ask God for help
    print("Asking God for HELP...")
    await client.send("PRIVMSG God :HELP")
    await asyncio.sleep(0.3)
    await client.recv()

    # Check for help response
    help_responses = [line for line in client.buffer if 'Commands' in line or 'PRIVMSG' in line]
    if help_responses:
        print(f"✓ God provided help")
        for line in help_responses[:5]:  # Show first 5 lines
            print(f"  {line}")
    else:
        print("✗ No help from God")
        print(f"Buffer: {client.buffer}")

    client.close()

async def test_admin_privmsg():
    """Test that admins can send PRIVMSG as System/God"""
    print("\n=== Testing Admin PRIVMSG Masquerading ===")

    # Admin client
    admin = SimpleIRCClient()
    await admin.connect()
    await admin.login("John", "password")

    # Regular user client
    user = SimpleIRCClient()
    await user.connect()
    await user.login("TestUser2")

    # Clear buffers
    admin.buffer = []
    user.buffer = []

    # Admin sends PRIVMSG as God to TestUser2
    print("Admin sending PRIVMSG as God to TestUser2...")
    await admin.send("PRIVMSG God :PRIVMSG TestUser2 Greetings, mortal!")
    await asyncio.sleep(0.5)
    await user.recv()

    # Check if TestUser2 received message from God
    messages = [line for line in user.buffer if 'God!' in line and 'PRIVMSG' in line and 'mortal' in line]
    if messages:
        print(f"✓ User received message from God: {messages[0]}")
    else:
        print("✗ User did not receive message from God")
        print(f"User buffer: {user.buffer}")

    admin.close()
    user.close()

async def test_admin_notice():
    """Test that admins can send NOTICE as System/God"""
    print("\n=== Testing Admin NOTICE Masquerading ===")

    # Admin client
    admin = SimpleIRCClient()
    await admin.connect()
    await admin.login("John", "password")

    # Regular user client
    user = SimpleIRCClient()
    await user.connect()
    await user.login("TestUser3")

    # Clear buffers
    admin.buffer = []
    user.buffer = []

    # Admin sends NOTICE as System to TestUser3
    print("Admin sending NOTICE as System to TestUser3...")
    await admin.send("PRIVMSG System :NOTICE TestUser3 System notification!")
    await asyncio.sleep(0.5)
    await user.recv()

    # Check if TestUser3 received notice from System
    notices = [line for line in user.buffer if 'System!' in line and 'NOTICE' in line and 'notification' in line]
    if notices:
        print(f"✓ User received notice from System: {notices[0]}")
    else:
        print("✗ User did not receive notice from System")
        print(f"User buffer: {user.buffer}")

    admin.close()
    user.close()

async def test_admin_invite():
    """Test that admins can invite System/God to channels"""
    print("\n=== Testing Admin INVITE ===")

    admin = SimpleIRCClient()
    await admin.connect()
    await admin.login("John", "password")

    # Create a channel
    await admin.send("JOIN #test")
    await asyncio.sleep(0.3)
    await admin.recv()

    # Clear buffer
    admin.buffer = []

    # Invite God to channel
    print("Inviting God to #test...")
    await admin.send("INVITE God #test")
    await asyncio.sleep(0.5)
    await admin.recv()

    # Check for God joining
    joins = [line for line in admin.buffer if ':God!' in line and 'JOIN' in line]
    modes = [line for line in admin.buffer if 'MODE #test +q God' in line]

    if joins:
        print(f"✓ God joined channel: {joins[0]}")
    else:
        print("✗ God did not join channel")

    if modes:
        print(f"✓ God received +q (owner): {modes[0]}")
    else:
        print("✗ God did not receive +q")

    if not joins and not modes:
        print(f"Buffer: {admin.buffer}")

    admin.close()

async def main():
    """Run all tests"""
    print("=" * 70)
    print("Testing System and God Mystical Entities")
    print("=" * 70)

    await test_random_responses()
    await test_admin_help()
    await test_admin_privmsg()
    await test_admin_notice()
    await test_admin_invite()

    print("\n" + "=" * 70)
    print("Testing Complete")
    print("=" * 70)

if __name__ == '__main__':
    asyncio.run(main())
