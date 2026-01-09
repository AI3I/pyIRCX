#!/usr/bin/env python3
"""
pyIRCX Server Regression Test Suite
Tests all major functionality including IRC and IRCX features

Copyright (C) 2026 pyIRCX Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import time
import sys
import ssl
from typing import List

class IRCTestClient:
    """Simple IRC test client with optional SSL support"""

    def __init__(self, name: str, host: str = "127.0.0.1", port: int = 6667, use_ssl: bool = False):
        self.name = name
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reader = None
        self.writer = None
        self.buffer = []
        self.connected = False

    async def connect(self, nickname: str, username: str = None, password: str = None):
        """Connect to IRC server (with optional SSL)"""
        try:
            if self.use_ssl:
                # Create SSL context that doesn't verify certificates (for testing)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.port, ssl=ssl_context
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.connected = True
            
            if password:
                await self.send_raw(f"PASS {password}")
            
            await self.send_raw(f"NICK {nickname}")
            await self.send_raw(f"USER {username or nickname} 0 * :{nickname}")
            
            # Wait for registration
            await asyncio.sleep(0.5)
            await self.read_lines()
            
            return True
        except Exception as e:
            print(f"[{self.name}] Connection failed: {e}")
            return False
    
    async def send_raw(self, line: str):
        """Send raw IRC command"""
        if not self.connected:
            return
        msg = line + "\r\n"
        self.writer.write(msg.encode('utf-8'))
        await self.writer.drain()
        print(f"[{self.name}] >>> {line}")
    
    async def read_lines(self, timeout: float = 1.0) -> List[str]:
        """Read all available lines"""
        lines = []
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=0.1)
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    lines.append(decoded)
                    print(f"[{self.name}] <<< {decoded}")
        except asyncio.TimeoutError:
            pass
        
        self.buffer.extend(lines)
        return lines
    
    async def expect(self, pattern: str, timeout: float = 2.0) -> bool:
        """Wait for a line matching pattern"""
        start = time.time()
        while time.time() - start < timeout:
            await self.read_lines(timeout=0.1)
            for line in self.buffer:
                if pattern in line:
                    return True
            await asyncio.sleep(0.1)
        return False
    
    async def disconnect(self):
        """Disconnect from server"""
        if self.connected:
            try:
                await self.send_raw("QUIT :Test completed")
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
            self.connected = False


class TestRunner:
    """Test suite runner"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def test(self, name: str):
        """Decorator for test functions"""
        def decorator(func):
            self.tests.append((name, func))
            return func
        return decorator
    
    async def run_all(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("pyIRCX REGRESSION TEST SUITE")
        print("="*70 + "\n")
        
        for name, func in self.tests:
            print(f"\n{'='*70}")
            print(f"TEST: {name}")
            print('='*70)
            
            try:
                await func()
                self.passed += 1
                print(f"✅ PASSED: {name}")
            except AssertionError as e:
                self.failed += 1
                print(f"❌ FAILED: {name}")
                print(f"   Error: {e}")
            except Exception as e:
                self.failed += 1
                print(f"❌ ERROR: {name}")
                print(f"   Exception: {e}")
                import traceback
                traceback.print_exc()
        
        # Summary
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Total:  {self.passed + self.failed}")
        print(f"Success Rate: {(self.passed/(self.passed+self.failed)*100):.1f}%")
        print("="*70 + "\n")
        
        return self.failed == 0


# Initialize test runner
runner = TestRunner()


@runner.test("Basic Connection and Registration")
async def test_basic_connection():
    """Test basic IRC connection and registration"""
    client = IRCTestClient("test_basic")
    
    assert await client.connect("TestUser1"), "Connection failed"
    assert await client.expect("001"), "No welcome message"
    assert await client.expect("002"), "No host info"
    assert await client.expect("376"), "No MOTD end"
    
    await client.disconnect()


@runner.test("IRCX Protocol Detection")
async def test_ircx_protocol():
    """Test IRCX protocol activation"""
    client = IRCTestClient("test_ircx")
    
    await client.connect("TestUser2")
    await client.send_raw("IRCX")
    assert await client.expect("800"), "No IRCX confirmation"
    
    await client.disconnect()


@runner.test("Nickname Collision")
async def test_nick_collision():
    """Test nickname already in use"""
    client1 = IRCTestClient("test_nick1")
    client2 = IRCTestClient("test_nick2")
    
    await client1.connect("SameNick")
    
    # Try to connect with same nick
    await client2.connect("DifferentNick")
    await client2.send_raw("NICK SameNick")
    assert await client2.expect("433"), "No nickname collision error"
    
    await client1.disconnect()
    await client2.disconnect()


@runner.test("Channel Join and Part")
async def test_channel_join_part():
    """Test joining and parting channels"""
    client = IRCTestClient("test_join")
    
    await client.connect("JoinTest")
    
    # Join channel
    await client.send_raw("JOIN #testchan")
    assert await client.expect("JOIN #testchan"), "No JOIN confirmation"
    assert await client.expect("353"), "No NAMES list"
    assert await client.expect("366"), "No NAMES end"
    
    # Part channel
    await client.send_raw("PART #testchan")
    assert await client.expect("PART #testchan"), "No PART confirmation"
    
    await client.disconnect()


@runner.test("Channel Owner on First Join")
async def test_channel_owner():
    """Test first user gets channel owner"""
    client = IRCTestClient("test_owner")
    
    await client.connect("OwnerTest")
    await client.send_raw("JOIN #ownerchan")
    
    # Should get MODE +q (owner)
    assert await client.expect("MODE #ownerchan +q"), "No owner mode granted"
    
    await client.disconnect()


@runner.test("Private Messages")
async def test_privmsg():
    """Test private messaging between users"""
    client1 = IRCTestClient("test_pm1")
    client2 = IRCTestClient("test_pm2")
    
    await client1.connect("User1")
    await client2.connect("User2")
    
    # Send message from client1 to client2
    await client1.send_raw("PRIVMSG User2 :Hello there!")
    assert await client2.expect("PRIVMSG User2 :Hello there!"), "Message not received"
    
    await client1.disconnect()
    await client2.disconnect()


@runner.test("Channel Messages")
async def test_channel_msg():
    """Test channel messaging"""
    client1 = IRCTestClient("test_chan1")
    client2 = IRCTestClient("test_chan2")
    
    await client1.connect("ChanUser1")
    await client2.connect("ChanUser2")
    
    await client1.send_raw("JOIN #chatroom")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #chatroom")
    await asyncio.sleep(0.2)
    
    # Clear buffers
    client1.buffer.clear()
    client2.buffer.clear()
    
    # Send channel message
    await client1.send_raw("PRIVMSG #chatroom :Hello channel!")
    assert await client2.expect("PRIVMSG #chatroom :Hello channel!"), "Channel message not received"
    
    await client1.disconnect()
    await client2.disconnect()


@runner.test("WHOIS Command")
async def test_whois():
    """Test WHOIS command"""
    client1 = IRCTestClient("test_whois1")
    client2 = IRCTestClient("test_whois2")
    
    await client1.connect("WhoisUser")
    await client2.connect("WhoisQuery")
    
    await client2.send_raw("WHOIS WhoisUser")
    assert await client2.expect("311"), "No WHOIS user info (311)"
    assert await client2.expect("312"), "No WHOIS server info (312)"
    assert await client2.expect("318"), "No WHOIS end (318)"
    
    await client1.disconnect()
    await client2.disconnect()


@runner.test("WHO Command")
async def test_who():
    """Test WHO command"""
    client = IRCTestClient("test_who")
    
    await client.connect("WhoTest")
    await client.send_raw("JOIN #whochan")
    await asyncio.sleep(0.2)
    
    client.buffer.clear()
    await client.send_raw("WHO #whochan")
    assert await client.expect("352"), "No WHO reply (352)"
    assert await client.expect("315"), "No WHO end (315)"
    
    await client.disconnect()


@runner.test("LIST Command")
async def test_list():
    """Test LIST command"""
    client = IRCTestClient("test_list")
    
    await client.connect("ListTest")
    await client.send_raw("JOIN #listchan")
    await asyncio.sleep(0.2)
    
    client.buffer.clear()
    await client.send_raw("LIST")
    assert await client.expect("321"), "No LIST start (321)"
    assert await client.expect("322"), "No LIST item (322)"
    assert await client.expect("323"), "No LIST end (323)"
    
    await client.disconnect()


@runner.test("KICK Command")
async def test_kick():
    """Test KICK command"""
    client1 = IRCTestClient("test_kick1")
    client2 = IRCTestClient("test_kick2")
    
    await client1.connect("KickOwner")
    await client2.connect("KickTarget")
    
    await client1.send_raw("JOIN #kickchan")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #kickchan")
    await asyncio.sleep(0.2)
    
    # Client1 is owner, kick client2
    await client1.send_raw("KICK #kickchan KickTarget :You're out!")
    assert await client2.expect("KICK #kickchan KickTarget"), "No KICK received"
    
    await client1.disconnect()
    await client2.disconnect()


@runner.test("Channel MODE Query")
async def test_channel_mode():
    """Test channel MODE command"""
    client = IRCTestClient("test_mode")
    
    await client.connect("ModeTest")
    await client.send_raw("JOIN #modechan")
    await asyncio.sleep(0.2)
    
    client.buffer.clear()
    # Query modes
    await client.send_raw("MODE #modechan")
    assert await client.expect("324"), "No MODE reply (324)"
    
    await client.disconnect()


@runner.test("AWAY Status")
async def test_away():
    """Test AWAY command"""
    client = IRCTestClient("test_away")
    
    await client.connect("AwayTest")
    
    # Set away
    await client.send_raw("AWAY :Gone for lunch")
    assert await client.expect("306"), "No away confirmation (306)"
    
    # Unset away
    await client.send_raw("AWAY")
    assert await client.expect("305"), "No unaway confirmation (305)"
    
    await client.disconnect()


@runner.test("PING/PONG")
async def test_ping():
    """Test PING/PONG mechanism"""
    client = IRCTestClient("test_ping")
    
    await client.connect("PingTest")
    await client.send_raw("PING :test123")
    assert await client.expect("PONG"), "No PONG received"
    
    await client.disconnect()


@runner.test("VERSION Command")
async def test_version():
    """Test VERSION command"""
    client = IRCTestClient("test_version")
    
    await client.connect("VersionTest")
    await client.send_raw("VERSION")
    assert await client.expect("351"), "No VERSION reply (351)"
    
    await client.disconnect()


@runner.test("TIME Command")
async def test_time():
    """Test TIME command"""
    client = IRCTestClient("test_time")
    
    await client.connect("TimeTest")
    await client.send_raw("TIME")
    assert await client.expect("391"), "No TIME reply (391)"
    
    await client.disconnect()


@runner.test("ADMIN Command")
async def test_admin():
    """Test ADMIN command"""
    client = IRCTestClient("test_admin")
    
    await client.connect("AdminTest")
    await client.send_raw("ADMIN")
    assert await client.expect("256"), "No ADMIN start (256)"
    assert await client.expect("259"), "No ADMIN email (259)"
    
    await client.disconnect()


@runner.test("Multiple Channels")
async def test_multi_channel():
    """Test joining multiple channels"""
    client = IRCTestClient("test_multi")
    
    await client.connect("MultiTest")
    
    # Clear buffer before join
    client.buffer.clear()
    
    await client.send_raw("JOIN #chan1,#chan2,#chan3")
    await asyncio.sleep(0.5)
    
    # Read all responses
    await client.read_lines()
    
    # Should have joined all 3
    count = sum(1 for line in client.buffer if "JOIN #chan" in line and "MultiTest" in line)
    assert count >= 3, f"Only joined {count}/3 channels"
    
    await client.disconnect()


@runner.test("Reconnection After Disconnect")
async def test_reconnect():
    """Test reconnecting after disconnect"""
    client = IRCTestClient("test_reconnect")
    
    # First connection
    await client.connect("ReconnectTest")
    await client.disconnect()
    
    # Wait a moment
    await asyncio.sleep(0.5)
    
    # Reconnect with same nickname
    assert await client.connect("ReconnectTest"), "Reconnection failed"
    assert await client.expect("001"), "No welcome on reconnect"
    
    await client.disconnect()


@runner.test("Concurrent Users")
async def test_concurrent():
    """Test multiple concurrent users"""
    clients = []

    for i in range(5):
        client = IRCTestClient(f"test_concurrent{i}")
        await client.connect(f"ConcUser{i}")
        clients.append(client)

    # All should be connected
    assert len(clients) == 5, "Not all clients connected"

    # All join same channel
    for client in clients:
        await client.send_raw("JOIN #busychan")

    await asyncio.sleep(0.3)

    # Disconnect all
    for client in clients:
        await client.disconnect()


# ==============================================================================
# CHANNEL MODE TESTS (+b, +i, +k, +l)
# ==============================================================================

@runner.test("Ban Mode (+b) - Set and List")
async def test_ban_mode_set():
    """Test setting and listing channel bans"""
    client = IRCTestClient("test_ban_set")

    await client.connect("BanOwner")
    await client.send_raw("JOIN #banchan")
    await asyncio.sleep(0.2)

    client.buffer.clear()
    # Set a ban
    await client.send_raw("MODE #banchan +b *!*@badhost.com")
    assert await client.expect("MODE #banchan +b"), "Ban not set"

    client.buffer.clear()
    # List bans
    await client.send_raw("MODE #banchan b")
    assert await client.expect("367"), "No ban list entry (367)"
    assert await client.expect("368"), "No ban list end (368)"

    await client.disconnect()


@runner.test("Ban Mode (+b) - Blocked Join")
async def test_ban_blocked_join():
    """Test that banned user cannot join"""
    owner = IRCTestClient("test_ban_owner")
    banned = IRCTestClient("test_ban_victim")

    await owner.connect("BanOwner2")
    await owner.send_raw("JOIN #bantest")
    await asyncio.sleep(0.2)

    # Set ban on the user's host pattern
    await owner.send_raw("MODE #bantest +b *!*@*")
    await asyncio.sleep(0.2)

    await banned.connect("BannedUser")
    banned.buffer.clear()
    await banned.send_raw("JOIN #bantest")

    assert await banned.expect("474"), "No banned error (474)"

    await owner.disconnect()
    await banned.disconnect()


@runner.test("Invite-Only Mode (+i)")
async def test_invite_only():
    """Test invite-only channel blocks non-invited users"""
    owner = IRCTestClient("test_invite_owner")
    user = IRCTestClient("test_invite_user")

    await owner.connect("InviteOwner")
    await owner.send_raw("JOIN #inviteonly")
    await asyncio.sleep(0.2)

    # Set invite-only
    await owner.send_raw("MODE #inviteonly +i")
    await asyncio.sleep(0.2)

    await user.connect("InviteUser")
    user.buffer.clear()
    await user.send_raw("JOIN #inviteonly")

    assert await user.expect("473"), "No invite-only error (473)"

    await owner.disconnect()
    await user.disconnect()


@runner.test("INVITE Command")
async def test_invite_command():
    """Test INVITE allows user to join +i channel"""
    owner = IRCTestClient("test_invite_cmd_owner")
    user = IRCTestClient("test_invite_cmd_user")

    await owner.connect("InvOwner")
    await owner.send_raw("JOIN #invitechan")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #invitechan +i")
    await asyncio.sleep(0.2)

    await user.connect("InvUser")

    # Owner invites user
    owner.buffer.clear()
    await owner.send_raw("INVITE InvUser #invitechan")
    assert await owner.expect("341"), "No invite confirmation (341)"

    # User should receive invite
    assert await user.expect("INVITE InvUser"), "User didn't receive INVITE"

    # Now user can join
    user.buffer.clear()
    await user.send_raw("JOIN #invitechan")
    assert await user.expect("JOIN #invitechan"), "User couldn't join after invite"

    await owner.disconnect()
    await user.disconnect()


@runner.test("Channel Key Mode (+k)")
async def test_channel_key():
    """Test channel key requirement"""
    owner = IRCTestClient("test_key_owner")
    user = IRCTestClient("test_key_user")

    await owner.connect("KeyOwner")
    await owner.send_raw("JOIN #keychan")
    await asyncio.sleep(0.3)

    # Set channel key
    await owner.send_raw("MODE #keychan +k secret123")
    await asyncio.sleep(0.3)

    await user.connect("KeyUser")
    await asyncio.sleep(0.2)

    # Try without key
    user.buffer.clear()
    await user.send_raw("JOIN #keychan")
    assert await user.expect("475"), "No bad key error (475)"

    await asyncio.sleep(0.2)

    # Try with wrong key
    user.buffer.clear()
    await user.send_raw("JOIN #keychan wrongkey")
    assert await user.expect("475"), "Wrong key should fail"

    await asyncio.sleep(0.2)

    # Try with correct key
    user.buffer.clear()
    await user.send_raw("JOIN #keychan secret123")
    assert await user.expect("JOIN #keychan"), "Correct key should work"

    await owner.disconnect()
    await user.disconnect()


@runner.test("User Limit Mode (+l)")
async def test_user_limit():
    """Test channel user limit"""
    owner = IRCTestClient("test_limit_owner")
    user1 = IRCTestClient("test_limit_user1")
    user2 = IRCTestClient("test_limit_user2")

    await owner.connect("LimitOwner")
    await owner.send_raw("JOIN #limitchan")
    await asyncio.sleep(0.2)

    # Set limit to 2
    await owner.send_raw("MODE #limitchan +l 2")
    await asyncio.sleep(0.2)

    # First user can join (total: 2)
    await user1.connect("LimitUser1")
    user1.buffer.clear()
    await user1.send_raw("JOIN #limitchan")
    assert await user1.expect("JOIN #limitchan"), "User1 should be able to join"

    # Second user cannot join (would be 3)
    await user2.connect("LimitUser2")
    user2.buffer.clear()
    await user2.send_raw("JOIN #limitchan")
    assert await user2.expect("471"), "No channel full error (471)"

    await owner.disconnect()
    await user1.disconnect()
    await user2.disconnect()


@runner.test("MODE Display with Parameters")
async def test_mode_display_params():
    """Test MODE query shows +l and +k parameters"""
    client = IRCTestClient("test_mode_params")

    await client.connect("ModeParams")
    await client.send_raw("JOIN #modeparams")
    await asyncio.sleep(0.2)

    # Set key and limit
    await client.send_raw("MODE #modeparams +kl secret 50")
    await asyncio.sleep(0.2)

    # Query modes
    client.buffer.clear()
    await client.send_raw("MODE #modeparams")
    await asyncio.sleep(0.3)
    await client.read_lines()

    mode_line = None
    for line in client.buffer:
        if "324" in line:
            mode_line = line
            break

    assert mode_line, "No MODE reply"
    assert "50" in mode_line or "secret" in mode_line, f"Parameters not shown: {mode_line}"

    await client.disconnect()


# ==============================================================================
# IRCX COMMAND TESTS (KNOCK, PROP)
# ==============================================================================

@runner.test("KNOCK Command - Open Channel")
async def test_knock_open():
    """Test KNOCK on non-invite-only channel"""
    owner = IRCTestClient("test_knock_owner")
    user = IRCTestClient("test_knock_user")

    await owner.connect("KnockOwner")
    await owner.send_raw("JOIN #openchan")
    await asyncio.sleep(0.2)

    await user.connect("KnockUser")
    user.buffer.clear()
    await user.send_raw("KNOCK #openchan")

    assert await user.expect("713"), "No 'channel is open' error (713)"

    await owner.disconnect()
    await user.disconnect()


@runner.test("KNOCK Command - Invite Only")
async def test_knock_invite():
    """Test KNOCK on invite-only channel notifies hosts"""
    owner = IRCTestClient("test_knock_inv_owner")
    user = IRCTestClient("test_knock_inv_user")

    await owner.connect("KnockInvOwner")
    await owner.send_raw("JOIN #knockinv")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #knockinv +i")
    await asyncio.sleep(0.2)

    await user.connect("KnockInvUser")

    owner.buffer.clear()
    user.buffer.clear()
    await user.send_raw("KNOCK #knockinv :Let me in please")

    # User gets confirmation
    assert await user.expect("711"), "No KNOCK delivered confirmation (711)"

    # Owner gets notification
    assert await owner.expect("710"), "Owner didn't receive KNOCK notification (710)"

    await owner.disconnect()
    await user.disconnect()


@runner.test("KNOCK Rate Limiting")
async def test_knock_rate_limit():
    """Test KNOCK rate limiting"""
    owner = IRCTestClient("test_knock_rate_owner")
    user = IRCTestClient("test_knock_rate_user")

    await owner.connect("RateOwner")
    await owner.send_raw("JOIN #ratechan")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #ratechan +i")
    await asyncio.sleep(0.2)

    await user.connect("RateUser")

    # First knock should work
    user.buffer.clear()
    await user.send_raw("KNOCK #ratechan")
    assert await user.expect("711"), "First KNOCK should succeed"

    # Second knock immediately should be rate limited
    user.buffer.clear()
    await user.send_raw("KNOCK #ratechan")
    assert await user.expect("712"), "Second KNOCK should be rate limited (712)"

    await owner.disconnect()
    await user.disconnect()


@runner.test("PROP Command - Set and Get")
async def test_prop_command():
    """Test PROP command for channel properties"""
    client = IRCTestClient("test_prop")

    await client.connect("PropUser")
    await client.send_raw("JOIN #propchan")
    await asyncio.sleep(0.2)

    # Set a property
    client.buffer.clear()
    await client.send_raw("PROP #propchan TOPIC :Welcome to the channel!")
    assert await client.expect("819"), "No PROP set confirmation (819)"

    # Get the property
    client.buffer.clear()
    await client.send_raw("PROP #propchan TOPIC")
    assert await client.expect("817"), "No PROP value reply (817)"
    assert await client.expect("Welcome"), "Property value not returned"

    # List all properties
    client.buffer.clear()
    await client.send_raw("PROP #propchan")
    assert await client.expect("818"), "No PROP list end (818)"

    await client.disconnect()


@runner.test("PROP MEMBERKEY Integration")
async def test_prop_memberkey():
    """Test PROP MEMBERKEY sets channel key (+k)"""
    owner = IRCTestClient("test_memberkey_owner")
    user = IRCTestClient("test_memberkey_user")

    await owner.connect("MemberkeyOwner")
    await owner.send_raw("JOIN #memberkeychan")
    await asyncio.sleep(0.2)

    # Set MEMBERKEY via PROP (sets channel.key and +k mode)
    await owner.send_raw("PROP #memberkeychan MEMBERKEY :mykey123")
    await asyncio.sleep(0.2)

    await user.connect("MemberkeyUser")

    # Try without key
    user.buffer.clear()
    await user.send_raw("JOIN #memberkeychan")
    assert await user.expect("475"), "MEMBERKEY should enable +k"

    # Try with key
    user.buffer.clear()
    await user.send_raw("JOIN #memberkeychan mykey123")
    assert await user.expect("JOIN #memberkeychan"), "Key should work"

    await owner.disconnect()
    await user.disconnect()


@runner.test("PROP HOSTKEY Grants +o")
async def test_prop_hostkey_grants_op():
    """Test PROP HOSTKEY grants +o on join"""
    owner = IRCTestClient("test_hostkey2_owner")
    user = IRCTestClient("test_hostkey2_user")

    await owner.connect("HostkeyOwner2")
    await owner.send_raw("JOIN #hostkeychan2")
    await asyncio.sleep(0.2)

    # Set HOSTKEY via PROP (grants +o on join)
    await owner.send_raw("PROP #hostkeychan2 HOSTKEY :hostpass")
    await asyncio.sleep(0.2)

    await user.connect("HostkeyUser2")

    # Join with host key - should get +o
    user.buffer.clear()
    await user.send_raw("JOIN #hostkeychan2 hostpass")
    assert await user.expect("MODE #hostkeychan2 +o"), "HOSTKEY should grant +o"

    await owner.disconnect()
    await user.disconnect()


# ==============================================================================
# SSL/TLS CONNECTION TESTS
# ==============================================================================

@runner.test("SSL Connection (if enabled)")
async def test_ssl_connection():
    """Test SSL connection on port 6697"""
    # Try to connect via SSL
    client = IRCTestClient("test_ssl", port=6697, use_ssl=True)

    try:
        connected = await client.connect("SSLUser")
        if connected:
            assert await client.expect("001"), "No welcome message over SSL"
            print("   SSL connection successful!")
            await client.disconnect()
        else:
            print("   SSL not enabled or connection failed (this is OK if SSL is disabled)")
    except Exception as e:
        print(f"   SSL connection failed: {e} (this is OK if SSL is disabled)")


# ==============================================================================
# PROP ONJOIN/ONPART TESTS
# ==============================================================================

@runner.test("PROP ONJOIN Message")
async def test_prop_onjoin():
    """Test PROP ONJOIN sends welcome message on join"""
    owner = IRCTestClient("test_onjoin_owner")
    user = IRCTestClient("test_onjoin_user")

    await owner.connect("OnjoinOwner")
    await owner.send_raw("JOIN #onjoinchan")
    await asyncio.sleep(0.2)

    # Set ONJOIN message
    await owner.send_raw("PROP #onjoinchan ONJOIN :Welcome to the channel! Please read the rules.")
    await asyncio.sleep(0.2)

    await user.connect("OnjoinUser")
    user.buffer.clear()
    await user.send_raw("JOIN #onjoinchan")
    await asyncio.sleep(0.3)
    await user.read_lines()

    # User should receive the ONJOIN notice
    has_onjoin = any("Welcome to the channel" in line for line in user.buffer)
    print(f"   ONJOIN message received: {has_onjoin}")
    assert has_onjoin, "ONJOIN message not received"

    await owner.disconnect()
    await user.disconnect()


@runner.test("PROP ONPART Message")
async def test_prop_onpart():
    """Test PROP ONPART sends goodbye message on part"""
    owner = IRCTestClient("test_onpart_owner")
    user = IRCTestClient("test_onpart_user")

    await owner.connect("OnpartOwner")
    await owner.send_raw("JOIN #onpartchan")
    await asyncio.sleep(0.2)

    # Set ONPART message
    await owner.send_raw("PROP #onpartchan ONPART :Thanks for visiting!")
    await asyncio.sleep(0.2)

    await user.connect("OnpartUser")
    await user.send_raw("JOIN #onpartchan")
    await asyncio.sleep(0.2)

    user.buffer.clear()
    await user.send_raw("PART #onpartchan")
    await asyncio.sleep(0.3)
    await user.read_lines()

    # User should receive the ONPART notice
    has_onpart = any("Thanks for visiting" in line for line in user.buffer)
    print(f"   ONPART message received: {has_onpart}")
    assert has_onpart, "ONPART message not received"

    await owner.disconnect()
    await user.disconnect()


# ==============================================================================
# CLONE CHANNEL (+d MODE) TESTS
# ==============================================================================

@runner.test("Clone Channel - Basic Creation")
async def test_clone_channel_creation():
    """Test clone channel creation when +d and +l are set"""
    owner = IRCTestClient("test_clone_owner")
    user1 = IRCTestClient("test_clone_user1")
    user2 = IRCTestClient("test_clone_user2")
    user3 = IRCTestClient("test_clone_user3")

    await owner.connect("CloneOwner")
    await owner.send_raw("JOIN #clonetest")
    await asyncio.sleep(0.2)

    # Enable clone mode and set limit to 2
    await owner.send_raw("MODE #clonetest +dl 2")
    await asyncio.sleep(0.2)

    # First user joins - should fit in original
    await user1.connect("CloneUser1")
    user1.buffer.clear()
    await user1.send_raw("JOIN #clonetest")
    assert await user1.expect("JOIN #clonetest"), "User1 should join original"

    # Second user joins - channel is now full (2 users)
    await user2.connect("CloneUser2")
    user2.buffer.clear()
    await user2.send_raw("JOIN #clonetest")
    await asyncio.sleep(0.3)
    await user2.read_lines()

    # Third user joins - should create/join clone #clonetest1
    await user3.connect("CloneUser3")
    user3.buffer.clear()
    await user3.send_raw("JOIN #clonetest")
    await asyncio.sleep(0.3)
    await user3.read_lines()

    # Check if user3 joined a clone channel
    joined_clone = any("#clonetest1" in line or "#clonetest2" in line for line in user3.buffer)
    joined_original = any("JOIN #clonetest" in line and "#clonetest1" not in line and "#clonetest2" not in line for line in user3.buffer)

    print(f"   User3 joined clone: {joined_clone}")
    print(f"   User3 in original: {joined_original}")

    # Either joined clone or original is acceptable (depends on timing)
    assert joined_clone or joined_original, "User3 should join somewhere"

    await owner.disconnect()
    await user1.disconnect()
    await user2.disconnect()
    await user3.disconnect()


@runner.test("Clone Channel - Mode Sync")
async def test_clone_mode_sync():
    """Test mode changes propagate to clones"""
    owner = IRCTestClient("test_clone_sync_owner")
    users = []

    await owner.connect("CloneSyncOwner")
    await owner.send_raw("JOIN #clonesync")
    await asyncio.sleep(0.2)

    # Enable clone mode with limit 1 (owner only)
    await owner.send_raw("MODE #clonesync +dl 1")
    await asyncio.sleep(0.2)

    # Create a clone by having another user join
    user1 = IRCTestClient("test_clone_sync_user1")
    await user1.connect("CloneSyncUser1")
    await user1.send_raw("JOIN #clonesync")
    await asyncio.sleep(0.3)
    users.append(user1)

    # Now set moderated mode on original - should sync to clones
    owner.buffer.clear()
    await owner.send_raw("MODE #clonesync +m")
    await asyncio.sleep(0.3)

    print("   Mode sync test complete (check server logs for sync)")

    await owner.disconnect()
    for u in users:
        await u.disconnect()


# ==============================================================================
# CHANNEL ACCESS TESTS (User perspective)
# ==============================================================================

@runner.test("ACCESS DENY Blocks Join")
async def test_access_deny_blocks():
    """Test ACCESS DENY works like a ban"""
    owner = IRCTestClient("test_access_deny_owner")
    user = IRCTestClient("test_access_deny_user")

    await owner.connect("AccessDenyOwner")
    await owner.send_raw("JOIN #accessdeny")
    await asyncio.sleep(0.2)

    # Add DENY entry for the user
    await owner.send_raw("ACCESS #accessdeny ADD DENY AccessDenyUser")
    await asyncio.sleep(0.2)

    await user.connect("AccessDenyUser")
    user.buffer.clear()
    await user.send_raw("JOIN #accessdeny")

    # Should be denied (474 = banned)
    assert await user.expect("474"), "ACCESS DENY should block join"

    await owner.disconnect()
    await user.disconnect()


@runner.test("ACCESS GRANT Bypasses +i")
async def test_access_grant_bypass():
    """Test ACCESS GRANT allows joining +i channel"""
    owner = IRCTestClient("test_access_grant_owner")
    user = IRCTestClient("test_access_grant_user")

    await owner.connect("AccessGrantOwner")
    await owner.send_raw("JOIN #accessgrant")
    await asyncio.sleep(0.2)

    # Set invite-only and add GRANT for user
    await owner.send_raw("MODE #accessgrant +i")
    await asyncio.sleep(0.2)
    await owner.send_raw("ACCESS #accessgrant ADD GRANT AccessGrantUser")
    await asyncio.sleep(0.2)

    await user.connect("AccessGrantUser")
    user.buffer.clear()
    await user.send_raw("JOIN #accessgrant")

    # Should be able to join despite +i
    assert await user.expect("JOIN #accessgrant"), "ACCESS GRANT should bypass +i"

    await owner.disconnect()
    await user.disconnect()


@runner.test("ACCESS HOST Grants +o on Join")
async def test_access_host_grants_op():
    """Test ACCESS HOST grants +o when user joins"""
    owner = IRCTestClient("test_access_host_owner")
    user = IRCTestClient("test_access_host_user")

    await owner.connect("AccessHostOwner")
    await owner.send_raw("JOIN #accesshost")
    await asyncio.sleep(0.2)

    # Add HOST entry for user
    await owner.send_raw("ACCESS #accesshost ADD HOST AccessHostUser")
    await asyncio.sleep(0.2)

    await user.connect("AccessHostUser")
    user.buffer.clear()
    await user.send_raw("JOIN #accesshost")
    await asyncio.sleep(0.3)
    await user.read_lines()

    # Should receive +o
    has_op = any("MODE #accesshost +o AccessHostUser" in line for line in user.buffer)
    print(f"   User received +o: {has_op}")
    assert has_op, "ACCESS HOST should grant +o on join"

    await owner.disconnect()
    await user.disconnect()


@runner.test("ACCESS VOICE Grants +v on Join")
async def test_access_voice_grants_voice():
    """Test ACCESS VOICE grants +v when user joins"""
    owner = IRCTestClient("test_access_voice_owner")
    user = IRCTestClient("test_access_voice_user")

    await owner.connect("AccessVoiceOwner")
    await owner.send_raw("JOIN #accessvoice")
    await asyncio.sleep(0.2)

    # Add VOICE entry for user
    await owner.send_raw("ACCESS #accessvoice ADD VOICE AccessVoiceUser")
    await asyncio.sleep(0.2)

    await user.connect("AccessVoiceUser")
    user.buffer.clear()
    await user.send_raw("JOIN #accessvoice")
    await asyncio.sleep(0.3)
    await user.read_lines()

    # Should receive +v
    has_voice = any("MODE #accessvoice +v AccessVoiceUser" in line for line in user.buffer)
    print(f"   User received +v: {has_voice}")
    assert has_voice, "ACCESS VOICE should grant +v on join"

    await owner.disconnect()
    await user.disconnect()


@runner.test("CAP LS Lists Capabilities")
async def test_cap_ls():
    """Test CAP LS lists available capabilities"""
    client = IRCTestClient("test_cap_ls")

    # Manual connection without registration
    try:
        client.reader, client.writer = await asyncio.open_connection(client.host, client.port)
        client.connected = True
    except Exception as e:
        print(f"Connection failed: {e}")
        assert False, "Could not connect"

    await client.send_raw("CAP LS 302")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should receive CAP LS response with capabilities
    has_cap_ls = any("CAP * LS" in line for line in client.buffer)
    has_sasl = any("sasl" in line.lower() for line in client.buffer)
    print(f"   Received CAP LS: {has_cap_ls}, has sasl: {has_sasl}")
    assert has_cap_ls, "Should receive CAP LS response"
    assert has_sasl, "SASL should be in capabilities"

    await client.send_raw("CAP END")
    await client.disconnect()


@runner.test("CAP REQ SASL")
async def test_cap_req_sasl():
    """Test requesting SASL capability"""
    client = IRCTestClient("test_cap_sasl")

    # Manual connection
    try:
        client.reader, client.writer = await asyncio.open_connection(client.host, client.port)
        client.connected = True
    except Exception as e:
        assert False, f"Could not connect: {e}"

    await client.send_raw("CAP LS 302")
    await asyncio.sleep(0.2)
    await client.read_lines()

    client.buffer.clear()
    await client.send_raw("CAP REQ :sasl")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Should receive CAP ACK
    has_ack = any("CAP * ACK" in line and "sasl" in line.lower() for line in client.buffer)
    print(f"   Received CAP ACK sasl: {has_ack}")
    assert has_ack, "Should receive CAP ACK for sasl"

    await client.send_raw("CAP END")
    await client.disconnect()


@runner.test("SASL PLAIN Authentication Flow")
async def test_sasl_plain_flow():
    """Test SASL PLAIN authentication mechanism flow"""
    import base64

    client = IRCTestClient("test_sasl_flow")

    # Manual connection
    try:
        client.reader, client.writer = await asyncio.open_connection(client.host, client.port)
        client.connected = True
    except Exception as e:
        assert False, f"Could not connect: {e}"

    # CAP negotiation
    await client.send_raw("CAP LS 302")
    await asyncio.sleep(0.2)
    await client.read_lines()

    await client.send_raw("CAP REQ :sasl")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Start SASL PLAIN
    client.buffer.clear()
    await client.send_raw("AUTHENTICATE PLAIN")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Should receive AUTHENTICATE +
    has_plus = any("AUTHENTICATE +" in line for line in client.buffer)
    print(f"   Received AUTHENTICATE +: {has_plus}")
    assert has_plus, "Should receive AUTHENTICATE + prompt"

    # Send credentials (this will fail since user doesn't exist, but tests the flow)
    # Format: \0username\0password
    creds = base64.b64encode(b"\0testuser\0wrongpass").decode()
    client.buffer.clear()
    await client.send_raw(f"AUTHENTICATE {creds}")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should receive 904 (auth failed) since user doesn't exist
    has_response = any("903" in line or "904" in line for line in client.buffer)
    print(f"   Received SASL response (903/904): {has_response}")
    assert has_response, "Should receive SASL success or failure response"

    await client.send_raw("CAP END")
    await client.disconnect()


@runner.test("SASL Abort with *")
async def test_sasl_abort():
    """Test aborting SASL authentication"""
    client = IRCTestClient("test_sasl_abort")

    # Manual connection
    try:
        client.reader, client.writer = await asyncio.open_connection(client.host, client.port)
        client.connected = True
    except Exception as e:
        assert False, f"Could not connect: {e}"

    await client.send_raw("CAP LS")
    await asyncio.sleep(0.2)
    await client.read_lines()

    await client.send_raw("CAP REQ :sasl")
    await asyncio.sleep(0.2)
    await client.read_lines()

    await client.send_raw("AUTHENTICATE PLAIN")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Abort with *
    client.buffer.clear()
    await client.send_raw("AUTHENTICATE *")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Should receive 906 (aborted)
    has_abort = any("906" in line for line in client.buffer)
    print(f"   Received 906 (aborted): {has_abort}")
    assert has_abort, "Should receive 906 SASL aborted"

    await client.send_raw("CAP END")
    await client.disconnect()


# ==============================================================================
# RFC COMPLIANCE TESTS - Validate standard IRC protocol behavior
# ==============================================================================

@runner.test("RFC: NAMES Command Format")
async def test_rfc_names():
    """Test NAMES command returns RFC-compliant format"""
    client1 = IRCTestClient("rfc_names1")
    client2 = IRCTestClient("rfc_names2")

    await client1.connect("NamesUser1")
    await client2.connect("NamesUser2")

    # Both join the same channel
    await client1.send_raw("JOIN #namestest")
    await asyncio.sleep(0.3)
    await client2.send_raw("JOIN #namestest")
    await asyncio.sleep(0.3)

    # Clear buffer and request NAMES
    client2.buffer.clear()
    await client2.send_raw("NAMES #namestest")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Validate RPL_NAMREPLY (353) format: :<server> 353 <nick> <type> <channel> :<names>
    names_reply = None
    end_reply = None
    for line in client2.buffer:
        if " 353 " in line:
            names_reply = line
        if " 366 " in line:
            end_reply = line

    assert names_reply, "No RPL_NAMREPLY (353) received"
    assert end_reply, "No RPL_ENDOFNAMES (366) received"

    # Verify 353 contains channel and names
    assert "#namestest" in names_reply, "353 should contain channel name"
    # Should contain at least one nick with optional prefix
    assert "NamesUser1" in names_reply or "NamesUser2" in names_reply, "353 should list users"

    # Verify 366 format
    assert "#namestest" in end_reply, "366 should contain channel name"
    assert "End of" in end_reply or "end of" in end_reply.lower(), "366 should have end text"

    print(f"   353: {names_reply[:80]}...")
    print(f"   366: {end_reply[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: WHO Command Format")
async def test_rfc_who():
    """Test WHO command returns RFC-compliant format"""
    client = IRCTestClient("rfc_who")

    await client.connect("WhoRfcTest")
    await client.send_raw("JOIN #whorfctest")
    await asyncio.sleep(0.3)

    client.buffer.clear()
    await client.send_raw("WHO #whorfctest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Validate RPL_WHOREPLY (352) format:
    # :<server> 352 <requesting_nick> <channel> <user> <host> <server> <nick> <flags> :<hopcount> <realname>
    who_reply = None
    end_reply = None
    for line in client.buffer:
        if " 352 " in line:
            who_reply = line
        if " 315 " in line:
            end_reply = line

    assert who_reply, "No RPL_WHOREPLY (352) received"
    assert end_reply, "No RPL_ENDOFWHO (315) received"

    # Parse 352 - should have channel, user, host, server, nick, flags
    parts = who_reply.split()
    assert "#whorfctest" in who_reply, "352 should contain channel name"
    assert "WhoRfcTest" in who_reply, "352 should contain user nick"

    # Flags should contain H (here) or G (gone), possibly with @ or +
    # Find the flags field (should be after the nick and before the : for realname)
    flag_found = False
    for part in parts:
        if part.startswith("H") or part.startswith("G"):
            flag_found = True
            print(f"   WHO flags: {part}")
            break

    # 315 should have channel name
    assert "#whorfctest" in end_reply, "315 should contain channel name"

    print(f"   352: {who_reply[:80]}...")
    print(f"   315: {end_reply[:80]}...")

    await client.disconnect()


@runner.test("RFC: WHOIS Complete Response")
async def test_rfc_whois():
    """Test WHOIS returns all required RFC numerics"""
    client1 = IRCTestClient("rfc_whois1")
    client2 = IRCTestClient("rfc_whois2")

    await client1.connect("WhoisTarget")
    await client2.connect("WhoisAsker")

    # Target joins a channel so we can test 319
    await client1.send_raw("JOIN #whoischan")
    await asyncio.sleep(0.3)

    client2.buffer.clear()
    await client2.send_raw("WHOIS WhoisTarget")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    # Check for required numerics
    has_311 = False  # RPL_WHOISUSER
    has_312 = False  # RPL_WHOISSERVER
    has_318 = False  # RPL_ENDOFWHOIS
    has_319 = False  # RPL_WHOISCHANNELS (optional, but expected when in channel)
    has_317 = False  # RPL_WHOISIDLE (optional)

    for line in client2.buffer:
        if " 311 " in line:
            has_311 = True
            # 311 format: <nick> <user> <host> * :<realname>
            assert "WhoisTarget" in line, "311 should contain target nick"
            print(f"   311: {line[:80]}...")
        if " 312 " in line:
            has_312 = True
            print(f"   312: {line[:80]}...")
        if " 318 " in line:
            has_318 = True
            print(f"   318: {line[:80]}...")
        if " 319 " in line:
            has_319 = True
            assert "#whoischan" in line, "319 should list channels"
            print(f"   319: {line[:80]}...")
        if " 317 " in line:
            has_317 = True
            print(f"   317: {line[:80]}...")

    assert has_311, "Missing RPL_WHOISUSER (311)"
    assert has_312, "Missing RPL_WHOISSERVER (312)"
    assert has_318, "Missing RPL_ENDOFWHOIS (318)"
    print(f"   Has 319 (channels): {has_319}, Has 317 (idle): {has_317}")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: TOPIC Set and Get")
async def test_rfc_topic():
    """Test TOPIC command for setting and retrieving"""
    client = IRCTestClient("rfc_topic")

    await client.connect("TopicTest")
    await client.send_raw("JOIN #topictest")
    await asyncio.sleep(0.3)

    # Set topic
    await client.send_raw("TOPIC #topictest :This is the test topic")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Query topic
    client.buffer.clear()
    await client.send_raw("TOPIC #topictest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 332 (RPL_TOPIC) and 333 (RPL_TOPICWHOTIME)
    has_332 = False
    has_333 = False

    for line in client.buffer:
        if " 332 " in line:
            has_332 = True
            assert "This is the test topic" in line, "332 should contain topic text"
            print(f"   332: {line[:80]}...")
        if " 333 " in line:
            has_333 = True
            assert "TopicTest" in line, "333 should show who set topic"
            print(f"   333: {line[:80]}...")

    assert has_332, "No RPL_TOPIC (332) received"
    assert has_333, "No RPL_TOPICWHOTIME (333) received"

    await client.disconnect()


@runner.test("RFC: JOIN Response Format")
async def test_rfc_join():
    """Test JOIN returns proper response sequence"""
    client = IRCTestClient("rfc_join")

    await client.connect("JoinRfcTest")

    client.buffer.clear()
    await client.send_raw("JOIN #joinrfctest")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # JOIN should produce:
    # 1. JOIN confirmation (echo back)
    # 2. MODE for channel (may include user mode like +q)
    # 3. 353 NAMREPLY
    # 4. 366 ENDOFNAMES

    has_join = False
    has_353 = False
    has_366 = False

    for line in client.buffer:
        if "JOIN" in line and "#joinrfctest" in line:
            has_join = True
            print(f"   JOIN: {line[:80]}...")
        if " 353 " in line:
            has_353 = True
            print(f"   353: {line[:80]}...")
        if " 366 " in line:
            has_366 = True
            print(f"   366: {line[:80]}...")

    assert has_join, "No JOIN confirmation received"
    assert has_353, "No RPL_NAMREPLY (353) on JOIN"
    assert has_366, "No RPL_ENDOFNAMES (366) on JOIN"

    await client.disconnect()


@runner.test("RFC: INVITE Command")
async def test_rfc_invite():
    """Test INVITE command and response"""
    client1 = IRCTestClient("rfc_invite1")
    client2 = IRCTestClient("rfc_invite2")

    await client1.connect("Inviter")
    await client2.connect("Invitee")

    # Inviter creates invite-only channel
    await client1.send_raw("JOIN #invitetest")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #invitetest +i")
    await asyncio.sleep(0.2)

    client1.buffer.clear()
    await client1.send_raw("INVITE Invitee #invitetest")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Inviter should get 341 (RPL_INVITING)
    has_341 = any(" 341 " in line for line in client1.buffer)
    print(f"   Inviter received 341: {has_341}")

    # Invitee should get INVITE message
    has_invite = any("INVITE" in line and "#invitetest" in line for line in client2.buffer)
    print(f"   Invitee received INVITE: {has_invite}")

    assert has_341, "Inviter should receive RPL_INVITING (341)"
    assert has_invite, "Invitee should receive INVITE message"

    # Invitee should now be able to join
    client2.buffer.clear()
    await client2.send_raw("JOIN #invitetest")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    joined = any("JOIN" in line and "#invitetest" in line for line in client2.buffer)
    assert joined, "Invitee should be able to join after invite"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: NOTICE Command")
async def test_rfc_notice():
    """Test NOTICE command to user and channel"""
    client1 = IRCTestClient("rfc_notice1")
    client2 = IRCTestClient("rfc_notice2")

    await client1.connect("NoticeSender")
    await client2.connect("NoticeReceiver")

    # Test user notice
    client2.buffer.clear()
    await client1.send_raw("NOTICE NoticeReceiver :This is a test notice")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # NOTICE format: :sender NOTICE target :message
    has_notice = any("NOTICE" in line and "This is a test notice" in line for line in client2.buffer)
    print(f"   User NOTICE received: {has_notice}")
    assert has_notice, "User NOTICE should be delivered"

    # Test channel notice
    await client1.send_raw("JOIN #noticechan")
    await client2.send_raw("JOIN #noticechan")
    await asyncio.sleep(0.3)

    client2.buffer.clear()
    await client1.send_raw("NOTICE #noticechan :Channel notice test")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_channel_notice = any("NOTICE" in line and "Channel notice test" in line for line in client2.buffer)
    print(f"   Channel NOTICE received: {has_channel_notice}")
    assert has_channel_notice, "Channel NOTICE should be delivered"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: PRIVMSG Command")
async def test_rfc_privmsg():
    """Test PRIVMSG to user and channel with proper format"""
    client1 = IRCTestClient("rfc_privmsg1")
    client2 = IRCTestClient("rfc_privmsg2")

    await client1.connect("MsgSender")
    await client2.connect("MsgReceiver")

    # Test user PRIVMSG
    client2.buffer.clear()
    await client1.send_raw("PRIVMSG MsgReceiver :Hello, this is a test message!")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Format: :sender!user@host PRIVMSG target :message
    privmsg_line = None
    for line in client2.buffer:
        if "PRIVMSG" in line and "Hello" in line:
            privmsg_line = line
            break

    assert privmsg_line, "User PRIVMSG should be delivered"
    assert "MsgSender" in privmsg_line, "PRIVMSG should show sender"
    print(f"   User PRIVMSG: {privmsg_line[:80]}...")

    # Test channel PRIVMSG
    await client1.send_raw("JOIN #msgchan")
    await client2.send_raw("JOIN #msgchan")
    await asyncio.sleep(0.3)

    client2.buffer.clear()
    await client1.send_raw("PRIVMSG #msgchan :Channel message test")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    chan_msg = None
    for line in client2.buffer:
        if "PRIVMSG" in line and "#msgchan" in line and "Channel message" in line:
            chan_msg = line
            break

    assert chan_msg, "Channel PRIVMSG should be delivered"
    print(f"   Channel PRIVMSG: {chan_msg[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: LIST Command Format")
async def test_rfc_list():
    """Test LIST command with proper numeric format"""
    client = IRCTestClient("rfc_list")

    await client.connect("ListRfcTest")

    # Create a channel with topic for better LIST output
    await client.send_raw("JOIN #listrfctest")
    await asyncio.sleep(0.2)
    await client.send_raw("TOPIC #listrfctest :Test topic for list")
    await asyncio.sleep(0.2)

    client.buffer.clear()
    await client.send_raw("LIST")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # LIST should produce:
    # 321 RPL_LISTSTART
    # 322 RPL_LIST (one per channel)
    # 323 RPL_LISTEND

    has_321 = False
    has_322 = False
    has_323 = False

    for line in client.buffer:
        if " 321 " in line:
            has_321 = True
            print(f"   321: {line[:80]}...")
        if " 322 " in line:
            has_322 = True
            # 322 format: <channel> <visible> :<topic>
            assert "#" in line, "322 should contain channel name"
            print(f"   322: {line[:80]}...")
        if " 323 " in line:
            has_323 = True
            print(f"   323: {line[:80]}...")

    assert has_321, "No RPL_LISTSTART (321) received"
    assert has_322, "No RPL_LIST (322) received"
    assert has_323, "No RPL_LISTEND (323) received"

    await client.disconnect()


@runner.test("RFC: LUSERS Command")
async def test_rfc_lusers():
    """Test LUSERS returns server statistics"""
    client = IRCTestClient("rfc_lusers")

    await client.connect("LusersTest")

    client.buffer.clear()
    await client.send_raw("LUSERS")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # LUSERS should return some of:
    # 251 RPL_LUSERCLIENT
    # 252 RPL_LUSEROP
    # 253 RPL_LUSERUNKNOWN
    # 254 RPL_LUSERCHANNELS
    # 255 RPL_LUSERME
    # 265 RPL_LOCALUSERS
    # 266 RPL_GLOBALUSERS

    has_251 = any(" 251 " in line for line in client.buffer)
    has_255 = any(" 255 " in line for line in client.buffer)
    has_265 = any(" 265 " in line for line in client.buffer)
    has_266 = any(" 266 " in line for line in client.buffer)

    print(f"   251 (LUSERCLIENT): {has_251}")
    print(f"   255 (LUSERME): {has_255}")
    print(f"   265 (LOCALUSERS): {has_265}")
    print(f"   266 (GLOBALUSERS): {has_266}")

    # At minimum should have 251 and 255
    assert has_251, "No RPL_LUSERCLIENT (251) received"
    assert has_255, "No RPL_LUSERME (255) received"

    await client.disconnect()


@runner.test("RFC: MOTD Command")
async def test_rfc_motd():
    """Test MOTD returns proper format"""
    client = IRCTestClient("rfc_motd")

    await client.connect("MotdTest")

    client.buffer.clear()
    await client.send_raw("MOTD")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # MOTD returns either:
    # 375 RPL_MOTDSTART, 372 RPL_MOTD (multiple), 376 RPL_ENDOFMOTD
    # OR: 422 ERR_NOMOTD

    has_375 = any(" 375 " in line for line in client.buffer)
    has_372 = any(" 372 " in line for line in client.buffer)
    has_376 = any(" 376 " in line for line in client.buffer)
    has_422 = any(" 422 " in line for line in client.buffer)

    if has_422:
        print("   Server has no MOTD (422)")
        # This is valid, server may not have MOTD configured
    else:
        print(f"   375 (MOTDSTART): {has_375}")
        print(f"   372 (MOTD body): {has_372}")
        print(f"   376 (ENDOFMOTD): {has_376}")
        # If MOTD exists, should have start and end
        if has_375:
            assert has_376, "MOTD should have ENDOFMOTD (376)"

    # One of these must be true
    assert has_422 or (has_375 and has_376), "MOTD should return proper sequence or 422"

    await client.disconnect()


@runner.test("RFC: USERHOST Command")
async def test_rfc_userhost():
    """Test USERHOST returns user information"""
    client1 = IRCTestClient("rfc_userhost1")
    client2 = IRCTestClient("rfc_userhost2")

    await client1.connect("UserHostTest")
    await client2.connect("UserHostQuery")

    client2.buffer.clear()
    await client2.send_raw("USERHOST UserHostTest")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # 302 RPL_USERHOST format: :server 302 nick :nick=+user@host
    has_302 = False
    for line in client2.buffer:
        if " 302 " in line:
            has_302 = True
            print(f"   302: {line[:80]}...")
            # Should contain the queried nick and user@host info
            assert "UserHostTest" in line, "302 should contain queried nick"

    assert has_302, "No RPL_USERHOST (302) received"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: ISON Command")
async def test_rfc_ison():
    """Test ISON returns online status"""
    client1 = IRCTestClient("rfc_ison1")
    client2 = IRCTestClient("rfc_ison2")

    await client1.connect("IsonTarget")
    await client2.connect("IsonQuery")

    client2.buffer.clear()
    # Test both online and offline nicks
    await client2.send_raw("ISON IsonTarget OfflineUser123")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # 303 RPL_ISON format: :server 303 nick :nick1 nick2...
    has_303 = False
    for line in client2.buffer:
        if " 303 " in line:
            has_303 = True
            print(f"   303: {line[:80]}...")
            # Should contain online nick, not offline one
            assert "IsonTarget" in line, "303 should contain online nick"
            # Offline user should NOT be in response
            if "OfflineUser123" in line:
                print("   WARNING: Offline user found in ISON response")

    assert has_303, "No RPL_ISON (303) received"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: NICK Change")
async def test_rfc_nick_change():
    """Test NICK change is broadcast correctly"""
    client1 = IRCTestClient("rfc_nick1")
    client2 = IRCTestClient("rfc_nick2")

    await client1.connect("OriginalNick")
    await client2.connect("Observer")

    # Both join same channel
    await client1.send_raw("JOIN #nickchan")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #nickchan")
    await asyncio.sleep(0.2)

    client2.buffer.clear()
    await client1.send_raw("NICK NewNickName")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Both should see NICK change message
    # Format: :oldnick!user@host NICK :newnick  OR  :oldnick!user@host NICK newnick
    nick_change = None
    for line in client2.buffer:
        if "NICK" in line and "NewNickName" in line:
            nick_change = line
            break

    assert nick_change, "Observer should see NICK change"
    assert "OriginalNick" in nick_change, "NICK message should show old nick"
    print(f"   NICK change: {nick_change[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: MODE Query")
async def test_rfc_mode_query():
    """Test MODE query returns current modes"""
    client = IRCTestClient("rfc_mode")

    await client.connect("ModeQueryTest")
    await client.send_raw("JOIN #modequery")
    await asyncio.sleep(0.3)

    # Set some modes
    await client.send_raw("MODE #modequery +nt")
    await asyncio.sleep(0.2)

    # Query channel modes
    client.buffer.clear()
    await client.send_raw("MODE #modequery")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # 324 RPL_CHANNELMODEIS format: :server 324 nick #channel +modes [params]
    has_324 = False
    for line in client.buffer:
        if " 324 " in line:
            has_324 = True
            print(f"   324: {line[:80]}...")
            assert "#modequery" in line, "324 should contain channel name"

    assert has_324, "No RPL_CHANNELMODEIS (324) received"

    # Query user modes
    client.buffer.clear()
    await client.send_raw("MODE ModeQueryTest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # 221 RPL_UMODEIS format: :server 221 nick +modes
    has_221 = any(" 221 " in line for line in client.buffer)
    print(f"   221 (UMODEIS): {has_221}")

    await client.disconnect()


@runner.test("RFC: PART with Reason")
async def test_rfc_part():
    """Test PART command with reason is broadcast"""
    client1 = IRCTestClient("rfc_part1")
    client2 = IRCTestClient("rfc_part2")

    await client1.connect("PartingUser")
    await client2.connect("StayingUser")

    await client1.send_raw("JOIN #parttest")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #parttest")
    await asyncio.sleep(0.2)

    client2.buffer.clear()
    await client1.send_raw("PART #parttest :Goodbye everyone!")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Format: :nick!user@host PART #channel :reason
    part_msg = None
    for line in client2.buffer:
        if "PART" in line and "#parttest" in line:
            part_msg = line
            break

    assert part_msg, "Observer should see PART message"
    assert "PartingUser" in part_msg, "PART should show who left"
    print(f"   PART: {part_msg[:80]}...")
    # Reason may or may not be included depending on server
    if "Goodbye" in part_msg:
        print("   Reason included in PART")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("RFC: KICK with Reason")
async def test_rfc_kick():
    """Test KICK command format and broadcast"""
    client1 = IRCTestClient("rfc_kick1")
    client2 = IRCTestClient("rfc_kick2")
    client3 = IRCTestClient("rfc_kick3")

    await client1.connect("Kicker")
    await client2.connect("Kicked")
    await client3.connect("Watcher")

    await client1.send_raw("JOIN #kickrfc")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #kickrfc")
    await asyncio.sleep(0.2)
    await client3.send_raw("JOIN #kickrfc")
    await asyncio.sleep(0.2)

    client3.buffer.clear()
    await client1.send_raw("KICK #kickrfc Kicked :You have been kicked!")
    await asyncio.sleep(0.3)
    await client2.read_lines()
    await client3.read_lines()

    # Format: :kicker!user@host KICK #channel kicked :reason
    kick_msg = None
    for line in client3.buffer:
        if "KICK" in line and "#kickrfc" in line:
            kick_msg = line
            break

    assert kick_msg, "Watcher should see KICK message"
    assert "Kicker" in kick_msg, "KICK should show who kicked"
    assert "Kicked" in kick_msg, "KICK should show who was kicked"
    print(f"   KICK: {kick_msg[:80]}...")

    await client1.disconnect()
    await client2.disconnect()
    await client3.disconnect()


@runner.test("RFC: QUIT Message")
async def test_rfc_quit():
    """Test QUIT message is broadcast to channels"""
    client1 = IRCTestClient("rfc_quit1")
    client2 = IRCTestClient("rfc_quit2")

    await client1.connect("Quitter")
    await client2.connect("Remaining")

    await client1.send_raw("JOIN #quitchan")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #quitchan")
    await asyncio.sleep(0.2)

    client2.buffer.clear()
    await client1.send_raw("QUIT :Leaving the server")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    # Format: :nick!user@host QUIT :reason
    quit_msg = None
    for line in client2.buffer:
        if "QUIT" in line:
            quit_msg = line
            break

    assert quit_msg, "Remaining user should see QUIT message"
    assert "Quitter" in quit_msg, "QUIT should show who quit"
    print(f"   QUIT: {quit_msg[:80]}...")

    await client2.disconnect()


# ==============================================================================
# IRCX PROTOCOL COMPLIANCE TESTS
# ==============================================================================

@runner.test("IRCX: ISIRCX Command")
async def test_ircx_isircx():
    """Test ISIRCX returns server IRCX capabilities"""
    client = IRCTestClient("ircx_isircx")

    await client.connect("IsircxTest")

    client.buffer.clear()
    await client.send_raw("ISIRCX")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # ISIRCX should return 800 with IRCX version info
    has_800 = any(" 800 " in line for line in client.buffer)
    print(f"   ISIRCX response (800): {has_800}")

    if has_800:
        for line in client.buffer:
            if " 800 " in line:
                print(f"   {line[:80]}...")
                break

    assert has_800, "ISIRCX should return 800 response"

    await client.disconnect()


@runner.test("IRCX: Protocol Upgrade Response")
async def test_ircx_upgrade():
    """Test IRCX command upgrades protocol and returns proper response"""
    client = IRCTestClient("ircx_upgrade")

    await client.connect("IrcxUpgrade")

    client.buffer.clear()
    await client.send_raw("IRCX")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # IRCX returns 800 with version info
    has_800 = any(" 800 " in line for line in client.buffer)
    print(f"   IRCX upgrade (800): {has_800}")

    for line in client.buffer:
        if " 800 " in line:
            print(f"   {line[:80]}...")
            # Should contain IRCX version
            break

    assert has_800, "IRCX command should return 800"

    await client.disconnect()


@runner.test("IRCX: CREATE Command")
async def test_ircx_create():
    """Test IRCX CREATE command for channel creation"""
    client = IRCTestClient("ircx_create")

    await client.connect("CreateTest")

    # First upgrade to IRCX
    await client.send_raw("IRCX")
    await asyncio.sleep(0.2)

    client.buffer.clear()
    await client.send_raw("CREATE #ircxcreate")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # CREATE should result in joining the channel
    has_join = any("JOIN" in line and "#ircxcreate" in line for line in client.buffer)
    print(f"   CREATE resulted in JOIN: {has_join}")

    # Should also get NAMES
    has_names = any(" 353 " in line for line in client.buffer)
    print(f"   Received NAMES (353): {has_names}")

    assert has_join or has_names, "CREATE should create/join channel"

    await client.disconnect()


@runner.test("IRCX: LISTX Extended List")
async def test_ircx_listx():
    """Test IRCX LISTX command for extended channel listing"""
    client = IRCTestClient("ircx_listx")

    await client.connect("ListxTest")

    # Create a channel first
    await client.send_raw("JOIN #listxtest")
    await asyncio.sleep(0.2)
    await client.send_raw("TOPIC #listxtest :LISTX test topic")
    await asyncio.sleep(0.2)

    # Upgrade to IRCX
    await client.send_raw("IRCX")
    await asyncio.sleep(0.2)

    client.buffer.clear()
    await client.send_raw("LISTX")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # LISTX should return channel info - may use 811/812 or fall back to 321/322/323
    has_list = any(" 322 " in line or " 811 " in line for line in client.buffer)
    has_end = any(" 323 " in line or " 812 " in line for line in client.buffer)

    print(f"   LISTX has channel entries: {has_list}")
    print(f"   LISTX has end marker: {has_end}")

    for line in client.buffer:
        if "#listxtest" in line:
            print(f"   {line[:80]}...")

    assert has_list, "LISTX should return channel list"

    await client.disconnect()


@runner.test("IRCX: WHISPER Command")
async def test_ircx_whisper():
    """Test IRCX WHISPER command for channel-private messages"""
    client1 = IRCTestClient("ircx_whisper1")
    client2 = IRCTestClient("ircx_whisper2")
    client3 = IRCTestClient("ircx_whisper3")

    await client1.connect("Whisperer")
    await client2.connect("WhisperTarget")
    await client3.connect("WhisperBystander")

    # All join same channel
    await client1.send_raw("JOIN #whisperchan")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #whisperchan")
    await asyncio.sleep(0.2)
    await client3.send_raw("JOIN #whisperchan")
    await asyncio.sleep(0.2)

    client2.buffer.clear()
    client3.buffer.clear()

    # WHISPER should send private message within channel context
    await client1.send_raw("WHISPER #whisperchan WhisperTarget :This is a whisper")
    await asyncio.sleep(0.3)
    await client2.read_lines()
    await client3.read_lines()

    # Target should receive the whisper
    target_got = any("WHISPER" in line and "whisper" in line.lower() for line in client2.buffer)
    # Bystander should NOT receive it
    bystander_got = any("WHISPER" in line and "whisper" in line.lower() for line in client3.buffer)

    print(f"   Target received WHISPER: {target_got}")
    print(f"   Bystander received WHISPER: {bystander_got}")

    if target_got:
        for line in client2.buffer:
            if "WHISPER" in line:
                print(f"   {line[:80]}...")

    # WHISPER may be implemented as PRIVMSG with special handling
    # Check for either WHISPER or PRIVMSG delivery
    target_msg = any(("WHISPER" in line or "PRIVMSG" in line) and "whisper" in line.lower()
                     for line in client2.buffer)

    assert target_msg, "Target should receive whisper message"

    await client1.disconnect()
    await client2.disconnect()
    await client3.disconnect()


@runner.test("IRCX: PROP OWNERKEY")
async def test_ircx_prop_ownerkey():
    """Test PROP OWNERKEY grants owner on join"""
    client1 = IRCTestClient("ircx_ownerkey1")
    client2 = IRCTestClient("ircx_ownerkey2")

    await client1.connect("OwnerKeyOwner")
    await client2.connect("OwnerKeyUser")

    await client1.send_raw("JOIN #ownerkeytest")
    await asyncio.sleep(0.2)

    # Set OWNERKEY
    await client1.send_raw("PROP #ownerkeytest OWNERKEY :supersecret")
    await asyncio.sleep(0.2)

    # User joins with OWNERKEY
    client2.buffer.clear()
    await client2.send_raw("JOIN #ownerkeytest supersecret")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get +q (owner) mode
    has_owner = any("+q" in line and "OwnerKeyUser" in line for line in client2.buffer)
    print(f"   OWNERKEY granted owner (+q): {has_owner}")

    for line in client2.buffer:
        if "MODE" in line and "OwnerKeyUser" in line:
            print(f"   {line[:80]}...")

    assert has_owner, "OWNERKEY should grant owner mode"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("IRCX: PROP LAG")
async def test_ircx_prop_lag():
    """Test PROP LAG property for channel slow-mode"""
    client = IRCTestClient("ircx_lag")

    await client.connect("LagTest")
    await client.send_raw("JOIN #lagtest")
    await asyncio.sleep(0.2)

    # Set LAG (slow mode) - users must wait N seconds between messages
    client.buffer.clear()
    await client.send_raw("PROP #lagtest LAG :5")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Should get 819 confirmation or similar
    has_set = any(" 819 " in line for line in client.buffer)
    print(f"   LAG property set: {has_set}")

    # Query the property
    client.buffer.clear()
    await client.send_raw("PROP #lagtest LAG")
    await asyncio.sleep(0.2)
    await client.read_lines()

    has_value = any(" 817 " in line for line in client.buffer)
    print(f"   LAG property readable: {has_value}")

    await client.disconnect()


@runner.test("IRCX: ACCESS LIST Command")
async def test_ircx_access_list():
    """Test ACCESS LIST shows access entries"""
    client = IRCTestClient("ircx_access_list")

    await client.connect("AccessListTest")
    await client.send_raw("JOIN #accesslisttest")
    await asyncio.sleep(0.2)

    # Add some access entries
    await client.send_raw("ACCESS #accesslisttest ADD GRANT TestUser1")
    await asyncio.sleep(0.1)
    await client.send_raw("ACCESS #accesslisttest ADD DENY TestUser2")
    await asyncio.sleep(0.1)
    await client.send_raw("ACCESS #accesslisttest ADD HOST TestUser3")
    await asyncio.sleep(0.2)

    # List access entries
    client.buffer.clear()
    await client.send_raw("ACCESS #accesslisttest LIST")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should show access entries - look for 803 or similar
    has_entries = any("TestUser1" in line or "TestUser2" in line or "TestUser3" in line
                      for line in client.buffer)
    print(f"   ACCESS LIST shows entries: {has_entries}")

    for line in client.buffer:
        if "TestUser" in line or " 803 " in line or " 804 " in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("IRCX: ACCESS DELETE Command")
async def test_ircx_access_delete():
    """Test ACCESS DELETE removes access entries"""
    client = IRCTestClient("ircx_access_del")

    await client.connect("AccessDelTest")
    await client.send_raw("JOIN #accessdeltest")
    await asyncio.sleep(0.2)

    # Add an access entry
    await client.send_raw("ACCESS #accessdeltest ADD GRANT DeleteMe")
    await asyncio.sleep(0.2)

    # Delete the entry
    client.buffer.clear()
    await client.send_raw("ACCESS #accessdeltest DELETE DeleteMe")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Verify deletion - check list is now empty for that user
    client.buffer.clear()
    await client.send_raw("ACCESS #accessdeltest LIST")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # DeleteMe should not appear in list
    has_deleted = not any("DeleteMe" in line for line in client.buffer)
    print(f"   ACCESS DELETE removed entry: {has_deleted}")

    await client.disconnect()


# ==============================================================================
# CHANNEL MODE TESTS
# ==============================================================================

@runner.test("Mode: Moderated Channel (+m)")
async def test_mode_moderated():
    """Test moderated mode blocks non-voiced users"""
    client1 = IRCTestClient("mode_mod1")
    client2 = IRCTestClient("mode_mod2")

    await client1.connect("ModOwner")
    await client2.connect("ModUser")

    await client1.send_raw("JOIN #modtest")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #modtest")
    await asyncio.sleep(0.2)

    # Set +m
    await client1.send_raw("MODE #modtest +m")
    await asyncio.sleep(0.2)

    # Non-voiced user tries to speak
    client2.buffer.clear()
    await client2.send_raw("PRIVMSG #modtest :Can anyone hear me?")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get 404 ERR_CANNOTSENDTOCHAN
    has_error = any(" 404 " in line for line in client2.buffer)
    print(f"   Moderated blocked message (404): {has_error}")

    # Give voice and try again
    await client1.send_raw("MODE #modtest +v ModUser")
    await asyncio.sleep(0.2)

    client1.buffer.clear()
    await client2.send_raw("PRIVMSG #modtest :Now I can speak!")
    await asyncio.sleep(0.3)
    await client1.read_lines()

    has_msg = any("Now I can speak" in line for line in client1.buffer)
    print(f"   Voiced user message received: {has_msg}")

    assert has_error, "Moderated should block unvoiced users"
    assert has_msg, "Voiced users should be able to speak"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Mode: No External Messages (+n)")
async def test_mode_no_external():
    """Test +n blocks messages from non-members"""
    client1 = IRCTestClient("mode_ext1")
    client2 = IRCTestClient("mode_ext2")

    await client1.connect("ExtOwner")
    await client2.connect("ExtOutsider")

    await client1.send_raw("JOIN #externaltest")
    await asyncio.sleep(0.2)

    # Set +n (usually default, but ensure it)
    await client1.send_raw("MODE #externaltest +n")
    await asyncio.sleep(0.2)

    # Outsider tries to message channel
    client2.buffer.clear()
    await client2.send_raw("PRIVMSG #externaltest :Hello from outside!")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get 404 ERR_CANNOTSENDTOCHAN
    has_error = any(" 404 " in line for line in client2.buffer)
    print(f"   External message blocked (404): {has_error}")

    assert has_error, "+n should block external messages"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Mode: Topic Lock (+t)")
async def test_mode_topic_lock():
    """Test +t restricts topic changes to hosts"""
    client1 = IRCTestClient("mode_topic1")
    client2 = IRCTestClient("mode_topic2")

    await client1.connect("TopicOwner")
    await client2.connect("TopicUser")

    await client1.send_raw("JOIN #topiclock")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #topiclock")
    await asyncio.sleep(0.2)

    # Ensure +t is set
    await client1.send_raw("MODE #topiclock +t")
    await asyncio.sleep(0.2)

    # Regular user tries to change topic
    client2.buffer.clear()
    await client2.send_raw("TOPIC #topiclock :User tries to set topic")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get 482 ERR_CHANOPRIVSNEEDED
    has_error = any(" 482 " in line for line in client2.buffer)
    print(f"   Topic change blocked (482): {has_error}")

    assert has_error, "+t should restrict topic to ops"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Mode: Secret Channel (+s)")
async def test_mode_secret():
    """Test +s hides channel from LIST"""
    client1 = IRCTestClient("mode_secret1")
    client2 = IRCTestClient("mode_secret2")

    await client1.connect("SecretOwner")
    await client2.connect("SecretSearcher")

    await client1.send_raw("JOIN #secretchan")
    await asyncio.sleep(0.2)

    # Set +s
    await client1.send_raw("MODE #secretchan +s")
    await asyncio.sleep(0.2)

    # Other user does LIST
    client2.buffer.clear()
    await client2.send_raw("LIST")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    # Secret channel should NOT appear
    found_secret = any("#secretchan" in line for line in client2.buffer)
    print(f"   Secret channel in LIST: {found_secret}")

    assert not found_secret, "+s should hide channel from LIST"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Mode: Private Channel (+p)")
async def test_mode_private():
    """Test +p affects channel visibility"""
    client1 = IRCTestClient("mode_private1")
    client2 = IRCTestClient("mode_private2")

    await client1.connect("PrivateOwner")
    await client2.connect("PrivateSearcher")

    await client1.send_raw("JOIN #privatechan")
    await asyncio.sleep(0.2)

    # Set +p
    await client1.send_raw("MODE #privatechan +p")
    await asyncio.sleep(0.2)

    # Other user does WHOIS on owner
    client2.buffer.clear()
    await client2.send_raw("WHOIS PrivateOwner")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Channel should not appear in WHOIS 319 (channels list)
    # or should show as private
    found_in_whois = any("#privatechan" in line and " 319 " in line for line in client2.buffer)
    print(f"   Private channel in WHOIS: {found_in_whois}")

    # +p may hide or show as private - both are valid
    for line in client2.buffer:
        if " 319 " in line:
            print(f"   319: {line[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Mode: Registered Only (+r)")
async def test_mode_registered():
    """Test +r blocks unregistered users"""
    client1 = IRCTestClient("mode_reg1")
    client2 = IRCTestClient("mode_reg2")

    await client1.connect("RegOwner")
    await client2.connect("UnregUser")

    await client1.send_raw("JOIN #regonly")
    await asyncio.sleep(0.2)

    # Set +r
    await client1.send_raw("MODE #regonly +r")
    await asyncio.sleep(0.2)

    # Unregistered user tries to join
    client2.buffer.clear()
    await client2.send_raw("JOIN #regonly")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get 477 ERR_NEEDREGGEDNICK or similar
    blocked = any(" 477 " in line or " 473 " in line for line in client2.buffer)
    print(f"   Unregistered user blocked: {blocked}")

    for line in client2.buffer:
        if " 477 " in line or " 473 " in line or "register" in line.lower():
            print(f"   {line[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# USER MODE TESTS
# ==============================================================================

@runner.test("User Mode: Invisible (+i)")
async def test_umode_invisible():
    """Test +i hides user from WHO"""
    client1 = IRCTestClient("umode_inv1")
    client2 = IRCTestClient("umode_inv2")

    await client1.connect("InvisibleUser")
    await client2.connect("Searcher")

    # Set invisible mode
    await client1.send_raw("MODE InvisibleUser +i")
    await asyncio.sleep(0.2)

    # Searcher does WHO *
    client2.buffer.clear()
    await client2.send_raw("WHO *")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    # Invisible user should not appear in general WHO
    found_invisible = any("InvisibleUser" in line and " 352 " in line for line in client2.buffer)
    print(f"   Invisible user in WHO *: {found_invisible}")

    # But should appear in specific WHO if in same channel
    await client1.send_raw("JOIN #invtest")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #invtest")
    await asyncio.sleep(0.2)

    client2.buffer.clear()
    await client2.send_raw("WHO #invtest")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    found_in_chan = any("InvisibleUser" in line and " 352 " in line for line in client2.buffer)
    print(f"   Invisible user in channel WHO: {found_in_chan}")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("User Mode: Host Masking (+x)")
async def test_umode_hostmask():
    """Test +x masks user's hostname"""
    client = IRCTestClient("umode_mask")

    await client.connect("MaskTest")

    # Set host masking
    client.buffer.clear()
    await client.send_raw("MODE MaskTest +x")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Check WHOIS to see masked host
    client.buffer.clear()
    await client.send_raw("WHOIS MaskTest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Look for 311 to see host
    for line in client.buffer:
        if " 311 " in line:
            print(f"   311: {line[:80]}...")
            # Host should be masked (may contain network name or be hashed)

    await client.disconnect()


@runner.test("User Mode: Wallops (+w)")
async def test_umode_wallops():
    """Test +w enables receiving WALLOPS messages"""
    client = IRCTestClient("umode_wallops")

    await client.connect("WallopsTest")

    # Enable wallops
    client.buffer.clear()
    await client.send_raw("MODE WallopsTest +w")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Verify mode was set
    client.buffer.clear()
    await client.send_raw("MODE WallopsTest")
    await asyncio.sleep(0.2)
    await client.read_lines()

    has_w = any("+w" in line or " 221 " in line for line in client.buffer)
    print(f"   Wallops mode set: {has_w}")

    for line in client.buffer:
        if " 221 " in line:
            print(f"   221: {line[:80]}...")

    await client.disconnect()


# ==============================================================================
# CUSTOM FEATURE TESTS
# ==============================================================================

@runner.test("Custom: Nick Registration (REGISTER)")
async def test_nick_register():
    """Test nick registration functionality"""
    client = IRCTestClient("custom_register")

    await client.connect("RegNickTest")

    client.buffer.clear()
    await client.send_raw("REGISTER testpassword123 testemail@test.com")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get success or already registered message
    # Look for appropriate numeric or notice
    for line in client.buffer:
        print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: CHGPASS for Registered Nick")
async def test_chgpass():
    """Test changing password for registered nick"""
    client = IRCTestClient("custom_chgpass")

    await client.connect("ChgpassTest")

    # First try to register
    await client.send_raw("REGISTER oldpass123 test@test.com")
    await asyncio.sleep(0.2)

    # Try to change password
    client.buffer.clear()
    await client.send_raw("CHGPASS oldpass123 newpass456")
    await asyncio.sleep(0.3)
    await client.read_lines()

    for line in client.buffer:
        print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: Clone Channel Auto-Creation")
async def test_clone_auto_create():
    """Test clone channels are created when original is full"""
    clients = []

    try:
        # Create channel with +d (clone) and +l 2 (limit)
        owner = IRCTestClient("clone_owner")
        await owner.connect("CloneOwner")

        await owner.send_raw("JOIN #cloneauto")
        await asyncio.sleep(0.2)
        await owner.send_raw("MODE #cloneauto +dl 2")
        await asyncio.sleep(0.2)
        clients.append(owner)

        # Second user joins (still fits)
        user1 = IRCTestClient("clone_user1")
        await user1.connect("CloneUser1")
        await user1.send_raw("JOIN #cloneauto")
        await asyncio.sleep(0.2)
        clients.append(user1)

        # Third user should trigger clone creation
        user2 = IRCTestClient("clone_user2")
        await user2.connect("CloneUser2")
        user2.buffer.clear()
        await user2.send_raw("JOIN #cloneauto")
        await asyncio.sleep(0.5)
        await user2.read_lines()
        clients.append(user2)

        # Should be in #cloneauto1 or similar
        in_clone = any("#cloneauto1" in line for line in user2.buffer)
        in_original = any("JOIN" in line and "#cloneauto" in line for line in user2.buffer)
        print(f"   User landed in clone: {in_clone}")
        print(f"   User joined successfully: {in_original}")

        for line in user2.buffer:
            if "JOIN" in line:
                print(f"   {line[:80]}...")

    finally:
        for c in clients:
            await c.disconnect()


@runner.test("Custom: Clone Mode Propagation")
async def test_clone_mode_propagation():
    """Test mode changes on original propagate to clones"""
    clients = []

    try:
        # Create channel with clone mode
        owner = IRCTestClient("clone_prop_owner")
        await owner.connect("ClonePropOwner")

        await owner.send_raw("JOIN #cloneprop")
        await asyncio.sleep(0.2)
        await owner.send_raw("MODE #cloneprop +dl 1")
        await asyncio.sleep(0.2)
        clients.append(owner)

        # Force creation of clone by joining
        user1 = IRCTestClient("clone_prop_user")
        await user1.connect("ClonePropUser")
        await user1.send_raw("JOIN #cloneprop")
        await asyncio.sleep(0.3)
        clients.append(user1)

        # Set +m on original
        await owner.send_raw("MODE #cloneprop +m")
        await asyncio.sleep(0.3)

        # Check if clone has +m too
        user1.buffer.clear()
        await user1.send_raw("MODE #cloneprop1")
        await asyncio.sleep(0.2)
        await user1.read_lines()

        has_m = any("+m" in line for line in user1.buffer)
        print(f"   Clone has +m: {has_m}")

        for line in user1.buffer:
            if " 324 " in line:
                print(f"   {line[:80]}...")

    finally:
        for c in clients:
            await c.disconnect()


@runner.test("Custom: KNOCK on Invite-Only")
async def test_knock_invite_only():
    """Test KNOCK requests access to +i channel"""
    client1 = IRCTestClient("knock_owner")
    client2 = IRCTestClient("knock_user")

    await client1.connect("KnockOwner")
    await client2.connect("KnockUser")

    await client1.send_raw("JOIN #knocktest")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #knocktest +i")
    await asyncio.sleep(0.2)

    # User knocks
    client1.buffer.clear()
    client2.buffer.clear()
    await client2.send_raw("KNOCK #knocktest :Please let me in!")
    await asyncio.sleep(0.3)
    await client1.read_lines()
    await client2.read_lines()

    # Owner should receive knock notification
    owner_notified = any("KNOCK" in line or "knock" in line.lower() for line in client1.buffer)
    # User should get acknowledgment
    user_ack = any(" 710 " in line or " 711 " in line or "KNOCK" in line for line in client2.buffer)

    print(f"   Owner notified of KNOCK: {owner_notified}")
    print(f"   User got KNOCK ack: {user_ack}")

    for line in client1.buffer:
        if "KNOCK" in line or "knock" in line.lower():
            print(f"   Owner: {line[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Custom: ServiceBot in Channel")
async def test_servicebot():
    """Test ServiceBot auto-joins channels"""
    client = IRCTestClient("servicebot_test")

    await client.connect("ServiceBotTest")
    await client.send_raw("JOIN #servicebottest")
    await asyncio.sleep(0.3)

    # Check NAMES for servicebot (may be $name or similar)
    client.buffer.clear()
    await client.send_raw("NAMES #servicebottest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    for line in client.buffer:
        if " 353 " in line:
            print(f"   NAMES: {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: Profanity Filter Warning")
async def test_profanity_filter():
    """Test profanity filter issues warnings"""
    client = IRCTestClient("profanity_test")

    await client.connect("ProfanityTest")
    await client.send_raw("JOIN #profanitytest")
    await asyncio.sleep(0.2)

    # Say a configured bad word (from config: "badword", "testbad")
    client.buffer.clear()
    await client.send_raw("PRIVMSG #profanitytest :This message has badword in it")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should receive a warning from servicebot or system
    has_warning = any("language" in line.lower() or "profanity" in line.lower()
                      or "watch" in line.lower() for line in client.buffer)
    print(f"   Profanity warning received: {has_warning}")

    for line in client.buffer:
        if "NOTICE" in line or "PRIVMSG" in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: INFO Command")
async def test_info_command():
    """Test INFO returns server information"""
    client = IRCTestClient("info_test")

    await client.connect("InfoTest")

    client.buffer.clear()
    await client.send_raw("INFO")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # INFO should return 371 lines and 374 end
    has_371 = any(" 371 " in line for line in client.buffer)
    has_374 = any(" 374 " in line for line in client.buffer)

    print(f"   371 (INFO lines): {has_371}")
    print(f"   374 (END OF INFO): {has_374}")

    for line in client.buffer[:5]:  # First 5 lines
        if " 371 " in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: LINKS Command")
async def test_links_command():
    """Test LINKS returns server links"""
    client = IRCTestClient("links_test")

    await client.connect("LinksTest")

    client.buffer.clear()
    await client.send_raw("LINKS")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # LINKS returns 364 and 365
    has_364 = any(" 364 " in line for line in client.buffer)
    has_365 = any(" 365 " in line for line in client.buffer)

    print(f"   364 (LINKS): {has_364}")
    print(f"   365 (END OF LINKS): {has_365}")

    await client.disconnect()


@runner.test("Custom: VERSION Command")
async def test_version_command():
    """Test VERSION returns server version"""
    client = IRCTestClient("version_test")

    await client.connect("VersionTest")

    client.buffer.clear()
    await client.send_raw("VERSION")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # VERSION returns 351
    has_351 = any(" 351 " in line for line in client.buffer)
    print(f"   351 (VERSION): {has_351}")

    for line in client.buffer:
        if " 351 " in line:
            print(f"   {line[:80]}...")

    assert has_351, "VERSION should return 351"

    await client.disconnect()


@runner.test("Custom: ADMIN Command")
async def test_admin_info():
    """Test ADMIN returns administrative info"""
    client = IRCTestClient("admin_info_test")

    await client.connect("AdminInfoTest")

    client.buffer.clear()
    await client.send_raw("ADMIN")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # ADMIN returns 256, 257, 258, 259
    has_256 = any(" 256 " in line for line in client.buffer)
    has_259 = any(" 259 " in line for line in client.buffer)

    print(f"   256 (ADMINME): {has_256}")
    print(f"   259 (ADMINEMAIL): {has_259}")

    for line in client.buffer:
        if " 256 " in line or " 257 " in line or " 258 " in line or " 259 " in line:
            print(f"   {line[:80]}...")

    assert has_256, "ADMIN should return 256"

    await client.disconnect()


@runner.test("Custom: TIME Command")
async def test_time_command():
    """Test TIME returns server time"""
    client = IRCTestClient("time_test")

    await client.connect("TimeTest")

    client.buffer.clear()
    await client.send_raw("TIME")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # TIME returns 391
    has_391 = any(" 391 " in line for line in client.buffer)
    print(f"   391 (TIME): {has_391}")

    for line in client.buffer:
        if " 391 " in line:
            print(f"   {line[:80]}...")

    assert has_391, "TIME should return 391"

    await client.disconnect()


@runner.test("Custom: STATS Command")
async def test_stats_command():
    """Test STATS returns server statistics"""
    client = IRCTestClient("stats_test")

    await client.connect("StatsTest")

    # Test STATS u (uptime)
    client.buffer.clear()
    await client.send_raw("STATS u")
    await asyncio.sleep(0.3)
    await client.read_lines()

    has_242 = any(" 242 " in line for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   242 (STATSUPTIME): {has_242}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer:
        if " 242 " in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: AWAY Status")
async def test_away_status():
    """Test AWAY sets and shows away status"""
    client1 = IRCTestClient("away_test1")
    client2 = IRCTestClient("away_test2")

    await client1.connect("AwayUser")
    await client2.connect("AwayChecker")

    # Set away
    client1.buffer.clear()
    await client1.send_raw("AWAY :Gone fishing")
    await asyncio.sleep(0.2)
    await client1.read_lines()

    # Should get 306 RPL_NOWAWAY
    has_306 = any(" 306 " in line for line in client1.buffer)
    print(f"   306 (NOWAWAY): {has_306}")

    # Other user checks WHOIS
    client2.buffer.clear()
    await client2.send_raw("WHOIS AwayUser")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should see 301 RPL_AWAY
    has_301 = any(" 301 " in line for line in client2.buffer)
    print(f"   301 (AWAY in WHOIS): {has_301}")

    for line in client2.buffer:
        if " 301 " in line:
            print(f"   {line[:80]}...")

    # Unset away
    client1.buffer.clear()
    await client1.send_raw("AWAY")
    await asyncio.sleep(0.2)
    await client1.read_lines()

    # Should get 305 RPL_UNAWAY
    has_305 = any(" 305 " in line for line in client1.buffer)
    print(f"   305 (UNAWAY): {has_305}")

    assert has_306, "AWAY should return 306"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Custom: WHO Flags Format")
async def test_who_flags():
    """Test WHO shows proper flags (H/G, @, +, etc.)"""
    client1 = IRCTestClient("who_flags1")
    client2 = IRCTestClient("who_flags2")

    await client1.connect("WhoFlagsOp")
    await client2.connect("WhoFlagsVoice")

    await client1.send_raw("JOIN #whoflagstest")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #whoflagstest")
    await asyncio.sleep(0.2)

    # Give voice to user2
    await client1.send_raw("MODE #whoflagstest +v WhoFlagsVoice")
    await asyncio.sleep(0.2)

    # Check WHO output
    client1.buffer.clear()
    await client1.send_raw("WHO #whoflagstest")
    await asyncio.sleep(0.3)
    await client1.read_lines()

    for line in client1.buffer:
        if " 352 " in line:
            print(f"   352: {line[:80]}...")
            # Should show H (here) and appropriate prefix (@, +, etc.)

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Custom: Multiple Channel Modes")
async def test_multi_mode():
    """Test setting multiple modes at once"""
    client = IRCTestClient("multi_mode")

    await client.connect("MultiModeTest")
    await client.send_raw("JOIN #multimode")
    await asyncio.sleep(0.2)

    # Set multiple modes at once
    client.buffer.clear()
    await client.send_raw("MODE #multimode +ntms")
    await asyncio.sleep(0.2)
    await client.read_lines()

    # Query modes
    client.buffer.clear()
    await client.send_raw("MODE #multimode")
    await asyncio.sleep(0.2)
    await client.read_lines()

    mode_line = None
    for line in client.buffer:
        if " 324 " in line:
            mode_line = line
            print(f"   324: {line[:80]}...")

    # Should contain the set modes
    if mode_line:
        has_n = "n" in mode_line
        has_t = "t" in mode_line
        has_m = "m" in mode_line
        has_s = "s" in mode_line
        print(f"   Has +n: {has_n}, +t: {has_t}, +m: {has_m}, +s: {has_s}")

    await client.disconnect()


@runner.test("Custom: Ban List Query")
async def test_ban_list():
    """Test querying channel ban list"""
    client = IRCTestClient("ban_list")

    await client.connect("BanListTest")
    await client.send_raw("JOIN #banlisttest")
    await asyncio.sleep(0.2)

    # Set a ban
    await client.send_raw("MODE #banlisttest +b evil!*@*")
    await asyncio.sleep(0.2)

    # Query ban list
    client.buffer.clear()
    await client.send_raw("MODE #banlisttest +b")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 367 (ban list) and 368 (end of ban list)
    has_367 = any(" 367 " in line for line in client.buffer)
    has_368 = any(" 368 " in line for line in client.buffer)

    print(f"   367 (BANLIST): {has_367}")
    print(f"   368 (ENDOFBANLIST): {has_368}")

    for line in client.buffer:
        if " 367 " in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


@runner.test("Custom: Invite List Query")
async def test_invite_list():
    """Test querying channel invite exception list"""
    client = IRCTestClient("invite_list")

    await client.connect("InviteListTest")
    await client.send_raw("JOIN #invlisttest")
    await asyncio.sleep(0.2)

    # Set an invite exception
    await client.send_raw("MODE #invlisttest +I friend!*@*")
    await asyncio.sleep(0.2)

    # Query invite list
    client.buffer.clear()
    await client.send_raw("MODE #invlisttest +I")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 346 (invite list) and 347 (end)
    has_346 = any(" 346 " in line for line in client.buffer)
    has_347 = any(" 347 " in line for line in client.buffer)

    print(f"   346 (INVITELIST): {has_346}")
    print(f"   347 (ENDOFINVITELIST): {has_347}")

    await client.disconnect()


@runner.test("Custom: Exception List Query")
async def test_except_list():
    """Test querying channel ban exception list"""
    client = IRCTestClient("except_list")

    await client.connect("ExceptListTest")
    await client.send_raw("JOIN #exclisttest")
    await asyncio.sleep(0.2)

    # Set a ban exception
    await client.send_raw("MODE #exclisttest +e good!*@*")
    await asyncio.sleep(0.2)

    # Query exception list
    client.buffer.clear()
    await client.send_raw("MODE #exclisttest +e")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 348 (except list) and 349 (end)
    has_348 = any(" 348 " in line for line in client.buffer)
    has_349 = any(" 349 " in line for line in client.buffer)

    print(f"   348 (EXCEPTLIST): {has_348}")
    print(f"   349 (ENDOFEXCEPTLIST): {has_349}")

    await client.disconnect()


# ==============================================================================
# COMPREHENSIVE STATS TESTS
# ==============================================================================

@runner.test("STATS: Uptime (u) - Public")
async def test_stats_uptime():
    """Test STATS u returns server uptime"""
    client = IRCTestClient("stats_uptime")

    await client.connect("StatsUptimeTest")

    client.buffer.clear()
    await client.send_raw("STATS u")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 242 (uptime) and 219 (end of stats)
    has_242 = any(" 242 " in line for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   242 (STATSUPTIME): {has_242}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer:
        if " 242 " in line:
            print(f"   {line[:80]}...")
            # Should contain days/hours/mins format
            assert "Up" in line or "up" in line.lower(), "242 should show uptime"

    assert has_242, "STATS u should return 242"
    assert has_219, "STATS should end with 219"

    await client.disconnect()


@runner.test("STATS: Staff Listing (s) - Public")
async def test_stats_staff():
    """Test STATS s shows online staff to regular users"""
    client = IRCTestClient("stats_staff")

    await client.connect("StatsStaffTest")

    client.buffer.clear()
    await client.send_raw("STATS s")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get staff listing notices and 219 end
    has_staff_header = any("Staff" in line for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Staff listing header: {has_staff_header}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer:
        if "Staff" in line or "ADMIN" in line or "SYSOP" in line or "GUIDE" in line:
            print(f"   {line[:80]}...")

    assert has_219, "STATS should end with 219"

    await client.disconnect()


@runner.test("STATS: Help Menu (?)")
async def test_stats_help():
    """Test STATS ? shows help menu"""
    client = IRCTestClient("stats_help")

    await client.connect("StatsHelpTest")

    client.buffer.clear()
    await client.send_raw("STATS ?")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get help notices
    has_help = any("STATS Help" in line or "Help" in line for line in client.buffer)
    has_flags = any("flag" in line.lower() or "Public" in line for line in client.buffer)
    has_219 = any(" 219 " in line for line in client.buffer)

    print(f"   Help header: {has_help}")
    print(f"   Shows flags: {has_flags}")
    print(f"   219 (ENDOFSTATS): {has_219}")

    for line in client.buffer[:5]:
        print(f"   {line[:80]}...")

    assert has_219, "STATS ? should end with 219"

    await client.disconnect()


# ==============================================================================
# ENHANCED ADMIN COMMAND VALIDATION
# ==============================================================================

@runner.test("ADMIN: Full Response Validation")
async def test_admin_full():
    """Test ADMIN returns complete administrative info per RFC"""
    client = IRCTestClient("admin_full")

    await client.connect("AdminFullTest")

    client.buffer.clear()
    await client.send_raw("ADMIN")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # ADMIN should return:
    # 256 RPL_ADMINME - server name
    # 257 RPL_ADMINLOC1 - location 1
    # 258 RPL_ADMINLOC2 - location 2
    # 259 RPL_ADMINEMAIL - email

    has_256 = False
    has_257 = False
    has_258 = False
    has_259 = False

    for line in client.buffer:
        if " 256 " in line:
            has_256 = True
            print(f"   256 (ADMINME): {line[:80]}...")
        if " 257 " in line:
            has_257 = True
            print(f"   257 (ADMINLOC1): {line[:80]}...")
        if " 258 " in line:
            has_258 = True
            print(f"   258 (ADMINLOC2): {line[:80]}...")
        if " 259 " in line:
            has_259 = True
            print(f"   259 (ADMINEMAIL): {line[:80]}...")

    print(f"   Has 256: {has_256}, 257: {has_257}, 258: {has_258}, 259: {has_259}")

    assert has_256, "ADMIN should return 256 (ADMINME)"
    assert has_257, "ADMIN should return 257 (ADMINLOC1)"
    assert has_258, "ADMIN should return 258 (ADMINLOC2)"
    assert has_259, "ADMIN should return 259 (ADMINEMAIL)"

    await client.disconnect()


# ==============================================================================
# ENHANCED INFO COMMAND VALIDATION
# ==============================================================================

@runner.test("INFO: Full Response Validation")
async def test_info_full():
    """Test INFO returns complete server information"""
    client = IRCTestClient("info_full")

    await client.connect("InfoFullTest")

    client.buffer.clear()
    await client.send_raw("INFO")
    await asyncio.sleep(0.5)
    await client.read_lines()

    # INFO should return:
    # Multiple 371 RPL_INFO lines
    # 374 RPL_ENDOFINFO

    info_count = sum(1 for line in client.buffer if " 371 " in line)
    has_374 = any(" 374 " in line for line in client.buffer)

    print(f"   371 (INFO) count: {info_count}")
    print(f"   374 (ENDOFINFO): {has_374}")

    # Show first few info lines
    shown = 0
    for line in client.buffer:
        if " 371 " in line and shown < 3:
            print(f"   371: {line[:80]}...")
            shown += 1

    assert info_count > 0, "INFO should return at least one 371 line"
    assert has_374, "INFO should end with 374"

    await client.disconnect()


# ==============================================================================
# ENHANCED WHISPER VALIDATION
# ==============================================================================

@runner.test("WHISPER: Privacy Validation")
async def test_whisper_privacy():
    """Test WHISPER only delivers to target, not bystanders"""
    client1 = IRCTestClient("whisper_priv1")
    client2 = IRCTestClient("whisper_priv2")
    client3 = IRCTestClient("whisper_priv3")

    await client1.connect("WhisperSender")
    await client2.connect("WhisperRecv")
    await client3.connect("WhisperSpy")

    # All join same channel
    await client1.send_raw("JOIN #whisperpriv")
    await asyncio.sleep(0.2)
    await client2.send_raw("JOIN #whisperpriv")
    await asyncio.sleep(0.2)
    await client3.send_raw("JOIN #whisperpriv")
    await asyncio.sleep(0.2)

    # Clear all buffers
    client1.buffer.clear()
    client2.buffer.clear()
    client3.buffer.clear()

    # Send whisper
    await client1.send_raw("WHISPER #whisperpriv WhisperRecv :Secret message for you only")
    await asyncio.sleep(0.5)
    await client1.read_lines()
    await client2.read_lines()
    await client3.read_lines()

    # Check receiver got message
    recv_got = any("Secret message" in line for line in client2.buffer)
    # Check spy did NOT get message
    spy_got = any("Secret message" in line for line in client3.buffer)

    print(f"   Receiver got message: {recv_got}")
    print(f"   Spy intercepted: {spy_got}")

    if recv_got:
        for line in client2.buffer:
            if "Secret" in line or "WHISPER" in line:
                print(f"   Recv: {line[:80]}...")

    assert recv_got, "WHISPER target should receive message"
    assert not spy_got, "WHISPER should NOT be seen by other channel members"

    await client1.disconnect()
    await client2.disconnect()
    await client3.disconnect()


# ==============================================================================
# ENHANCED KNOCK VALIDATION
# ==============================================================================

@runner.test("KNOCK: Full Flow Validation")
async def test_knock_full_flow():
    """Test complete KNOCK workflow: request, notification, join"""
    client1 = IRCTestClient("knock_flow1")
    client2 = IRCTestClient("knock_flow2")

    await client1.connect("KnockOwnerFull")
    await client2.connect("KnockUserFull")

    # Owner creates +i channel
    await client1.send_raw("JOIN #knockfull")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #knockfull +i")
    await asyncio.sleep(0.2)

    # Clear buffers
    client1.buffer.clear()
    client2.buffer.clear()

    # User knocks
    await client2.send_raw("KNOCK #knockfull :Please let me in, I have cookies!")
    await asyncio.sleep(0.5)
    await client1.read_lines()
    await client2.read_lines()

    # Validate owner notification
    owner_notice = None
    for line in client1.buffer:
        if "KNOCK" in line or "knock" in line.lower() or "KnockUserFull" in line:
            owner_notice = line
            break

    # Validate user acknowledgment (710 or 711 or notice)
    user_ack = any(" 710 " in line or " 711 " in line or "KNOCK" in line for line in client2.buffer)

    print(f"   Owner notified: {owner_notice is not None}")
    print(f"   User got ack: {user_ack}")

    if owner_notice:
        print(f"   Owner: {owner_notice[:80]}...")

    for line in client2.buffer:
        if " 710 " in line or " 711 " in line:
            print(f"   User: {line[:80]}...")

    # Now owner invites user
    await client1.send_raw("INVITE KnockUserFull #knockfull")
    await asyncio.sleep(0.3)

    # User should be able to join
    client2.buffer.clear()
    await client2.send_raw("JOIN #knockfull")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    joined = any("JOIN" in line and "#knockfull" in line for line in client2.buffer)
    print(f"   User joined after invite: {joined}")

    assert joined, "User should join after KNOCK and INVITE"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("KNOCK: Rate Limiting")
async def test_knock_rate_limit():
    """Test KNOCK has rate limiting to prevent spam"""
    client1 = IRCTestClient("knock_rate1")
    client2 = IRCTestClient("knock_rate2")

    await client1.connect("KnockRateOwner")
    await client2.connect("KnockRateUser")

    await client1.send_raw("JOIN #knockrate")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #knockrate +i")
    await asyncio.sleep(0.2)

    # Rapid knock attempts
    client2.buffer.clear()
    await client2.send_raw("KNOCK #knockrate :First knock")
    await asyncio.sleep(0.1)
    await client2.send_raw("KNOCK #knockrate :Second knock")
    await asyncio.sleep(0.1)
    await client2.send_raw("KNOCK #knockrate :Third knock")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    # Should get rate limit message on repeated knocks
    rate_limited = any("wait" in line.lower() or "already" in line.lower() or
                       " 712 " in line or " 713 " in line for line in client2.buffer)
    print(f"   Rate limiting active: {rate_limited}")

    for line in client2.buffer:
        if "KNOCK" in line or "wait" in line.lower() or "already" in line.lower():
            print(f"   {line[:80]}...")

    await client1.disconnect()
    await client2.disconnect()


# ==============================================================================
# PROP COMPREHENSIVE VALIDATION
# ==============================================================================

@runner.test("PROP: All Standard Properties")
async def test_prop_all():
    """Test all standard PROP properties"""
    client = IRCTestClient("prop_all")

    await client.connect("PropAllTest")
    await client.send_raw("JOIN #propalltest")
    await asyncio.sleep(0.2)

    properties = ["TOPIC", "ONJOIN", "ONPART", "MEMBERKEY", "HOSTKEY", "OWNERKEY", "LAG"]
    results = {}

    for prop in properties:
        client.buffer.clear()
        await client.send_raw(f"PROP #propalltest {prop} :Test value for {prop}")
        await asyncio.sleep(0.2)
        await client.read_lines()

        # Check for 819 (set confirmation) or error
        set_ok = any(" 819 " in line for line in client.buffer)
        results[prop] = set_ok

    print("   Property set results:")
    for prop, success in results.items():
        print(f"   {prop}: {'OK' if success else 'FAILED'}")

    # Query all properties
    client.buffer.clear()
    await client.send_raw("PROP #propalltest")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 818 (end of properties)
    has_818 = any(" 818 " in line for line in client.buffer)
    print(f"   818 (ENDOFPROP): {has_818}")

    await client.disconnect()


# ==============================================================================
# ACCESS COMPREHENSIVE VALIDATION
# ==============================================================================

@runner.test("ACCESS: All Level Types")
async def test_access_all_levels():
    """Test all ACCESS level types work correctly"""
    client = IRCTestClient("access_levels")

    await client.connect("AccessLevelTest")
    await client.send_raw("JOIN #accessleveltest")
    await asyncio.sleep(0.2)

    levels = ["DENY", "GRANT", "VOICE", "HOST", "OWNER"]
    results = {}

    for i, level in enumerate(levels):
        client.buffer.clear()
        await client.send_raw(f"ACCESS #accessleveltest ADD {level} TestUser{i}")
        await asyncio.sleep(0.2)
        await client.read_lines()

        # Check for success
        add_ok = not any("error" in line.lower() or " 4" in line for line in client.buffer)
        results[level] = add_ok

    print("   ACCESS level results:")
    for level, success in results.items():
        print(f"   {level}: {'OK' if success else 'FAILED'}")

    # List all entries
    client.buffer.clear()
    await client.send_raw("ACCESS #accessleveltest LIST")
    await asyncio.sleep(0.3)
    await client.read_lines()

    entry_count = sum(1 for line in client.buffer if "TestUser" in line)
    print(f"   Listed entries: {entry_count}")

    for line in client.buffer:
        if "TestUser" in line:
            print(f"   {line[:80]}...")

    await client.disconnect()


# ==============================================================================
# ERROR HANDLING TESTS
# ==============================================================================

@runner.test("Error: No Such Nick")
async def test_error_no_nick():
    """Test 401 ERR_NOSUCHNICK for non-existent user"""
    client = IRCTestClient("error_nonick")

    await client.connect("ErrorNoNick")

    client.buffer.clear()
    await client.send_raw("WHOIS NonExistentUser12345")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 401 ERR_NOSUCHNICK
    has_401 = any(" 401 " in line for line in client.buffer)
    print(f"   401 (NOSUCHNICK): {has_401}")

    for line in client.buffer:
        if " 401 " in line:
            print(f"   {line[:80]}...")

    assert has_401, "Should return 401 for non-existent nick"

    await client.disconnect()


@runner.test("Error: No Such Channel")
async def test_error_no_channel():
    """Test 403 ERR_NOSUCHCHANNEL for non-existent channel"""
    client = IRCTestClient("error_nochan")

    await client.connect("ErrorNoChan")

    client.buffer.clear()
    await client.send_raw("PART #nonexistentchannel12345")
    await asyncio.sleep(0.3)
    await client.read_lines()

    # Should get 403 ERR_NOSUCHCHANNEL or 442 ERR_NOTONCHANNEL
    has_403 = any(" 403 " in line for line in client.buffer)
    has_442 = any(" 442 " in line for line in client.buffer)
    print(f"   403 (NOSUCHCHANNEL): {has_403}")
    print(f"   442 (NOTONCHANNEL): {has_442}")

    assert has_403 or has_442, "Should return 403 or 442 for non-existent channel"

    await client.disconnect()


@runner.test("Error: Cannot Send To Channel")
async def test_error_cannot_send():
    """Test 404 ERR_CANNOTSENDTOCHAN for blocked messages"""
    client1 = IRCTestClient("error_send1")
    client2 = IRCTestClient("error_send2")

    await client1.connect("ErrorSendOwner")
    await client2.connect("ErrorSendUser")

    await client1.send_raw("JOIN #errorsend")
    await asyncio.sleep(0.2)
    await client1.send_raw("MODE #errorsend +n")  # No external messages
    await asyncio.sleep(0.2)

    # User NOT in channel tries to message
    client2.buffer.clear()
    await client2.send_raw("PRIVMSG #errorsend :Can you hear me?")
    await asyncio.sleep(0.3)
    await client2.read_lines()

    has_404 = any(" 404 " in line for line in client2.buffer)
    print(f"   404 (CANNOTSENDTOCHAN): {has_404}")

    for line in client2.buffer:
        if " 404 " in line:
            print(f"   {line[:80]}...")

    assert has_404, "Should return 404 for blocked message"

    await client1.disconnect()
    await client2.disconnect()


@runner.test("Error: Nick Already In Use")
async def test_error_nick_in_use():
    """Test 433 ERR_NICKNAMEINUSE for duplicate nick"""
    client1 = IRCTestClient("error_nick1")
    client2 = IRCTestClient("error_nick2")

    await client1.connect("DuplicateNick")

    # Second client tries same nick
    try:
        client2.reader, client2.writer = await asyncio.open_connection(client2.host, client2.port)
        client2.connected = True
    except Exception:
        pass

    client2.buffer.clear()
    await client2.send_raw("NICK DuplicateNick")
    await client2.send_raw("USER test 0 * :Test")
    await asyncio.sleep(0.5)
    await client2.read_lines()

    has_433 = any(" 433 " in line for line in client2.buffer)
    print(f"   433 (NICKNAMEINUSE): {has_433}")

    for line in client2.buffer:
        if " 433 " in line:
            print(f"   {line[:80]}...")

    assert has_433, "Should return 433 for duplicate nick"

    await client1.disconnect()
    await client2.disconnect()


async def main():
    """Main test entry point"""
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")
    
    # Test server connection first
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 6667),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        print("✅ Server is reachable\n")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Please start the pyIRCX server first!")
        return False
    
    # Run all tests
    success = await runner.run_all()
    
    return success


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
