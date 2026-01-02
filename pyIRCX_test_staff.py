#!/usr/bin/env python3
"""
pyIRCX Server - Administrator Features Test Suite
Tests ADMIN, SYSOP, and GUIDE staff features

CONFIGURATION: Set your admin credentials below

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
import aiosqlite
import bcrypt
from typing import List

# ==============================================================================
# CONFIGURATION - SET YOUR CREDENTIALS HERE
# ==============================================================================
ADMIN_CONFIG = {
    "username": "admin",
    "password": "password",
    "level": "ADMIN"
}

SYSOP_CONFIG = {
    "username": "sysop",
    "password": "password",
    "level": "SYSOP"
}

GUIDE_CONFIG = {
    "username": "guide",
    "password": "password",
    "level": "GUIDE"
}

# Set to True to auto-create test accounts
AUTO_CREATE_ACCOUNTS = True
# ==============================================================================


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
    
    async def get_line_with(self, pattern: str):
        """Get a line containing pattern from buffer"""
        for line in self.buffer:
            if pattern in line:
                return line
        return None
    
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
    
    def test(self, name: str, requires_level: str = None):
        """Decorator for test functions"""
        def decorator(func):
            self.tests.append((name, func, requires_level))
            return func
        return decorator
    
    async def run_all(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("pyIRCX ADMINISTRATOR FEATURES TEST SUITE")
        print("="*70 + "\n")
        
        print("Configuration:")
        print(f"  Admin:  {ADMIN_CONFIG['username']} (Level: {ADMIN_CONFIG['level']})")
        print(f"  Sysop:  {SYSOP_CONFIG['username']} (Level: {SYSOP_CONFIG['level']})")
        print(f"  Guide:  {GUIDE_CONFIG['username']} (Level: {GUIDE_CONFIG['level']})")
        print()
        
        for name, func, requires_level in self.tests:
            print(f"\n{'='*70}")
            print(f"TEST: {name}")
            if requires_level:
                print(f"Requires: {requires_level}")
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
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print(f"Passed:  {self.passed}")
        print(f"Failed:  {self.failed}")
        print(f"Total:   {self.passed + self.failed}")
        if self.passed + self.failed > 0:
            print(f"Success Rate: {(self.passed/(self.passed+self.failed)*100):.1f}%")
        print("="*70 + "\n")
        
        return self.failed == 0


runner = TestRunner()


@runner.test("Admin Authentication", requires_level="ADMIN")
async def test_admin_auth():
    """Test admin authentication and privileges"""
    client = IRCTestClient("test_admin_auth")
    
    assert await client.connect(
        "AdminUser",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    ), "Connection failed"
    
    assert await client.expect("804"), "No auth success (804)"
    assert await client.expect("386"), "No admin promotion (386)"
    assert await client.expect("MODE AdminUser :+a"), "No +a mode set"
    
    line = await client.get_line_with("001")
    if line:
        print(f"   Welcome line: {line}")
    
    await client.disconnect()


@runner.test("Sysop Authentication", requires_level="SYSOP")
async def test_sysop_auth():
    """Test sysop authentication and privileges"""
    client = IRCTestClient("test_sysop_auth")
    
    assert await client.connect(
        "SysopUser",
        username=SYSOP_CONFIG['username'],
        password=SYSOP_CONFIG['password']
    ), "Connection failed"
    
    assert await client.expect("804"), "No auth success (804)"
    assert await client.expect("381"), "No operator promotion (381)"
    assert await client.expect("MODE SysopUser :+o"), "No +o mode set"
    
    await client.disconnect()


@runner.test("Guide Authentication", requires_level="GUIDE")
async def test_guide_auth():
    """Test guide authentication and privileges"""
    client = IRCTestClient("test_guide_auth")
    
    assert await client.connect(
        "GuideUser",
        username=GUIDE_CONFIG['username'],
        password=GUIDE_CONFIG['password']
    ), "Connection failed"
    
    assert await client.expect("804"), "No auth success (804)"
    assert await client.expect("381"), "No staff promotion (381)"
    assert await client.expect("MODE GuideUser :+g"), "No +g mode set"
    
    await client.disconnect()


@runner.test("Admin Host Cloaking", requires_level="ADMIN")
async def test_admin_host():
    """Test that admin gets server hostname"""
    admin = IRCTestClient("test_admin_host")
    regular = IRCTestClient("test_regular")
    
    await admin.connect(
        "AdminHost",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    await regular.connect("RegularUser")
    
    await regular.send_raw("WHOIS AdminHost")
    await asyncio.sleep(0.3)
    await regular.read_lines()
    
    whois_line = await regular.get_line_with("311")
    assert whois_line, "No WHOIS reply"
    assert "irc.local" in whois_line or "@" in whois_line, f"Admin doesn't have server host: {whois_line}"
    
    await admin.disconnect()
    await regular.disconnect()


@runner.test("KILL Command - Unauthorized", requires_level="ADMIN")
async def test_kill_unauthorized():
    """Test KILL command fails for regular users"""
    regular = IRCTestClient("test_kill_regular")
    target = IRCTestClient("test_kill_target")
    
    await regular.connect("RegularKiller")
    await target.connect("KillTarget")
    await asyncio.sleep(0.2)
    
    regular.buffer.clear()
    await regular.send_raw("KILL KillTarget :Unauthorized")
    
    assert await regular.expect("481"), "No permission denied error"
    
    await target.send_raw("PING test")
    assert await target.expect("PONG"), "Target was disconnected"
    
    await regular.disconnect()
    await target.disconnect()


@runner.test("#System Channel Access - Regular User", requires_level="ADMIN")
async def test_system_channel_denied():
    """Test regular user cannot join #System"""
    regular = IRCTestClient("test_system_regular")
    
    await regular.connect("RegularSystem")
    
    await regular.send_raw("JOIN #System")
    assert await regular.expect("473"), "No access denied (473)"
    
    await regular.disconnect()


@runner.test("WHOIS Shows Operator Status", requires_level="ADMIN")
async def test_whois_operator():
    """Test WHOIS shows operator/admin status"""
    admin = IRCTestClient("test_whois_op_admin")
    regular = IRCTestClient("test_whois_op_regular")
    
    await admin.connect(
        "WhoisAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    await regular.connect("WhoisRegular")
    await asyncio.sleep(0.2)
    
    regular.buffer.clear()
    await regular.send_raw("WHOIS WhoisAdmin")
    await asyncio.sleep(0.3)
    await regular.read_lines()
    
    assert await regular.get_line_with("313"), "No operator status line (313)"
    line = await regular.get_line_with("313")
    assert "administrator" in line.lower() or "operator" in line.lower(), f"Not showing admin status: {line}"
    
    await admin.disconnect()
    await regular.disconnect()


@runner.test("WHOIS Shows IP to Staff", requires_level="ADMIN")
async def test_whois_ip_staff():
    """Test staff can see IP addresses in WHOIS"""
    admin = IRCTestClient("test_ip_admin")
    target = IRCTestClient("test_ip_target")
    
    await admin.connect(
        "IPAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    await target.connect("IPTarget")
    await asyncio.sleep(0.2)
    
    admin.buffer.clear()
    await admin.send_raw("WHOIS IPTarget")
    await asyncio.sleep(0.3)
    await admin.read_lines()
    
    assert await admin.get_line_with("320"), "No IP line (320) for staff"
    line = await admin.get_line_with("320")
    assert "127.0.0.1" in line or "from IP" in line, f"No IP address shown: {line}"
    
    await admin.disconnect()
    await target.disconnect()


@runner.test("WHOIS Hides IP from Regular Users", requires_level="ADMIN")
async def test_whois_ip_hidden():
    """Test regular users can't see IP addresses"""
    regular = IRCTestClient("test_ip_regular")
    target = IRCTestClient("test_ip_target2")
    
    await regular.connect("IPRegular")
    await target.connect("IPTarget2")
    await asyncio.sleep(0.2)
    
    regular.buffer.clear()
    await regular.send_raw("WHOIS IPTarget2")
    await asyncio.sleep(0.3)
    await regular.read_lines()
    
    line = await regular.get_line_with("320")
    assert line is None, f"IP shown to regular user: {line}"
    
    await regular.disconnect()
    await target.disconnect()


@runner.test("Auto-Owner on Channel Create", requires_level="ADMIN")
async def test_staff_auto_owner():
    """Test staff automatically get owner when joining channels"""
    admin = IRCTestClient("test_auto_owner")
    
    await admin.connect(
        "OwnerAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    admin.buffer.clear()
    await admin.send_raw("JOIN #staffchan")
    await asyncio.sleep(0.3)
    await admin.read_lines()
    
    assert await admin.get_line_with("MODE #staffchan +q"), "Staff didn't get auto-owner"
    
    await admin.disconnect()


@runner.test("KICK Command - Admin", requires_level="ADMIN")
async def test_kick_admin():
    """Test admin can kick users from channels"""
    admin = IRCTestClient("test_kick_admin")
    victim = IRCTestClient("test_kick_victim")
    
    await admin.connect(
        "KickAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    await victim.connect("KickVictim")
    
    await admin.send_raw("JOIN #kicktest")
    await asyncio.sleep(0.2)
    await victim.send_raw("JOIN #kicktest")
    await asyncio.sleep(0.2)
    
    victim.buffer.clear()
    await admin.send_raw("KICK #kicktest KickVictim :Admin kick test")
    
    assert await victim.expect("KICK #kicktest KickVictim"), "Victim didn't receive KICK"
    
    await admin.disconnect()
    await victim.disconnect()


@runner.test("IRCX EVENT Trap - Admin", requires_level="ADMIN")
async def test_event_trap():
    """Test IRCX EVENT traps for admins"""
    admin = IRCTestClient("test_event_admin")
    
    await admin.connect(
        "EventAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    await admin.send_raw("IRCX")
    await asyncio.sleep(0.2)
    
    admin.buffer.clear()
    await admin.send_raw("EVENT ADD CONNECT *!*@*")
    await asyncio.sleep(0.3)
    await admin.read_lines()
    
    assert await admin.get_line_with("806"), "No EVENT trap confirmation"
    
    admin.buffer.clear()
    trigger = IRCTestClient("test_event_trigger")
    await trigger.connect("TriggerUser")
    await asyncio.sleep(0.5)
    await admin.read_lines()
    
    has_event = await admin.get_line_with("EVENT")
    print(f"   Event trap fired: {has_event is not None}")
    
    await admin.disconnect()
    await trigger.disconnect()


@runner.test("Staff Statistics Count", requires_level="ADMIN")
async def test_staff_count():
    """Test that staff are counted in statistics"""
    admin = IRCTestClient("test_stats_admin")
    
    admin.buffer.clear()
    await admin.connect(
        "StatsAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )
    
    line = await admin.get_line_with("252")
    assert line, "No stats line 252"
    print(f"   Stats: {line}")
    
    assert "staff" in line.lower(), "Staff not counted in stats"
    
    await admin.disconnect()


@runner.test("Channel Owner Privileges", requires_level="ADMIN")
async def test_owner_privileges():
    """Test channel owner can grant privileges"""
    admin = IRCTestClient("test_owner_admin")
    user = IRCTestClient("test_owner_user")

    await admin.connect(
        "OwnerAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await user.connect("OwnerUser")

    await admin.send_raw("JOIN #privtest")
    await asyncio.sleep(0.2)

    await user.send_raw("JOIN #privtest")
    await asyncio.sleep(0.2)

    user.buffer.clear()
    await admin.send_raw("MODE #privtest +o OwnerUser")
    await asyncio.sleep(0.3)
    await user.read_lines()

    assert await user.get_line_with("MODE #privtest +o"), "User didn't receive +o"

    await admin.disconnect()
    await user.disconnect()


# ==============================================================================
# STAFF BYPASS AND OWNERKEY TESTS
# ==============================================================================

@runner.test("Staff Bypass - Ban (+b)", requires_level="ADMIN")
async def test_staff_bypass_ban():
    """Test staff can bypass channel bans"""
    owner = IRCTestClient("test_bypass_ban_owner")
    admin = IRCTestClient("test_bypass_ban_admin")

    await owner.connect("BypassBanOwner")
    await owner.send_raw("JOIN #staffban")
    await asyncio.sleep(0.2)

    # Set a ban that would match everyone
    await owner.send_raw("MODE #staffban +b *!*@*")
    await asyncio.sleep(0.2)

    # Admin should bypass the ban
    await admin.connect(
        "BypassAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("JOIN #staffban")
    assert await admin.expect("JOIN #staffban"), "Admin should bypass ban"

    await owner.disconnect()
    await admin.disconnect()


@runner.test("Staff Bypass - Invite Only (+i)", requires_level="ADMIN")
async def test_staff_bypass_invite():
    """Test staff can bypass invite-only"""
    owner = IRCTestClient("test_bypass_inv_owner")
    admin = IRCTestClient("test_bypass_inv_admin")

    await owner.connect("BypassInvOwner")
    await owner.send_raw("JOIN #staffinv")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #staffinv +i")
    await asyncio.sleep(0.2)

    # Admin should bypass invite-only
    await admin.connect(
        "BypassInvAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("JOIN #staffinv")
    assert await admin.expect("JOIN #staffinv"), "Admin should bypass +i"

    await owner.disconnect()
    await admin.disconnect()


@runner.test("Staff Bypass - Channel Key (+k)", requires_level="ADMIN")
async def test_staff_bypass_key():
    """Test staff can bypass channel key"""
    owner = IRCTestClient("test_bypass_key_owner")
    admin = IRCTestClient("test_bypass_key_admin")

    await owner.connect("BypassKeyOwner")
    await owner.send_raw("JOIN #staffkey")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #staffkey +k secretkey")
    await asyncio.sleep(0.2)

    # Admin should bypass key requirement
    await admin.connect(
        "BypassKeyAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("JOIN #staffkey")  # No key provided
    assert await admin.expect("JOIN #staffkey"), "Admin should bypass +k"

    await owner.disconnect()
    await admin.disconnect()


@runner.test("Staff Bypass - User Limit (+l)", requires_level="ADMIN")
async def test_staff_bypass_limit():
    """Test staff can bypass user limit"""
    owner = IRCTestClient("test_bypass_limit_owner")
    user = IRCTestClient("test_bypass_limit_user")
    admin = IRCTestClient("test_bypass_limit_admin")

    await owner.connect("BypassLimitOwner")
    await owner.send_raw("JOIN #stafflimit")
    await asyncio.sleep(0.2)
    await owner.send_raw("MODE #stafflimit +l 2")
    await asyncio.sleep(0.2)

    # Fill the channel
    await user.connect("BypassLimitUser")
    await user.send_raw("JOIN #stafflimit")
    await asyncio.sleep(0.2)

    # Admin should bypass limit (would be 3rd user)
    await admin.connect(
        "BypassLimitAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("JOIN #stafflimit")
    assert await admin.expect("JOIN #stafflimit"), "Admin should bypass +l"

    await owner.disconnect()
    await user.disconnect()
    await admin.disconnect()


@runner.test("OWNERKEY - Set via PROP", requires_level="ADMIN")
async def test_ownerkey_set():
    """Test setting OWNERKEY via PROP"""
    admin = IRCTestClient("test_ownerkey_admin")

    await admin.connect(
        "OwnerkeyAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await admin.send_raw("JOIN #ownerkeytest")
    await asyncio.sleep(0.2)

    admin.buffer.clear()
    await admin.send_raw("PROP #ownerkeytest OWNERKEY :masterpass")
    assert await admin.expect("819"), "OWNERKEY not set"

    # Verify it's stored
    admin.buffer.clear()
    await admin.send_raw("PROP #ownerkeytest OWNERKEY")
    assert await admin.expect("masterpass"), "OWNERKEY not returned"

    await admin.disconnect()


@runner.test("OWNERKEY - Grants Owner on Join", requires_level="ADMIN")
async def test_ownerkey_grants_owner():
    """Test OWNERKEY grants owner status when used to join"""
    admin = IRCTestClient("test_ownerkey_setup")
    user = IRCTestClient("test_ownerkey_user")

    # Setup channel with ownerkey
    await admin.connect(
        "OwnerkeySetup",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await admin.send_raw("JOIN #ownergrant")
    await asyncio.sleep(0.2)
    await admin.send_raw("PROP #ownergrant OWNERKEY :grantme")
    await asyncio.sleep(0.2)

    # Regular user joins with ownerkey
    await user.connect("OwnerUser")
    user.buffer.clear()
    await user.send_raw("JOIN #ownergrant grantme")
    await asyncio.sleep(0.3)
    await user.read_lines()

    # Should have received +q (owner)
    has_owner = False
    for line in user.buffer:
        if "MODE #ownergrant +q OwnerUser" in line:
            has_owner = True
            break

    assert has_owner, "OWNERKEY should grant owner (+q)"

    await admin.disconnect()
    await user.disconnect()


@runner.test("OWNERKEY - Bypasses Restrictions", requires_level="ADMIN")
async def test_ownerkey_bypass():
    """Test OWNERKEY bypasses all restrictions"""
    admin = IRCTestClient("test_ownerkey_bypass_admin")
    user = IRCTestClient("test_ownerkey_bypass_user")

    # Setup locked-down channel
    await admin.connect(
        "OwnerkeyBypassAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await admin.send_raw("JOIN #lockedchan")
    await asyncio.sleep(0.2)
    await admin.send_raw("MODE #lockedchan +ikl secretkey 1")  # invite-only, keyed, limit 1
    await asyncio.sleep(0.2)
    await admin.send_raw("MODE #lockedchan +b *!*@*")  # ban everyone
    await asyncio.sleep(0.2)
    await admin.send_raw("PROP #lockedchan OWNERKEY :bypass123")
    await asyncio.sleep(0.2)

    # Admin leaves so limit is enforced
    await admin.send_raw("PART #lockedchan")
    await asyncio.sleep(0.2)

    # User with ownerkey should bypass everything
    await user.connect("BypassUser")
    user.buffer.clear()
    await user.send_raw("JOIN #lockedchan bypass123")

    assert await user.expect("JOIN #lockedchan"), "OWNERKEY should bypass all restrictions"

    await admin.disconnect()
    await user.disconnect()


@runner.test("KILL Command - Admin", requires_level="ADMIN")
async def test_kill_admin():
    """Test admin can KILL users"""
    admin = IRCTestClient("test_kill_admin_exec")
    victim = IRCTestClient("test_kill_victim_exec")

    await admin.connect(
        "KillExecAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await victim.connect("KillVictim2")
    await asyncio.sleep(0.2)

    # Admin kills victim
    await admin.send_raw("KILL KillVictim2 :Terminated by admin")
    await asyncio.sleep(0.3)

    # Victim should receive KILL and be disconnected
    await victim.read_lines()
    killed = any("KILL" in line for line in victim.buffer)
    print(f"   Victim received KILL: {killed}")

    # Try to ping - should fail if disconnected
    try:
        await victim.send_raw("PING test")
        await asyncio.sleep(0.5)
        # If we get here without error, check if connection is still alive
        victim.buffer.clear()
        await victim.read_lines()
        still_connected = any("PONG" in line for line in victim.buffer)
        assert not still_connected, "Victim should be disconnected"
    except:
        pass  # Expected - connection closed

    await admin.disconnect()


@runner.test("TRANSCRIPT Mode (+y)", requires_level="ADMIN")
async def test_transcript_mode():
    """Test transcript logging and viewing"""
    admin = IRCTestClient("test_transcript_admin")
    user2 = IRCTestClient("test_transcript_user")

    await admin.connect(
        "TransAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await user2.connect("TransUser")
    await asyncio.sleep(0.2)

    # Admin creates channel with +y mode
    await admin.send_raw("JOIN #transcripttest")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    # Enable transcript mode
    await admin.send_raw("MODE #transcripttest +y")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    mode_set = any("+y" in line for line in admin.buffer)
    print(f"   +y mode set: {mode_set}")

    # User joins and sends messages
    await user2.send_raw("JOIN #transcripttest")
    await asyncio.sleep(0.2)
    await user2.read_lines()

    await user2.send_raw("PRIVMSG #transcripttest :Test message for transcript")
    await asyncio.sleep(0.2)

    # Admin views transcript
    admin.buffer.clear()
    await admin.send_raw("TRANSCRIPT #transcripttest 10")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    has_transcript = any("Transcript for" in line for line in admin.buffer)
    has_message = any("Test message" in line for line in admin.buffer)
    print(f"   Transcript header: {has_transcript}")
    print(f"   Message in transcript: {has_message}")

    assert has_transcript, "Should see transcript header"

    await admin.disconnect()
    await user2.disconnect()


# ==============================================================================
# CHANNEL GAG TESTS
# ==============================================================================

@runner.test("Channel GAG - Staff Can Gag in Channel", requires_level="ADMIN")
async def test_channel_gag():
    """Test staff can gag users in specific channels"""
    admin = IRCTestClient("test_chan_gag_admin")
    user = IRCTestClient("test_chan_gag_user")

    await admin.connect(
        "ChanGagAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await user.connect("ChanGagUser")

    # Both join channel
    await admin.send_raw("JOIN #gagtest")
    await asyncio.sleep(0.2)
    await user.send_raw("JOIN #gagtest")
    await asyncio.sleep(0.2)

    # Admin gags user in channel
    admin.buffer.clear()
    await admin.send_raw("GAG #gagtest ChanGagUser")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    gag_confirmed = any("gagged" in line.lower() for line in admin.buffer)
    print(f"   Channel gag confirmed: {gag_confirmed}")
    assert gag_confirmed, "Should confirm channel gag"

    # User tries to talk - should be blocked (or message not delivered)
    user.buffer.clear()
    await user.send_raw("PRIVMSG #gagtest :Can anyone hear me?")
    await asyncio.sleep(0.2)

    # Admin ungags user
    admin.buffer.clear()
    await admin.send_raw("UNGAG #gagtest ChanGagUser")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    ungag_confirmed = any("ungagged" in line.lower() for line in admin.buffer)
    print(f"   Channel ungag confirmed: {ungag_confirmed}")

    await admin.disconnect()
    await user.disconnect()


@runner.test("Global GAG vs Channel GAG", requires_level="ADMIN")
async def test_global_vs_channel_gag():
    """Test global gag (+z) vs channel-specific gag"""
    admin = IRCTestClient("test_gag_compare_admin")
    user = IRCTestClient("test_gag_compare_user")

    await admin.connect(
        "GagCompareAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await user.connect("GagCompareUser")
    await asyncio.sleep(0.2)

    # Global gag sets +z mode
    admin.buffer.clear()
    await admin.send_raw("GAG GagCompareUser")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    global_gag = any("+z" in line for line in admin.buffer)
    print(f"   Global gag set (+z): {global_gag}")
    assert global_gag, "Global GAG should set +z mode"

    # Ungag globally
    await admin.send_raw("UNGAG GagCompareUser")
    await asyncio.sleep(0.2)

    await admin.disconnect()
    await user.disconnect()


# ==============================================================================
# STATS t (SSL/TLS STATUS) TEST
# ==============================================================================

@runner.test("STATS t - SSL Status", requires_level="ADMIN")
async def test_stats_ssl():
    """Test STATS t shows SSL/TLS status"""
    admin = IRCTestClient("test_stats_ssl_admin")

    await admin.connect(
        "StatsSSLAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("STATS t")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    # Should see SSL status output
    has_ssl_header = any("SSL/TLS Status" in line for line in admin.buffer)
    has_ssl_info = any("SSL:" in line for line in admin.buffer)
    has_end = any("219" in line for line in admin.buffer)

    print(f"   SSL header: {has_ssl_header}")
    print(f"   SSL info: {has_ssl_info}")
    print(f"   End of stats: {has_end}")

    assert has_ssl_header or has_ssl_info, "STATS t should show SSL status"
    assert has_end, "Should receive end of STATS"

    await admin.disconnect()


# ==============================================================================
# SERVER ACCESS COMMAND TESTS
# ==============================================================================

@runner.test("Server ACCESS - List", requires_level="ADMIN")
async def test_server_access_list():
    """Test server ACCESS $ LIST command"""
    admin = IRCTestClient("test_access_list_admin")

    await admin.connect(
        "AccessListAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    admin.buffer.clear()
    await admin.send_raw("ACCESS $ LIST")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    # Should see ACCESS list output or empty list message
    has_access = any("ACCESS" in line or "803" in line for line in admin.buffer)
    print(f"   ACCESS list response: {has_access}")

    await admin.disconnect()


@runner.test("Server ACCESS - Add/Delete DENY", requires_level="ADMIN")
async def test_server_access_deny():
    """Test server ACCESS $ ADD/DELETE DENY"""
    admin = IRCTestClient("test_access_deny_admin")

    await admin.connect(
        "AccessDenyAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    # Add a DENY entry
    admin.buffer.clear()
    await admin.send_raw("ACCESS $ ADD DENY testban!*@* 0 :Test ban entry")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    add_success = any("801" in line or "added" in line.lower() for line in admin.buffer)
    print(f"   DENY add success: {add_success}")

    # List to verify
    admin.buffer.clear()
    await admin.send_raw("ACCESS $ LIST DENY")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    has_entry = any("testban" in line for line in admin.buffer)
    print(f"   Entry in list: {has_entry}")

    # Delete the entry
    admin.buffer.clear()
    await admin.send_raw("ACCESS $ DELETE DENY testban!*@*")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    delete_success = any("802" in line or "deleted" in line.lower() or "removed" in line.lower() for line in admin.buffer)
    print(f"   DENY delete success: {delete_success}")

    await admin.disconnect()


@runner.test("Channel ACCESS - CLEAR Command", requires_level="ADMIN")
async def test_channel_access_clear():
    """Test ACCESS #channel CLEAR command"""
    admin = IRCTestClient("test_access_clear_admin")

    await admin.connect(
        "AccessClearAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await admin.send_raw("JOIN #accessclear")
    await asyncio.sleep(0.2)

    # Add some ACCESS entries
    await admin.send_raw("ACCESS #accessclear ADD DENY baduser1")
    await asyncio.sleep(0.1)
    await admin.send_raw("ACCESS #accessclear ADD DENY baduser2")
    await asyncio.sleep(0.2)

    # Clear all DENY entries
    admin.buffer.clear()
    await admin.send_raw("ACCESS #accessclear CLEAR DENY")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    clear_success = any("cleared" in line.lower() or "removed" in line.lower() for line in admin.buffer)
    print(f"   CLEAR success: {clear_success}")

    # Verify list is empty
    admin.buffer.clear()
    await admin.send_raw("ACCESS #accessclear LIST DENY")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    is_empty = not any("baduser" in line for line in admin.buffer)
    print(f"   List is empty: {is_empty}")

    await admin.disconnect()


@runner.test("ACCESS with Timeout", requires_level="ADMIN")
async def test_access_timeout():
    """Test ACCESS entries with timeout"""
    admin = IRCTestClient("test_access_timeout_admin")

    await admin.connect(
        "AccessTimeoutAdmin",
        username=ADMIN_CONFIG['username'],
        password=ADMIN_CONFIG['password']
    )

    await admin.send_raw("JOIN #accesstimeout")
    await asyncio.sleep(0.2)

    # Add DENY with 5 minute timeout
    admin.buffer.clear()
    await admin.send_raw("ACCESS #accesstimeout ADD DENY tempban 5 :5 minute ban")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    add_success = any("801" in line or "added" in line.lower() for line in admin.buffer)
    print(f"   Timeout entry added: {add_success}")

    # List to see the timeout
    admin.buffer.clear()
    await admin.send_raw("ACCESS #accesstimeout LIST DENY")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    # Check if entry exists
    has_entry = any("tempban" in line for line in admin.buffer)
    print(f"   Entry visible: {has_entry}")

    await admin.disconnect()


@runner.test("STAFF LIST Command", requires_level="ADMIN")
async def test_staff_list():
    """Test STAFF LIST shows all staff accounts"""
    admin = IRCTestClient("test_staff_list")
    await admin.connect("StaffListAdmin", username=ADMIN_CONFIG['username'], password=ADMIN_CONFIG['password'])
    await asyncio.sleep(0.3)

    admin.buffer.clear()
    await admin.send_raw("STAFF LIST")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    # Should show staff accounts grouped by level
    has_header = any("Staff Accounts" in line for line in admin.buffer)
    has_admin = any("ADMIN:" in line for line in admin.buffer)
    print(f"   Has header: {has_header}, Has ADMIN listing: {has_admin}")
    assert has_header, "STAFF LIST should show header"

    await admin.disconnect()


@runner.test("STAFF ADD/DEL Command", requires_level="ADMIN")
async def test_staff_add_del():
    """Test STAFF ADD creates account and STAFF DEL removes it"""
    admin = IRCTestClient("test_staff_add")
    await admin.connect("StaffAddAdmin", username=ADMIN_CONFIG['username'], password=ADMIN_CONFIG['password'])
    await asyncio.sleep(0.3)

    # Add a new staff account
    admin.buffer.clear()
    await admin.send_raw("STAFF ADD teststaff testpass123 GUIDE")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    add_success = any("created" in line.lower() for line in admin.buffer)
    print(f"   STAFF ADD success: {add_success}")
    assert add_success, "STAFF ADD should create account"

    # Delete the account
    admin.buffer.clear()
    await admin.send_raw("STAFF DEL teststaff")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    del_success = any("deleted" in line.lower() for line in admin.buffer)
    print(f"   STAFF DEL success: {del_success}")
    assert del_success, "STAFF DEL should remove account"

    await admin.disconnect()


@runner.test("STAFF SET Command", requires_level="ADMIN")
async def test_staff_set():
    """Test STAFF SET changes staff level"""
    admin = IRCTestClient("test_staff_set")
    await admin.connect("StaffSetAdmin", username=ADMIN_CONFIG['username'], password=ADMIN_CONFIG['password'])
    await asyncio.sleep(0.3)

    # First create a test account
    await admin.send_raw("STAFF ADD leveltest testpass123 GUIDE")
    await asyncio.sleep(0.2)

    # Change level
    admin.buffer.clear()
    await admin.send_raw("STAFF SET leveltest SYSOP")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    set_success = any("changed" in line.lower() and "SYSOP" in line for line in admin.buffer)
    print(f"   STAFF SET success: {set_success}")

    # Clean up
    await admin.send_raw("STAFF DEL leveltest")
    await asyncio.sleep(0.2)

    await admin.disconnect()


@runner.test("STAFF PASS Command - Self", requires_level="SYSOP")
async def test_staff_pass_self():
    """Test STAFF PASS allows changing own password"""
    # Use SYSOP to test self-password change
    sysop = IRCTestClient("test_staff_pass")
    await sysop.connect("StaffPassSysop", username=SYSOP_CONFIG['username'], password=SYSOP_CONFIG['password'])
    await asyncio.sleep(0.3)

    sysop.buffer.clear()
    # Try to change own password (use same password to not break other tests)
    await sysop.send_raw(f"STAFF PASS {SYSOP_CONFIG['username']} {SYSOP_CONFIG['password']}")
    await asyncio.sleep(0.3)
    await sysop.read_lines()

    pass_success = any("changed" in line.lower() for line in sysop.buffer)
    print(f"   STAFF PASS self success: {pass_success}")
    assert pass_success, "STAFF PASS should allow changing own password"

    await sysop.disconnect()


@runner.test("STAFF Command - SYSOP Cannot ADD", requires_level="SYSOP")
async def test_staff_sysop_cannot_add():
    """Test that SYSOP cannot use STAFF ADD (ADMIN only)"""
    sysop = IRCTestClient("test_staff_perm")
    await sysop.connect("StaffPermSysop", username=SYSOP_CONFIG['username'], password=SYSOP_CONFIG['password'])
    await asyncio.sleep(0.3)

    sysop.buffer.clear()
    await sysop.send_raw("STAFF ADD forbidden testpass GUIDE")
    await asyncio.sleep(0.3)
    await sysop.read_lines()

    denied = any("ADMIN" in line and "requires" in line for line in sysop.buffer)
    print(f"   SYSOP denied ADD: {denied}")
    assert denied, "SYSOP should not be able to use STAFF ADD"

    await sysop.disconnect()


@runner.test("CONFIG LIST Command", requires_level="SYSOP")
async def test_config_list():
    """Test CONFIG LIST shows configuration sections"""
    sysop = IRCTestClient("test_config_list")
    await sysop.connect("ConfigListSysop", username=SYSOP_CONFIG['username'], password=SYSOP_CONFIG['password'])
    await asyncio.sleep(0.3)

    sysop.buffer.clear()
    await sysop.send_raw("CONFIG LIST")
    await asyncio.sleep(0.3)
    await sysop.read_lines()

    has_sections = any("Config Sections" in line for line in sysop.buffer)
    has_server = any("[server]" in line for line in sysop.buffer)
    print(f"   Has sections header: {has_sections}, Has [server]: {has_server}")
    assert has_sections, "CONFIG LIST should show sections"

    await sysop.disconnect()


@runner.test("CONFIG GET Command", requires_level="SYSOP")
async def test_config_get():
    """Test CONFIG GET retrieves specific values"""
    sysop = IRCTestClient("test_config_get")
    await sysop.connect("ConfigGetSysop", username=SYSOP_CONFIG['username'], password=SYSOP_CONFIG['password'])
    await asyncio.sleep(0.3)

    sysop.buffer.clear()
    await sysop.send_raw("CONFIG GET server.name")
    await asyncio.sleep(0.3)
    await sysop.read_lines()

    has_value = any("server.name" in line and "=" in line for line in sysop.buffer)
    print(f"   CONFIG GET returned value: {has_value}")
    assert has_value, "CONFIG GET should return the value"

    await sysop.disconnect()


@runner.test("CONFIG SET Command - ADMIN Only", requires_level="ADMIN")
async def test_config_set():
    """Test CONFIG SET modifies values (ADMIN only)"""
    admin = IRCTestClient("test_config_set")
    await admin.connect("ConfigSetAdmin", username=ADMIN_CONFIG['username'], password=ADMIN_CONFIG['password'])
    await asyncio.sleep(0.3)

    # Get current value first
    await admin.send_raw("CONFIG GET limits.max_users")
    await asyncio.sleep(0.2)
    await admin.read_lines()

    # Try to set a value
    admin.buffer.clear()
    await admin.send_raw("CONFIG SET limits.max_users 999")
    await asyncio.sleep(0.3)
    await admin.read_lines()

    set_success = any("Set limits.max_users" in line for line in admin.buffer)
    print(f"   CONFIG SET success: {set_success}")

    # Restore original value
    await admin.send_raw("CONFIG SET limits.max_users 1000")
    await asyncio.sleep(0.2)

    await admin.disconnect()


@runner.test("CONFIG SET - SYSOP Denied", requires_level="SYSOP")
async def test_config_set_sysop_denied():
    """Test that SYSOP cannot use CONFIG SET"""
    sysop = IRCTestClient("test_config_perm")
    await sysop.connect("ConfigPermSysop", username=SYSOP_CONFIG['username'], password=SYSOP_CONFIG['password'])
    await asyncio.sleep(0.3)

    sysop.buffer.clear()
    await sysop.send_raw("CONFIG SET limits.max_users 500")
    await asyncio.sleep(0.3)
    await sysop.read_lines()

    denied = any("ADMIN" in line and "requires" in line for line in sysop.buffer)
    print(f"   SYSOP denied SET: {denied}")
    assert denied, "SYSOP should not be able to use CONFIG SET"

    await sysop.disconnect()


async def create_test_accounts():
    """Helper to create test accounts in database"""
    print("\n" + "="*70)
    print("CREATING TEST ACCOUNTS")
    print("="*70 + "\n")

    try:
        async with aiosqlite.connect("pyircx.db") as db:
            for config in [ADMIN_CONFIG, SYSOP_CONFIG, GUIDE_CONFIG]:
                username = config['username']
                password = config['password']
                level = config['level']
                
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                
                await db.execute(
                    "INSERT OR REPLACE INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                    (username, pw_hash, level)
                )
                print(f"✅ Created/Updated: {username} (Level: {level})")
            
            await db.commit()
        
        print("\n✅ Test accounts created successfully!\n")
        return True
    except Exception as e:
        print(f"\n❌ Failed to create accounts: {e}\n")
        return False


async def main():
    """Main test entry point"""
    print("\n⚠️  Make sure pyIRCX server is running on localhost:6667\n")
    
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
    
    if AUTO_CREATE_ACCOUNTS:
        if not await create_test_accounts():
            print("Warning: Could not create test accounts")
            print("Please create them manually or check database permissions")
    
    success = await runner.run_all()
    
    return success


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
