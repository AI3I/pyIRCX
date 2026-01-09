#!/usr/bin/env python3
"""
pyIRCX Server Linking Test Suite
Tests server-to-server linking functionality

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
import sys
import json
import tempfile
import os
import signal

class IRCTestClient:
    """Simple IRC test client"""
    def __init__(self, host="127.0.0.1", port=6667):
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.buffer = []

    async def connect(self, nickname, username=None):
        """Connect to IRC server"""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.send_raw(f"NICK {nickname}")
        await self.send_raw(f"USER {username or nickname} 0 * :{nickname}")
        await asyncio.sleep(0.5)
        await self.read_lines()
        self.buffer.clear()

    async def send_raw(self, message):
        """Send raw IRC command"""
        self.writer.write((message + "\r\n").encode())
        await self.writer.drain()

    async def read_lines(self, timeout=1.0):
        """Read available lines"""
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=0.1)
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                self.buffer.append(decoded)
                print(f"   <<< {decoded}")
        except asyncio.TimeoutError:
            pass

    async def disconnect(self):
        """Disconnect from server"""
        if self.writer:
            try:
                await self.send_raw("QUIT :Test done")
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass


class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def test(self, name):
        def decorator(func):
            self.tests.append((name, func))
            return func
        return decorator

    async def run_all(self):
        for name, func in self.tests:
            print(f"\n{'='*70}")
            print(f"TEST: {name}")
            print('='*70)
            try:
                await func()
                print(f"✅ PASSED: {name}")
                self.passed += 1
            except AssertionError as e:
                print(f"❌ FAILED: {name}")
                print(f"   Reason: {e}")
                self.failed += 1
            except Exception as e:
                print(f"❌ ERROR: {name}")
                print(f"   Exception: {e}")
                import traceback
                traceback.print_exc()
                self.failed += 1

        print(f"\n{'='*70}")
        print(f"RESULTS: {self.passed} passed, {self.failed} failed")
        print('='*70)
        return self.failed == 0


runner = TestRunner()


@runner.test("LINKS Command - Single Server")
async def test_links_single():
    """Test LINKS command on single server"""
    client = IRCTestClient("127.0.0.1", 6667)
    await client.connect("LinksTest")
    
    await client.send_raw("LINKS")
    await asyncio.sleep(0.3)
    await client.read_lines()
    
    has_364 = any(" 364 " in line for line in client.buffer)
    has_365 = any(" 365 " in line for line in client.buffer)
    
    assert has_364, "Should return 364 (RPL_LINKS)"
    assert has_365, "Should return 365 (RPL_ENDOFLINKS)"
    
    await client.disconnect()


@runner.test("CONNECT Command - Permission Check")
async def test_connect_permission():
    """Test CONNECT requires admin/sysop privileges"""
    client = IRCTestClient("127.0.0.1", 6667)
    await client.connect("PermTest")
    
    await client.send_raw("CONNECT test.server")
    await asyncio.sleep(0.3)
    await client.read_lines()
    
    # Should get permission denied (481) since we're not admin
    has_481 = any(" 481 " in line for line in client.buffer)
    
    assert has_481, "Should return 481 (permission denied) for non-admin"
    
    await client.disconnect()


@runner.test("Linking Module Load")
async def test_linking_module():
    """Test that linking module loads without errors"""
    try:
        import linking
        assert hasattr(linking, 'ServerLinkManager'), "Should have ServerLinkManager class"
        assert hasattr(linking, 'LinkedServer'), "Should have LinkedServer class"
        print("   ✓ linking module loaded successfully")
        print("   ✓ ServerLinkManager class exists")
        print("   ✓ LinkedServer class exists")
    except ImportError as e:
        raise AssertionError(f"Failed to import linking module: {e}")


@runner.test("Config Schema - Linking Section")
async def test_config_schema():
    """Test that config has linking section"""
    with open('pyircx_config.json', 'r') as f:
        config = json.load(f)
    
    assert 'linking' in config, "Config should have 'linking' section"
    assert 'enabled' in config['linking'], "Should have 'enabled' field"
    assert 'bind_host' in config['linking'], "Should have 'bind_host' field"
    assert 'bind_port' in config['linking'], "Should have 'bind_port' field"
    assert 'links' in config['linking'], "Should have 'links' array"
    
    print(f"   ✓ Config has linking section")
    print(f"   ✓ enabled: {config['linking']['enabled']}")
    print(f"   ✓ bind_port: {config['linking']['bind_port']}")


async def main():
    """Main test entry point"""
    print("\n⚠️  Running Server Linking Tests")
    print("This will test the linking module and commands\n")
    
    # Test server connection
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 6667),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        print("✅ Server is reachable on 127.0.0.1:6667\n")
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
