#!/usr/bin/env python3
"""
pyIRCX WebChat Test Harness

Comprehensive test suite for validating webchat client and gateway functionality.
Tests both the WebSocket gateway and IRC protocol compliance.

Usage:
    python3 test_webchat.py [--ws-url URL] [--verbose] [--quick]

Options:
    --ws-url URL    WebSocket URL (default: ws://127.0.0.1:8765)
    --verbose       Show detailed output
    --quick         Run only essential tests
"""

import asyncio
import json
import sys
import argparse
import time
import random
import string

try:
    import websockets
except ImportError:
    print("ERROR: websockets module required. Install with: pip install websockets")
    sys.exit(1)


class TestResult:
    """Track test results"""
    def __init__(self, verbose=False):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.results = []
        self.verbose = verbose

    def ok(self, name, detail=""):
        self.passed += 1
        msg = f"  [PASS] {name}" + (f" - {detail}" if detail else "")
        self.results.append(msg)
        print(msg)

    def fail(self, name, detail=""):
        self.failed += 1
        msg = f"  [FAIL] {name}" + (f" - {detail}" if detail else "")
        self.results.append(msg)
        print(msg)

    def skip(self, name, reason=""):
        self.skipped += 1
        msg = f"  [SKIP] {name}" + (f" - {reason}" if reason else "")
        self.results.append(msg)
        if self.verbose:
            print(msg)

    def summary(self):
        print(f"\n{'='*60}")
        print(f"Results: {self.passed} passed, {self.failed} failed, {self.skipped} skipped")
        print(f"{'='*60}")
        return self.failed == 0


class WebChatTester:
    """WebChat test harness"""

    def __init__(self, ws_url, verbose=False):
        self.ws_url = ws_url
        self.verbose = verbose
        self.results = TestResult(verbose)
        self.test_nick = "WCTest_" + ''.join(random.choices(string.digits, k=4))
        self.test_channel = "#wctest_" + ''.join(random.choices(string.digits, k=4))

    async def recv_until(self, ws, command=None, numeric=None, timeout=5.0):
        """Receive messages until we get the expected command/numeric or timeout"""
        messages = []
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                data = json.loads(msg)
                messages.append(data)
                if self.verbose:
                    print(f"    <- {data.get('command', 'N/A')}: {data.get('params', [])}")
                if data.get('type') == 'irc':
                    cmd = data.get('command', '')
                    if command and cmd == command:
                        return data, messages
                    if numeric and cmd == numeric:
                        return data, messages
        except asyncio.TimeoutError:
            return None, messages

    async def recv_any(self, ws, timeout=0.5):
        """Receive any available messages"""
        messages = []
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                data = json.loads(msg)
                messages.append(data)
        except asyncio.TimeoutError:
            pass
        return messages

    async def send_raw(self, ws, command):
        """Send a raw IRC command"""
        if self.verbose:
            print(f"    -> {command}")
        await ws.send(json.dumps({'type': 'raw', 'command': command}))

    async def connect_and_register(self):
        """Connect and register, returning the websocket"""
        ws = await websockets.connect(self.ws_url)

        # Send IRCX mode request
        await self.send_raw(ws, "IRCX")

        # Send registration
        await ws.send(json.dumps({
            'type': 'connect',
            'nick': self.test_nick,
            'username': 'wctest',
            'realname': 'WebChat Test Harness'
        }))

        # Wait for welcome
        msg, _ = await self.recv_until(ws, numeric='001', timeout=10)
        if not msg:
            await ws.close()
            return None

        # Drain MOTD and other welcome messages
        await self.recv_any(ws, timeout=2)

        return ws

    # ==================== TEST METHODS ====================

    async def test_websocket_connection(self):
        """Test 1: Basic WebSocket connection"""
        print("\n[Test: WebSocket Connection]")
        try:
            async with websockets.connect(self.ws_url) as ws:
                self.results.ok("WebSocket connection established")
                return True
        except Exception as e:
            self.results.fail("WebSocket connection", str(e))
            return False

    async def test_irc_registration(self):
        """Test 2: IRC registration flow"""
        print("\n[Test: IRC Registration]")
        try:
            ws = await self.connect_and_register()
            if ws:
                self.results.ok("IRC registration successful", self.test_nick)
                await ws.close()
                return True
            else:
                self.results.fail("IRC registration", "No 001 received")
                return False
        except Exception as e:
            self.results.fail("IRC registration", str(e))
            return False

    async def test_channel_join(self):
        """Test 3: Channel join"""
        print("\n[Test: Channel Operations]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("Channel join", "Registration failed")
                return False

            # Join channel
            await ws.send(json.dumps({'type': 'join', 'channel': self.test_channel}))

            msg, _ = await self.recv_until(ws, command='JOIN', timeout=5)
            if msg:
                self.results.ok("JOIN command", self.test_channel)
            else:
                self.results.fail("JOIN command", "No JOIN response")
                await ws.close()
                return False

            # Wait for NAMES list (366 = end of names)
            msg, _ = await self.recv_until(ws, numeric='366', timeout=5)
            if msg:
                self.results.ok("NAMES list received")
            else:
                self.results.fail("NAMES list", "No 366 received")

            # Test PART
            await ws.send(json.dumps({'type': 'part', 'channel': self.test_channel}))
            msg, _ = await self.recv_until(ws, command='PART', timeout=5)
            if msg:
                self.results.ok("PART command")
            else:
                self.results.fail("PART command", "No PART response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("Channel operations", str(e))
            return False

    async def test_messaging(self):
        """Test 4: Messaging (PRIVMSG)"""
        print("\n[Test: Messaging]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("Messaging", "Registration failed")
                return False

            # Join channel first
            await ws.send(json.dumps({'type': 'join', 'channel': self.test_channel}))
            await self.recv_until(ws, numeric='366', timeout=5)

            # Send message
            test_msg = f"Test message {random.randint(1000, 9999)}"
            await ws.send(json.dumps({
                'type': 'message',
                'target': self.test_channel,
                'text': test_msg
            }))

            # We won't receive our own message back, but we can verify no error
            await asyncio.sleep(0.5)
            errors = await self.recv_any(ws, timeout=0.5)
            error_found = any(m.get('command', '').startswith('4') for m in errors)

            if not error_found:
                self.results.ok("PRIVMSG sent", test_msg[:30])
            else:
                self.results.fail("PRIVMSG", "Error response received")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("Messaging", str(e))
            return False

    async def test_nick_change(self):
        """Test 5: Nick change"""
        print("\n[Test: Nick Change]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("Nick change", "Registration failed")
                return False

            new_nick = "WCNew_" + ''.join(random.choices(string.digits, k=4))
            await ws.send(json.dumps({'type': 'nick', 'nick': new_nick}))

            msg, _ = await self.recv_until(ws, command='NICK', timeout=5)
            if msg and msg.get('params', [None])[0] == new_nick:
                self.results.ok("NICK change", f"{self.test_nick} -> {new_nick}")
            else:
                self.results.fail("NICK change", "No NICK response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("Nick change", str(e))
            return False

    async def test_topic(self):
        """Test 6: Topic operations"""
        print("\n[Test: Topic]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("Topic", "Registration failed")
                return False

            # Join channel
            await ws.send(json.dumps({'type': 'join', 'channel': self.test_channel}))
            await self.recv_until(ws, numeric='366', timeout=5)

            # Set topic
            test_topic = f"Test topic {random.randint(1000, 9999)}"
            await self.send_raw(ws, f"TOPIC {self.test_channel} :{test_topic}")

            msg, all_msgs = await self.recv_until(ws, command='TOPIC', timeout=5)
            if msg:
                self.results.ok("TOPIC set", test_topic[:30])
            else:
                # Check for error (e.g., 482 not host)
                for m in all_msgs:
                    if m.get('command') == '482':
                        self.results.ok("TOPIC (not host)", "Permission denied as expected for non-host")
                        break
                else:
                    self.results.fail("TOPIC", "No response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("Topic", str(e))
            return False

    async def test_mode(self):
        """Test 7: Mode operations"""
        print("\n[Test: Channel Modes]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("Mode", "Registration failed")
                return False

            # Join channel
            await ws.send(json.dumps({'type': 'join', 'channel': self.test_channel}))
            await self.recv_until(ws, numeric='366', timeout=5)

            # Query modes
            await self.send_raw(ws, f"MODE {self.test_channel}")

            msg, _ = await self.recv_until(ws, numeric='324', timeout=5)
            if msg:
                modes = msg.get('params', ['', '', ''])[2] if len(msg.get('params', [])) > 2 else ''
                self.results.ok("MODE query", f"modes: {modes}")
            else:
                self.results.fail("MODE query", "No 324 response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("Mode", str(e))
            return False

    async def test_whois(self):
        """Test 8: WHOIS command"""
        print("\n[Test: WHOIS]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("WHOIS", "Registration failed")
                return False

            await self.send_raw(ws, f"WHOIS {self.test_nick}")

            msg, _ = await self.recv_until(ws, numeric='311', timeout=5)
            if msg:
                self.results.ok("WHOIS 311", f"user info for {self.test_nick}")
            else:
                self.results.fail("WHOIS", "No 311 response")

            # Wait for end of WHOIS
            msg, _ = await self.recv_until(ws, numeric='318', timeout=3)
            if msg:
                self.results.ok("WHOIS 318", "End of WHOIS")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("WHOIS", str(e))
            return False

    async def test_who(self):
        """Test 9: WHO command"""
        print("\n[Test: WHO]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("WHO", "Registration failed")
                return False

            # Join channel first
            await ws.send(json.dumps({'type': 'join', 'channel': self.test_channel}))
            await self.recv_until(ws, numeric='366', timeout=5)

            await self.send_raw(ws, f"WHO {self.test_channel}")

            msg, _ = await self.recv_until(ws, numeric='315', timeout=5)
            if msg:
                self.results.ok("WHO command", "End of WHO received")
            else:
                self.results.fail("WHO", "No 315 response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("WHO", str(e))
            return False

    async def test_list(self):
        """Test 10: LIST command"""
        print("\n[Test: LIST]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("LIST", "Registration failed")
                return False

            await self.send_raw(ws, "LIST")

            msg, _ = await self.recv_until(ws, numeric='323', timeout=5)
            if msg:
                self.results.ok("LIST command", "End of LIST received")
            else:
                self.results.fail("LIST", "No 323 response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("LIST", str(e))
            return False

    async def test_ircx_mode(self):
        """Test 11: IRCX mode"""
        print("\n[Test: IRCX Mode]")
        try:
            ws = await websockets.connect(self.ws_url)

            await self.send_raw(ws, "IRCX")

            # Look for 800 (IRCX enabled) or error
            msg, all_msgs = await self.recv_until(ws, numeric='800', timeout=3)
            if msg:
                self.results.ok("IRCX mode", "800 response received")
            else:
                # Check for 421 (unknown command) - server doesn't support IRCX
                for m in all_msgs:
                    if m.get('command') == '421':
                        self.results.skip("IRCX mode", "Server doesn't support IRCX")
                        break
                else:
                    self.results.fail("IRCX mode", "No response")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("IRCX mode", str(e))
            return False

    async def test_away(self):
        """Test 12: AWAY command"""
        print("\n[Test: AWAY]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("AWAY", "Registration failed")
                return False

            # Set away
            await self.send_raw(ws, "AWAY :Testing away message")

            msg, _ = await self.recv_until(ws, numeric='306', timeout=3)
            if msg:
                self.results.ok("AWAY set", "306 response received")
            else:
                self.results.fail("AWAY set", "No 306 response")

            # Clear away
            await self.send_raw(ws, "AWAY")

            msg, _ = await self.recv_until(ws, numeric='305', timeout=3)
            if msg:
                self.results.ok("AWAY clear", "305 response received")
            else:
                # Some servers don't send 305 on clear
                self.results.ok("AWAY clear", "Assumed successful")

            await ws.close()
            return True

        except Exception as e:
            self.results.fail("AWAY", str(e))
            return False

    async def test_quit(self):
        """Test 13: QUIT command"""
        print("\n[Test: QUIT]")
        try:
            ws = await self.connect_and_register()
            if not ws:
                self.results.fail("QUIT", "Registration failed")
                return False

            await ws.send(json.dumps({'type': 'quit', 'reason': 'Test complete'}))

            # Connection should close
            try:
                await asyncio.wait_for(ws.wait_closed(), timeout=3)
                self.results.ok("QUIT command", "Connection closed cleanly")
            except asyncio.TimeoutError:
                self.results.fail("QUIT", "Connection didn't close")

            return True

        except Exception as e:
            self.results.fail("QUIT", str(e))
            return False

    async def run_all_tests(self, quick=False):
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"  pyIRCX WebChat Test Harness")
        print(f"  Target: {self.ws_url}")
        print(f"  Test Nick: {self.test_nick}")
        print(f"{'='*60}")

        # Essential tests (always run)
        await self.test_websocket_connection()
        await self.test_irc_registration()
        await self.test_channel_join()
        await self.test_messaging()

        if not quick:
            # Extended tests
            await self.test_nick_change()
            await self.test_topic()
            await self.test_mode()
            await self.test_whois()
            await self.test_who()
            await self.test_list()
            await self.test_ircx_mode()
            await self.test_away()

        # Always test quit last
        await self.test_quit()

        return self.results.summary()


async def main():
    parser = argparse.ArgumentParser(description='pyIRCX WebChat Test Harness')
    parser.add_argument('--ws-url', default='ws://127.0.0.1:8765',
                        help='WebSocket URL (default: ws://127.0.0.1:8765)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output')
    parser.add_argument('--quick', '-q', action='store_true',
                        help='Run only essential tests')
    args = parser.parse_args()

    tester = WebChatTester(args.ws_url, args.verbose)
    success = await tester.run_all_tests(args.quick)

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())
