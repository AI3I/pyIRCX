#!/usr/bin/env python3
"""
pyIRCX v2.0.0 Stress Test & Load Testing
Simulates realistic IRC usage with hundreds of concurrent clients

Scenarios:
- Regular users: Join/part channels, chat, change nicks
- Staff users: Mode changes, kicks, kills, stats
- Service users: Register nicks, send offline messages
- Network load: Cross-server operations
"""

import asyncio
import random
import time
import sys
import argparse
from dataclasses import dataclass
from typing import List, Dict
import socket

# Configuration
@dataclass
class StressConfig:
    """Stress test configuration"""
    num_users: int = 100          # Total concurrent users
    num_staff: int = 5             # Staff members
    num_channels: int = 20         # Channels to use
    duration: int = 300            # Test duration (seconds)
    message_rate: int = 10         # Messages per second (network-wide)
    join_rate: int = 5             # Joins/parts per second
    mode_rate: int = 2             # Mode changes per second
    servers: List[tuple] = None    # (host, port) tuples
    
    def __post_init__(self):
        if self.servers is None:
            self.servers = [
                ('127.0.0.1', 6667),  # Trunk
                ('127.0.0.1', 6668),  # Branch 1
                ('127.0.0.1', 6669),  # Branch 2
            ]

# Simple IRC client for stress testing
class StressClient:
    """Minimal IRC client for load testing"""
    def __init__(self, nickname, host='127.0.0.1', port=6667):
        self.nickname = nickname
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.connected = False
        self.channels = set()
        
    async def connect(self):
        """Connect to IRC server"""
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.writer.write(f"NICK {self.nickname}\r\n".encode())
            self.writer.write(f"USER {self.nickname} 0 * :{self.nickname}\r\n".encode())
            await self.writer.drain()
            
            # Read welcome
            await asyncio.sleep(0.5)
            try:
                await asyncio.wait_for(self.reader.read(4096), timeout=1.0)
            except:
                pass
            
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection error for {self.nickname}: {e}")
            return False
    
    async def send(self, command):
        """Send IRC command"""
        if not self.connected:
            return
        try:
            self.writer.write(f"{command}\r\n".encode())
            await self.writer.drain()
        except Exception as e:
            print(f"Send error for {self.nickname}: {e}")
            self.connected = False
    
    async def disconnect(self):
        """Disconnect from server"""
        if self.connected:
            try:
                await self.send("QUIT :Stress test complete")
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
            self.connected = False

# User behavior simulators
class RegularUser:
    """Simulates regular user behavior"""
    def __init__(self, client: StressClient, channels: List[str]):
        self.client = client
        self.available_channels = channels
        self.active = True
        
    async def run(self, duration: int):
        """Run user simulation"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.active:
            action = random.choice(['join', 'chat', 'part', 'nick', 'idle'])
            
            if action == 'join' and len(self.client.channels) < 5:
                # Join a random channel
                chan = random.choice(self.available_channels)
                await self.client.send(f"JOIN {chan}")
                self.client.channels.add(chan)
                await asyncio.sleep(random.uniform(1, 3))
                
            elif action == 'chat' and self.client.channels:
                # Send message to random joined channel
                chan = random.choice(list(self.client.channels))
                msg = random.choice([
                    "Hello everyone!",
                    "How's it going?",
                    "Anyone here?",
                    "What's up?",
                    "Nice server!",
                    "Testing pyIRCX",
                    "This is fun!",
                    "LOL",
                    "Anyone want to chat?",
                    "Great features!",
                ])
                await self.client.send(f"PRIVMSG {chan} :{msg}")
                await asyncio.sleep(random.uniform(2, 10))
                
            elif action == 'part' and self.client.channels:
                # Leave a random channel
                chan = random.choice(list(self.client.channels))
                await self.client.send(f"PART {chan}")
                self.client.channels.discard(chan)
                await asyncio.sleep(random.uniform(5, 15))
                
            elif action == 'nick':
                # Change nickname
                new_nick = f"{self.client.nickname}_{random.randint(1, 99)}"
                await self.client.send(f"NICK {new_nick}")
                self.client.nickname = new_nick
                await asyncio.sleep(random.uniform(30, 60))
                
            else:  # idle
                await asyncio.sleep(random.uniform(5, 20))

class StaffUser:
    """Simulates staff member behavior"""
    def __init__(self, client: StressClient, channels: List[str], is_admin=True):
        self.client = client
        self.available_channels = channels
        self.is_admin = is_admin
        self.active = True
        
    async def run(self, duration: int):
        """Run staff simulation"""
        # Authenticate as staff
        await self.client.send("PASS changeme")  # Default admin password
        await asyncio.sleep(1)
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.active:
            action = random.choice(['join', 'stats', 'mode', 'topic', 'idle'])
            
            if action == 'join' and len(self.client.channels) < 10:
                chan = random.choice(self.available_channels)
                await self.client.send(f"JOIN {chan}")
                self.client.channels.add(chan)
                await asyncio.sleep(2)
                
            elif action == 'stats':
                stat_type = random.choice(['u', 'c', 'a', 'o', 'g'])
                await self.client.send(f"STATS {stat_type}")
                await asyncio.sleep(random.uniform(30, 60))
                
            elif action == 'mode' and self.client.channels:
                chan = random.choice(list(self.client.channels))
                mode_change = random.choice(['+m', '-m', '+n', '-n', '+t', '-t'])
                await self.client.send(f"MODE {chan} {mode_change}")
                await asyncio.sleep(random.uniform(10, 30))
                
            elif action == 'topic' and self.client.channels:
                chan = random.choice(list(self.client.channels))
                topics = [
                    "Welcome to the channel!",
                    "Rules: Be respectful",
                    "pyIRCX v2.0.0 stress test",
                    "Testing in progress",
                    "General discussion",
                ]
                topic = random.choice(topics)
                await self.client.send(f"TOPIC {chan} :{topic}")
                await asyncio.sleep(random.uniform(60, 120))
                
            else:  # idle
                await asyncio.sleep(random.uniform(10, 30))

class ServiceUser:
    """Simulates user interacting with services"""
    def __init__(self, client: StressClient):
        self.client = client
        self.active = True
        self.registered = False
        
    async def run(self, duration: int):
        """Run service interaction simulation"""
        end_time = time.time() + duration
        
        # Register nickname
        if random.random() < 0.7:  # 70% register their nick
            await self.client.send(f"PRIVMSG Registrar :REGISTER testpass{random.randint(1000, 9999)}")
            self.registered = True
            await asyncio.sleep(2)
        
        while time.time() < end_time and self.active:
            action = random.choice(['offline_msg', 'check_help', 'idle'])
            
            if action == 'offline_msg':
                # Send offline message to someone
                target = f"User{random.randint(1, 100)}"
                msg = "Hey, are you there?"
                await self.client.send(f"PRIVMSG Messenger :SEND {target} {msg}")
                await asyncio.sleep(random.uniform(60, 180))
                
            elif action == 'check_help':
                service = random.choice(['Registrar', 'Messenger', 'NewsFlash'])
                await self.client.send(f"PRIVMSG {service} :HELP")
                await asyncio.sleep(random.uniform(120, 300))
                
            else:  # idle
                await asyncio.sleep(random.uniform(30, 90))

# Main stress test coordinator
class StressTest:
    """Coordinates stress test execution"""
    def __init__(self, config: StressConfig):
        self.config = config
        self.clients: List[StressClient] = []
        self.tasks: List[asyncio.Task] = []
        self.start_time = None
        self.stats = {
            'connected': 0,
            'failed': 0,
            'messages_sent': 0,
            'errors': 0,
        }
        
    def generate_channels(self) -> List[str]:
        """Generate channel names"""
        prefixes = ['test', 'stress', 'load', 'chat', 'general', 'random', 
                   'lobby', 'help', 'discuss', 'group']
        suffixes = ['room', 'chan', 'zone', 'lounge', 'spot', 'hub']
        
        channels = []
        for i in range(self.config.num_channels):
            if random.random() < 0.5:
                name = f"#{random.choice(prefixes)}{i+1}"
            else:
                name = f"#{random.choice(prefixes)}-{random.choice(suffixes)}"
            channels.append(name)
        
        return channels
    
    async def create_clients(self, channels: List[str]):
        """Create all client connections"""
        print(f"Creating {self.config.num_users} clients...")
        
        for i in range(self.config.num_users):
            # Distribute across servers
            server = self.config.servers[i % len(self.config.servers)]
            host, port = server
            
            nickname = f"User{i+1}"
            client = StressClient(nickname, host, port)
            
            # Connect
            if await client.connect():
                self.clients.append(client)
                self.stats['connected'] += 1
                
                # Decide user type
                if i < self.config.num_staff:
                    # Staff user
                    user = StaffUser(client, channels, is_admin=(i == 0))
                    task = asyncio.create_task(user.run(self.config.duration))
                elif i < self.config.num_staff + 10:
                    # Service user
                    user = ServiceUser(client)
                    task = asyncio.create_task(user.run(self.config.duration))
                else:
                    # Regular user
                    user = RegularUser(client, channels)
                    task = asyncio.create_task(user.run(self.config.duration))
                
                self.tasks.append(task)
            else:
                self.stats['failed'] += 1
            
            # Stagger connections
            if (i + 1) % 10 == 0:
                await asyncio.sleep(0.5)
                print(f"  Connected: {i+1}/{self.config.num_users}")
        
        print(f"✓ {self.stats['connected']} clients connected, {self.stats['failed']} failed\n")
    
    async def monitor(self):
        """Monitor test progress"""
        print("Stress test running...")
        print(f"Duration: {self.config.duration}s")
        print(f"Servers: {len(self.config.servers)}")
        print(f"Channels: {self.config.num_channels}")
        print()
        
        while True:
            await asyncio.sleep(30)
            
            elapsed = time.time() - self.start_time
            remaining = self.config.duration - elapsed
            
            if remaining <= 0:
                break
            
            # Count active clients
            active = sum(1 for c in self.clients if c.connected)
            
            print(f"[{int(elapsed)}s] Active clients: {active}/{self.stats['connected']} | "
                  f"Remaining: {int(remaining)}s")
    
    async def cleanup(self):
        """Disconnect all clients"""
        print("\nCleaning up...")
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Disconnect clients
        for client in self.clients:
            await client.disconnect()
        
        print("✓ Cleanup complete")
    
    async def run(self):
        """Run stress test"""
        print("=" * 80)
        print("pyIRCX v2.0.0 Stress Test".center(80))
        print("=" * 80)
        print()
        
        channels = self.generate_channels()
        print(f"Generated {len(channels)} channels: {', '.join(channels[:5])}...\n")
        
        self.start_time = time.time()
        
        try:
            # Create and connect clients
            await self.create_clients(channels)
            
            # Monitor test
            monitor_task = asyncio.create_task(self.monitor())
            
            # Wait for duration
            await asyncio.sleep(self.config.duration)
            
            # Cancel monitor
            monitor_task.cancel()
            
        finally:
            await self.cleanup()
        
        # Print final stats
        print("\n" + "=" * 80)
        print("Stress Test Complete".center(80))
        print("=" * 80)
        print(f"Duration:         {self.config.duration}s")
        print(f"Clients created:  {self.config.num_users}")
        print(f"Clients connected: {self.stats['connected']}")
        print(f"Connection failures: {self.stats['failed']}")
        print(f"Success rate:     {(self.stats['connected']/self.config.num_users*100):.1f}%")
        print()
        
        if self.stats['failed'] == 0:
            print("✓ All clients connected successfully!")
        else:
            print(f"⚠ {self.stats['failed']} clients failed to connect")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='pyIRCX Stress Test')
    parser.add_argument('--users', type=int, default=100, help='Number of concurrent users (default: 100)')
    parser.add_argument('--staff', type=int, default=5, help='Number of staff users (default: 5)')
    parser.add_argument('--channels', type=int, default=20, help='Number of channels (default: 20)')
    parser.add_argument('--duration', type=int, default=300, help='Test duration in seconds (default: 300)')
    parser.add_argument('--quick', action='store_true', help='Quick test (50 users, 60s)')
    parser.add_argument('--heavy', action='store_true', help='Heavy test (500 users, 600s)')
    
    args = parser.parse_args()
    
    # Configure based on preset or args
    if args.quick:
        config = StressConfig(num_users=50, duration=60, num_channels=10)
    elif args.heavy:
        config = StressConfig(num_users=500, duration=600, num_channels=50)
    else:
        config = StressConfig(
            num_users=args.users,
            num_staff=args.staff,
            num_channels=args.channels,
            duration=args.duration,
        )
    
    # Run stress test
    stress = StressTest(config)
    try:
        asyncio.run(stress.run())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
