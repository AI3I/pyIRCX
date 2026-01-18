#!/usr/bin/env python3
"""
pyIRCX v2.0.0 Master Test Runner
Runs all test suites with comprehensive reporting
"""

import subprocess
import sys
import os
import time
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(80)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")

def print_section(text):
    """Print formatted section"""
    print(f"\n{Colors.OKBLUE}{Colors.BOLD}{text}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'-' * len(text)}{Colors.ENDC}")

def run_test_suite(name, script_path, description=""):
    """Run a test suite and return success status"""
    print_section(f"Running: {name}")
    if description:
        print(f"{Colors.OKCYAN}{description}{Colors.ENDC}\n")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            cwd='.',  # Run from project root
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per suite
        )
        
        elapsed = time.time() - start_time
        
        # Print output
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"{Colors.WARNING}{result.stderr}{Colors.ENDC}")
        
        # Check result
        if result.returncode == 0:
            print(f"{Colors.OKGREEN}✓ {name} completed successfully in {elapsed:.2f}s{Colors.ENDC}")
            return True, elapsed
        else:
            print(f"{Colors.FAIL}✗ {name} failed with exit code {result.returncode}{Colors.ENDC}")
            return False, elapsed
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}✗ {name} timed out after 5 minutes{Colors.ENDC}")
        return False, 300
    except FileNotFoundError:
        print(f"{Colors.WARNING}⚠ {name} not found at {script_path}{Colors.ENDC}")
        return None, 0
    except Exception as e:
        print(f"{Colors.FAIL}✗ {name} error: {e}{Colors.ENDC}")
        return False, 0

def main():
    """Main test runner"""
    print_header("pyIRCX v2.0.0 Test Suite")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Working Directory: {os.getcwd()}\n")
    
    # Define test suites
    test_suites = [
        {
            'name': 'User Management Tests',
            'path': 'testing/users.py',
            'description': 'Registration, authentication, user modes, WHOIS/WHO'
        },
        {
            'name': 'IRC Command Tests',
            'path': 'testing/commands.py',
            'description': 'JOIN, PART, MODE, TOPIC, KICK, INVITE, PRIVMSG, NOTICE'
        },
        {
            'name': 'Staff Features Tests',
            'path': 'testing/staff.py',
            'description': 'ADMIN/SYSOP/GUIDE authentication, STAFF command, permissions'
        },
        {
            'name': 'Services Tests',
            'path': 'testing/services.py',
            'description': 'Registrar, Messenger, NewsFlash, ServiceBots'
        },
        {
            'name': 'Access Control Tests',
            'path': 'testing/access.py',
            'description': 'IRCX ACCESS lists, permissions, masks'
        },
        {
            'name': 'Help System Tests',
            'path': 'testing/help.py',
            'description': 'HELP command, fuzzy matching, all topics'
        },
        {
            'name': 'STATS Command Tests',
            'path': 'testing/stats.py',
            'description': 'STATS u/c/a/o/g/v, uptime, connections'
        },
        {
            'name': 'Distributed Networking Tests',
            'path': 'testing/distributed.py',
            'description': 'Trunk/branch topology, cross-server operations, 3-server network'
        },
        {
            'name': 'Network Topology Tests',
            'path': 'testing/network_topology.py',
            'description': 'Server divergences (SQUIT), convergences (CONNECT), channel/user state during topology changes'
        },
    ]
    
    # Track results
    results = []
    total_time = 0
    
    # Run each test suite
    for suite in test_suites:
        success, elapsed = run_test_suite(
            suite['name'],
            suite['path'],
            suite.get('description', '')
        )
        results.append({
            'name': suite['name'],
            'success': success,
            'time': elapsed
        })
        total_time += elapsed
        time.sleep(0.5)  # Brief pause between suites
    
    # Print summary
    print_header("Test Results Summary")
    
    passed = sum(1 for r in results if r['success'] is True)
    failed = sum(1 for r in results if r['success'] is False)
    skipped = sum(1 for r in results if r['success'] is None)
    total = len(results)
    
    print(f"Total Suites:  {total}")
    print(f"{Colors.OKGREEN}Passed:        {passed}{Colors.ENDC}")
    print(f"{Colors.FAIL}Failed:        {failed}{Colors.ENDC}")
    print(f"{Colors.WARNING}Skipped:       {skipped}{Colors.ENDC}")
    print(f"Total Time:    {total_time:.2f}s\n")
    
    # Detailed results
    print_section("Detailed Results")
    for result in results:
        if result['success'] is True:
            status = f"{Colors.OKGREEN}✓ PASS{Colors.ENDC}"
        elif result['success'] is False:
            status = f"{Colors.FAIL}✗ FAIL{Colors.ENDC}"
        else:
            status = f"{Colors.WARNING}⚠ SKIP{Colors.ENDC}"
        
        print(f"{status} {result['name']:<40} ({result['time']:.2f}s)")
    
    # Exit code
    print()
    if failed == 0:
        print(f"{Colors.OKGREEN}{Colors.BOLD}All tests passed!{Colors.ENDC}")
        return 0
    else:
        print(f"{Colors.FAIL}{Colors.BOLD}{failed} test suite(s) failed{Colors.ENDC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
