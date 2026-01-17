#!/bin/bash
# Test script for trunk & branch server linking with 2 branches

echo "=== pyIRCX Trunk & Multi-Branch Test ==="
echo

# Clean up old test databases
rm -f trunk_pyircx.db branch_pyircx.db branch2_pyircx.db

echo "Starting TRUNK server on port 6667 (linking on 7001)..."
python3 pyircx.py --config config_trunk.json &
TRUNK_PID=$!
echo "Trunk PID: $TRUNK_PID"
sleep 3

echo
echo "Starting BRANCH1 server on port 6668 (linking on 7002)..."
python3 pyircx.py --config config_branch.json &
BRANCH1_PID=$!
echo "Branch1 PID: $BRANCH1_PID"
sleep 3

echo
echo "Starting BRANCH2 server on port 6669 (linking on 7003)..."
python3 pyircx.py --config config_branch2.json &
BRANCH2_PID=$!
echo "Branch2 PID: $BRANCH2_PID"
sleep 3

echo
echo "=== Servers Running ==="
echo "Trunk:   127.0.0.1:6667 (IRC) | 127.0.0.1:7001 (Link)"
echo "Branch1: 127.0.0.1:6668 (IRC) | 127.0.0.1:7002 (Link)"
echo "Branch2: 127.0.0.1:6669 (IRC) | 127.0.0.1:7003 (Link)"
echo
echo "Test connections:"
echo "  Trunk:   telnet 127.0.0.1 6667"
echo "  Branch1: telnet 127.0.0.1 6668"
echo "  Branch2: telnet 127.0.0.1 6669"
echo
echo "To stop: kill $TRUNK_PID $BRANCH1_PID $BRANCH2_PID"
echo
echo "Press Ctrl+C to stop all servers..."

# Wait for Ctrl+C
trap "kill $TRUNK_PID $BRANCH1_PID $BRANCH2_PID 2>/dev/null; echo; echo 'Servers stopped'; exit 0" INT TERM

# Wait indefinitely
wait
