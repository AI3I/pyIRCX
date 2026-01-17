#!/bin/bash
# Test script for trunk & branch server linking

echo "=== pyIRCX Trunk & Branch Test ==="
echo

# Clean up old test databases
rm -f trunk_pyircx.db branch_pyircx.db

echo "Starting TRUNK server on port 6667 (linking on 7001)..."
python3 pyircx.py --config config_trunk.json &
TRUNK_PID=$!
echo "Trunk PID: $TRUNK_PID"
sleep 3

echo
echo "Starting BRANCH server on port 6668 (linking on 7002)..."
python3 pyircx.py --config config_branch.json &
BRANCH_PID=$!
echo "Branch PID: $BRANCH_PID"
sleep 3

echo
echo "=== Servers Running ==="
echo "Trunk:  127.0.0.1:6667 (IRC) | 127.0.0.1:7001 (Link)"
echo "Branch: 127.0.0.1:6668 (IRC) | 127.0.0.1:7002 (Link)"
echo
echo "Test connections:"
echo "  Trunk:  telnet 127.0.0.1 6667"
echo "  Branch: telnet 127.0.0.1 6668"
echo
echo "To stop: kill $TRUNK_PID $BRANCH_PID"
echo
echo "Press Ctrl+C to stop all servers..."

# Wait for Ctrl+C
trap "kill $TRUNK_PID $BRANCH_PID 2>/dev/null; echo; echo 'Servers stopped'; exit 0" INT TERM

# Wait indefinitely
wait
