#!/bin/bash
# Simple server startup script
cd /home/jdlewis/GitHub/pyIRCX

# Clean up
rm -f trunk_pyircx.db branch_pyircx.db branch2_pyircx.db

# Start trunk
python3 pyircx.py --config config_trunk.json >/tmp/trunk.log 2>&1 &
TRUNK_PID=$!
echo "Trunk started: PID $TRUNK_PID"

# Wait
sleep 4

# Start branch1
python3 pyircx.py --config config_branch.json >/tmp/branch1.log 2>&1 &
BRANCH1_PID=$!
echo "Branch1 started: PID $BRANCH1_PID"

# Wait
sleep 4

# Start branch2
python3 pyircx.py --config config_branch2.json >/tmp/branch2.log 2>&1 &
BRANCH2_PID=$!
echo "Branch2 started: PID $BRANCH2_PID"

# Wait for linking
sleep 4

echo ""
echo "=== Server Status ==="
echo "Trunk PID: $TRUNK_PID"
echo "Branch1 PID: $BRANCH1_PID"
echo "Branch2 PID: $BRANCH2_PID"
echo ""
echo "To stop: kill $TRUNK_PID $BRANCH1_PID $BRANCH2_PID"
