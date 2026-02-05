#!/bin/bash
#
# pyIRCX Test Runner v2.0.0
# Automated test execution with server management
#
# NOTE: For best results, configure server with relaxed connection throttling:
#   security.enable_connection_throttle: false
#   OR security.connection_throttle: 100
#

set -e
set -o pipefail  # Ensure pipeline failures are detected

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_HOST="127.0.0.1"
TEST_PORT="${PYIRCX_TEST_TRUNK_PORT:-${PYIRCX_TEST_BASE_PORT:-6666}}"
TEST_BRANCH1_PORT="${PYIRCX_TEST_BRANCH1_PORT:-6668}"
TEST_BRANCH2_PORT="${PYIRCX_TEST_BRANCH2_PORT:-6669}"
TRUNK_LINK_PORT="${PYIRCX_TEST_TRUNK_LINK_PORT:-${PYIRCX_TEST_LINK_BASE_PORT:-7001}}"
BRANCH1_LINK_PORT="${PYIRCX_TEST_BRANCH1_LINK_PORT:-7002}"
BRANCH2_LINK_PORT="${PYIRCX_TEST_BRANCH2_LINK_PORT:-7003}"
LINK_PASSWORD="testlink"
SERVER_WAIT=5
TEST_TIMEOUT=120

# Logging
TIMESTAMP=$(date +%s)
DATETIME=$(date '+%Y-%m-%d %H:%M:%S')
LOG_DIR="tests/integration/logs"
LOG_FILE="${LOG_DIR}/test_run_${TIMESTAMP}.md"
LATEST_LINK="${LOG_DIR}/latest.md"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Flags
CLEANUP_SERVER=0
SERVER_PID=""
BRANCH1_PID=""
BRANCH2_PID=""
TEST_DIR=""

# Cleanup function
cleanup() {
    if [ $CLEANUP_SERVER -eq 1 ]; then
        if [ -n "$BRANCH2_PID" ]; then
            echo -e "${YELLOW}Stopping branch2 server (PID: $BRANCH2_PID)...${NC}"
            kill $BRANCH2_PID 2>/dev/null || true
            wait $BRANCH2_PID 2>/dev/null || true
        fi
        if [ -n "$BRANCH1_PID" ]; then
            echo -e "${YELLOW}Stopping branch1 server (PID: $BRANCH1_PID)...${NC}"
            kill $BRANCH1_PID 2>/dev/null || true
            wait $BRANCH1_PID 2>/dev/null || true
        fi
        if [ -n "$SERVER_PID" ]; then
            echo -e "${YELLOW}Stopping trunk server (PID: $SERVER_PID)...${NC}"
            kill $SERVER_PID 2>/dev/null || true
            wait $SERVER_PID 2>/dev/null || true
        fi
        if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
            rm -rf "$TEST_DIR"
        fi
        echo -e "${GREEN}Test servers stopped${NC}"
    fi
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check if server is running
check_server() {
    echo -e "${BLUE}Checking if pyIRCX server is running...${NC}"

    # Check if nc (netcat) is available
    if ! command -v nc &> /dev/null; then
        # Try alternative methods
        if command -v timeout &> /dev/null && command -v bash &> /dev/null; then
            # Use bash TCP socket feature
            if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$TEST_HOST/$TEST_PORT" 2>/dev/null; then
                echo -e "${GREEN}✓ Server is running on $TEST_HOST:$TEST_PORT${NC}"
                return 0
            else
                echo -e "${YELLOW}✗ Server is not running on $TEST_HOST:$TEST_PORT${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}Warning: nc (netcat) not found. Assuming server needs to be started.${NC}"
            return 1
        fi
    elif nc -z $TEST_HOST $TEST_PORT 2>/dev/null; then
        echo -e "${GREEN}✓ Server is running on $TEST_HOST:$TEST_PORT${NC}"
        return 0
    else
        echo -e "${YELLOW}✗ Server is not running on $TEST_HOST:$TEST_PORT${NC}"
        return 1
    fi
}

port_in_use() {
    local host=$1
    local port=$2
    if command -v nc &> /dev/null; then
        nc -z "$host" "$port" 2>/dev/null
        return $?
    fi
    if command -v timeout &> /dev/null && command -v bash &> /dev/null; then
        timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null
        return $?
    fi
    return 1
}

select_free_ports() {
    # Skip auto-selection if ports are explicitly set via env
    if [ -n "$PYIRCX_TEST_TRUNK_PORT" ] || [ -n "$PYIRCX_TEST_BRANCH1_PORT" ] || [ -n "$PYIRCX_TEST_BRANCH2_PORT" ] || \
       [ -n "$PYIRCX_TEST_TRUNK_LINK_PORT" ] || [ -n "$PYIRCX_TEST_BRANCH1_LINK_PORT" ] || [ -n "$PYIRCX_TEST_BRANCH2_LINK_PORT" ] || \
       [ -n "$PYIRCX_TEST_BASE_PORT" ] || [ -n "$PYIRCX_TEST_LINK_BASE_PORT" ]; then
        return
    fi

    # Ensure fixed branch ports are free
    if port_in_use "$TEST_HOST" "$TEST_BRANCH1_PORT" || port_in_use "$TEST_HOST" "$TEST_BRANCH2_PORT"; then
        echo -e "${RED}Error: Branch ports $TEST_BRANCH1_PORT/$TEST_BRANCH2_PORT already in use.${NC}"
        echo -e "${RED}Set PYIRCX_TEST_BRANCH1_PORT/PYIRCX_TEST_BRANCH2_PORT to override.${NC}"
        exit 1
    fi

    # Find a free trunk port (avoid 6667 to keep it open for installed instance)
    local base
    for base in 6666 6665 6664 6663 6662 6661 6660 6659 6658 6657 6656 6655; do
        if port_in_use "$TEST_HOST" "$base"; then
            continue
        fi
        TEST_PORT="$base"
        break
    done

    if port_in_use "$TEST_HOST" "$TEST_PORT"; then
        echo -e "${RED}Error: No free trunk port found near 6666.${NC}"
        echo -e "${RED}Set PYIRCX_TEST_TRUNK_PORT to override.${NC}"
        exit 1
    fi

    # Find free link ports block in 7001-7099
    local link_base
    for link_base in 7001 7004 7007 7010 7013 7016 7019 7022 7025 7028 7031 7034 7037 7040 7043 7046 7049 7052 7055 7058 7061 7064 7067 7070 7073 7076 7079 7082 7085 7088 7091 7094 7097; do
        if port_in_use "$TEST_HOST" "$link_base" || port_in_use "$TEST_HOST" "$((link_base+1))" || port_in_use "$TEST_HOST" "$((link_base+2))"; then
            continue
        fi
        TRUNK_LINK_PORT="$link_base"
        BRANCH1_LINK_PORT="$((link_base+1))"
        BRANCH2_LINK_PORT="$((link_base+2))"
        echo -e "${YELLOW}Selected ports: trunk=$TEST_PORT, branch1=$TEST_BRANCH1_PORT, branch2=$TEST_BRANCH2_PORT (links $TRUNK_LINK_PORT-$BRANCH2_LINK_PORT)${NC}"
        return
    done

    echo -e "${RED}Error: No free link port block found in 7001-7099.${NC}"
    echo -e "${RED}Set PYIRCX_TEST_TRUNK_LINK_PORT/PYIRCX_TEST_BRANCH1_LINK_PORT/PYIRCX_TEST_BRANCH2_LINK_PORT to override.${NC}"
    exit 1
}

wait_for_port() {
    local host=$1
    local port=$2
    local timeout_secs=${3:-5}
    local end=$((SECONDS + timeout_secs))
    while [ $SECONDS -lt $end ]; do
        if command -v nc &> /dev/null; then
            if nc -z "$host" "$port" 2>/dev/null; then
                return 0
            fi
        elif command -v timeout &> /dev/null && command -v bash &> /dev/null; then
            if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
                return 0
            fi
        else
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Start test servers (trunk + 2 branches)
start_test_servers() {
    echo -e "${BLUE}Starting temporary test servers (trunk + 2 branches)...${NC}"

    if [ ! -f "pyircx.py" ]; then
        echo -e "${RED}Error: pyircx.py not found in current directory${NC}"
        echo "Please run this script from the pyIRCX directory"
        exit 1
    fi

    TEST_DIR=$(mktemp -d "/tmp/pyircx_test_${TIMESTAMP}_XXXX")
    CONFIG_TRUNK="${TEST_DIR}/pyircx_trunk.json"
    CONFIG_BRANCH1="${TEST_DIR}/pyircx_branch1.json"
    CONFIG_BRANCH2="${TEST_DIR}/pyircx_branch2.json"
    DB_TRUNK="${TEST_DIR}/pyircx_trunk.db"
    DB_BRANCH1="${TEST_DIR}/pyircx_branch1.db"
    DB_BRANCH2="${TEST_DIR}/pyircx_branch2.db"

    # Use sync sqlite3 pool and disable thread executor in test harness
    export PYIRCX_SYNC_DB=1
    export PYIRCX_NO_THREADS=1

    python3 - <<PY
import json
from pathlib import Path

base = json.loads(Path("pyircx_config.json").read_text())

def make_config(name, port, role, bind_port, links, db_path, is_hub, hub_server):
    cfg = json.loads(json.dumps(base))
    cfg["server"]["name"] = name
    cfg["network"]["listen_addr"] = "127.0.0.1"
    cfg["network"]["listen_ports"] = [port]
    cfg["linking"]["enabled"] = True
    cfg["linking"]["server_role"] = role
    cfg["linking"]["bind_host"] = "127.0.0.1"
    cfg["linking"]["bind_port"] = bind_port
    cfg["linking"]["links"] = links
    cfg["database"]["path"] = db_path
    cfg["services"]["mode"] = "centralized"
    cfg["services"]["is_services_hub"] = is_hub
    cfg["services"]["hub_server"] = hub_server
    cfg["ssl"]["enabled"] = False
    cfg["security"]["auth_require_ssl"] = False
    cfg["security"]["pass_require_ssl"] = False
    return cfg

trunk_name = "trunk.testnet.local"
branch1_name = "branch1.testnet.local"
branch2_name = "branch2.testnet.local"

link_password = "${LINK_PASSWORD}"

trunk_links = [
    {"name": branch1_name, "host": "127.0.0.1", "port": ${BRANCH1_LINK_PORT}, "password": link_password, "autoconnect": False},
    {"name": branch2_name, "host": "127.0.0.1", "port": ${BRANCH2_LINK_PORT}, "password": link_password, "autoconnect": False},
]

branch1_links = [
    {"name": trunk_name, "host": "127.0.0.1", "port": ${TRUNK_LINK_PORT}, "password": link_password, "autoconnect": True},
]

branch2_links = [
    {"name": trunk_name, "host": "127.0.0.1", "port": ${TRUNK_LINK_PORT}, "password": link_password, "autoconnect": True},
]

configs = {
    "${CONFIG_TRUNK}": make_config(trunk_name, ${TEST_PORT}, "trunk", ${TRUNK_LINK_PORT}, trunk_links, "${DB_TRUNK}", True, trunk_name),
    "${CONFIG_BRANCH1}": make_config(branch1_name, ${TEST_BRANCH1_PORT}, "branch", ${BRANCH1_LINK_PORT}, branch1_links, "${DB_BRANCH1}", False, trunk_name),
    "${CONFIG_BRANCH2}": make_config(branch2_name, ${TEST_BRANCH2_PORT}, "branch", ${BRANCH2_LINK_PORT}, branch2_links, "${DB_BRANCH2}", False, trunk_name),
}

for path, cfg in configs.items():
    Path(path).write_text(json.dumps(cfg, indent=2))
PY

    # Start servers in background
    python3 pyircx.py --config "$CONFIG_TRUNK" > "${TEST_DIR}/trunk.log" 2>&1 &
    SERVER_PID=$!
    python3 pyircx.py --config "$CONFIG_BRANCH1" > "${TEST_DIR}/branch1.log" 2>&1 &
    BRANCH1_PID=$!
    python3 pyircx.py --config "$CONFIG_BRANCH2" > "${TEST_DIR}/branch2.log" 2>&1 &
    BRANCH2_PID=$!
    CLEANUP_SERVER=1

    echo -e "${YELLOW}Waiting ${SERVER_WAIT} seconds for servers to start...${NC}"
    sleep $SERVER_WAIT

    if ! wait_for_port "$TEST_HOST" "$TEST_PORT" 20; then
        echo -e "${RED}Error: Trunk server failed to start on $TEST_HOST:$TEST_PORT${NC}"
        echo "See ${TEST_DIR}/trunk.log"
        exit 1
    fi
    if ! wait_for_port "$TEST_HOST" "$TEST_BRANCH1_PORT" 20; then
        echo -e "${RED}Error: Branch1 server failed to start on $TEST_HOST:$TEST_BRANCH1_PORT${NC}"
        echo "See ${TEST_DIR}/branch1.log"
        exit 1
    fi
    if ! wait_for_port "$TEST_HOST" "$TEST_BRANCH2_PORT" 20; then
        echo -e "${RED}Error: Branch2 server failed to start on $TEST_HOST:$TEST_BRANCH2_PORT${NC}"
        echo "See ${TEST_DIR}/branch2.log"
        exit 1
    fi

    # Create test accounts in trunk DB
    if ! python3 tests/integration/setup_test_accounts.py --db "$DB_TRUNK" > "${TEST_DIR}/accounts.log" 2>&1; then
        echo -e "${RED}Error: Failed to create test accounts${NC}"
        echo "See ${TEST_DIR}/accounts.log"
        exit 1
    fi

    # Export test environment for suites
    export PYIRCX_TEST_HOST="$TEST_HOST"
    export PYIRCX_TEST_TRUNK_PORT="$TEST_PORT"
    export PYIRCX_TEST_BRANCH1_PORT="$TEST_BRANCH1_PORT"
    export PYIRCX_TEST_BRANCH2_PORT="$TEST_BRANCH2_PORT"
    export PYIRCX_TEST_DB_TRUNK="$DB_TRUNK"
    export PYIRCX_TEST_DB_BRANCH1="$DB_BRANCH1"
    export PYIRCX_TEST_DB_BRANCH2="$DB_BRANCH2"
    export PYIRCX_TEST_CONFIG_TRUNK="$CONFIG_TRUNK"
    export PYIRCX_TEST_CONFIG_BRANCH1="$CONFIG_BRANCH1"
    export PYIRCX_TEST_CONFIG_BRANCH2="$CONFIG_BRANCH2"
    export PYIRCX_TEST_TRUNK_NAME="trunk.testnet.local"
    export PYIRCX_TEST_BRANCH1_NAME="branch1.testnet.local"
    export PYIRCX_TEST_BRANCH2_NAME="branch2.testnet.local"
    export PYIRCX_TEST_TRUNK_LINK_PORT="$TRUNK_LINK_PORT"
    export PYIRCX_TEST_BRANCH1_LINK_PORT="$BRANCH1_LINK_PORT"
    export PYIRCX_TEST_BRANCH2_LINK_PORT="$BRANCH2_LINK_PORT"

    echo -e "${GREEN}✓ Test servers started (PIDs: trunk=$SERVER_PID, b1=$BRANCH1_PID, b2=$BRANCH2_PID)${NC}"
    echo -e "${GREEN}✓ Test configs/logs in ${TEST_DIR}${NC}"
}

# Run a test suite
run_test_suite() {
    local test_file=$1
    local test_name=$2

    echo ""
    echo "========================================"
    echo -e "${BLUE}Running: $test_name${NC}"
    echo "========================================"

    {
        echo ""
        echo "---"
        echo ""
        echo "### $test_name"
        echo ""
    } >> "$LOG_FILE"

    if [ ! -f "$test_file" ]; then
        echo -e "${YELLOW}Warning: $test_file not found, skipping...${NC}"
        echo "**Status**: ⚠️ SKIPPED (file not found)" >> "$LOG_FILE"
        return 0
    fi

    # Capture start time
    local start_time=$(date +%s)

    # Run test and capture output - show on console AND save to temp file
    local temp_log=$(mktemp)

    echo "**Start Time**: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo '```' >> "$LOG_FILE"

    # Run test with tee to show output AND capture it
    if timeout $TEST_TIMEOUT python3 "$test_file" 2>&1 | tee -a "$temp_log"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Append captured output to log
        cat "$temp_log" >> "$LOG_FILE"
        echo '```' >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "**End Time**: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
        echo "**Duration**: ${duration}s" >> "$LOG_FILE"
        echo "**Status**: ✅ PASSED" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"

        echo -e "${GREEN}✓ $test_name: PASSED${NC} (${duration}s)"
        rm "$temp_log"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Append captured output to log
        cat "$temp_log" >> "$LOG_FILE"
        echo '```' >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "**End Time**: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
        echo "**Duration**: ${duration}s" >> "$LOG_FILE"
        echo "**Status**: ❌ FAILED" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"

        echo -e "${RED}✗ $test_name: FAILED${NC} (${duration}s)"
        rm "$temp_log"
        return 1
    fi
}

# Write markdown header
write_log_header() {
    cat > "$LOG_FILE" <<EOF
# pyIRCX Test Run Report

**Date**: $DATETIME
**Timestamp**: $TIMESTAMP
**Host**: $(hostname)
**User**: $(whoami)

---

## Test Environment

EOF
}

# Main execution
main() {
    select_free_ports
    # Initialize log file
    write_log_header

    echo ""
    echo "========================================"
    echo "pyIRCX v2.0.0 TEST RUNNER"
    echo "========================================"
    echo ""
    echo "📝 Logging to: $LOG_FILE"
    echo ""

    # Log to markdown
    {
        echo "**Test Runner**: pyIRCX v2.0.0"
        echo ""
    } >> "$LOG_FILE"

    # Check Python version
    echo -e "${BLUE}Checking Python version...${NC}"
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

    echo "- **Python Version**: $PYTHON_VERSION" >> "$LOG_FILE"

    # Check for test directory
    echo -e "${BLUE}Checking for test files...${NC}"
    if [ ! -d "tests/integration" ]; then
        echo -e "${RED}Error: tests/integration/ directory not found${NC}"
        exit 1
    fi

    TESTS_FOUND=0

    # Core functionality tests
    if [ -f "tests/integration/core/users.py" ]; then
        echo -e "${GREEN}✓ tests/integration/core/users.py (115 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/staff/staff.py" ]; then
        echo -e "${GREEN}✓ tests/integration/staff/staff.py (39 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/staff/authentication.py" ]; then
        echo -e "${GREEN}✓ tests/integration/staff/authentication.py (18 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/network/links.py" ]; then
        echo -e "${GREEN}✓ tests/integration/network/links.py (4 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/network/distributed.py" ]; then
        echo -e "${GREEN}✓ tests/integration/network/distributed.py (multi-server tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/network/topology.py" ]; then
        echo -e "${GREEN}✓ tests/integration/network/topology.py (split/rejoin tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/ircx/access.py" ]; then
        echo -e "${GREEN}✓ tests/integration/ircx/access.py (10 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi

    # Feature tests
    if [ -f "tests/integration/core/stats.py" ]; then
        echo -e "${GREEN}✓ tests/integration/core/stats.py (16 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/core/help.py" ]; then
        echo -e "${GREEN}✓ tests/integration/core/help.py (15 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "tests/integration/ircx/services.py" ]; then
        echo -e "${GREEN}✓ tests/integration/ircx/services.py (13 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi

    if [ $TESTS_FOUND -eq 0 ]; then
        echo -e "${RED}Error: No test files found in testing/ directory${NC}"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}Found $TESTS_FOUND test suites${NC}"
    echo ""

    {
        echo "- **Test Suites Found**: $TESTS_FOUND"
        echo "- **Server**: trunk=$TEST_HOST:$TEST_PORT, branch1=$TEST_HOST:$TEST_BRANCH1_PORT, branch2=$TEST_HOST:$TEST_BRANCH2_PORT"
        echo ""
        echo "---"
        echo ""
        echo "## Test Execution"
        echo ""
    } >> "$LOG_FILE"

    # Check if server is running
    if check_server; then
        echo -e "${RED}Error: A server is already running on $TEST_HOST:$TEST_PORT${NC}"
        echo -e "${YELLOW}Please stop existing servers before running integration tests:${NC}"
        echo -e "${YELLOW}  pkill -f 'python.*pyircx.py' && sleep 2${NC}"
        exit 1
    else
        echo -e "${YELLOW}Starting test servers automatically...${NC}"
        echo "- Server: Started automatically (trunk+branches)" >> "$LOG_FILE"
        start_test_servers
    fi

    echo ""
    echo "## Test Suite Execution" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "Each test suite below shows complete output including all test cases." >> "$LOG_FILE"

    # Run test suites
    TOTAL_SUITES=0
    PASSED_SUITES=0
    FAILED_SUITES=0

    # Core IRC/IRCX tests
    if [ -f "tests/integration/core/users.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/core/users.py" "IRC/IRCX Protocol Tests (115 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Staff authentication tests
    if [ -f "tests/integration/staff/staff.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/staff/staff.py" "Staff PASS Authentication Tests (39 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # AUTH command tests
    if [ -f "tests/integration/staff/authentication.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/staff/authentication.py" "AUTH Command & MFA Tests (18 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Server linking tests
    if [ -f "tests/integration/network/links.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/network/links.py" "Server Linking Tests (4 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Distributed networking tests (trunk + 2 branches)
    if [ -f "tests/integration/network/distributed.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/network/distributed.py" "Distributed Networking Tests (multi-server)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Network topology tests (splits/rejoins)
    if [ -f "tests/integration/network/topology.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/network/topology.py" "Network Topology Tests (splits/joins)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Access control tests
    if [ -f "tests/integration/ircx/access.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/ircx/access.py" "Access Control Tests (10 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # STATS system tests
    if [ -f "tests/integration/core/stats.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/core/stats.py" "STATS System Tests (16 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # HELP system tests
    if [ -f "tests/integration/core/help.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/core/help.py" "HELP System Tests (15 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Service improvements tests
    if [ -f "tests/integration/ircx/services.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/ircx/services.py" "Service Improvements Tests (13 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # WebChat gateway tests (optional - requires gateway running)
    if [ -f "tests/integration/web/webchat.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "tests/integration/web/webchat.py" "WebChat Gateway Tests"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Summary
    echo ""
    echo "========================================"
    echo -e "${BLUE}TEST SUMMARY${NC}"
    echo "========================================"
    echo -e "Total test suites: $TOTAL_SUITES"
    echo -e "Total test cases: ~243"
    echo -e "${GREEN}Passed: $PASSED_SUITES${NC}"

    if [ $FAILED_SUITES -gt 0 ]; then
        echo -e "${RED}Failed: $FAILED_SUITES${NC}"
    else
        echo -e "Failed: $FAILED_SUITES"
    fi

    echo ""

    # Write summary to log
    {
        echo ""
        echo "---"
        echo ""
        echo "# Test Run Summary"
        echo ""
        echo "| Metric | Value |"
        echo "|--------|-------|"
        echo "| **Total Suites** | $TOTAL_SUITES |"
        echo "| **Total Cases** | ~243 |"
        echo "| **Passed** | $PASSED_SUITES |"
        echo "| **Failed** | $FAILED_SUITES |"
        echo "| **Success Rate** | $(awk "BEGIN {printf \"%.1f\", ($PASSED_SUITES/$TOTAL_SUITES)*100}")% |"
        echo ""
    } >> "$LOG_FILE"

    if [ $FAILED_SUITES -eq 0 ]; then
        echo -e "${GREEN}✓✓✓ ALL TESTS PASSED ✓✓✓${NC}"
        echo ""
        echo "Test coverage includes:"
        echo "  - IRC/IRCX Protocol (115 tests)"
        echo "  - Core Commands (28 tests - JOIN/PART/QUIT/INVITE/MODE/TOPIC/etc.)"
        echo "  - Staff Authentication (39 tests)"
        echo "  - AUTH Command & MFA (18 tests)"
        echo "  - Server Linking (4 tests)"
        echo "  - Access Control (10 tests)"
        echo "  - STATS System (16 tests)"
        echo "  - HELP System (15 tests)"
        echo "  - Service Improvements (13 tests)"
        echo ""

        {
            echo "### ✅ Result: ALL TESTS PASSED"
            echo ""
            echo "**Test Coverage:**"
            echo "- IRC/IRCX Protocol (115 tests)"
            echo "- Core Commands (28 tests - JOIN/PART/QUIT/INVITE/MODE/TOPIC/etc.)"
            echo "- Staff Authentication (39 tests)"
            echo "- AUTH Command & MFA (18 tests)"
            echo "- Server Linking (4 tests)"
            echo "- Access Control (10 tests)"
            echo "- STATS System (16 tests)"
            echo "- HELP System (15 tests)"
            echo "- Service Improvements (13 tests)"
            echo ""
            echo "---"
            echo ""
            echo "*Report generated: $(date)*"
        } >> "$LOG_FILE"

        # Create symlink to latest
        ln -sf "test_run_${TIMESTAMP}.md" "$LATEST_LINK"

        echo "📝 Test report saved to: $LOG_FILE"
        echo "📎 Latest report: $LATEST_LINK"
        echo ""

        exit 0
    else
        echo -e "${RED}✗✗✗ SOME TESTS FAILED ✗✗✗${NC}"
        echo ""
        echo "Check test output above for details"
        echo "See tests/integration/README.md for troubleshooting guide"
        echo ""

        {
            echo "### ❌ Result: SOME TESTS FAILED"
            echo ""
            echo "**Failed Suites:** $FAILED_SUITES"
            echo ""
            echo "Please review the error output above for details."
            echo ""
            echo "**Troubleshooting:**"
            echo "- Check tests/integration/README.md for guidance"
            echo "- Verify server is running correctly"
            echo "- Check test accounts exist: \`sudo python3 tests/integration/setup_test_accounts.py\`"
            echo ""
            echo "---"
            echo ""
            echo "*Report generated: $(date)*"
        } >> "$LOG_FILE"

        # Create symlink to latest
        ln -sf "test_run_${TIMESTAMP}.md" "$LATEST_LINK"

        echo "📝 Test report saved to: $LOG_FILE"
        echo "📎 Latest report: $LATEST_LINK"
        echo ""

        exit 1
    fi
}

# Run main function
main "$@"
