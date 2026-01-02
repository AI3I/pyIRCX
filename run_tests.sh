#!/bin/bash
#
# pyIRCX Test Runner
# Automated test execution with server management
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_HOST="127.0.0.1"
TEST_PORT=6667
SERVER_WAIT=3
TEST_TIMEOUT=60

# Flags
CLEANUP_SERVER=0
SERVER_PID=""

# Cleanup function
cleanup() {
    if [ $CLEANUP_SERVER -eq 1 ] && [ -n "$SERVER_PID" ]; then
        echo -e "${YELLOW}Stopping test server (PID: $SERVER_PID)...${NC}"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        echo -e "${GREEN}Test server stopped${NC}"
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

# Start test server
start_test_server() {
    echo -e "${BLUE}Starting temporary test server...${NC}"

    # Check if pyircx.py exists
    if [ ! -f "pyircx.py" ]; then
        echo -e "${RED}Error: pyircx.py not found in current directory${NC}"
        echo "Please run this script from the pyIRCX directory"
        exit 1
    fi

    # Start server in background
    python3 pyircx.py --config pyircx_config.json > /tmp/pyircx_test.log 2>&1 &
    SERVER_PID=$!
    CLEANUP_SERVER=1

    echo -e "${YELLOW}Waiting ${SERVER_WAIT} seconds for server to start...${NC}"
    sleep $SERVER_WAIT

    # Verify server started
    SERVER_STARTED=0
    if command -v nc &> /dev/null; then
        if nc -z $TEST_HOST $TEST_PORT 2>/dev/null; then
            SERVER_STARTED=1
        fi
    elif command -v timeout &> /dev/null && command -v bash &> /dev/null; then
        if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$TEST_HOST/$TEST_PORT" 2>/dev/null; then
            SERVER_STARTED=1
        fi
    else
        # Assume it started if the process is still running
        if kill -0 $SERVER_PID 2>/dev/null; then
            SERVER_STARTED=1
            echo -e "${YELLOW}Warning: Cannot verify server port, assuming it started${NC}"
        fi
    fi

    if [ $SERVER_STARTED -eq 0 ]; then
        echo -e "${RED}Error: Failed to start test server${NC}"
        echo "Check /tmp/pyircx_test.log for errors"
        exit 1
    fi

    echo -e "${GREEN}✓ Test server started (PID: $SERVER_PID)${NC}"
}

# Run a test suite
run_test_suite() {
    local test_file=$1
    local test_name=$2

    echo ""
    echo "========================================"
    echo -e "${BLUE}Running: $test_name${NC}"
    echo "========================================"

    if [ ! -f "$test_file" ]; then
        echo -e "${YELLOW}Warning: $test_file not found, skipping...${NC}"
        return 0
    fi

    if timeout $TEST_TIMEOUT python3 "$test_file"; then
        echo -e "${GREEN}✓ $test_name: PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_name: FAILED${NC}"
        return 1
    fi
}

# Main execution
main() {
    echo ""
    echo "========================================"
    echo "pyIRCX TEST RUNNER"
    echo "========================================"
    echo ""

    # Check Python version
    echo -e "${BLUE}Checking Python version...${NC}"
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

    # Check for required test files
    echo -e "${BLUE}Checking for test files...${NC}"
    TESTS_FOUND=0
    if [ -f "pyIRCX_test_users.py" ]; then
        echo -e "${GREEN}✓ pyIRCX_test_users.py${NC}"
        ((TESTS_FOUND++))
    fi
    if [ -f "pyIRCX_test_links.py" ]; then
        echo -e "${GREEN}✓ pyIRCX_test_links.py${NC}"
        ((TESTS_FOUND++))
    fi
    if [ -f "pyIRCX_test_staff.py" ]; then
        echo -e "${GREEN}✓ pyIRCX_test_staff.py${NC}"
        ((TESTS_FOUND++))
    fi

    if [ $TESTS_FOUND -eq 0 ]; then
        echo -e "${RED}Error: No test files found${NC}"
        exit 1
    fi

    echo ""

    # Check if server is running, start if needed
    if ! check_server; then
        echo -e "${YELLOW}Starting test server automatically...${NC}"
        start_test_server
    else
        echo -e "${BLUE}Using existing server instance${NC}"
    fi

    echo ""

    # Run test suites
    TOTAL_SUITES=0
    PASSED_SUITES=0
    FAILED_SUITES=0

    # User/IRC tests
    if [ -f "pyIRCX_test_users.py" ]; then
        ((TOTAL_SUITES++))
        if run_test_suite "pyIRCX_test_users.py" "User/IRC Protocol Tests (50 tests)"; then
            ((PASSED_SUITES++))
        else
            ((FAILED_SUITES++))
        fi
    fi

    # Server linking tests
    if [ -f "pyIRCX_test_links.py" ]; then
        ((TOTAL_SUITES++))
        if run_test_suite "pyIRCX_test_links.py" "Server Linking Tests (4 tests)"; then
            ((PASSED_SUITES++))
        else
            ((FAILED_SUITES++))
        fi
    fi

    # Staff authentication tests (optional, may timeout)
    if [ -f "pyIRCX_test_staff.py" ]; then
        ((TOTAL_SUITES++))
        echo ""
        echo -e "${YELLOW}Note: Staff tests may take longer or timeout, this is normal${NC}"
        if run_test_suite "pyIRCX_test_staff.py" "Staff Authentication Tests"; then
            ((PASSED_SUITES++))
        else
            ((FAILED_SUITES++))
            echo -e "${YELLOW}Staff test failure is non-critical${NC}"
        fi
    fi

    # Summary
    echo ""
    echo "========================================"
    echo -e "${BLUE}TEST SUMMARY${NC}"
    echo "========================================"
    echo -e "Total test suites: $TOTAL_SUITES"
    echo -e "${GREEN}Passed: $PASSED_SUITES${NC}"

    if [ $FAILED_SUITES -gt 0 ]; then
        echo -e "${RED}Failed: $FAILED_SUITES${NC}"
    else
        echo -e "Failed: $FAILED_SUITES"
    fi

    echo ""

    if [ $FAILED_SUITES -eq 0 ]; then
        echo -e "${GREEN}✓✓✓ ALL TESTS PASSED ✓✓✓${NC}"
        echo ""
        exit 0
    else
        echo -e "${RED}✗✗✗ SOME TESTS FAILED ✗✗✗${NC}"
        echo ""
        echo "Check test output above for details"
        echo "See TESTING.md for troubleshooting guide"
        echo ""
        exit 1
    fi
}

# Run main function
main "$@"
