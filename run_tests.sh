#!/bin/bash
#
# pyIRCX Test Runner v1.1.5
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
TEST_TIMEOUT=120

# Logging
TIMESTAMP=$(date +%s)
DATETIME=$(date '+%Y-%m-%d %H:%M:%S')
LOG_DIR="testing/logs"
LOG_FILE="${LOG_DIR}/test_run_${TIMESTAMP}.md"
LATEST_LINK="${LOG_DIR}/latest.md"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

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
    # Initialize log file
    write_log_header

    echo ""
    echo "========================================"
    echo "pyIRCX v1.1.8 TEST RUNNER"
    echo "========================================"
    echo ""
    echo "📝 Logging to: $LOG_FILE"
    echo ""

    # Log to markdown
    {
        echo "**Test Runner**: pyIRCX v1.1.8"
        echo ""
    } >> "$LOG_FILE"

    # Check Python version
    echo -e "${BLUE}Checking Python version...${NC}"
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

    echo "- **Python Version**: $PYTHON_VERSION" >> "$LOG_FILE"

    # Check for test directory
    echo -e "${BLUE}Checking for test files...${NC}"
    if [ ! -d "testing" ]; then
        echo -e "${RED}Error: testing/ directory not found${NC}"
        exit 1
    fi

    TESTS_FOUND=0

    # Core functionality tests
    if [ -f "testing/users.py" ]; then
        echo -e "${GREEN}✓ testing/users.py (115 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/commands.py" ]; then
        echo -e "${GREEN}✓ testing/commands.py (28 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/staff.py" ]; then
        echo -e "${GREEN}✓ testing/staff.py (39 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/test_auth.py" ]; then
        echo -e "${GREEN}✓ testing/test_auth.py (18 tests - v1.1.8)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/links.py" ]; then
        echo -e "${GREEN}✓ testing/links.py (4 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/access.py" ]; then
        echo -e "${GREEN}✓ testing/access.py (10 tests)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi

    # v1.1.5 feature tests
    if [ -f "testing/stats.py" ]; then
        echo -e "${GREEN}✓ testing/stats.py (16 tests - v1.1.5)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/help.py" ]; then
        echo -e "${GREEN}✓ testing/help.py (15 tests - v1.1.5)${NC}"
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
    if [ -f "testing/services.py" ]; then
        echo -e "${GREEN}✓ testing/services.py (13 tests - v1.1.5)${NC}"
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
        echo "- **Server**: $TEST_HOST:$TEST_PORT"
        echo ""
        echo "---"
        echo ""
        echo "## Test Execution"
        echo ""
    } >> "$LOG_FILE"

    # Check if server is running, start if needed
    if ! check_server; then
        echo -e "${YELLOW}Starting test server automatically...${NC}"
        echo "- Server: Started automatically (PID: will be set)" >> "$LOG_FILE"
        start_test_server
    else
        echo -e "${BLUE}Using existing server instance${NC}"
        echo "- Server: Using existing instance" >> "$LOG_FILE"
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
    if [ -f "testing/users.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/users.py" "IRC/IRCX Protocol Tests (115 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Core command tests
    if [ -f "testing/commands.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/commands.py" "Core Command Tests (28 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Staff authentication tests
    if [ -f "testing/staff.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/staff.py" "Staff PASS Authentication Tests (39 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # AUTH command tests (v1.1.8)
    if [ -f "testing/test_auth.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        echo ""
        echo -e "${BLUE}=== v1.1.8 Feature Tests ===${NC}"
        if run_test_suite "testing/test_auth.py" "AUTH Command & MFA Tests (18 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Server linking tests
    if [ -f "testing/links.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/links.py" "Server Linking Tests (4 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # Access control tests
    if [ -f "testing/access.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/access.py" "Access Control Tests (10 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # v1.1.5 STATS system tests
    if [ -f "testing/stats.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        echo ""
        echo -e "${BLUE}=== v1.1.5 Feature Tests ===${NC}"
        if run_test_suite "testing/stats.py" "STATS System Tests (16 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # v1.1.5 HELP system tests
    if [ -f "testing/help.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/help.py" "HELP System Tests (15 tests)"; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi
    fi

    # v1.1.5 service improvements tests
    if [ -f "testing/services.py" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        if run_test_suite "testing/services.py" "Service Improvements Tests (13 tests)"; then
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
        echo "  - Server Linking (4 tests)"
        echo "  - Access Control (10 tests)"
        echo "  - v1.1.5 STATS System (16 tests)"
        echo "  - v1.1.5 HELP System (15 tests)"
        echo "  - v1.1.5 Service Improvements (13 tests)"
        echo ""

        {
            echo "### ✅ Result: ALL TESTS PASSED"
            echo ""
            echo "**Test Coverage:**"
            echo "- IRC/IRCX Protocol (115 tests)"
            echo "- Core Commands (28 tests - JOIN/PART/QUIT/INVITE/MODE/TOPIC/etc.)"
            echo "- Staff Authentication (39 tests)"
            echo "- Server Linking (4 tests)"
            echo "- Access Control (10 tests)"
            echo "- v1.1.5 STATS System (16 tests)"
            echo "- v1.1.5 HELP System (15 tests)"
            echo "- v1.1.5 Service Improvements (13 tests)"
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
        echo "See TESTING_v1.1.5.md for troubleshooting guide"
        echo ""

        {
            echo "### ❌ Result: SOME TESTS FAILED"
            echo ""
            echo "**Failed Suites:** $FAILED_SUITES"
            echo ""
            echo "Please review the error output above for details."
            echo ""
            echo "**Troubleshooting:**"
            echo "- Check TESTING_v1.1.5.md for guidance"
            echo "- Verify server is running correctly"
            echo "- Check test accounts exist: \`sudo python3 testing/setup_test_accounts.py\`"
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
