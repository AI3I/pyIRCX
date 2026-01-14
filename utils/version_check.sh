#!/bin/bash
# version_check.sh - Verify version consistency before release
# Usage: ./utils/version_check.sh [expected_version]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== pyIRCX Version Consistency Check ===${NC}\n"

# Get version from pyircx.py
if [ ! -f "pyircx.py" ]; then
    echo -e "${RED}Error: pyircx.py not found. Run from project root.${NC}"
    exit 1
fi

VERSION=$(grep "__version__" pyircx.py | head -1 | cut -d'"' -f2)
echo -e "${GREEN}Current version in pyircx.py: ${VERSION}${NC}"

# If expected version provided, compare
if [ ! -z "$1" ]; then
    if [ "$VERSION" != "$1" ]; then
        echo -e "${RED}ERROR: Version mismatch! Expected $1, found $VERSION${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Version matches expected: $VERSION${NC}"
    fi
fi

# Check for release notes file
echo -e "\n${BLUE}=== Checking Release Notes ===${NC}"
RELEASE_FILE="RELEASE_v${VERSION}.md"
if [ -f "$RELEASE_FILE" ]; then
    echo -e "${GREEN}✓ $RELEASE_FILE exists${NC}"
    # Check if release date is today
    TODAY=$(date +"%B %d, %Y")
    if grep -q "$TODAY" "$RELEASE_FILE"; then
        echo -e "${GREEN}✓ Release date is current${NC}"
    else
        echo -e "${YELLOW}⚠ Release date may need updating in $RELEASE_FILE${NC}"
    fi
else
    echo -e "${RED}✗ $RELEASE_FILE NOT FOUND${NC}"
fi

# Check README.md for version mentions
echo -e "\n${BLUE}=== Checking README.md ===${NC}"
if [ -f "README.md" ]; then
    if grep -q "$VERSION" README.md; then
        echo -e "${GREEN}✓ Version $VERSION mentioned in README.md${NC}"
    else
        echo -e "${YELLOW}⚠ Version $VERSION not found in README.md${NC}"
    fi
else
    echo -e "${YELLOW}⚠ README.md not found${NC}"
fi

# Check for inconsistent version numbers
echo -e "\n${BLUE}=== Searching for Potentially Outdated Version Numbers ===${NC}"
OLD_VERSIONS=$(grep -rh "1\.[0-9]\.[0-9]" --include="*.md" --include="*.py" . 2>/dev/null | \
    grep -v ".git" | \
    grep -v "RELEASE_v" | \
    grep -v "CHANGELOG" | \
    grep -v "version_check.sh" | \
    grep -o "1\.[0-9]\.[0-9]" | \
    sort -u | \
    grep -v "$VERSION" || true)

if [ -z "$OLD_VERSIONS" ]; then
    echo -e "${GREEN}✓ No old version numbers found${NC}"
else
    echo -e "${YELLOW}Found these version numbers (may need updating):${NC}"
    echo "$OLD_VERSIONS" | while read ver; do
        echo -e "  - $ver"
    done
fi

# Check for bare except clauses (code quality)
echo -e "\n${BLUE}=== Code Quality: Bare Except Clauses ===${NC}"
BARE_EXCEPTS=$(grep -rn "except:" --include="*.py" . 2>/dev/null | grep -v ".git" | wc -l)
if [ "$BARE_EXCEPTS" -eq 0 ]; then
    echo -e "${GREEN}✓ No bare except clauses found${NC}"
else
    echo -e "${RED}✗ Found $BARE_EXCEPTS bare except clause(s)${NC}"
    grep -rn "except:" --include="*.py" . 2>/dev/null | grep -v ".git" | head -5
fi

# Check for debug statements
echo -e "\n${BLUE}=== Code Quality: Debug Statements ===${NC}"
DEBUG_PRINTS=$(grep -rn "^[^#]*print(" --include="*.py" . 2>/dev/null | \
    grep -v ".git" | \
    grep -v "def print" | \
    grep -v "test_" | \
    wc -l)
if [ "$DEBUG_PRINTS" -eq 0 ]; then
    echo -e "${GREEN}✓ No debug print() statements found${NC}"
else
    echo -e "${YELLOW}⚠ Found $DEBUG_PRINTS print() statement(s) (may be intentional)${NC}"
fi

# Check copyright years
echo -e "\n${BLUE}=== Checking Copyright Years ===${NC}"
CURRENT_YEAR=$(date +%Y)
OLD_COPYRIGHT=$(grep -rh "Copyright.*202[0-9]" --include="*.py" . 2>/dev/null | \
    grep -v ".git" | \
    grep -v "$CURRENT_YEAR" | \
    wc -l)
if [ "$OLD_COPYRIGHT" -eq 0 ]; then
    echo -e "${GREEN}✓ All copyright years are current${NC}"
else
    echo -e "${YELLOW}⚠ Found $OLD_COPYRIGHT file(s) with old copyright year${NC}"
fi

# Check if git is clean
echo -e "\n${BLUE}=== Git Status ===${NC}"
if [ -z "$(git status --porcelain)" ]; then
    echo -e "${GREEN}✓ Git working directory is clean${NC}"
else
    echo -e "${YELLOW}⚠ Uncommitted changes detected:${NC}"
    git status --short
fi

# Check if tag exists
echo -e "\n${BLUE}=== Git Tags ===${NC}"
if git tag -l | grep -q "v${VERSION}"; then
    echo -e "${GREEN}✓ Tag v${VERSION} exists${NC}"
else
    echo -e "${YELLOW}⚠ Tag v${VERSION} not created yet${NC}"
fi

# Summary
echo -e "\n${BLUE}=== Summary ===${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Ready for release: "

ISSUES=0
[ ! -f "$RELEASE_FILE" ] && ((ISSUES++))
[ "$BARE_EXCEPTS" -gt 0 ] && ((ISSUES++))

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo -e "\n${BLUE}Next steps:${NC}"
    echo "  1. Review changes: git diff"
    echo "  2. Commit: git commit -m 'Release v${VERSION}'"
    echo "  3. Tag: git tag -a v${VERSION} -m 'Release v${VERSION}'"
    echo "  4. Push: git push origin main && git push origin --tags"
    echo "  5. Release: gh release create v${VERSION} --title 'Title' --notes-file ${RELEASE_FILE}"
else
    echo -e "${YELLOW}⚠ $ISSUES issue(s) found - review before release${NC}"
    exit 1
fi
