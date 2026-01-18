#!/bin/bash
# Repository Migration Script
# Updates all GitHub and path references to new repository

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}pyIRCX Repository Migration Script${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if parameters provided
if [ $# -lt 2 ]; then
    echo -e "${RED}Error: Missing parameters${NC}"
    echo ""
    echo "Usage: $0 <new-github-username> <new-repo-name> [new-copyright-holder]"
    echo ""
    echo "Example:"
    echo "  $0 mycompany pyircx-server \"MyCompany Inc.\""
    echo ""
    echo "Current references:"
    echo "  - AI3I/pyIRCX (7 occurrences)"
    echo "  - jdlewis/pyIRCX (1 occurrence)"
    echo "  - yourusername/pyIRCX (4 placeholder occurrences)"
    echo "  - anthropics/pyIRCX (1 error occurrence)"
    echo ""
    exit 1
fi

NEW_USER="$1"
NEW_REPO="$2"
NEW_COPYRIGHT="${3:-}"

echo -e "${YELLOW}New Repository Details:${NC}"
echo -e "  GitHub User: ${GREEN}${NEW_USER}${NC}"
echo -e "  Repository:  ${GREEN}${NEW_REPO}${NC}"
if [ -n "$NEW_COPYRIGHT" ]; then
    echo -e "  Copyright:   ${GREEN}${NEW_COPYRIGHT}${NC}"
fi
echo ""

read -p "Continue with migration? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Migration cancelled${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 1: Backing up affected files...${NC}"
mkdir -p .migration_backup
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) \
    -not -path "./.git/*" -not -path "./.claude/*" -not -path "./.migration_backup/*" \
    -exec cp --parents {} .migration_backup/ \; 2>/dev/null || true
echo -e "${GREEN}✓ Backup created in .migration_backup/${NC}"

echo ""
echo -e "${BLUE}Step 2: Replacing GitHub repository references...${NC}"

# Replace AI3I/pyIRCX
echo -e "  Replacing AI3I/pyIRCX..."
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) \
    -not -path "./.git/*" -not -path "./.claude/*" -not -path "./.migration_backup/*" \
    -exec sed -i "s|github\.com/AI3I/pyIRCX|github.com/${NEW_USER}/${NEW_REPO}|g" {} +

# Replace jdlewis/pyIRCX
echo -e "  Replacing jdlewis/pyIRCX..."
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) \
    -not -path "./.git/*" -not -path "./.claude/*" -not -path "./.migration_backup/*" \
    -exec sed -i "s|github\.com/jdlewis/pyIRCX|github.com/${NEW_USER}/${NEW_REPO}|g" {} +

# Replace yourusername/pyIRCX (placeholder)
echo -e "  Replacing yourusername/pyIRCX..."
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) \
    -not -path "./.git/*" -not -path "./.claude/*" -not -path "./.migration_backup/*" \
    -exec sed -i "s|github\.com/yourusername/pyIRCX|github.com/${NEW_USER}/${NEW_REPO}|g" {} +

# Replace anthropics/pyIRCX (error)
echo -e "  Replacing anthropics/pyIRCX..."
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) \
    -not -path "./.git/*" -not -path "./.claude/*" -not -path "./.migration_backup/*" \
    -exec sed -i "s|github\.com/anthropics/pyIRCX|github.com/${NEW_USER}/${NEW_REPO}|g" {} +

echo -e "${GREEN}✓ GitHub references updated${NC}"

echo ""
echo -e "${BLUE}Step 3: Replacing local paths...${NC}"

# Replace absolute paths with relative paths
echo -e "  Updating webadmin/INSTALL.md..."
sed -i 's|sudo cp -r /home/jdlewis/GitHub/pyIRCX/webadmin/\*|sudo cp -r ./webadmin/*|g' webadmin/INSTALL.md

echo -e "  Updating docs/development/VERSION_MANAGEMENT.md..."
sed -i 's|/home/jdlewis/GitHub/pyIRCX/RELEASE_CHECKLIST\.md|docs/development/RELEASE_CHECKLIST.md|g' docs/development/VERSION_MANAGEMENT.md

echo -e "  Updating docs/api/API_REFERENCE.md..."
sed -i 's|- Documentation: /home/jdlewis/GitHub/pyIRCX/docs/|- Documentation: docs/|g' docs/api/API_REFERENCE.md

echo -e "${GREEN}✓ Local paths updated to relative paths${NC}"

if [ -n "$NEW_COPYRIGHT" ]; then
    echo ""
    echo -e "${BLUE}Step 4: Updating copyright holder...${NC}"
    sed -i "s|Copyright © 2026 John D\\. Lewis|Copyright © 2026 ${NEW_COPYRIGHT}|g" README.md
    echo -e "${GREEN}✓ Copyright updated${NC}"
fi

echo ""
echo -e "${BLUE}Step 5: Verifying changes...${NC}"

# Count occurrences
OLD_REFS=$(grep -r "AI3I/pyIRCX\|jdlewis/pyIRCX\|yourusername/pyIRCX\|anthropics/pyIRCX" . \
    --include="*.md" --include="*.sh" --include="*.py" \
    --exclude-dir=.git --exclude-dir=.claude --exclude-dir=.migration_backup 2>/dev/null | wc -l || echo "0")
NEW_REFS=$(grep -r "${NEW_USER}/${NEW_REPO}" . \
    --include="*.md" --include="*.sh" --include="*.py" \
    --exclude-dir=.git --exclude-dir=.claude --exclude-dir=.migration_backup 2>/dev/null | wc -l || echo "0")
OLD_PATHS=$(grep -r "/home/jdlewis/GitHub/pyIRCX" . \
    --include="*.md" --include="*.sh" --include="*.py" \
    --exclude-dir=.git --exclude-dir=.claude --exclude-dir=.migration_backup 2>/dev/null | wc -l || echo "0")

echo ""
echo -e "  Old repository references remaining: ${OLD_REFS}"
echo -e "  New repository references created:    ${NEW_REFS}"
echo -e "  Old absolute paths remaining:         ${OLD_PATHS}"
echo ""

if [ "$OLD_REFS" -eq 0 ] && [ "$NEW_REFS" -gt 0 ] && [ "$OLD_PATHS" -eq 0 ]; then
    echo -e "${GREEN}✓ Migration completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Summary:${NC}"
    echo -e "  - ${NEW_REFS} references updated to ${NEW_USER}/${NEW_REPO}"
    echo -e "  - All absolute paths converted to relative paths"
    if [ -n "$NEW_COPYRIGHT" ]; then
        echo -e "  - Copyright updated to ${NEW_COPYRIGHT}"
    fi
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Review changes: ${BLUE}git diff${NC}"
    echo -e "  2. Test functionality"
    echo -e "  3. Commit changes: ${BLUE}git add . && git commit -m \"Migrate to ${NEW_USER}/${NEW_REPO}\"${NC}"
    echo -e "  4. Remove backup: ${BLUE}rm -rf .migration_backup${NC}"
    echo ""
else
    echo -e "${YELLOW}⚠ Migration completed with warnings${NC}"
    if [ "$OLD_REFS" -gt 0 ]; then
        echo -e "  ${RED}Warning: ${OLD_REFS} old repository references still exist${NC}"
        echo -e "  Run: ${BLUE}grep -r \"AI3I/pyIRCX\\|jdlewis/pyIRCX\\|yourusername/pyIRCX\\|anthropics/pyIRCX\" . --include=\"*.md\" --include=\"*.sh\" --include=\"*.py\" --exclude-dir=.git${NC}"
    fi
    if [ "$OLD_PATHS" -gt 0 ]; then
        echo -e "  ${RED}Warning: ${OLD_PATHS} absolute paths still exist${NC}"
        echo -e "  Run: ${BLUE}grep -r \"/home/jdlewis/GitHub/pyIRCX\" . --include=\"*.md\" --include=\"*.sh\" --include=\"*.py\" --exclude-dir=.git${NC}"
    fi
    if [ "$NEW_REFS" -eq 0 ]; then
        echo -e "  ${RED}Warning: No new repository references created${NC}"
    fi
    echo ""
    echo -e "${YELLOW}Backup available at: .migration_backup/${NC}"
    echo ""
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Migration script completed${NC}"
echo -e "${BLUE}========================================${NC}"
