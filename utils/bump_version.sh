#!/bin/bash
# bump_version.sh - Update version number across the project
# Usage: ./utils/bump_version.sh <new_version>
# Example: ./utils/bump_version.sh 1.2.0

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo -e "${RED}Error: Version number required${NC}"
    echo "Usage: $0 <version>"
    echo "Example: $0 1.2.0"
    exit 1
fi

NEW_VERSION="$1"

# Validate version format (semantic versioning)
if ! echo "$NEW_VERSION" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+$"; then
    echo -e "${RED}Error: Invalid version format. Use MAJOR.MINOR.PATCH (e.g., 1.2.0)${NC}"
    exit 1
fi

echo -e "${BLUE}=== Bumping pyIRCX Version to ${NEW_VERSION} ===${NC}\n"

# Check if in project root
if [ ! -f "pyircx.py" ]; then
    echo -e "${RED}Error: pyircx.py not found. Run from project root.${NC}"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(grep "__version__" pyircx.py | head -1 | cut -d'"' -f2)
echo -e "Current version: ${YELLOW}${CURRENT_VERSION}${NC}"
echo -e "New version:     ${GREEN}${NEW_VERSION}${NC}\n"

# Confirm with user
read -p "Proceed with version bump? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Get current timestamp
TIMESTAMP=$(date "+%a %b %d %I:%M:%S %p %Z %Y")

echo -e "\n${BLUE}Updating files...${NC}"

# 1. Update pyircx.py
echo -n "  - pyircx.py ... "
sed -i "s/__version__ = \".*\"/__version__ = \"${NEW_VERSION}\"/" pyircx.py
sed -i "s/__created__ = \".*\"/__created__ = \"${TIMESTAMP}\"/" pyircx.py
echo -e "${GREEN}✓${NC}"

# 2. Update README.md if version is mentioned
if [ -f "README.md" ] && grep -q "$CURRENT_VERSION" README.md; then
    echo -n "  - README.md ... "
    sed -i "s/${CURRENT_VERSION}/${NEW_VERSION}/g" README.md
    echo -e "${GREEN}✓${NC}"
fi

# 3. Check if release notes template should be created
RELEASE_FILE="RELEASE_v${NEW_VERSION}.md"
if [ ! -f "$RELEASE_FILE" ]; then
    echo -n "  - Creating $RELEASE_FILE ... "
    cat > "$RELEASE_FILE" << EOF
# pyIRCX v${NEW_VERSION} Release Notes

**Release Date:** $(date "+%B %d, %Y")
**Focus:** [Brief description of main focus]

---

## 🔒 Security Improvements

[List security-related changes]

---

## ✨ New Features

[List new features]

---

## 🐛 Bug Fixes

[List bug fixes]

---

## ⚡ Performance Improvements

[List performance improvements]

---

## 📋 All Changes from v${CURRENT_VERSION}

1. [Change 1]
2. [Change 2]
3. [Change 3]

---

## 📁 Files Modified

### Core Server
- \`pyircx.py\`: [Description]
- [Other files]

---

## 🔧 Upgrade Instructions

### From v${CURRENT_VERSION}

1. **Stop the server:**
   \`\`\`bash
   sudo systemctl stop pyircx
   \`\`\`

2. **Backup your configuration:**
   \`\`\`bash
   sudo cp /etc/pyircx/pyircx_config.json /etc/pyircx/pyircx_config.json.backup
   \`\`\`

3. **Pull the latest code:**
   \`\`\`bash
   cd /opt/pyircx
   sudo git pull
   \`\`\`

4. **Restart the server:**
   \`\`\`bash
   sudo systemctl start pyircx
   sudo systemctl status pyircx
   \`\`\`

5. **Verify logs:**
   \`\`\`bash
   sudo journalctl -u pyircx -n 50
   \`\`\`

---

## ⚠️ Breaking Changes

**[None/List breaking changes]**

---

## 📊 Code Quality Metrics

- **Lines of Code:** ~12,000 (main codebase)
- **Test Coverage:** [Update as needed]
- **Exception Handling:** 100% specific (no bare except clauses)

---

For questions, issues, or contributions, please visit:
https://github.com/0x8007000E/pyIRCX
EOF
    echo -e "${GREEN}✓${NC}"
else
    echo -e "  - ${YELLOW}$RELEASE_FILE already exists (not overwriting)${NC}"
fi

echo -e "\n${GREEN}Version bump complete!${NC}\n"

echo -e "${BLUE}Next steps:${NC}"
echo "  1. Edit $RELEASE_FILE and fill in release notes"
echo "  2. Review changes: git diff"
echo "  3. Test the server: sudo systemctl restart pyircx && systemctl status pyircx"
echo "  4. Run version check: ./utils/version_check.sh ${NEW_VERSION}"
echo "  5. Commit: git add -A && git commit -m 'Release v${NEW_VERSION}'"
echo "  6. Tag: git tag -a v${NEW_VERSION} -m 'Description'"
echo "  7. Push: git push origin main && git push origin --tags"
echo "  8. Release: gh release create v${NEW_VERSION} --title 'Title' --notes-file $RELEASE_FILE"

echo -e "\n${YELLOW}Don't forget to review RELEASE_CHECKLIST.md!${NC}"
