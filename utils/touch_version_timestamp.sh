#!/bin/bash
# touch_version_timestamp.sh - Refresh the shared created/build timestamp
# Usage: ./utils/touch_version_timestamp.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ ! -f "version.json" ]; then
    echo -e "${RED}Error: version.json not found. Run from project root.${NC}"
    exit 1
fi

CURRENT_VERSION=$(python3 -c 'import json; print(json.load(open("version.json"))["version"])')
OLD_TIMESTAMP=$(python3 -c 'import json; print(json.load(open("version.json"))["created"])')
NEW_TIMESTAMP=$(date "+%a %b %d %I:%M:%S %p %Z %Y")

echo -e "${BLUE}=== Refreshing pyIRCX Build Timestamp ===${NC}\n"
echo -e "Version:        ${GREEN}${CURRENT_VERSION}${NC}"
echo -e "Old timestamp:  ${YELLOW}${OLD_TIMESTAMP}${NC}"
echo -e "New timestamp:  ${GREEN}${NEW_TIMESTAMP}${NC}\n"

python3 - <<PY
import json
from pathlib import Path

path = Path("version.json")
data = json.loads(path.read_text(encoding="utf-8"))
data["created"] = "${NEW_TIMESTAMP}"
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

echo -e "${GREEN}Timestamp updated in version.json${NC}"
echo -e "${YELLOW}Next step:${NC} review with \`git diff version.json\`"
