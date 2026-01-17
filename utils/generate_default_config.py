#!/usr/bin/env python3
"""
Generate default pyircx_config.json from ServerConfig.DEFAULT

Copyright (C) 2026 pyIRCX Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import json
import re

def extract_default_config(pyircx_path):
    """Extract DEFAULT dict from pyircx.py"""
    with open(pyircx_path, 'r') as f:
        content = f.read()
    
    # Find ServerConfig.DEFAULT 
    match = re.search(r'class ServerConfig:.*?DEFAULT = ({.*?)\n\n    def ', content, re.DOTALL)
    if not match:
        print("Error: Could not find ServerConfig.DEFAULT", file=sys.stderr)
        return None
    
    # Extract the dict string
    default_str = match.group(1)
    
    # Parse it as Python code
    try:
        config = eval(default_str)
        return config
    except Exception as e:
        print(f"Error parsing DEFAULT: {e}", file=sys.stderr)
        return None

def main():
    pyircx_path = sys.argv[1] if len(sys.argv) > 1 else '/opt/pyircx/pyircx.py'
    output_path = sys.argv[2] if len(sys.argv) > 2 else '/etc/pyircx/pyircx_config.json'
    
    config = extract_default_config(pyircx_path)
    if config is None:
        sys.exit(1)
    
    with open(output_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Generated default config at {output_path}")

if __name__ == '__main__':
    main()
