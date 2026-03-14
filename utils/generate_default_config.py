#!/usr/bin/env python3
"""
Generate default pyircx_config.json from ServerConfig.DEFAULT
"""

import sys
import json
import re
import ast

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
    
    # Parse as a literal Python structure only (no code execution)
    try:
        config = ast.literal_eval(default_str)
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
