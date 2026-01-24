#!/usr/bin/env python3
"""
Validation script for responses.py

Checks for:
  1. Forbidden characters (\\r, \\n, \\0) in template strings
  2. Invalid format placeholders (must be valid Python identifiers)
  3. Orphaned keys (defined in responses.py but never referenced in code)
  4. Missing keys (referenced in code but not defined in responses.py)
  5. Import check (responses.py loads without errors)

Usage:
    python validate_responses.py          # Run all checks
    python validate_responses.py --quiet  # Only show errors
"""

import os
import re
import sys
import string


# =============================================================================
# CONFIGURATION
# =============================================================================

# Files and directories to scan for key references
SCAN_DIRS = ['.', 'webchat']
SCAN_EXTENSIONS = ['.py']
SKIP_FILES = ['responses.py', 'validate_responses.py']
SKIP_DIRS = ['tests', '__pycache__', '.git', 'node_modules']

# Keys that are used as plain string values (never run through .format() themselves)
# These may contain literal { } characters that are displayed to users as-is
PLAIN_STRING_KEYS = {
    'usage_register',       # Contains {*|<email>} as IRC syntax notation
}

# Format placeholder pattern: matches {name} but not {{ or }}
PLACEHOLDER_PATTERN = re.compile(r'\{([^{}]+)\}')

# Patterns to find key references in code
# Direct dict access: SERVER_MESSAGES['key'] or SERVER_MESSAGES["key"]
SERVER_MESSAGES_PATTERN = re.compile(r"SERVER_MESSAGES\[['\"]([^'\"]+)['\"]\]")
# send_notice / send_server_message: second arg is a key lookup
SEND_NOTICE_PATTERN = re.compile(r"send_(?:notice|server_message)\(\s*\w+,\s*['\"]([^'\"]+)['\"]")
# _send_service_msg: third arg is the key (first arg can be a string literal or variable)
SEND_SERVICE_PATTERN = re.compile(r"_send_service_msg\(\s*(?:\w+|['\"][^'\"]+['\"])\s*,\s*\w+,\s*['\"]([^'\"]+)['\"]")
# get_log_message("key", ...)
GET_LOG_MESSAGE_PATTERN = re.compile(r"get_log_message\(['\"]([^'\"]+)['\"]")
# RESPONSES.get("key") or RESPONSES["key"]
RESPONSES_PATTERN = re.compile(r"RESPONSES(?:\.get)?\(?['\"]([^'\"]+)['\"]")


# =============================================================================
# VALIDATION CHECKS
# =============================================================================

def check_forbidden_chars(templates, dict_name):
    """Check for \\r, \\n, \\0 in template strings"""
    errors = []
    for key, value in templates.items():
        strings = value if isinstance(value, list) else [value]
        for i, s in enumerate(strings):
            if not isinstance(s, str):
                continue
            location = f"{dict_name}['{key}']" + (f"[{i}]" if isinstance(value, list) else "")
            if '\r' in s:
                errors.append(f"  {location}: contains \\r (carriage return)")
            if '\n' in s:
                errors.append(f"  {location}: contains \\n (newline)")
            if '\0' in s:
                errors.append(f"  {location}: contains \\0 (null byte)")
    return errors


def check_placeholders(templates, dict_name, skip_keys=None):
    """Check that all format placeholders are valid Python identifiers"""
    errors = []
    skip_keys = skip_keys or set()
    for key, value in templates.items():
        if key in skip_keys:
            continue
        strings = value if isinstance(value, list) else [value]
        for i, s in enumerate(strings):
            if not isinstance(s, str):
                continue
            location = f"{dict_name}['{key}']" + (f"[{i}]" if isinstance(value, list) else "")
            # Remove escaped braces ({{ and }}) before checking placeholders
            cleaned = s.replace('{{', '').replace('}}', '')
            for match in PLACEHOLDER_PATTERN.finditer(cleaned):
                placeholder = match.group(1)
                # Skip format specs like {0:>10} or {name!r}
                name = placeholder.split(':')[0].split('!')[0].strip()
                if not name:
                    continue
                if not name.isidentifier():
                    errors.append(f"  {location}: invalid placeholder '{{{placeholder}}}' "
                                  f"('{name}' is not a valid Python identifier)")
    return errors


def find_referenced_keys(base_path):
    """Scan codebase for all referenced keys"""
    server_msg_keys = set()
    log_msg_keys = set()
    responses_keys = set()

    for scan_dir in SCAN_DIRS:
        dir_path = os.path.join(base_path, scan_dir)
        if not os.path.isdir(dir_path):
            continue

        for root, dirs, files in os.walk(dir_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for filename in files:
                if not any(filename.endswith(ext) for ext in SCAN_EXTENSIONS):
                    continue
                if filename in SKIP_FILES:
                    continue

                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                except (IOError, UnicodeDecodeError):
                    continue

                # Find all key references
                for match in SERVER_MESSAGES_PATTERN.finditer(content):
                    server_msg_keys.add(match.group(1))

                # send_notice/send_server_message keys reference SERVER_MESSAGES
                for match in SEND_NOTICE_PATTERN.finditer(content):
                    server_msg_keys.add(match.group(1))

                # _send_service_msg third arg is a SERVER_MESSAGES key
                for match in SEND_SERVICE_PATTERN.finditer(content):
                    server_msg_keys.add(match.group(1))

                for match in GET_LOG_MESSAGE_PATTERN.finditer(content):
                    log_msg_keys.add(match.group(1))

                for match in RESPONSES_PATTERN.finditer(content):
                    responses_keys.add(match.group(1))

    return server_msg_keys, log_msg_keys, responses_keys


def check_orphaned_keys(defined_keys, referenced_keys, dict_name):
    """Find keys defined in dict but never referenced in code"""
    orphaned = defined_keys - referenced_keys
    if orphaned:
        return [f"  {dict_name}['{key}']" for key in sorted(orphaned)]
    return []


def check_missing_keys(defined_keys, referenced_keys, dict_name):
    """Find keys referenced in code but not defined in dict"""
    missing = referenced_keys - defined_keys
    if missing:
        return [f"  {dict_name}['{key}']" for key in sorted(missing)]
    return []


# =============================================================================
# MAIN
# =============================================================================

def main():
    quiet = '--quiet' in sys.argv

    # Determine base path (script location)
    base_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_path)

    # =========================================================================
    # Step 1: Import check
    # =========================================================================
    if not quiet:
        print("Checking responses.py import...")

    try:
        sys.path.insert(0, base_path)
        import responses
    except Exception as e:
        print(f"FAIL: responses.py failed to import: {e}")
        return 1

    if not quiet:
        print(f"  OK: Imported successfully")
        print(f"  RESPONSES: {len(responses.RESPONSES)} entries")
        print(f"  SERVER_MESSAGES: {len(responses.SERVER_MESSAGES)} entries")
        print(f"  LOG_MESSAGES: {len(responses.LOG_MESSAGES)} entries")
        print()

    total_errors = 0
    total_warnings = 0

    # =========================================================================
    # Step 2: Forbidden characters
    # =========================================================================
    if not quiet:
        print("Checking for forbidden characters...")

    errors = []
    errors += check_forbidden_chars(responses.RESPONSES, "RESPONSES")
    errors += check_forbidden_chars(responses.SERVER_MESSAGES, "SERVER_MESSAGES")
    errors += check_forbidden_chars(responses.LOG_MESSAGES, "LOG_MESSAGES")
    if hasattr(responses, 'SERVICE_HELP'):
        errors += check_forbidden_chars(responses.SERVICE_HELP, "SERVICE_HELP")

    if errors:
        print(f"  ERRORS ({len(errors)}):")
        for err in errors:
            print(f"    {err}")
        total_errors += len(errors)
    elif not quiet:
        print("  OK: No forbidden characters found")
    if not quiet:
        print()

    # =========================================================================
    # Step 3: Format placeholders
    # =========================================================================
    if not quiet:
        print("Checking format placeholders...")

    errors = []
    errors += check_placeholders(responses.RESPONSES, "RESPONSES")
    errors += check_placeholders(responses.SERVER_MESSAGES, "SERVER_MESSAGES", skip_keys=PLAIN_STRING_KEYS)
    errors += check_placeholders(responses.LOG_MESSAGES, "LOG_MESSAGES")
    if hasattr(responses, 'SERVICE_HELP'):
        errors += check_placeholders(responses.SERVICE_HELP, "SERVICE_HELP")

    if errors:
        print(f"  ERRORS ({len(errors)}):")
        for err in errors:
            print(f"    {err}")
        total_errors += len(errors)
    elif not quiet:
        print("  OK: All placeholders are valid")
    if not quiet:
        print()

    # =========================================================================
    # Step 4: Cross-reference check
    # =========================================================================
    if not quiet:
        print("Scanning codebase for key references...")

    ref_server, ref_log, ref_responses = find_referenced_keys(base_path)

    if not quiet:
        print(f"  Found {len(ref_server)} SERVER_MESSAGES references")
        print(f"  Found {len(ref_log)} get_log_message references")
        print(f"  Found {len(ref_responses)} RESPONSES references")
        print()

    # --- Missing keys (referenced but not defined) ---
    if not quiet:
        print("Checking for missing keys (referenced in code but not defined)...")

    defined_server = set(responses.SERVER_MESSAGES.keys())
    defined_log = set(responses.LOG_MESSAGES.keys())
    defined_responses = set(responses.RESPONSES.keys())

    # send_notice/send_server_message check both SERVER_MESSAGES and RESPONSES,
    # so numeric keys (like "860") in RESPONSES are valid for those lookups
    combined_server = defined_server | defined_responses

    errors = []
    errors += check_missing_keys(combined_server, ref_server, "SERVER_MESSAGES")
    errors += check_missing_keys(defined_log, ref_log, "LOG_MESSAGES")
    errors += check_missing_keys(defined_responses, ref_responses, "RESPONSES")

    if errors:
        print(f"  ERRORS ({len(errors)}) - these will cause KeyError at runtime:")
        for err in errors:
            print(f"    {err}")
        total_errors += len(errors)
    elif not quiet:
        print("  OK: All referenced keys are defined")
    if not quiet:
        print()

    # --- Orphaned keys (defined but not referenced) ---
    if not quiet:
        print("Checking for orphaned keys (defined but not referenced in code)...")

    warnings = []
    warnings += check_orphaned_keys(defined_server, ref_server, "SERVER_MESSAGES")
    warnings += check_orphaned_keys(defined_log, ref_log, "LOG_MESSAGES")
    # Skip RESPONSES orphan check - numeric codes are referenced dynamically

    if warnings:
        print(f"  WARNINGS ({len(warnings)}) - possibly unused:")
        if not quiet:
            print("  (Note: Dynamic key references like f\"prefix_{var}\" cannot be")
            print("   detected by static analysis. Some warnings may be false positives.)")
        for warn in warnings:
            print(f"    {warn}")
        total_warnings += len(warnings)
    elif not quiet:
        print("  OK: All defined keys are referenced")
    if not quiet:
        print()

    # =========================================================================
    # Summary
    # =========================================================================
    print("=" * 60)
    if total_errors == 0 and total_warnings == 0:
        print("PASSED: All checks passed, no issues found.")
    elif total_errors == 0:
        print(f"PASSED with {total_warnings} warning(s).")
    else:
        print(f"FAILED: {total_errors} error(s), {total_warnings} warning(s).")
    print("=" * 60)

    return 1 if total_errors > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
