#!/usr/bin/env python3
"""
Utility to generate bcrypt hashes for server link passwords

Usage:
    python3 hash_link_password.py <password>

Or for interactive mode (password not visible in shell history):
    python3 hash_link_password.py

The generated hash should be placed in the 'password' field of the
linking.links configuration in /etc/pyircx/pyircx_config.json

Example config:
{
  "linking": {
    "enabled": true,
    "links": [
      {
        "name": "hub.example.com",
        "host": "10.0.0.1",
        "port": 7000,
        "password": "$2b$12$abcdefghijklmnopqrstuvwxyz123456789..."
      }
    ]
  }
}
"""

import sys
import bcrypt
import getpass


def hash_password(password: str) -> str:
    """Generate bcrypt hash for a password"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode('utf-8')


def main():
    if len(sys.argv) > 1:
        # Password provided as command line argument
        password = sys.argv[1]
    else:
        # Interactive mode - prompt for password
        password = getpass.getpass("Enter server link password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords do not match!", file=sys.stderr)
            sys.exit(1)

    if not password:
        print("Password cannot be empty!", file=sys.stderr)
        sys.exit(1)

    # Generate hash
    password_hash = hash_password(password)

    print("\nBcrypt hash generated successfully:")
    print(password_hash)
    print("\nAdd this hash to your linking.links[].password configuration.")
    print("The hash is compatible with both incoming and outgoing server links.")


if __name__ == '__main__':
    main()
