#!/usr/bin/env python3
"""
Mode Constants and Utilities for pyIRCX Server

This module contains IRC/IRCX mode definitions, categories, and helper functions.
"""

# ==============================================================================
# USER MODES
# ==============================================================================

# User mode definitions: mode_char -> (description, staff_only, auto_set)
USER_MODES = {
    'a': ('IRC administrator', True, True),      # ADMIN - highest staff level
    'g': ('IRC guide', True, True),              # GUIDE - helper/moderator
    'i': ('Invisible', False, False),            # Hidden from WHO *
    'o': ('IRC operator', True, True),           # SYSOP - operator level
    'r': ('Registered nickname', False, True),   # Auto-set when identified
    's': ('Service', True, True),                # Server bots/services
    'x': ('IRCX mode enabled', False, False),    # IRCX protocol extensions
    'z': ('Gagged', True, False),                # Cannot send messages
    'G': ('God (divine entity)', True, True),    # Special mystical entity
    'S': ('System (omnipresent)', True, True),   # Special mystical entity
}

# Default user modes string for ISUPPORT
USER_MODES_STR = 'agiorsxz'

# Staff modes (confer special privileges)
STAFF_MODES = {'a', 'o', 'g'}

# High staff modes (admin or operator)
HIGH_STAFF_MODES = {'a', 'o'}

# Service modes (bots and services)
SERVICE_MODES = {'s', 'G', 'S'}

# ==============================================================================
# CHANNEL MODES
# ==============================================================================

# Channel mode definitions: mode_char -> (description, requires_param, param_on_set_only)
CHANNEL_MODES = {
    # Standard IRC modes
    'i': ('Invite-only', False, False),
    'k': ('Channel key (password)', True, False),
    'l': ('User limit', True, True),
    'm': ('Moderated', False, False),
    'n': ('No external messages', False, False),
    'p': ('Private', False, False),
    's': ('Secret', False, False),
    't': ('Topic protection', False, False),

    # IRCX extended modes
    'a': ('Auth-only (registered users)', False, False),
    'd': ('Cloneable', False, False),
    'e': ('Is a clone', False, False),
    'f': ('Strip formatting codes', False, False),
    'g': ('Guide auto-op', False, False),
    'h': ('Hidden JOIN/PART/QUIT', False, False),
    'j': ('No invites allowed', False, False),
    'r': ('Registered channel', False, False),
    'u': ('Knock allowed', False, False),
    'w': ('No whispers', False, False),
    'x': ('Auditorium mode', False, False),
    'y': ('Transcript logging', False, False),
    'z': ('Locked (auth + registered)', False, False),
}

# Default channel modes string for ISUPPORT
CHANNEL_MODES_STR = 'adefghijklmnprstuwxyz'

# IRCv3 CHANMODES parameter format: A,B,C,D
# A = list modes (always have parameter)
# B = always require parameter
# C = require parameter only when setting
# D = never have parameter
CHANMODES_PARAM = ',k,l,adefghijmnprstuwxyz'

# Modes that always require a parameter
PARAM_MODES = {'k'}

# Modes that require parameter only when setting (+)
PARAM_ON_SET_MODES = {'l'}

# Modes with no parameters
NO_PARAM_MODES = {'a', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'm', 'n', 'p', 'r', 's', 't', 'u', 'w', 'x', 'y', 'z'}

# List modes (can have multiple entries)
LIST_MODES = {'b'}  # Bans

# Prefix modes (channel membership levels)
PREFIX_MODES = {
    'q': ('owner', '.'),    # Channel owner
    'o': ('host', '@'),     # Channel operator/host
    'v': ('voice', '+'),    # Voice
}

# Order of prefix display (highest to lowest)
PREFIX_ORDER = ['q', 'o', 'v']

# ==============================================================================
# MODE CATEGORIES
# ==============================================================================

# Modes that can only be set by staff
STAFF_ONLY_CHANNEL_MODES = {'z'}

# Modes that are auto-set (not user-settable)
AUTO_SET_CHANNEL_MODES = {'e', 'r'}

# Modes implied by +z (locked channel)
LOCKED_CHANNEL_MODES = {'z', 'a', 'r'}

# Common display modes for LIST/LISTX
DISPLAY_MODES = ['t', 'n', 's', 'm', 'i', 'h', 'p', 'k', 'l', 'u', 'd']

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_mode_description(mode_char, is_channel=False):
    """Get human-readable description of a mode."""
    if is_channel:
        mode_info = CHANNEL_MODES.get(mode_char)
        if mode_info:
            return mode_info[0]
        prefix_info = PREFIX_MODES.get(mode_char)
        if prefix_info:
            return f"Channel {prefix_info[0]}"
    else:
        mode_info = USER_MODES.get(mode_char)
        if mode_info:
            return mode_info[0]
    return f"Unknown mode {mode_char}"


def mode_requires_param(mode_char, adding=True):
    """Check if a channel mode requires a parameter."""
    if mode_char in PARAM_MODES:
        return True
    if mode_char in PARAM_ON_SET_MODES and adding:
        return True
    if mode_char in PREFIX_MODES:
        return True  # Always need target nick
    if mode_char in LIST_MODES:
        return True  # Always need mask
    return False


def is_valid_user_mode(mode_char):
    """Check if a character is a valid user mode."""
    return mode_char in USER_MODES


def is_valid_channel_mode(mode_char):
    """Check if a character is a valid channel mode or prefix mode."""
    return mode_char in CHANNEL_MODES or mode_char in PREFIX_MODES or mode_char in LIST_MODES


def get_prefix_for_mode(mode_char):
    """Get the prefix character for a channel membership mode."""
    if mode_char in PREFIX_MODES:
        return PREFIX_MODES[mode_char][1]
    return None


def get_mode_for_prefix(prefix_char):
    """Get the mode character for a prefix."""
    for mode, (name, prefix) in PREFIX_MODES.items():
        if prefix == prefix_char:
            return mode
    return None


def build_channel_mode_string(modes_dict, include_params=False, channel=None):
    """Build a mode string from a modes dictionary.

    Args:
        modes_dict: Dict of mode_char -> bool/value
        include_params: Whether to include parameter values
        channel: Channel object for getting param values (key, limit)

    Returns:
        str: Mode string like "+tnsk" or "+tnsk secretkey" with params
    """
    active_modes = [k for k, v in modes_dict.items() if v]
    mode_str = ''.join(sorted(active_modes))

    if not include_params or not channel:
        return mode_str

    params = []
    if 'l' in active_modes and hasattr(channel, 'user_limit') and channel.user_limit:
        params.append(str(channel.user_limit))
    if 'k' in active_modes and hasattr(channel, 'key') and channel.key:
        params.append(channel.key)

    if params:
        return f"{mode_str} {' '.join(params)}"
    return mode_str
