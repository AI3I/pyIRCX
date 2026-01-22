#!/usr/bin/env python3
"""
Channel class for pyIRCX Server

This module contains the Channel class representing an IRC channel,
with support for IRCX extensions like access lists, clone channels, and properties.
"""

import asyncio
import fnmatch
import json
import logging
import time
import uuid

from responses import get_log_message

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

logger = logging.getLogger('pyIRCX')


class Channel:
    def __init__(self, name):
        self.name = name
        self.members = {}
        self.owners = set()
        self.hosts = set()
        self.voices = set()
        # Channel modes: a=auth-only, d=clone-enabled, e=is-clone, f=strip-formatting, g=guide-op, h=hidden,
        # i=invite-only, j=no-invitations, k=key, l=limit, m=moderated, n=no-external, p=private, r=registered,
        # s=secret, t=topic-protection, u=knock-mode, w=no-whispers, x=auditorium, y=transcript, z=locked
        mode_chars = CONFIG.get('modes', 'channel', default='adefghijklmnprstuwxyz') if CONFIG else 'adefghijklmnprstuwxyz'
        self.modes = {m: False for m in mode_chars}
        # Apply default channel modes from config
        default_modes = CONFIG.get('modes', 'channel_defaults', default='nt') if CONFIG else 'nt'
        for mode in default_modes:
            if mode in self.modes:
                self.modes[mode] = True
        self.topic = ""
        self.topic_set_by = ""
        self.topic_set_at = 0
        self.props = {}
        self.ban_list = []
        self.gagged = set()
        self.created_at = int(time.time())
        self.registered = False
        self.account_uuid = None
        self.key = None
        self.host_key = None
        self.owner_key = None
        self.voice_key = None
        self.user_limit = None
        self.knock_cooldowns = {}
        # Clone channel support
        self.clone_parent = None      # Name of original channel (if this is a clone)
        self.clone_children = []      # List of clone channel names (if this is original)
        self.clone_index = 0          # Clone number (0 for original, 1+ for clones)
        # IRCX PROP properties
        self.onjoin = None            # Message sent to user after joining (PRIVMSG from channel)
        self.onpart = None            # Message sent to user after parting (NOTICE)
        # Channel access list (IRCX ACCESS command)
        # Each level maps to list of (mask, set_by, set_at, timeout, reason) tuples
        # timeout=0 means permanent, otherwise it's Unix timestamp when entry expires
        self.access_list = {
            'OWNER': [],   # Grants +q on join
            'HOST': [],    # Grants +o on join
            'VOICE': [],   # Grants +v on join
            'GRANT': [],   # Allows access (for +i channels)
            'DENY': []     # Denies access (ban)
        }

    @property
    def is_local(self):
        """Check if this is a local channel (& prefix). Local channels are not persisted."""
        return self.name.startswith('&')

    def has_member(self, nickname):
        return nickname in self.members

    def is_owner(self, nickname):
        return nickname in self.owners

    def is_host(self, nickname):
        return nickname in self.hosts

    def get_prefix(self, nickname):
        """Get the highest prefix for a user (standard behavior)"""
        if nickname in self.owners:
            return "."
        elif nickname in self.hosts:
            return "@"
        elif nickname in self.voices:
            return "+"
        return ""

    def get_all_prefixes(self, nickname):
        """Get all prefixes for a user (IRCv3 multi-prefix)"""
        prefixes = ""
        if nickname in self.owners:
            prefixes += "."
        if nickname in self.hosts:
            prefixes += "@"
        if nickname in self.voices:
            prefixes += "+"
        return prefixes

    def is_banned(self, user):
        user_mask = f"{user.nickname}!{user.username}@{user.host}"
        for ban_mask in self.ban_list:
            if fnmatch.fnmatch(user_mask.lower(), ban_mask.lower()):
                return True
        return False

    def is_clone(self):
        """Return True if this channel is a clone (+e mode)"""
        return self.modes.get('e', False)

    def is_clone_enabled(self):
        """Return True if this channel has clone mode (+d)"""
        return self.modes.get('d', False)

    def is_full(self):
        """Return True if channel is at user limit"""
        if not self.modes.get('l') or not self.user_limit:
            return False
        return len(self.members) >= self.user_limit

    def check_access(self, user, level):
        """Check if user matches any access entry for the given level.
        Returns (matched, reason) tuple. Expired entries are skipped.
        """
        user_mask = f"{user.nickname}!{user.username}@{user.host}"
        now = int(time.time())
        for entry in self.access_list.get(level, []):
            mask, set_by, set_at, timeout, reason = entry
            # Skip expired entries
            if timeout > 0 and now >= timeout:
                continue
            if fnmatch.fnmatch(user_mask.lower(), mask.lower()):
                return True, reason
            # Also check just nickname match
            if fnmatch.fnmatch(user.nickname.lower(), mask.lower()):
                return True, reason
        return False, ""

    def get_access_grants(self, user):
        """Get all access levels that should be granted to user on join.
        Returns set of levels: {'OWNER', 'HOST', 'VOICE', 'GRANT'}
        """
        grants = set()
        for level in ['OWNER', 'HOST', 'VOICE', 'GRANT']:
            matched, _ = self.check_access(user, level)
            if matched:
                grants.add(level)
        return grants

    async def broadcast(self, msg, exclude=None):
        """Broadcast message to all channel members (except exclude) with proper async handling"""
        tasks = []
        for member in self.members.values():
            if member != exclude:
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_user_action(self, source_user, action, exclude=None):
        """
        Broadcast a user action (JOIN/PART/QUIT/etc) with host masking.
        Each viewer sees an appropriately masked prefix based on their staff status.

        Args:
            source_user: The user performing the action
            action: The IRC command and parameters (e.g., "JOIN #channel", "PART #channel :Bye")
            exclude: Optional user to exclude from broadcast
        """
        tasks = []
        for member in self.members.values():
            if member != exclude:
                # Generate message with prefix masked for this viewer
                prefix = source_user.prefix(viewer=member)
                msg = f":{prefix} {action}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def to_dict(self):
        return {
            'name': self.name,
            'topic': self.topic,
            'topic_set_by': self.topic_set_by,
            'topic_set_at': self.topic_set_at,
            'modes': {k: v for k, v in self.modes.items() if v},
            'props': self.props,
            'owners': list(self.owners),
            'hosts': list(self.hosts),
            'voices': list(self.voices),
            'ban_list': self.ban_list,
            'gagged': list(self.gagged),
            'created_at': self.created_at,
            'registered': self.registered,
            'account_uuid': self.account_uuid,
            'key': self.key,
            'host_key': self.host_key,
            'owner_key': self.owner_key,
            'voice_key': self.voice_key,
            'user_limit': self.user_limit,
            'clone_parent': self.clone_parent,
            'clone_children': self.clone_children,
            'clone_index': self.clone_index,
            'onjoin': self.onjoin,
            'onpart': self.onpart,
            'access_list': self.access_list
        }

    def get_properties_json(self):
        """Get channel properties as JSON for storage in registered_channels table"""
        return json.dumps({
            'topic': self.topic,
            'topic_set_by': self.topic_set_by,
            'topic_set_at': self.topic_set_at,
            'owners': list(self.owners),
            'hosts': list(self.hosts),
            'voices': list(self.voices),
            'ban_list': self.ban_list,
            'key': self.key,
            'host_key': self.host_key,
            'owner_key': self.owner_key,
            'voice_key': self.voice_key,
            'user_limit': self.user_limit,
            'onjoin': self.onjoin,
            'onpart': self.onpart,
            'access_list': self.access_list,
            'modes': {k: v for k, v in self.modes.items() if v}  # Only store enabled modes
        })

    def load_properties_json(self, properties_json):
        """Load channel properties from JSON"""
        if not properties_json:
            return
        try:
            props = json.loads(properties_json)
            self.topic = props.get('topic', '')
            self.topic_set_by = props.get('topic_set_by', '')
            self.topic_set_at = props.get('topic_set_at', 0)
            self.owners = set(props.get('owners', []))
            self.hosts = set(props.get('hosts', []))
            self.voices = set(props.get('voices', []))
            self.ban_list = props.get('ban_list', [])
            self.key = props.get('key', None)
            self.host_key = props.get('host_key', None)
            self.owner_key = props.get('owner_key', None)
            self.voice_key = props.get('voice_key', None)
            self.user_limit = props.get('user_limit', None)
            self.onjoin = props.get('onjoin', None)
            self.onpart = props.get('onpart', None)
            self.access_list = props.get('access_list', {
                'OWNER': [], 'HOST': [], 'VOICE': [], 'GRANT': [], 'DENY': []
            })
            # Restore modes
            saved_modes = props.get('modes', {})
            for mode, value in saved_modes.items():
                if mode in self.modes:
                    self.modes[mode] = value
        except Exception as e:
            logger.error(get_log_message("channel_props_error", error=e))

    @classmethod
    def from_dict(cls, data):
        channel = cls(data['name'])
        channel.topic = data.get('topic', '')
        channel.topic_set_by = data.get('topic_set_by', '')
        channel.topic_set_at = data.get('topic_set_at', 0)
        channel.props = data.get('props', {})
        channel.owners = set(data.get('owners', []))
        channel.hosts = set(data.get('hosts', []))
        channel.voices = set(data.get('voices', []))
        channel.ban_list = data.get('ban_list', [])
        channel.gagged = set(data.get('gagged', []))
        channel.created_at = data.get('created_at', int(time.time()))
        channel.registered = data.get('registered', False)
        channel.account_uuid = data.get('account_uuid', None)
        # Generate UUID for registered channels missing one
        if channel.registered and not channel.account_uuid:
            channel.account_uuid = str(uuid.uuid4())
        channel.key = data.get('key', None)
        channel.host_key = data.get('host_key', None)
        channel.owner_key = data.get('owner_key', None)
        channel.voice_key = data.get('voice_key', None)
        channel.user_limit = data.get('user_limit', None)
        channel.clone_parent = data.get('clone_parent', None)
        channel.clone_children = data.get('clone_children', [])
        channel.clone_index = data.get('clone_index', 0)
        channel.onjoin = data.get('onjoin', None)
        channel.onpart = data.get('onpart', None)
        channel.access_list = data.get('access_list', {
            'OWNER': [], 'HOST': [], 'VOICE': [], 'GRANT': [], 'DENY': []
        })
        for mode, value in data.get('modes', {}).items():
            if mode in channel.modes:
                channel.modes[mode] = value
        # Ensure +r mode matches registered flag
        if channel.registered and 'r' in channel.modes:
            channel.modes['r'] = True
        return channel
