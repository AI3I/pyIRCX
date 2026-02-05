#!/usr/bin/env python3
"""
Help Text Module for pyIRCX Server

This module contains all help text organized as data structures.
Topics can have regular lines, staff-only lines, admin-only lines, and high_staff-only lines.
Placeholders like {nickname} are replaced at runtime.
"""

import difflib

# Topic aliases - maps alternate names to canonical topic names
TOPIC_ALIASES = {
    "J": "JOIN",
    "LEAVE": "PART",
    "UMODE": "MODE",
    "CMODE": "MODE",
    "PROPERTY": "PROP",
    "PROPERTIES": "PROP",
    "MSG": "PRIVMSG",
    "MESSAGE": "PRIVMSG",
    "BACK": "AWAY",
    "2FA": "MFA",
    "TOTP": "MFA",
    "CHANGEPASS": "CHGPASS",
    "AUTHENTICATE": "AUTH",
    "DEAUTH": "DROP",
    "NICKNAME": "NICK",
    "EXIT": "QUIT",
    "BYE": "QUIT",
    "ALIAS": "ALIASES",
    "SHORTCUTS": "ALIASES",
    "DATA": "DATA",  # Also REQUEST, REPLY
    "REQUEST": "DATA",
    "REPLY": "DATA",
}

# All help topics organized by category
HELP_TOPICS = {
    # Index - shown when no topic specified
    "INDEX": {
        "lines": [
            "=== pyIRCX Help Topics ===",
            "Use /HELP <topic> for detailed information:",
            "  COMMANDS - All available commands",
            "  CHANNEL - Channel management commands",
            "  REGISTER - Nickname and channel registration",
            "  IRCX - IRCX-specific commands",
            "  USERMODES - User mode flags",
            "  CHANMODES - Channel mode flags",
            "  SERVICES - Available services",
        ],
        "staff_lines": [
            "  STAFF - Staff commands",
        ],
        "footer": [
            "Example: /HELP COMMANDS",
        ],
    },

    "COMMANDS": {
        "lines": [
            "=== All Commands ===",
            "Basic: NICK USER PASS QUIT PING PONG",
            "Messages: PRIVMSG MSG NOTICE",
            "Channels: JOIN PART KICK INVITE TOPIC NAMES LIST MODE",
            "Registration: REGISTER IDENTIFY UNREGISTER CHGPASS MFA (see /HELP REGISTER)",
            "User Info: WHO WHOIS WHOWAS ISON USERHOST AWAY",
            "Server Info: LUSERS MOTD INFO TIME VERSION STATS LINKS MAP ADMIN",
            "IRCX: IRCX ACCESS PROP EVENT WHISPER KNOCK TRANSCRIPT DATA",
            "Utility: SILENCE WATCH HELP",
            "Type /HELP <command> for details (e.g., /HELP WHOWAS)",
        ],
        "staff_lines": [
            "Staff: KILL STAFF CONFIG PROFANITY (see /HELP STAFF)",
        ],
    },

    "CHANNEL": {
        "lines": [
            "=== Channel Commands ===",
            "JOIN #channel [key] - Join a channel",
            "PART #channel [reason] - Leave a channel",
            "TOPIC #channel [text] - View/set channel topic",
            "NAMES #channel - List users in channel",
            "LIST [pattern] - List all channels",
            "INVITE nick #channel - Invite user to channel",
            "KICK #channel nickname [reason] - Remove user from channel",
            "MODE #channel [modes] - View/change channel modes",
            "Channel ranks: . (owner), @ (host), + (voice)",
        ],
    },

    "REGISTER": {
        "lines": [
            "=== Registration Commands ===",
            "Nickname Registration:",
            "  REGISTER <account> <email|*> <password> - Register your nickname",
            "  IDENTIFY <account> <password> - Log into registered nickname",
            "  UNREGISTER <account> - Delete your registration",
            "  MFA ENABLE - Enable two-factor authentication",
            "  MFA DISABLE <code> - Disable two-factor authentication",
            "  MFA VERIFY <code> - Complete MFA login",
            "Channel Registration:",
            "  REGISTER <#channel> [password] - Register a channel (owner only)",
            "  UNREGISTER <#channel> - Unregister a channel (owner only)",
            "Alternative: Use /MSG Registrar for NickServ-style interface",
            "Registered users get +r mode and can use locked channels",
        ],
    },

    "IRCX": {
        "lines": [
            "=== IRCX Commands ===",
            "IRCX - Enable IRCX mode",
            "CREATE <#channel> [key] - Create/join channel (alias for JOIN)",
            "ACCESS <#channel> LIST [level] - List access entries",
            "ACCESS <#channel> ADD <level> <mask> [reason] - Add access entry",
            "ACCESS <#channel> DELETE <level> <mask> - Remove access entry",
            "ACCESS <#channel> CLEAR <level> - Clear access list",
            "PROP <#channel> [property [value]] - View/set channel properties",
            "LISTX [pattern] - Extended channel list with modes",
            "WHISPER <#channel> <nickname> :[message] - Private message in channel",
            "DATA <#channel> <ID> :<data> - Send structured data to channel",
            "Access levels: OWNER, HOST, VOICE, GRANT, DENY",
        ],
    },

    "USERMODES": {
        "lines": [
            "=== User Modes ===",
            "  +b - Bot (marks user as a bot, shown in WHOIS and message tags)",
            "  +i - Invisible (hidden from WHO *)",
            "  +x - IRCX mode enabled",
            "  +r - Registered nickname (auto-set)",
            "=== Staff Modes ===",
            "  +a - IRC administrator (ADMIN)",
            "  +o - IRC operator (SYSOP)",
            "  +g - IRC guide (GUIDE)",
            "=== Other Modes ===",
            "  +s - Service (server bots and service accounts)",
            "  +z - Gagged (you cannot send messages to channels or users)",
            "Example: /MODE yournick +b (to mark yourself as a bot)",
        ],
    },

    "CHANMODES": {
        "lines": [
            "=== Channel Modes ===",
            "",
            "Standard IRC Modes:",
            "  +i - Invite-only: Users must be explicitly invited to join",
            "  +m - Moderated: Only users with voice (+) or higher can speak",
            "  +n - No external: Only channel members can send messages",
            "  +p - Private: Channel hidden from /WHOIS (but shown in /LIST)",
            "  +s - Secret: Channel hidden from /LIST and /WHOIS",
            "  +t - Topic protection: Only channel hosts can change the topic",
            "  +k <key> - Key: Password required to join",
            "  +l <limit> - Limit: Maximum number of users allowed (server cap applies)",
            "",
            "IRCX Extended Modes:",
            "  +a - Authenticated only: Only registered and identified users can join",
            "  +d - Cloneable: Allows users to create channel clones",
            "  +e - Clone: This channel is a clone of another channel",
            "  +f - No formatting: Formatting codes are removed from messages",
            "  +g - Guide access: IRC guides automatically receive owner (.) status",
            "  +h - Hidden: JOIN/PART/QUIT messages are not shown",
            "  +j - No invites: INVITE command is disabled",
            "  +r - Registered: Channel is registered (auto-set)",
            "  +u - Knock allowed: KNOCK requests allowed on invite-only channels",
            "  +w - No whispers: WHISPER command is disabled",
            "  +x - Auditorium: Only hosts see the full user list",
            "  +y - Transcript: Channel messages are logged to server",
            "  +z - Locked: Channel requires auth and is registered (+a +r auto-set)",
            "",
            "Examples:",
            "  /MODE #channel +im - Set invite-only and moderated",
            "  /MODE #channel +k secretpass - Set channel password",
            "  /MODE #channel +l 100 - Set user limit to 100",
            "  /MODE #channel -s+p - Remove secret, add private",
        ],
    },

    "SERVICES": {
        "lines": [
            "=== Services ===",
            "System - Service directory",
            "  /MSG System",
            "Registrar - Nickname registration",
            "  Commands: REGISTER IDENTIFY DROP INFO CHANNEL SET MFA",
            "  /MSG Registrar HELP",
            "Messenger - Offline messages",
            "  Commands: SEND READ DELETE COUNT",
            "  /MSG Messenger HELP",
            "NewsFlash - Network news",
            "  Commands: LIST ADD DELETE PUSH",
            "  /MSG NewsFlash HELP",
            "ServiceBot - Channel monitoring",
            "  Commands: HELP STATUS",
            "  /MSG ServiceBot01 HELP",
        ],
    },

    "STAFF": {
        "staff_only": True,
        "lines": [
            "=== Staff Commands ===",
            "",
            "Staff Levels:",
            "  ADMIN - IRC administrator (+a mode)",
            "  SYSOP - IRC operator (+o mode)",
            "  GUIDE - IRC guide (+g mode)",
            "",
            "KILL Commands:",
            "  KILL <nickname> [reason] - Disconnect a user",
            "  KILL <#channel> [reason] - Destroy channel and kick all users",
            "  KILL <pattern> [reason] - Kill users by IP/hostmask (e.g., 192.168.1.*)",
            "",
            "STAFF Management:",
            "  STAFF LIST - List all staff accounts",
            "  STAFF ADD <username> <level> - Add staff account (ADMIN/SYSOP/GUIDE)",
            "  STAFF DELETE <username> - Remove staff account",
            "  STAFF SET <username> <level> - Change staff level",
            "  STAFF PASS <username> <password> - Change staff password",
            "  STAFF MFA <username> ENABLE/DISABLE/STATUS - Manage MFA (ADMIN only)",
        ],
        "admin_lines": [
            "",
            "ADMIN-only Commands:",
            "  CONFIG GET <key> - View config value",
            "  CONFIG SET <key> <value> - Update config",
            "  PROFANITY - Manage profanity filter (see /HELP PROFANITY)",
            "  BROADCAST <message> - Send to all users",
        ],
    },

    # Individual command help
    "JOIN": {
        "lines": [
            "=== JOIN Command ===",
            "Usage: /JOIN <#channel> [key]",
            "Join a channel. If the channel doesn't exist, it will be created.",
            "Examples:",
            "  /JOIN #lobby - Join the lobby channel",
            "  /JOIN #private secretpass - Join with password",
            "  /JOIN #chat,#help - Join multiple channels",
        ],
    },

    "PART": {
        "lines": [
            "=== PART Command ===",
            "Usage: /PART <#channel> [reason]",
            "Leave a channel you're currently in.",
            "Examples:",
            "  /PART #lobby - Leave the lobby",
            "  /PART #chat Goodbye! - Leave with a message",
        ],
    },

    "MODE": {
        "lines": [
            "=== MODE Command ===",
            "Usage: /MODE <target> [+/-modes] [parameters]",
            "Set or view modes on yourself or a channel.",
            "User mode examples:",
            "  /MODE {nickname} - View your current modes",
            "  /MODE nickname +i - Set yourself invisible",
            "  /MODE nickname -i - Remove invisible mode",
            "Channel mode examples:",
            "  /MODE #channel - View channel modes",
            "  /MODE #channel +m - Set moderated",
            "  /MODE #channel +o alice - Give operator to alice",
            "  /MODE #channel +k password - Set channel key",
            "See: /HELP USERMODES and /HELP CHANMODES",
        ],
    },

    "TOPIC": {
        "lines": [
            "=== TOPIC Command ===",
            "Usage: /TOPIC <#channel> [new topic]",
            "View or change the topic of a channel.",
            "Examples:",
            "  /TOPIC #lobby - View current topic",
            "  /TOPIC #lobby Welcome to the lobby! - Set new topic",
            "Note: On +t channels, only hosts can change the topic",
        ],
    },

    "KICK": {
        "lines": [
            "=== KICK Command ===",
            "Usage: /KICK <#channel> <nickname> [reason]",
            "Remove a user from a channel (requires host/owner).",
            "Examples:",
            "  /KICK #lobby spammer - Kick user",
            "  /KICK #lobby alice Flooding - Kick with reason",
        ],
    },

    "INVITE": {
        "lines": [
            "=== INVITE Command ===",
            "Usage: /INVITE <nickname> <#channel>",
            "Invite a user to join a channel.",
            "Examples:",
            "  /INVITE alice #lobby - Invite alice to #lobby",
            "Note: Required for +i (invite-only) channels",
        ],
    },

    "WHOIS": {
        "lines": [
            "=== WHOIS/WHO Commands ===",
            "WHOIS Usage: /WHOIS <nickname>",
            "  Get detailed information about a user",
            "  Example: /WHOIS alice",
            "WHO Usage: /WHO <pattern>",
            "  List users matching a pattern",
            "  Examples:",
            "    /WHO #lobby - List users in #lobby",
            "    /WHO *alice* - Find users with 'alice' in nick",
            "    /WHO *@*.com - Find users by hostname",
        ],
    },

    "ACCESS": {
        "lines": [
            "=== ACCESS Command (IRCX) ===",
            "Manage channel access control lists (channel-level) or server access (staff).",
            "",
            "Channel-level ACCESS:",
            "  Usage: /ACCESS <#channel> <action> [level] [mask] [reason]",
            "  Actions: LIST, ADD, DELETE, CLEAR",
            "  Levels: OWNER, HOST, VOICE, GRANT, DENY",
            "  Examples:",
            "    /ACCESS #lobby LIST - View all entries",
            "    /ACCESS #lobby ADD HOST alice!*@* Trusted - Give host",
            "    /ACCESS #lobby ADD DENY *!*@spammer.com Banned",
            "    /ACCESS #lobby DELETE DENY *!*@spammer.com",
        ],
        "staff_lines": [
            "",
            "Server-level ACCESS (Staff):",
            "  Usage: /ACCESS <scope> <action> [level] [mask] [reason]",
            "  Control server/network-wide access restrictions",
            "  Scope: $ = local server only, * = all linked servers",
            "  Levels: GRANT (allow), DENY (ban)",
            "  Examples:",
            "    /ACCESS $ LIST - View local server access list",
            "    /ACCESS $ ADD DENY *!*@badhost.com Local ban",
            "    /ACCESS * ADD DENY *!*@spammer.net Network-wide ban",
            "    /ACCESS $ DELETE DENY *!*@badhost.com",
        ],
    },

    "PROP": {
        "lines": [
            "=== PROP Command (IRCX) ===",
            "Usage: /PROP <#channel> [property] [value]",
            "View or set extended channel properties.",
            "Examples:",
            "  /PROP #lobby - List all properties (hosts can view except OWNERKEY)",
            "  /PROP #lobby OWNERKEY mypassword - Set owner key (owner only)",
            "  /PROP #lobby TOPIC Welcome! - Set topic via PROP (owner only)",
            "  /PROP #lobby LAG 0 - Set lag property (owner only)",
            "Common properties: OWNERKEY, HOSTKEY, VOICEKEY, MEMBERKEY, TOPIC, ONJOIN, ONPART",
            "Note: Only channel owners can set properties",
        ],
    },

    "WHISPER": {
        "lines": [
            "=== WHISPER Command (IRCX) ===",
            "Usage: /WHISPER <#channel> <nickname> <message>",
            "Send a private message to someone in a channel.",
            "Only the target user sees the message.",
            "Examples:",
            "  /WHISPER #lobby alice Hey, check your messages",
            "Note: You cannot use this in channels with +w mode (whispers disabled)",
        ],
    },

    "DATA": {
        "lines": [
            "=== DATA / REQUEST / REPLY Commands (IRCX) ===",
            "Send tagged, structured data to users or channels.",
            "Requires IRCX mode (+x). Only received by IRCX-enabled clients.",
            "",
            "Syntax: /DATA <target> <tag> :<message>",
            "",
            "Command Types:",
            "  DATA - Send tagged data (one-way communication)",
            "  REQUEST - Send data expecting a reply",
            "  REPLY - Respond to a REQUEST",
            "",
            "Tag Format:",
            "  - 1-15 characters: letters, numbers, periods",
            "  - Must start with a letter",
            "  - Recommended: ORG.APP.FEATURE (e.g., MYORG.AVATAR)",
            "",
            "Reserved Tag Prefixes (require privileges):",
            "  ADM.* - IRC administrator (+a) only",
            "  SYS.* - IRC operator (+o) only",
            "  GDE.* - IRC guide (+g) only",
            "  OWN.* - Channel owner (+q) only",
            "  HST.* - Channel host (+o) only",
            "",
            "Examples:",
            "  /DATA #lobby MYAPP.AVATAR https://example.com/avatar.png",
            "  /REQUEST alice MYAPP.STATUS Get status",
            "  /REPLY alice MYAPP.STATUS Online",
        ],
        "staff_lines": [
            "  /DATA #lobby SYS.AD.BANNER <banner-url> (operator only)",
        ],
    },

    "NOTICE": {
        "lines": [
            "=== NOTICE Command ===",
            "Usage: /NOTICE <target> <message>",
            "Send a notice to a user or channel (no auto-reply expected).",
            "Examples:",
            "  /NOTICE alice Important: Server maintenance at 10 PM",
            "  /NOTICE #lobby Server will restart in 5 minutes",
        ],
        "high_staff_lines": [
            "  /NOTICE $ <message> - Server-wide notice (IRC operator or administrator only)",
            "  /NOTICE * <message> - Network-wide notice (IRC administrator only)",
        ],
        "footer": [
            "Note: NOTICE is typically used for automated responses and shouldn't trigger auto-replies",
        ],
    },

    "IDENTIFY": {
        "lines": [
            "=== Registration Commands ===",
            "REGISTER - Claim your nickname",
            "  Usage: /REGISTER <account> <email|*> <password>",
            "  Example: /REGISTER myaccount me@example.com mypassword",
            "  Example: /REGISTER myaccount * mypassword (no email)",
            "IDENTIFY - Log into your registered nickname",
            "  Usage: /IDENTIFY <account> <password>",
            "  Example: /IDENTIFY myaccount mypassword",
            "UNREGISTER - Delete your registration",
            "  Usage: /UNREGISTER <account>",
            "Alternative: /MSG Registrar or /MSG NickServ",
            "See also: /HELP MFA",
        ],
    },

    "UNREGISTER": {
        "alias": "IDENTIFY",
    },

    "MFA": {
        "lines": [
            "=== MFA (Two-Factor Authentication) ===",
            "Add extra security to your account with authenticator apps.",
            "MFA ENABLE - Enable two-factor authentication",
            "  Usage: /MFA ENABLE",
            "  You'll receive a QR code to scan with your authenticator app",
            "  (Google Authenticator, Authy, etc.)",
            "MFA VERIFY - Complete login with MFA code",
            "  Usage: /MFA VERIFY <6-digit-code>",
            "  Example: /MFA VERIFY 123456",
            "MFA DISABLE - Turn off MFA",
            "  Usage: /MFA DISABLE <6-digit-code>",
        ],
    },

    "AUTH": {
        "staff_only": True,
        "non_staff_lines": [
            "AUTH - Secure authentication for IRC guides, operators, and administrators",
            "This command is for IRC guides, operators, and administrators only.",
        ],
        "lines": [
            "=== AUTH Command (IRC guide/operator/administrator only) ===",
            "Securely elevate to IRC guide, operator, or administrator privileges after connecting.",
            "Usage: /AUTH <username> <password>",
            "Credentials are never transmitted until after connection established.",
            "If MFA is enabled, you will be prompted for verification code.",
            "",
            "MFA Commands:",
            "  /AUTH VERIFY <code> - Complete MFA verification",
            "  /AUTH ENABLE <password> - Enable MFA for your account",
            "  /AUTH DISABLE <password> <code> - Disable MFA (requires code)",
            "",
            "Examples:",
            "  /AUTH admin mypassword - Authenticate as IRC administrator",
            "  /AUTH VERIFY 123456 - Complete MFA login",
            "  /AUTH ENABLE mypassword - Set up two-factor authentication",
            "",
            "Security: Progressive delays on failures, account lockout after 5 attempts,",
            "optional SSL/TLS requirement, all attempts logged to #System channel.",
            "See also: /HELP DROP, /HELP STAFF",
        ],
    },

    "DROP": {
        "staff_only": True,
        "non_staff_lines": [
            "DROP - De-authentication for IRC guides, operators, and administrators",
            "This command is for IRC guides, operators, and administrators only.",
        ],
        "lines": [
            "=== DROP Command (IRC guide/operator/administrator only) ===",
            "Voluntarily drop IRC guide, operator, or administrator privileges.",
            "Usage: /DROP",
            "Removes your +a, +o, or +g mode and reverts to regular user.",
            "You can re-authenticate with /AUTH command when needed.",
            "",
            "Use cases:",
            "  - Testing features as a regular user",
            "  - Participating in events without staff status",
            "  - Temporarily reducing privileges for security",
            "See also: /HELP AUTH",
        ],
    },

    "LIST": {
        "lines": [
            "=== LIST / LISTX Commands ===",
            "LIST - Basic channel listing",
            "  Usage: /LIST [pattern]",
            "  Examples: /LIST, /LIST *help*, /LIST #lobby",
            "LISTX - Extended channel listing (IRCX mode required)",
            "  Usage: /LISTX [pattern]",
            "  Shows channel modes in addition to name, users, and topic",
            "  Format: <channel> <users> <modes> :<topic>",
            "  Example output: #lobby 15 +tn :Welcome to the lobby",
            "Note: Secret (+s) and hidden (+h) channels are hidden unless you're in them",
        ],
    },

    "LISTX": {
        "alias": "LIST",
    },

    "PRIVMSG": {
        "lines": [
            "=== PRIVMSG Command ===",
            "Usage: /MSG <target> <message>",
            "Send a message to a user or channel.",
            "Examples:",
            "  /MSG alice Hello! - Send private message to alice",
            "  /MSG #lobby Hello everyone! - Send to channel",
            "  /MSG Registrar HELP - Talk to a service",
            "  /MSG NickServ IDENTIFY password - Alternative syntax",
        ],
        "high_staff_lines": [
            "  /MSG $ <message> - Server-wide message (IRC operator or administrator only)",
            "  /MSG * <message> - Network-wide message (IRC administrator only)",
        ],
    },

    "AWAY": {
        "lines": [
            "=== AWAY Command ===",
            "Usage: /AWAY [message]",
            "Mark yourself as away with an optional message, or return from away status.",
            "Examples:",
            "  /AWAY Gone for lunch - Mark yourself away with message",
            "  /AWAY - When not away: marks you away with no message",
            "  /AWAY - When already away: returns you from away status",
            "Note: People will see your away message when they WHOIS you or message you",
        ],
    },

    "KILL": {
        "staff_only": True,
        "lines": [
            "=== KILL Command (IRC operator/administrator only) ===",
            "Usage: /KILL <target> [reason]",
            "Disconnect users or destroy channels. Requires IRC operator or administrator privileges.",
            "Examples:",
            "  /KILL alice Spamming - Disconnect user",
            "  /KILL #badchannel - Destroy channel and kick all users",
            "  /KILL 192.168.1.* Network abuse - Kill by IP pattern",
            "Use with caution!",
        ],
    },

    "WHOWAS": {
        "lines": [
            "=== WHOWAS Command ===",
            "Usage: /WHOWAS <nickname> [count]",
            "Show information about a user who has disconnected.",
            "Examples:",
            "  /WHOWAS alice - Show last known info for alice",
            "  /WHOWAS bob 5 - Show up to 5 history entries for bob",
            "Note: History is limited and may expire after a period of time",
        ],
    },

    "NAMES": {
        "lines": [
            "=== NAMES Command ===",
            "Usage: /NAMES [#channel]",
            "List all users in a channel with their status.",
            "Examples:",
            "  /NAMES #lobby - List all users in #lobby",
            "  /NAMES - List users in all visible channels",
            "Prefixes: . = owner, @ = host, + = voice",
            "Note: Only shows channels you have access to",
        ],
    },

    "KNOCK": {
        "lines": [
            "=== KNOCK Command (IRCX) ===",
            "Usage: /KNOCK <#channel> [message]",
            "Request an invitation to an invite-only channel.",
            "Examples:",
            "  /KNOCK #private - Request access",
            "  /KNOCK #vip I'd like to join - Request with message",
            "Note: Channel owners and hosts will be notified of your request",
            "Rate limited to once per minute per channel to prevent abuse",
        ],
    },

    "EVENT": {
        "lines": [
            "=== EVENT Command (IRCX) ===",
            "Usage: /EVENT ADD <type> <mask>",
            "Subscribe to server events by registering event traps.",
            "Examples:",
            "  /EVENT ADD JOIN * - Notify when anyone joins any channel",
            "  /EVENT ADD PART #lobby - Notify when someone leaves #lobby",
            "Note: Advanced IRCX feature for monitoring channel activity",
        ],
        "staff_lines": [
            "",
            "=== EVENT Command (IRCX - Staff Only) ===",
            "Real-time server monitoring for IRC operators and administrators.",
            "Requires: IRCX mode (+x) and operator or administrator privileges (+o or +a)",
            "",
            "EVENT ADD <class> [<mask>] - Subscribe to events",
            "EVENT DELETE <class> [<mask>] - Unsubscribe from events",
            "EVENT LIST [<class>] - List active subscriptions",
            "",
            "Event Classes:",
            "  CONNECT - User logon events",
            "  CHANNEL - Channel create/delete/topic events",
            "  MEMBER - Channel join/part/kick/quit events",
            "  SERVER - Server link/split events",
            "  SOCKET - Accepted but never fires",
            "  USER - User logoff/nick/mode events",
            "",
            "Examples:",
            "  /EVENT ADD MEMBER *!*@* - Monitor all channel membership changes",
            "  /EVENT ADD CONNECT *!*@192.168.* - Monitor local network connections",
            "  /EVENT DELETE MEMBER *!*@* - Stop monitoring membership",
            "  /EVENT LIST - Show all active subscriptions",
        ],
    },

    "TRANSCRIPT": {
        "lines": [
            "=== TRANSCRIPT Command (IRCX) ===",
            "Usage: /TRANSCRIPT <#channel> [lines] [offset]",
            "View channel transcript logs if transcript mode (+y) is enabled.",
            "Examples:",
            "  /TRANSCRIPT #lobby - View last 50 messages",
            "  /TRANSCRIPT #lobby 100 - View last 100 messages",
            "  /TRANSCRIPT #lobby 50 100 - View 50 messages starting from offset 100",
            "Note: Requires channel owner status or IRC operator/administrator",
            "To enable logging: Use /MODE #channel +y (owner only)",
        ],
    },

    "STATS": {
        "lines": [
            "=== STATS Command ===",
            "Usage: /STATS [query]",
            "Display server statistics and information.",
            "Examples:",
            "  /STATS - Show general server statistics",
            "  /STATS u - Show server uptime",
            "Use /STATS ? for complete list of available queries",
            "Note: Many detailed stats require staff privileges (guide, operator, or administrator)",
        ],
    },

    "PROFANITY": {
        "high_staff_only": True,
        "lines": [
            "=== PROFANITY Command (IRC operator/administrator only) ===",
            "Manage ServiceBot profanity filter in real-time.",
            "Commands:",
            "  /PROFANITY LIST - View current configuration",
            "  /PROFANITY ADD WORD <word> - Add word to filter",
            "  /PROFANITY ADD PATTERN <regex> - Add regex pattern",
            "  /PROFANITY DELETE WORD <word> - Remove word",
            "  /PROFANITY DELETE PATTERN <regex> - Remove pattern",
            "  /PROFANITY ENABLE - Enable filter",
            "  /PROFANITY DISABLE - Disable filter",
            "  /PROFANITY TEST <text> - Test if text matches",
            "Examples:",
            "  /PROFANITY ADD PATTERN (spam|viagra) - Block variations",
            "  /PROFANITY TEST Check this message - Test before adding",
            "Changes persist to config file automatically",
        ],
    },

    "CONFIG": {
        "high_staff_only": True,
        "lines": [
            "=== CONFIG Command (IRC operator/administrator) ===",
            "Usage: /CONFIG <GET|SET> <key> [value]",
            "View or modify server configuration at runtime.",
            "Examples:",
            "  /CONFIG GET server.motd - View MOTD setting",
            "  /CONFIG SET server.max_users 1000 - Update max users",
            "Note: Changes persist to config file. Use with caution.",
        ],
    },

    "INFO": {
        "lines": [
            "=== INFO Command ===",
            "Usage: /INFO",
            "Display detailed server information including:",
            "  - Server version and software",
            "  - Supported protocols (IRC, IRCX)",
            "  - Special features and capabilities",
            "  - Contact information",
        ],
    },

    "LUSERS": {
        "lines": [
            "=== LUSERS Command ===",
            "Usage: /LUSERS",
            "Display user and channel statistics including:",
            "  - Total users connected",
            "  - Number of staff and services",
            "  - Total channels",
            "  - Peak user counts",
        ],
    },

    "ISON": {
        "lines": [
            "=== ISON Command ===",
            "Usage: /ISON <nickname> [nickname2] [...]",
            "Check if one or more users are currently online.",
            "Examples:",
            "  /ISON alice - Check if alice is online",
            "  /ISON alice bob charlie - Check multiple users",
            "Returns only the nicknames that are currently online",
        ],
    },

    "USERHOST": {
        "lines": [
            "=== USERHOST Command ===",
            "Usage: /USERHOST <nickname> [nickname2] [...]",
            "Get user@host information for connected users.",
            "Examples:",
            "  /USERHOST alice - Get alice's user@host",
            "  /USERHOST alice bob - Check multiple users (max 5)",
            "Shows away status and operator status",
        ],
    },

    "SILENCE": {
        "lines": [
            "=== SILENCE Command ===",
            "Usage: /SILENCE [+/-mask]",
            "Block or unblock messages from specific users.",
            "Examples:",
            "  /SILENCE - List your silence list",
            "  /SILENCE +bob!*@* - Block all messages from bob",
            "  /SILENCE +*!*@spammer.com - Block all messages from host",
            "  /SILENCE -bob!*@* - Unblock bob",
            "Note: Silenced users will not be able to send you private messages or notices",
        ],
    },

    "WATCH": {
        "lines": [
            "=== WATCH Command ===",
            "Usage: /WATCH [+/-nickname]",
            "Get notified when users come online or go offline.",
            "Examples:",
            "  /WATCH - View your watch list",
            "  /WATCH +alice - Watch for alice",
            "  /WATCH -alice - Stop watching alice",
            "You'll receive notifications when watched users connect/disconnect",
        ],
    },

    "TIME": {
        "lines": [
            "=== TIME Command ===",
            "Usage: /TIME",
            "Display the current server time and timezone.",
            "Useful for coordinating events across timezones",
        ],
    },

    "VERSION": {
        "lines": [
            "=== VERSION Command ===",
            "Usage: /VERSION",
            "Display the server software version and information.",
            "Shows: pyIRCX version, creation date, and build info",
        ],
    },

    "NICK": {
        "lines": [
            "=== NICK Command ===",
            "Usage: /NICK <new_nickname>",
            "Change your nickname.",
            "Examples:",
            "  /NICK alice - Change your nickname to alice",
            "Rules: Nicknames must be 1-30 characters, start with a letter, and contain only letters, numbers, -, _, [, ], {, }, \\, or |",
            "Note: You cannot use reserved service names (System, Messenger, Registrar, *Serv, etc.)",
        ],
    },

    "QUIT": {
        "lines": [
            "=== QUIT Command ===",
            "Usage: /QUIT [message]",
            "Disconnect from the server.",
            "Examples:",
            "  /QUIT - Disconnect with default message",
            "  /QUIT Goodbye everyone! - Disconnect with custom message",
        ],
    },

    "ADMIN": {
        "lines": [
            "=== ADMIN Command ===",
            "Usage: /ADMIN",
            "Display administrative contact information for the server.",
            "Shows: Server location, organization, and admin contacts",
        ],
    },

    "LINKS": {
        "lines": [
            "=== LINKS Command ===",
            "Usage: /LINKS",
            "Display list of linked servers (for networks with multiple servers).",
            "Shows: Server names, relationships, and connection info",
            "Note: Single-server networks will show only one entry",
        ],
    },

    "MAP": {
        "lines": [
            "=== MAP Command ===",
            "Usage: /MAP",
            "Display network topology as a tree structure.",
            "Shows: Server hierarchy and user counts per server",
            "Useful for visualizing multi-server network layout",
        ],
    },

    "CHGPASS": {
        "lines": [
            "=== CHGPASS Command ===",
            "Usage: /CHGPASS <old_password> <new_password>",
            "Change your account password.",
            "Example:",
            "  /CHGPASS oldpass newpass - Change password",
            "Alternative: /MSG Registrar SET PASSWORD <old> <new>",
            "Note: You must be identified to your account first",
        ],
    },

    "MOTD": {
        "lines": [
            "=== MOTD Command ===",
            "Usage: /MOTD",
            "Display the server's Message of the Day.",
            "Shows welcome message, server rules, and important announcements.",
        ],
    },

    "MEMO": {
        "lines": [
            "=== MEMO Command ===",
            "Send and receive offline messages directly (alternative to /MSG Messenger).",
            "",
            "Usage:",
            "  /MEMO SEND <nickname> <message> - Send a message to a user",
            "  /MEMO LIST - List your pending messages",
            "  /MEMO READ [id] - Read message(s)",
            "  /MEMO DELETE <id|ALL> - Delete message(s)",
            "",
            "Examples:",
            "  /MEMO SEND alice Don't forget the meeting tomorrow!",
            "  /MEMO LIST - See all pending messages",
            "  /MEMO READ 1 - Read message #1",
            "  /MEMO DELETE ALL - Delete all messages",
        ],
    },

    "ALIASES": {
        "lines": [
            "=== Command Aliases ===",
            "Shortcut commands for faster typing:",
            "",
            "  /J  <channel>        - JOIN a channel",
            "  /P  <channel>        - PART (leave) a channel",
            "  /W  <nick>           - WHOIS user information",
            "  /M  <nick> <message> - MSG (send private message)",
            "  /N  <nickname>       - NICK (change nickname)",
            "  /Q  [message]        - QUIT (disconnect)",
            "  /T  <channel> [text] - TOPIC (view/set topic)",
            "  /K  <channel> <nick> - KICK user from channel",
            "  /I  <nick> <channel> - INVITE user to channel",
            "  /L  [filter]         - LIST channels",
            "  /WW <nick>           - WHOWAS (past user info)",
            "  /WH <channel> <msg>  - WHISPER (private channel message)",
            "",
            "Examples:",
            "  /J #lobby           - Same as /JOIN #lobby",
            "  /W alice            - Same as /WHOIS alice",
            "  /M bob Hello!       - Same as /MSG bob Hello!",
            "",
            "Note: All aliases are case-insensitive and work identically to full commands.",
        ],
    },

    "GAG": {
        "staff_only": True,
        "lines": [
            "=== GAG/UNGAG Commands (Staff) ===",
            "Prevent or restore a user's ability to send messages.",
            "",
            "Usage:",
            "  /GAG <nick> - Global gag (sets user mode +z)",
            "  /GAG <#channel> <nick> - Channel-specific gag",
            "  /UNGAG <nick> - Remove global gag",
            "  /UNGAG <#channel> <nick> - Remove channel gag",
            "",
            "Requirements:",
            "  - Global gag: Staff members only (IRC guides, operators, and administrators)",
            "  - Channel gag: Channel host/owner or staff",
            "",
            "Examples:",
            "  /GAG spammer - Globally prevent spammer from talking",
            "  /GAG #lobby troublemaker - Gag only in #lobby",
            "  /UNGAG spammer - Restore global ability to talk",
        ],
    },

    "UNGAG": {
        "alias": "GAG",
    },

    "CREATE": {
        "lines": [
            "=== CREATE Command (IRCX) ===",
            "Usage: /CREATE <#channel> [modes] [mode arguments]",
            "Create a new channel with initial modes. Requires IRCX mode.",
            "",
            "Examples:",
            "  /CREATE #test - Create simple channel",
            "  /CREATE #test mnt - Create with modes (moderated, no external, topic)",
            "  /CREATE #test ntl 50 - Create with modes and limit of 50 users",
            "  /CREATE #test ntkl 25 secret - Limit 25 users with key 'secret'",
            "  /CREATE #test c - Fail if channel exists (create-only flag)",
            "",
            "Common modes: m=moderated n=no external t=topic protect i=invite-only",
            "With arguments: k=key l=limit u=owner key",
            "Special: c=create-only (fail if exists)",
            "",
            "Note: Modes only apply to new channels. Use /MODE to change existing channels.",
            "See also: /HELP IRCX, /HELP CHANMODES, /HELP JOIN",
        ],
    },

    "CONNECT": {
        "admin_only": True,
        "lines": [
            "=== CONNECT/SQUIT Commands (IRC administrator only) ===",
            "Server linking commands for network administration.",
            "",
            "Usage:",
            "  /CONNECT <server> <port> [remote_server] - Link to remote server",
            "  /SQUIT <server> [reason] - Disconnect server from network",
            "",
            "Note: Requires IRC administrator privileges and proper server configuration",
        ],
    },

    "SQUIT": {
        "alias": "CONNECT",
    },

    "CHATHISTORY": {
        "lines": [
            "=== CHATHISTORY Command (IRCv3) ===",
            "Retrieve channel message history from transcript logs.",
            "",
            "Usage:",
            "  /CHATHISTORY LATEST <#channel> * <limit>",
            "  /CHATHISTORY BEFORE <#channel> timestamp=<ts> <limit>",
            "  /CHATHISTORY AFTER <#channel> timestamp=<ts> <limit>",
            "  /CHATHISTORY BETWEEN <#channel> timestamp=<ts1> timestamp=<ts2> <limit>",
            "",
            "Timestamp format: timestamp=2024-01-15T10:30:00.000Z (ISO 8601)",
            "",
            "Requirements:",
            "  - You must be a member of the channel",
            "  - Channel must have transcript mode (+y) enabled",
            "",
            "Examples:",
            "  /CHATHISTORY LATEST #lobby * 50 - Get last 50 messages",
            "  /CHATHISTORY BEFORE #lobby timestamp=2024-01-15T12:00:00Z 20",
        ],
    },

    "RENAME": {
        "staff_only": True,
        "lines": [
            "=== RENAME Command (IRC operator/administrator only) ===",
            "Rename a channel. All members are notified and channel state is preserved.",
            "",
            "Usage: /RENAME <#oldname> <#newname> [reason]",
            "",
            "Examples:",
            "  /RENAME #oldchan #newchan Channel reorganization",
            "  /RENAME #temp #permanent",
            "",
            "Requirements: IRC operator or administrator privileges",
            "Note: The new channel name must not already exist",
        ],
    },

    "TAGMSG": {
        "lines": [
            "=== TAGMSG Command (IRCv3) ===",
            "Send a message with tags only (no text content).",
            "Used for typing indicators, reactions, and other tag-only messages.",
            "",
            "Usage: @+tag=value TAGMSG <target>",
            "",
            "Requirements: message-tags capability must be enabled",
            "Note: Only recipients with message-tags capability will receive TAGMSG",
        ],
    },
}

# Valid topics for fuzzy matching suggestions
VALID_TOPICS = [
    # Main topics
    "COMMANDS", "CHANNEL", "REGISTER", "IRCX", "USERMODES", "CHANMODES", "SERVICES", "STAFF",
    # Basic commands
    "JOIN", "PART", "MODE", "TOPIC", "KICK", "INVITE", "QUIT", "EXIT", "BYE", "NICK", "NICKNAME", "CREATE",
    # User information
    "WHOIS", "WHO", "WHOWAS", "NAMES", "ISON", "USERHOST", "AWAY",
    # Channel and IRCX
    "ACCESS", "PROP", "PROPERTY", "WHISPER", "KNOCK", "EVENT", "TRANSCRIPT",
    # Messaging
    "MSG", "PRIVMSG", "MESSAGE", "NOTICE", "MEMO",
    # Registration and security
    "IDENTIFY", "UNREGISTER", "MFA", "2FA", "TOTP", "CHGPASS", "CHANGEPASS",
    # Channel listing
    "LIST", "LISTX",
    # User management
    "SILENCE", "WATCH",
    # Server info
    "INFO", "LUSERS", "STATS", "TIME", "VERSION", "ADMIN", "LINKS", "MOTD",
    # Command shortcuts
    "ALIASES", "ALIAS", "SHORTCUTS",
    # Staff commands
    "KILL", "PROFANITY", "CONFIG", "GAG", "UNGAG", "CONNECT", "SQUIT",
    # IRCv3 extensions
    "CHATHISTORY", "RENAME", "TAGMSG",
]


def get_help_suggestions(topic):
    """Suggest similar help topics for typos using fuzzy matching"""
    matches = difflib.get_close_matches(topic.upper(), VALID_TOPICS, n=3, cutoff=0.6)
    return matches


def get_topic_lines(topic, is_staff=False, is_admin=False, is_high_staff=False, nickname=None):
    """
    Get help lines for a topic with appropriate access level filtering.

    Args:
        topic: The help topic (case-insensitive)
        is_staff: Whether user is staff (guide, operator, or admin)
        is_admin: Whether user is admin
        is_high_staff: Whether user is operator or admin
        nickname: User's nickname for placeholder replacement

    Returns:
        tuple: (found, lines) where found is bool and lines is list of strings
    """
    if not topic:
        topic = "INDEX"
    else:
        topic = topic.upper()

    # Resolve aliases
    if topic in TOPIC_ALIASES:
        topic = TOPIC_ALIASES[topic]

    # Check if topic exists
    if topic not in HELP_TOPICS:
        return False, []

    topic_data = HELP_TOPICS[topic]

    # Handle alias redirect
    if "alias" in topic_data:
        topic = topic_data["alias"]
        topic_data = HELP_TOPICS.get(topic, {})
        if not topic_data:
            return False, []

    # Check access restrictions
    if topic_data.get("staff_only") and not is_staff:
        # Return non_staff_lines if available
        if "non_staff_lines" in topic_data:
            return True, topic_data["non_staff_lines"]
        return False, []

    if topic_data.get("admin_only") and not is_admin:
        return False, []

    if topic_data.get("high_staff_only") and not is_high_staff:
        return False, []

    # Build lines list
    lines = []

    # Add main lines
    if "lines" in topic_data:
        lines.extend(topic_data["lines"])

    # Add staff-only lines
    if is_staff and "staff_lines" in topic_data:
        lines.extend(topic_data["staff_lines"])

    # Add high_staff-only lines
    if is_high_staff and "high_staff_lines" in topic_data:
        lines.extend(topic_data["high_staff_lines"])

    # Add admin-only lines
    if is_admin and "admin_lines" in topic_data:
        lines.extend(topic_data["admin_lines"])

    # Add footer
    if "footer" in topic_data:
        lines.extend(topic_data["footer"])

    # Replace placeholders
    if nickname and lines:
        lines = [line.replace("{nickname}", nickname) for line in lines]

    return True, lines
