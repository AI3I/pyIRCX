#!/usr/bin/env python3
"""
IRC Response Templates for pyIRCX Server

This module contains the numeric response templates (RESPONSES), server message
templates (SERVER_MESSAGES), and log message templates (LOG_MESSAGES) used by
the IRC server.

Run `python validate_responses.py` after editing this file to check for errors.

RULES FOR EDITING TEMPLATES:
=============================================================================

1. FORBIDDEN CHARACTERS
   - No \\r (carriage return) or \\n (newline) in any string value.
     IRC messages are terminated by CR+LF; embedded newlines will corrupt
     the protocol stream and break client connections.
   - No \\0 (null byte). Not permitted in IRC messages.
   - Use multi-line lists (see rule 5) if you need multiple lines of output.

2. FORMAT PLACEHOLDERS
   - Use {name} syntax for variable substitution (Python str.format()).
   - Placeholder names must be valid Python identifiers: letters, digits,
     underscores only. No spaces, no special characters.
   - Each placeholder must exactly match what the calling code passes.
     A typo causes a KeyError at runtime (not at startup).
   - Example: "Welcome, {nickname}!" requires the caller to pass
     nickname="SomeNick" as a keyword argument.

3. LITERAL BRACES
   - To include a literal { or } in output, double it: {{ or }}.
   - Example: "Use {{bold}} for formatting" outputs "Use {bold} for formatting".

4. MESSAGE LENGTH
   - IRC protocol limits messages to 512 bytes total per line, including
     the protocol frame (:<source> NOTICE <target> :<text>\\r\\n).
   - Practical limit for message text is ~400 bytes after the frame overhead.
   - Keep templates concise. Long templates with many placeholders that
     expand to long values may be silently truncated by clients.

5. MULTI-LINE MESSAGES (lists)
   - For messages that span multiple lines, use a Python list of strings.
   - Each list element is sent as a separate NOTICE/PRIVMSG line.
   - Each element must still follow rules 1-4 individually.
   - Example: "help_topic": ["Line 1", "Line 2", "Line 3"]

6. DICTIONARY KEYS
   - Use lowercase with underscores (snake_case).
   - Prefix keys by category: validate_, link_, api_, usage_, audit_, etc.
   - Keys must be unique across the entire dictionary.

7. SECTION ORGANIZATION
   - Group related templates under comment headers.
   - Major sections use: # --- SECTION NAME ---
   - Sub-sections within a major section use: # Sub-section name
=============================================================================
"""

# ==============================================================================
# RESPONSE TABLE - IRC numeric replies
# ==============================================================================
RESPONSES = {
    "001": "Welcome to the {network}, {nick}!",
    "002": "Your host is {servername}, running version {version_label} {version}",
    "003": "This server was created {created_date}",
    "004": "{servername} {version_label} {version} {usermodes} {chanmodes}",
    "005": "CHANTYPES=#& PREFIX=(qov).@+ CHANMODES={chanmodes_param} NICKLEN={nicklen} MAXNICKLEN={nicklen} USERLEN={userlen} CHANNELLEN={chanlen} TOPICLEN={topiclen} AWAYLEN={awaylen} KICKLEN={kicklen} MODES={max_modes} MONITOR={monitorlen} SILENCE={silencelen} MAXTARGETS={maxtargets} SAFELIST UTF8ONLY BOT=b CHATHISTORY={max_chathistory} CASEMAPPING=rfc1459 STATUSMSG=.@+ NETWORK={network_name} IRCX ACCESS PROPS :are supported",
    "006": ":{text}",  # RPL_MAP entry
    "007": ":{message}",  # RPL_MAP end
    # STATS numerics (211-219, 242-243)
    "211": "{linkname} {sendq} {sent_msgs} {sent_kbytes} {recv_msgs} {recv_kbytes} {uptime} :{info}",  # RPL_STATSLINKINFO
    "212": "{command} {count} {bytes} {remote_count} :{info}",  # RPL_STATSCOMMANDS
    "213": "C {host} * {name} {port} {class}",  # RPL_STATSCLINE
    "214": "N {host} * {name} {port} {class}",  # RPL_STATSNLINE
    "215": "I {host} * {host2} {port} {class}",  # RPL_STATSILINE
    "216": "K {host} * {username} {port} {class}",  # RPL_STATSKLINE
    "217": "{mask} :{info}",  # RPL_STATSQLINE
    "218": "Y {class} {ping_freq} {connect_freq} {max_links} {sendq}",  # RPL_STATSYLINE
    "219": "{flag} :End of /STATS report",
    "242": ":Server Up {days} days {hours}:{mins:02d}:{secs:02d}",  # RPL_STATSUPTIME
    "243": "O {hostmask} * {nick} :{level}",  # RPL_STATSOLINE
    "221": "+{modes}",
    "251": "There are {users} users and {invisible} invisible on {server_count} servers",
    "252": "{ops} :staff and services online",
    "253": "{unknown} :unknown connection(s)",
    "254": "{channels} :channels formed",
    "255": "I have {users} clients and {server_count} servers",
    "265": "Current local users: {local}, max: {local_max}",
    "266": "Current global users: {global_users}, max: {global_max}",
    "256": "{servername} :Administrative info",
    "257": ":{loc1}",
    "258": ":{loc2}",
    "259": ":{email}",
    "301": "{target} :{message}",
    "302": "{userhosts}",
    "303": ":{nicks}",
    "305": "You are no longer marked as being away",
    "306": "You have been marked as being away",
    "307": "{target} :{message}",  # RPL_WHOISREGNICK
    "311": "{target} {ident} {host} * :{real}",
    "312": "{target} {servername} :pyIRCX Server",
    "313": "{target} :{role}",
    "314": "{target} {ident} {host} * :{real}",
    "315": "{target} :End of /WHO list",
    "317": "{target} {idle} {signon} :seconds idle, signon time",
    "318": "{target} :End of /WHOIS list",
    "319": "{target} :{channels}",
    "320": "{target} :from IP {ip}",
    "321": "Channel :Users Name",
    "322": "{channel} {users} :{topic}",
    "323": "End of /LIST",
    "324": "{channel} +{modes}{param_str}",
    "364": "{server} {uplink} :{hopcount} {desc}",  # RPL_LINKS
    "365": "* :{message}",  # RPL_ENDOFLINKS
    "331": "{channel} :No topic is set",
    "332": "{channel} :{topic}",
    "333": "{channel} {nick} {timestamp}",
    "335": "{target} :is a bot (automated)",  # RPL_WHOISBOT
    "341": "{target} {channel}",
    "351": "{version} {servername} :{version_label}",
    "352": "{channel} {ident} {host} {servername} {target} {flags} :0 {real}",
    "353": "= {channel} :{names}",
    "366": "{channel} :End of /NAMES list",
    "367": "{channel} {mask}",
    "368": "{channel} :End of channel ban list",
    "369": "{target} :End of WHOWAS",
    "371": ":{info}",
    "372": "-{text}",
    "374": ":End of /INFO list",
    "375": "- {servername} Message of the Day -",
    "376": "End of /MOTD command",
    "422": "MOTD File is missing",
    "381": "You are now an IRC {role}",
    "382": "{config_file} :{message}",  # RPL_REHASHING
    "386": "{message}",
    "391": ":Local time is {time}",
    "401": "{target} :That nickname or channel doesn't exist",
    "403": "{target} :That channel doesn't exist",
    "404": "{channel} :You cannot send to channel (check channel modes or your permissions)",
    "407": "{target} :You specified too many recipients",
    "410": "{message}",  # ERR_INVALIDCAPCMD
    "421": "{command} :This command is not recognized",
    "432": "{target} :{error}",
    "433": "{target} :Nickname is already in use",
    "441": "{target} {channel} :They aren't on that channel",
    "442": "{target} :You're not on that channel",
    "443": "{target} {channel} :They are already on that channel",
    "451": "You have not registered (use NICK and USER commands)",
    "461": "{command} :You did not provide enough parameters. See /HELP {command} for usage.",
    "462": "You may not reregister",
    "468": ":{error}",
    "471": "{target} :You cannot join channel (channel is full - user limit reached)",
    "473": "{target} :You cannot join channel (invite-only - you must be invited)",
    "474": "{target} :You cannot join channel (you are banned from this channel)",
    "475": "{target} :You cannot join channel (incorrect channel key/password)",
    "479": "{channel} :{error}",  # ERR_BADCHANNAME
    "464": "{message}",  # ERR_PASSWDMISMATCH - auth failure
    "481": "{message}",
    "482": "{target} :You're not a channel owner or host (+q or +o required)",
    "501": "{message}",  # ERR_UMODEUNKNOWNFLAG
    "696": "{target} {mode} :{message}",
    "710": "{channel} {knocker} {host} :{message}",
    "711": "{target} :Your knock request has been sent",
    "712": "{target} :You have sent too many knock requests. Please wait before trying again.",
    "713": "{target} :Channel is open",
    "714": "{target} :You are already on that channel",
    "716": "{target} :You cannot knock on this channel (+u mode)",
    "800": "1 0 {auth_status} 512 *",
    "803": "{target} :{message}",  # ACCESS list start
    "804": "{target} {level} {mask} {set_by}{details}",
    "805": "{target} :End of access list",
    "806": "{cls} {mask}",
    "807": "{cls} {mask}",
    "808": ":Start of events",
    "809": "{cls} {mask}",
    "810": ":End of events",
    "811": "Channel :Users Topic",
    "812": "{channel} {users} {modes} :{topic}",
    "813": "End of /LISTX",
    "814": "{servername} {timestamp} {cls} {action} {channel} {user_prefix} {ip_port} {data}",
    "817": "{target} {prop} :{value}",
    "818": "{target} :End of properties",
    "819": "{target} {prop} :{value}",
    # IRCX Service Protection (820-829)
    "820": "{target} :You cannot perform this action on services",
    "821": "{target} :You cannot kick services",
    "822": "{target} :You cannot ban services",
    "823": "{target} :You cannot kill services",
    "824": "{target} :You cannot gag services",
    "825": "{target} :You cannot add services to access deny list",
    # IRCX Rate Limiting (830-839)
    "830": ":You are being rate limited. Please wait before trying again.",
    "831": ":WHO command rate limited. Please wait before trying again.",
    "832": ":WHISPER rate limited (5 second cooldown)",
    "833": ":LIST command rate limited. Please wait before trying again.",
    "834": ":Sending too fast. Flood protection triggered. Please slow down.",
    "835": ":Please wait {seconds} seconds before changing nickname",
    # IRCX Channel Restrictions (840-849)
    "840": "{channel} :You cannot send to channel",
    "841": "{channel} :You cannot send to channel (moderated - only voiced users and channel operators can speak)",
    "842": "{channel} :You cannot send to channel (no external messages - you must join the channel first)",
    "843": "{channel} :Whispers are not allowed in this channel",
    "844": "{channel} :Invitations are not allowed in this channel",
    "845": "{channel} :Transcript mode not enabled (+y)",
    "846": "{channel} :{prop} is read-only",
    "847": "{target} :ServiceBot has reached max channels ({max})",
    "848": ":Only staff members can invite ServiceBots",
    # IRCX Access Control (850-859)
    "850": ":That is not a valid access level - valid: {levels}",
    "851": "{mask} :This mask is already in the {level} list",
    "852": "{mask} :This mask was not found in the {level} list",
    "853": ":You cannot remove owner-added entry (you are not the channel owner)",
    "854": "{target} :ACCESS {level} added: {mask}{timeout}",
    "855": "{target} :ACCESS {level} removed: {mask}",
    "856": "{target} :Cleared {count} {level} entries",
    "857": ":Only channel owners can clear access lists",
    "858": ":You cannot delete your own staff account",
    "859": ":You are already linked to {server}",
    # IRCX Command Usage (860-869)
    "860": ":Usage: {usage}",
    "861": ":That is not a valid configuration path. Use: section.key (e.g., limits.max_users)",
    "862": ":That is not a valid level. Use: {levels}",
    "863": ":That username is not valid: {error}",
    "864": ":That password is not valid (minimum 8 characters, must include letters and numbers)",
    "865": ":That MFA code is not valid. Please enter the 6-digit code from your authenticator app.",
    "866": ":That message ID is not valid",
    "867": ":That channel name is not valid (must start with # or & and contain only letters, numbers, -, _, or .)",
    "868": ":That nickname is not valid (must be 1-{nicklen} characters, start with a letter, and contain only letters, numbers, -, _, [, ], {{, }}, \\, or |)",
    "869": ":That parameter is not valid: {param}",
    # IRCX Registration/Auth (870-879)
    "870": ":Nickname {nick} is already registered",
    "871": ":Nickname {nick} is not registered",
    "872": ":You are already identified to a registered nickname",
    "873": ":You must be identified to unregister your nickname",
    "874": ":{message}",
    "875": ":{message}",
    "876": ":{message}",
    "877": ":Password accepted. MFA is enabled - please verify with: MFA VERIFY <code>",
    "878": ":MFA secret: {secret} - Add to your authenticator app, then verify with: MFA VERIFY <code>",
    "879": ":Your MFA has been disabled",
    # IRCX Staff Management (880-889)
    "880": ":The staff account {username} was created with level {level}",
    "881": ":The staff account {username} was deleted",
    "882": ":The staff account {username} was changed to level {level}",
    "883": ":{message}",
    "884": ":We couldn't list the staff accounts",
    "885": ":We couldn't create the staff account",
    "886": ":We couldn't delete the staff account",
    "887": ":We couldn't change the staff level",
    "888": ":We couldn't change the password",
    "889": ":The staff account {username} was not found",
    # IRCX Config/Admin (890-899)
    "890": ":{key} = {value}",
    "891": ":{key} set to {value}",
    "892": ":That configuration key was not found: {key}",
    "893": ":We couldn't access the configuration",
    "894": ":Connected to {server}",
    "895": ":Disconnected from {server}",
    "896": ":We couldn't connect to {server}",
    "897": ":The server {server} was not found in your links",
    "898": ":Link operation in progress",
    "899": ":Link timeout - operation aborted",
    # IRCX Database/System (900-909) - IRCv3 SASL numerics
    "900": "{account_host} {username} :{message}",  # RPL_LOGGEDIN
    "903": "{message}",  # RPL_SASLSUCCESS
    "904": "{message}",  # ERR_SASLFAIL
    "905": "{message}",  # ERR_SASLTOOLONG
    "906": "{message}",  # ERR_SASLABORTED
    "907": "{message}",  # ERR_SASLALREADY
    "908": "{mechanisms} :{message}",  # RPL_SASLMECHS
    # IRCX Service Messages (910-919)
    "910": ":Commands: {commands}",
    "911": ":That command is not recognized: {cmd}. Try: {suggestions}",
    "912": ":{message}",
    "913": ":No messages waiting",
    "914": ":You have {count} message(s) waiting",
    "915": ":Message sent to {target}",
    "916": ":Message {id} deleted",
    "917": ":All messages cleared",
    "918": ":Channel {channel} is already registered",
    "919": ":Channel {channel} is not registered",
    # IRCX Gag/Kill/Drop/MFA numerics (920-929)
    "920": ":{target} has been gagged in {channel}",
    "921": ":{target} has been ungagged in {channel}",
    "922": ":{target} has been globally gagged (+z)",
    "923": ":{target} has been globally ungagged (-z)",
    "924": ":*** User {target} has been killed ({reason})",
    "925": ":Channel {channel} destroyed ({count} users removed)",
    "926": "{channel} :{message}",  # ERR_CHANNELEXIST
    "927": ":Staff privileges dropped. You are now a regular user.",
    "928": ":MFA verified. You are now identified as {nickname}",
    "929": ":Pattern {pattern} matched {count} user(s)",
    # WATCH numerics
    "600": "{target} {ident} {host} {signon} :logged on",
    "601": "{target} {ident} {host} {signon} :logged off",
    "602": "{target} * * 0 :stopped watching",
    "604": "{target} {ident} {host} {signon} :is online",
    "605": "{target} * * 0 :is offline",
    "606": ":{nicks}",  # List of watched nicks
    "607": ":End of WATCH list",
    # SILENCE numerics
    "271": "{target} {mask}",
    "272": ":End of Silence List",
    # HELP numerics (704-706)
    "704": "{topic} :{text}",  # RPL_HELPSTART - Start of help section
    "705": "{topic} :{text}",  # RPL_HELPTXT - Help content line
    "706": "{topic} :End of {topic}",  # RPL_ENDOFHELP - End of help section
    # ERR_NOPRIVS (723)
    "723": "{priv} :Insufficient oper privileges",  # ERR_NOPRIVS
    # ERR_MONLISTFULL (734) - Monitor list is full
    "734": "{limit} {targets} :Monitor list is full",
    # IRCX Auth Error numerics (760-763)
    "760": ":AUTH command requires an SSL/TLS connection (port 6697)",
    "761": ":Too many failed authentication attempts",
    "762": ":Incorrect password",
    "763": ":Account locked. Try again in {remaining}s",
    # IRCX Database/Service Error numerics (764-766)
    "764": ":Registration failed. Please try again later. If the problem persists, contact an administrator.",
    "765": ":{message}",
    "766": ":Drop failed - please try again later",
    # IRCX Staff Command Output (930-939)
    "930": ":=== Staff Accounts ({count}) ===",  # Staff list header
    "931": ":{level} ({count}):",  # Staff level section header
    "932": ":  {username}{status}",  # Staff account entry
    "933": ":=== End of Staff Accounts ===",  # Staff list footer
    # IRCX Config Command Output (940-949)
    "940": ":--- Config [{section}] ---",  # Config section header
    "941": ":{key} = {value}",  # Config key-value entry
    "942": ":[{section}] ({count} keys)",  # Config section summary
    "943": ":--- End of Config ---",  # Config list footer
    # IRCX Profanity Filter Output (950-959)
    "950": ":=== Profanity Filter Configuration ===",  # Profanity header
    "951": ":Status: {status}",  # Profanity status
    "952": ":Filtered {type} ({count}):",  # Profanity type section
    "953": ":  - {item}",  # Profanity item entry
    "954": ":=== End of Profanity Configuration ===",  # Profanity footer
    # IRCX Message System Output (960-969)
    "960": ":--- Message List ({count} message(s)) ---",  # Message list header
    "961": ":{status}#{id} from {sender} at {time}: {preview}",  # Message list entry
    "962": ":--- End of Message List ---",  # Message list footer
    "963": ":--- Message #{id} from {sender} at {time} ---",  # Message read header
    "964": ":{text}",  # Message body line
    "965": ":--- End of Message ---",  # Message read footer
    # IRCX Stats Output (970-979)
    "970": ":=== {title} ===",  # Stats section header
    "971": ":--- {title} ---",  # Stats subsection header
    "972": ":{label}: {value}",  # Stats key-value entry
    "973": ":  {label}: {value}",  # Stats indented key-value entry
    "974": ":=== End of {title} ===",  # Stats section footer
    "975": ":--- End ---",  # Stats subsection footer
    "STAFF_LOG": "[{action}] {staff} -> {target}: {details}",
}

# ==============================================================================
# SERVER MESSAGES - NOTICE templates for informational messages
# ==============================================================================
SERVER_MESSAGES = {
    # --- PRIVILEGE & PERMISSION ERRORS ---
    "requires_admin": "{command} requires administrator privileges.",
    "requires_oper_admin": "{command} requires operator or administrator privileges.",
    "requires_staff": "{command} requires staff privileges.",
    "requires_ircx": "{command} requires IRCX mode. Use /IRCX to enable it.",
    "requires_identify": "You must identify first. Use IDENTIFY <password> to authenticate.",
    "requires_identify_unregister": "You must identify before you can unregister. Use IDENTIFY <password> to authenticate.",
    "requires_identify_mfa": "You must identify before you can enable MFA. Use IDENTIFY <password> to authenticate.",
    "who_restricted": "WHO * is restricted to staff. Try a more specific pattern such as WHO *nickname* instead.",
    "cannot_target_staff": "You cannot {action} staff members.",

    # --- RATE LIMITING ---
    "rate_limit_flood": "You're sending messages too quickly. Please slow down.",

    # --- GENERAL ERRORS ---
    "not_found": "{item} was not found.",
    "not_found_nick": "That nickname was not found.",
    "already_exists_account": "Staff account '{username}' already exists.",
    "auth_failed": "Authentication failed. Please check your credentials and try again.",
    "internal_error": "An internal error occurred. Please try again later.",
    "msg_format_invalid": "The message format is not valid.",

    # --- SERVICES AVAILABILITY ---
    "services_unavailable": "Services are currently unavailable because the trunk server is not connected.",
    "trunk_unavailable": "The trunk server is not connected, so staff management is currently unavailable.",

    # --- MFA MESSAGES ---
    "mfa_uri": "  URI: {uri}",
    "mfa_already_enabled": "MFA is already enabled for your account.",
    "mfa_not_enabled": "MFA is not currently enabled for your account.",
    "mfa_verify_failed": "MFA verification failed. Please try again later.",
    "mfa_setup_failed": "MFA setup failed. Please try again later.",
    "mfa_session_expired": "Your MFA session has expired. Please start the setup process again.",
    "mfa_enable_first": "Please run MFA ENABLE first to begin setup.",
    "mfa_enabled_success": "MFA is now enabled for your account.",
    "mfa_code_invalid_cancelled": "That code is not valid. MFA setup has been cancelled.",
    "mfa_disable_usage": "Usage: MFA DISABLE <code>",
    "mfa_disable_failed": "We couldn't disable MFA. Please try again later.",

    # --- REGISTRATION MESSAGES ---
    "reg_must_use_nickname": "You must be using the nickname you want to register.",
    "reg_request_sent": "Registration request sent to services. Please wait...",
    "reg_requires_identify": "You must identify to a registered nickname first. Use IDENTIFY <password> to authenticate.",
    "reg_channel_request_sent": "Channel registration request sent to services. Please wait...",
    "reg_nick_required": "Your nickname must be registered first. Use REGISTER <password> to register it.",
    "reg_usage_alt": "   or: REGISTER <#channel> [<password>]",

    # --- UNREGISTRATION MESSAGES ---
    "unreg_must_be_owner": "You can only unregister your own nickname.",
    "unreg_request_sent": "Unregistration request sent to services. Please wait...",
    "unreg_channel_request_sent": "Channel unregistration request sent to services. Please wait...",
    "unreg_staff_not_registered": "Your staff account is not registered.",

    # --- IDENTIFY MESSAGES ---
    "identify_must_use_nickname": "You must be using the nickname you want to identify as.",
    "identify_in_progress": "Identifying...",
    "identify_mfa_required": "Password accepted. MFA verification required - use: MFA VERIFY <code>",

    # --- AUTH COMMAND MESSAGES ---
    "auth_usage_full": "Usage: AUTH <username> <password> | AUTH VERIFY <code> | AUTH ENABLE <password> | AUTH DISABLE <password> <code>",
    "auth_usage_basic": "Usage: AUTH <username> <password>",
    "auth_plaintext_warning": "Warning: Your credentials would be transmitted in plaintext without SSL.",
    "auth_mfa_required": "Password accepted. MFA verification required.",
    "auth_enter_code": "Please enter your MFA code: /AUTH VERIFY <code>",
    "auth_verify_usage": "Usage: AUTH VERIFY <code>",
    "auth_session_expired": "Your authentication session has expired. Please authenticate again using AUTH.",
    "auth_mfa_config_error": "There is an MFA configuration error. Please contact an administrator.",
    "auth_enable_first": "Please run AUTH ENABLE first to set up MFA.",
    "auth_mfa_enabled": "MFA is now enabled for your account.",
    "auth_mfa_required_hint": "You will need to provide an MFA code when using AUTH from now on.",
    "auth_mfa_setup_cancelled": "That MFA code is not valid. Setup has been cancelled.",
    "auth_no_pending": "No pending authentication session. Please use AUTH <username> <password> to start.",
    "auth_or_enable": "Or run AUTH ENABLE first to set up MFA.",
    "auth_enable_usage": "Usage: AUTH ENABLE <password>",
    "auth_must_be_staff": "You must be authenticated as staff to enable MFA.",
    "auth_mfa_already_enabled": "MFA is already enabled for your account.",
    "auth_setup_failed": "MFA setup failed. Please try again later.",
    "auth_disable_usage": "Usage: AUTH DISABLE <password> <code>",
    "auth_staff_required": "You must be authenticated as staff.",
    "not_authenticated": "You are not authenticated as staff.",
    "auth_mfa_disabled": "MFA has been disabled for your account.",
    "auth_mfa_disable_failed": "We couldn't disable MFA. Please try again later.",
    "auth_success_as": "You are now authenticated as {level}.",
    "auth_numeric_success": "You are now authenticated as IRC {level}.",
    "drop_reauth_hint": "Use AUTH to re-authenticate if needed.",

    # --- CONFIGURATION MESSAGES ---
    "config_restart_note": "Note: Some configuration changes require a server restart to take effect.",
    "config_value_too_large": "That configuration value is too large (maximum {max_size}).",
    "config_section_unknown": "'{section}' is not a recognized configuration section.",
    "config_subcmd_unknown": "'{subcmd}' is not a recognized subcommand.",
    "config_file_not_found": "Configuration file '{config_file}' is required but not found. Please run the installation script or create the config file.",

    # --- MEMO SYSTEM MESSAGES ---
    "memo_send_usage": "Usage: MEMO SEND <nickname> <message>",
    "memo_del_usage": "Usage: MEMO DELETE <id|ALL>",
    "memo_request_sent": "Message request sent to services. Please wait...",
    "memo_send_failed": "We couldn't send the message. Please try again later.",
    "memo_nick_not_registered": "Nickname {target} is not registered.",
    "memo_list_failed": "We couldn't retrieve your messages. Please try again later.",
    "memo_not_found": "Message #{id} was not found.",
    "memo_no_unread": "You have no unread messages.",
    "memo_read_failed": "We couldn't retrieve your messages. Please try again later.",
    "memo_del_request_sent": "Message deletion request sent to services. Please wait...",
    "memo_delete_failed": "We couldn't delete the message. Please try again later.",
    "memo_unread_count": "You have {count} unread message(s). Use MEMO READ to view them.",

    # --- HELP SYSTEM MESSAGES ---
    "help_not_found": "No help available for: {topic}.",
    "help_suggestions": "Did you mean: {suggestions}?",
    "help_available_topics": "Available topics: COMMANDS, CHANNEL, REGISTER, IRCX, USERMODES, CHANMODES, SERVICES, ALIASES.",
    "help_staff_topic": "Staff topic: STAFF.",
    "help_try_command": "Try /HELP <command> for specific commands (e.g., /HELP JOIN)",

    # --- ACCESS & TAG ERRORS ---
    "access_denied_with_reason": "Access denied{reason}.",
    "server_restricted": "This server is restricted to authenticated staff and authorized users only.",
    "server_use_branch": "Please connect to a branch server instead.",
    "services_trunk_offline": "Services are temporarily unavailable because the trunk server is offline.",
    "tag_channel_only": "The {prefix}* tag prefix can only be used with channel targets.",
    "tag_requires_owner": "The OWN.* tag prefix requires channel owner status (+q) in {channel}.",
    "tag_requires_host": "The HST.* tag prefix requires channel host status in {channel}.",
    "tag_invalid_length": "That tag is not valid: must be 1-15 characters.",
    "tag_invalid_start": "That tag is not valid: must start with a letter.",
    "tag_invalid_chars": "That tag is not valid: only letters, numbers, and periods are allowed.",
    "tag_reserved_adm": "The ADM.* tag prefix is reserved for administrators.",
    "tag_reserved_sys": "The SYS.* tag prefix is reserved for operators.",
    "tag_reserved_gde": "The GDE.* tag prefix is reserved for guides.",
    "who_truncated": "WHO results have been truncated at {max} entries.",
    "ownerkey_owners_only": "Only channel owners can view the OWNERKEY.",
    "access_list_start": "Start of ACCESS list",

    # --- BROADCAST & MESSAGING ---
    "broadcast_sent": "Server-wide {type} sent to {count} user(s) on {server}.",
    "broadcast_restricted": "Server-wide messaging is restricted to staff.",
    "message_truncated": "Your message was truncated to {max} characters (protocol limit).",
    "data_target_no_ircx": "{target} does not support the IRCX protocol.",

    # --- TRANSCRIPT MESSAGES ---
    "transcript_unavailable": "No transcript is available for {channel}.",
    "transcript_header": "=== Transcript for {channel} ({count} lines) ===",
    "transcript_footer": "=== End of transcript ===",

    # --- WATCH/SILENCE MESSAGES ---
    "watch_cleared": "Your WATCH list has been cleared.",
    "silence_added": "Added {mask} to your SILENCE list.",
    "silence_removed": "Removed {mask} from your SILENCE list.",

    # --- PASS COMMAND MESSAGES ---
    "pass_too_short": "Password must be at least 6 characters.",
    "pass_service_unavailable_trunk": "Password service is unavailable because the trunk server is not connected.",
    "pass_service_unavailable": "Password service is currently unavailable.",
    "pass_nick_not_registered": "Your nickname is not registered. Staff accounts should use: STAFF PASS <username> <newpassword>",
    "pass_changed": "Your password has been changed successfully.",

    # --- EVENT COMMAND MESSAGES ---
    "event_add_usage": "Usage: EVENT ADD <class> [<mask>]",
    "event_delete_usage": "Usage: EVENT DELETE <class> [<mask>]",
    "event_trap_not_found": "No matching event trap was found.",

    # --- STATISTICS MESSAGES ---
    "stats_ssl_header": "--- SSL/TLS Status ---",
    "stats_servicebot_header": "--- ServiceBot Statistics ---",
    "stats_peak_header": "--- Peak Usage ---",
    "stats_message_header": "--- Message Statistics ---",
    "stats_flood_header": "--- Flood Protection ---",
    "stats_database_header": "--- Database Statistics ---",
    "stats_config_header": "--- Configuration ---",
    "stats_ban_header": "--- Ban Statistics ---",
    "stats_online_staff": "--- Online Staff ---",
    "stats_end": "--- End ---",
    # STATS help content
    "stats_help_header": "=== STATS Help ===",
    "stats_help_footer": "=== End of STATS Help ===",
    "stats_help_general_header": "Generally available flags:",
    "stats_help_general_u": "  u - Server uptime and version",
    "stats_help_general_s": "  s - Online staff listing",
    "stats_help_general_i": "  i - Invisible users count",
    "stats_help_general_x": "  x - IRCX users count",
    "stats_help_general_w": "  w - Authenticated users count",
    "stats_help_general_y": "  y - Anonymous users count",
    "stats_help_general_c": "  c - Server configuration summary",
    "stats_help_general_f": "  f - Flood protection status",
    "stats_help_general_n": "  n - Network statistics",
    "stats_help_staff_header": "IRC guide or staff flags:",
    "stats_help_staff_a": "  a - Online IRC administrators",
    "stats_help_staff_o": "  o - Online IRC operators",
    "stats_help_staff_g": "  g - Online IRC guides",
    "stats_help_staff_b": "  b - ServiceBot statistics",
    "stats_help_staff_z": "  z - Gagged users listing",
    "stats_help_oper_header": "IRC operator or administrator flags:",
    "stats_help_oper_d": "  d - Database statistics",
    "stats_help_oper_k": "  k - Bans and access lists",
    "stats_help_oper_l": "  l - Server linking statistics",
    "stats_help_oper_m": "  m - Message/command statistics",
    "stats_help_oper_p": "  p - Peak usage statistics",
    "stats_help_oper_t": "  t - SSL/TLS certificate status",
    "stats_help_oper_v": "  v - Command usage statistics",
    "stats_help_oper_star": "  * - All statistics combined",
    # STATS output content
    "stats_uptime": "Uptime: {days}d {hours}:{mins:02d}:{secs:02d}",
    "stats_users_header": "--- User Statistics ---",
    "stats_users_total": "  Total users: {count}",
    "stats_users_invisible": "  Invisible (+i): {count}",
    "stats_users_ircx": "  IRCX (+x): {count}",
    "stats_users_auth": "  Authenticated: {count}",
    "stats_users_anon": "  Anonymous (~): {count}",
    "stats_users_gagged": "  Gagged (+z): {count}",
    "stats_staff_header": "--- Staff Online ---",
    "stats_staff_admins": "  IRC administrators: {count}",
    "stats_staff_sysops": "  IRC operators: {count}",
    "stats_staff_guides": "  IRC guides: {count}",
    "stats_channels_header": "--- Channel Statistics ---",
    "stats_channels_global": "  Global channels (#): {count}",
    "stats_channels_local": "  Local channels (&): {count}",
    "stats_channels_registered": "  Registered: {count}",
    "stats_access_header": "--- Access Lists ---",
    "stats_access_deny": "  ACCESS DENY: {count}",
    "stats_access_grant": "  ACCESS GRANT: {count}",
    "stats_server_header": "--- Server Statistics ---",
    "stats_server_commands": "  Commands processed: {count}",
    "stats_server_connections": "  Total connections: {count}",
    "stats_server_max_users": "  Max users seen: {count}",
    "stats_command_header": "--- Command Usage ---",
    "stats_command_entry": "  {command}: {count}",
    "stats_peak_users": "  Peak users: {count}",
    "stats_peak_time": "  Peak time: {time}",
    "stats_flood_events": "  Flood events: {count}",
    "stats_flood_threshold": "  Threshold: {msgs} messages per {window}s",
    "stats_all_header": "=== STATS * - Full Statistics ===",
    "stats_all_footer": "=== End of STATS * ===",
    "stats_unknown_flag": "That STATS flag is not recognized: {flag}.",
    "stats_network_header": "--- Network Statistics ---",
    "stats_linking_header": "--- Server Linking ---",
    "stats_total_messages": "  Total messages: {count}",
    "stats_active_channels_by_msg": "  Active channels by messages:",
    "stats_channel_msg_entry": "    {channel}: {count}",
    "stats_active_bots": "  Active bots: {count}",
    "stats_total_violations": "  Total violations: {count}",
    "stats_violation_entry": "    {type}: {count}",
    "stats_total_actions": "  Total actions: {count}",
    "stats_server_bans": "  Server bans: {count}",
    "stats_db_path": "  Path: {path}",
    "stats_db_size_bytes": "  Size: {size:,} bytes ({kb:.1f} KB)",
    "stats_db_unavailable": "  Database statistics are temporarily unavailable.",
    "stats_db_not_configured": "  Database is not configured.",
    "stats_unavailable": "  Statistics are temporarily unavailable.",
    "stats_version": "  Version: {version} ({label})",
    "stats_dnsbl": "  DNSBL: {status}",
    "stats_ssl_cert": "Certificate: {file}",
    "stats_ssl_expires": "Expires: {expiry} ({days:.0f} days) [{status}]",
    "stats_ssl_subject": "Subject: {subject}",
    "stats_ssl_not_init": "SSL: not initialized",
    # Performance metrics
    "stats_perf_header": "--- Performance Metrics ---",
    "stats_config_reloads": "  Configuration cache reloads: {count}",
    "stats_channel_monitors": "  Active channel monitors: {count}",
    "stats_avg_msg_reload": "  Average messages per reload: {count:,}",
    # Real-time metrics
    "stats_realtime_header": "--- Real-Time Metrics ---",
    "stats_cmd_rate_avg": "  Commands/min (5min avg): {rate:.1f}",
    "stats_cmd_rate_peak": "  Peak commands/min: {count}",
    "stats_current_load": "  Current load: {pct:.1f}% ({current}/{max} users)",
    # Historical trends
    "stats_history_header": "--- Historical Trends ---",
    "stats_busiest_channels": "  Busiest channels (all-time):",
    "stats_busiest_channel_entry": "    {channel}: {count:,} messages",
    "stats_most_active_users": "  Most active users (all-time):",
    "stats_most_active_user_entry": "    {username}: {count:,} commands",
    # Distributed network
    "stats_distributed_header": "--- Distributed Network ---",
    "stats_server_role": "  Role: {role}",
    "stats_linked_servers": "  Linked servers: {count}",
    "stats_connected_servers": "  Connected servers:",
    "stats_linked_server_entry": "    {server} ({users} users)",
    "stats_divergence_header": "  Recent network divergences ({count}):",
    "stats_divergence_entry": "    {server} at {time}: {reason}",
    "stats_convergence_header": "  Recent network convergences ({count}):",
    "stats_convergence_entry": "    {server} at {time}",
    # Staff listing
    "stats_staff_admin_entry": "{nickname} (IRC administrator)",
    "stats_staff_oper_entry": "{nickname} (IRC operator)",
    "stats_staff_guide_entry": "{nickname} (IRC guide)",
    "stats_no_staff": "No staff currently online.",
    "stats_end_staff": "--- End of Staff ---",
    # Individual flag stats
    "stats_admins_header": "=== Online IRC administrators ({count}) ===",
    "stats_no_admins": "No IRC administrators currently online.",
    "stats_admin_entry": "  {prefix} (idle: {idle})",
    "stats_admins_footer": "=== End of IRC administrators ===",
    "stats_opers_header": "=== Online IRC operators ({count}) ===",
    "stats_no_opers": "No IRC operators currently online.",
    "stats_oper_entry": "  {prefix} (idle: {idle})",
    "stats_opers_footer": "=== End of IRC operators ===",
    "stats_guides_header": "=== Online IRC guides ({count}) ===",
    "stats_no_guides": "No IRC guides currently online.",
    "stats_guide_entry": "  {prefix} (idle: {idle})",
    "stats_guides_footer": "=== End of IRC guides ===",
    "stats_invisible_count": "Invisible users: {count}",
    "stats_access_deny_entries": "ACCESS DENY entries: {count}",
    "stats_access_deny_entry": "  {pattern} (by {by}){reason}",
    "stats_server_bans_count": "Server bans: {count}",
    "stats_server_ban_entry": "  {ip} ({duration}) by {by}",
    "stats_services_bots_header": "--- Services/Bots (+s) ---",
    "stats_service_entry": "{prefix}",
    "stats_gagged_header": "--- Gagged Users (+z) ---",
    "stats_gagged_entry": "{prefix}",
    "stats_max_users": "Max Users: {count}",
    "stats_user_modes": "User Modes: {modes}",
    "stats_chan_modes": "Channel Modes: {modes}",
    "stats_flood_enabled": "Flood Protection: {status}",
    "stats_db_nicks": "Registered nicknames: {count}",
    "stats_db_channels": "Registered channels: {count}",
    "stats_db_messages": "Offline messages: {count}",
    "stats_db_news": "Active news: {count}",
    "stats_news_unavailable": "News statistics are temporarily unavailable.",
    "stats_news_temp_unavailable": "News is temporarily unavailable.",
    "stats_linking_enabled": "Linking: {status}",
    "stats_linking_bind": "Bind: {host}:{port}",
    "stats_linking_configured": "Configured links: {count}",
    "stats_linking_name": "  {name}",
    "stats_linking_none": "(No links configured)",
    "stats_anonymous_count": "Anonymous users (~): {count}",
    "stats_ircx_count": "IRCX users: {count}",
    "stats_auth_count": "Authenticated users: {count}",
    "stats_ssl_key": "Key: {file}",
    "stats_ssl_min_tls": "Minimum TLS: {version}",
    "stats_ssl_ports": "SSL Ports: {ports}",
    "stats_peak_current": "Current users: {count}",
    "stats_peak_max": "Max users (all time): {count}",
    "stats_flood_status": "Enabled: {status}",
    "stats_flood_config": "Threshold: {msgs} messages per {window}s",
    "stats_flood_total": "Total flood events: {count}",
    "stats_most_active_channels": "Most active channels:",
    "stats_active_channel_entry": "  {channel}: {count}",
    "stats_no_message_data": "No message data available.",
    "stats_active_channels": "Active channels: {count}",
    "stats_servicebots_enabled": "ServiceBots enabled: {status}",
    "stats_violations_detected": "Violations detected:",
    "stats_no_violations": "No violations detected.",
    "stats_actions_taken": "Actions taken:",
    "stats_action_entry": "  {action}: {count}",
    "stats_profanity_status": "Profanity filter: {status}",
    "stats_malicious_status": "Malicious detection: {status}",
    "stats_users_count": "Users: {count}",
    "stats_channels_count": "Channels: {count}",
    "stats_services_count": "Services: {count}",
    "stats_uptime_short": "Uptime: {days}d {hours}:{mins:02d}",
    "stats_command_usage_header": "--- Command Usage Statistics ---",
    "stats_command_usage_entry": "{command}: {count}",
    "stats_no_command_data": "No command usage data available.",
    "stats_total_commands": "Total commands: {count}",
    # --- STAFF MANAGEMENT ---
    "staff_levels_hint": "Valid levels: ADMIN, SYSOP, GUIDE.",
    "staff_forwarded": "Command forwarded to the trunk server. Please wait...",
    "staff_password_min": "Your password must be at least 6 characters.",
    "staff_subcommands": "STAFF subcommands: LIST, ADD, DELETE, SET, PASS, MFA.",
    "staff_levels": "Staff levels: ADMIN, SYSOP, GUIDE.",
    "staff_list_none": "No staff accounts are currently configured.",
    "staff_already_level": "'{username}' is already set to level {level}.",
    "staff_pass_old_required": "Your current password is required to change your password.",
    "staff_pass_admin_hint": "Administrators changing others: STAFF PASS <username> <newpassword>.",
    "staff_pass_forwarded": "Password change request forwarded to the trunk server. Please wait...",
    "staff_mfa_already_enabled": "MFA is already enabled for {username}.",
    "staff_mfa_not_enabled": "MFA is not enabled for {username}.",
    "trunk_only_format": "This command format is only available on the trunk server.",
    "staff_pass_self_only": "You can only change your own staff password.",
    "staff_mfa_own_hint": "Use AUTH ENABLE to manage your own MFA.",
    "staff_mfa_usage": "Usage: STAFF MFA <username> ENABLE <code> | DISABLE <code> | STATUS",
    "staff_mfa_status": "MFA status for {username}: {status}.",
    "staff_mfa_secret_pending": "MFA secret exists but is awaiting first verification.",
    "staff_mfa_enable_usage": "Usage: STAFF MFA {username} ENABLE <code>",
    "staff_mfa_user_needs_secret": "The user must run AUTH ENABLE first to generate their MFA secret.",
    "staff_mfa_user_enable_first": "User {username} must run AUTH ENABLE first to generate their MFA secret.",
    "staff_mfa_invalid_code_for_user": "That MFA code is not valid for {username}.",
    "staff_mfa_enabled_for_user": "MFA has been enabled for {username}.",
    "staff_mfa_disable_usage": "Usage: STAFF MFA {username} DISABLE <code>",
    "staff_mfa_disable_code_required": "A current valid MFA code is required to disable MFA.",
    "staff_mfa_config_error_for_user": "There is an MFA configuration error for {username}.",
    "staff_mfa_disabled_for_user": "MFA has been disabled for {username}.",
    "staff_mfa_invalid_action": "'{action}' is not a valid MFA action.",
    "staff_mfa_available_actions": "Valid actions: ENABLE, DISABLE, or STATUS.",
    "staff_mfa_op_failed": "MFA operation failed. Please try again later.",
    "staff_unknown_subcommand": "'{subcmd}' is not a recognized STAFF subcommand.",
    "mfa_pending_registrar": "MFA verification is pending. Use: PRIVMSG Registrar :MFA VERIFY <code>",
    # --- PROFANITY FILTER MESSAGES ---
    "profanity_examples": "Examples: PROFANITY LIST, PROFANITY ADD WORD badword, PROFANITY ADD PATTERN (bad|terrible)",
    "profanity_header": "=== Profanity Filter Configuration ===",
    "profanity_status": "Status: {status}",
    "profanity_action": "Action: {action} (warn/gag/kick)",
    "profanity_case": "Case Sensitive: {status}",
    "profanity_words_header": "Filtered Words ({count}):",
    "profanity_words_none": "Filtered Words: (none)",
    "profanity_word_entry": "  - {word}",
    "profanity_patterns_header": "Regular Expression Patterns ({count}):",
    "profanity_patterns_none": "Regular Expression Patterns: (none)",
    "profanity_pattern_entry": "  - {pattern}",
    "profanity_add_usage": "Usage: PROFANITY ADD WORD <word> or PROFANITY ADD PATTERN <pattern>",
    "profanity_word_exists": "Word '{word}' is already in the filter.",
    "profanity_word_added": "Added word '{word}' to the profanity filter.",
    "profanity_pattern_exists": "Pattern '{pattern}' is already in the filter.",
    "profanity_pattern_added": "Added pattern '{pattern}' to the profanity filter.",
    "profanity_type_unknown": "That type '{type}' is not recognized. Use WORD or PATTERN.",
    "profanity_del_usage": "Usage: PROFANITY DELETE WORD <word> or PROFANITY DELETE PATTERN <pattern>",
    "profanity_word_not_found": "Word '{word}' is not in the filter.",
    "profanity_word_removed": "Removed word '{word}' from the profanity filter.",
    "profanity_pattern_not_found": "Pattern '{pattern}' is not in the filter.",
    "profanity_pattern_removed": "Removed pattern '{pattern}' from the profanity filter.",
    "profanity_enabled": "Profanity filter has been enabled.",
    "profanity_disabled": "Profanity filter has been disabled.",
    "profanity_test_usage": "Usage: PROFANITY TEST <text to check>",
    "profanity_test_would_catch": "TEST RESULT: Would be caught - matched: {matched}",
    "profanity_test_clean": "TEST RESULT: Would NOT be caught.",
    "profanity_unknown_subcommand": "That subcommand is not recognized: {subcmd}.",
    "profanity_subcommands": "PROFANITY subcommands: LIST, ADD, DELETE, ENABLE, DISABLE, TEST.",
    "profanity_available_subcommands": "Available: LIST, ADD, DELETE, ENABLE, DISABLE, TEST.",
    "profanity_blank_line": "",

    # --- SSL/TLS MESSAGES ---
    "ssl_enabled": "SSL: enabled",
    "ssl_disabled": "SSL: disabled",
    "ssl_no_certs": "SSL: enabled but no certificates loaded",
    "ssl_server": "Server: {server}",
    "ssl_network": "Network: {network}",

    # --- CHANNEL MESSAGES ---
    "channel_local_no_register": "Local channels (&) cannot be registered. Only global channels (#) can be registered.",
    "channel_already_exists": "That channel already exists and cannot be created with the +c flag.",
    "kill_cannot_system": "The #System channel cannot be removed.",

    # --- USER MODE MESSAGES ---
    "mode_cannot_set": "Mode +{mode} is server-controlled and cannot be manually changed.",
    "mode_cannot_unset_x": "Mode +x cannot be removed once set.",
    "mode_z_staff_controlled": "Mode +z is staff-controlled and cannot be manually changed.",
    "mode_changes_limit": "Too many mode changes specified (maximum {max} per command).",
    "mode_unknown_flag": "That MODE flag is not recognized.",
    "mode_key_required": "You must specify a parameter for mode +k.",
    "mode_limit_required": "You must specify a parameter for mode +l.",
    "mode_limit_exceeds_cap": "User limit capped at server maximum ({max} users per channel).",
    "mode_r_cannot_set": "You cannot manually set +r mode. Use the REGISTER command instead.",
    "mode_r_staff_only": "Only operators and administrators can unregister channels with -r.",
    "mode_z_staff_only": "Only operators, administrators, and services can set +z (locked) mode.",
    "mode_z_must_register": "The channel must be registered before it can be locked. Use REGISTER first.",

    # --- EVENT MESSAGES ---
    "event_classes": "That is not a valid event class. Valid classes: CONNECT, MEMBER, CHANNEL, USER, SERVER, SOCKET",
    "event_usage": "Usage: EVENT [ADD|DELETE|LIST] <class> [<mask>]",

    # --- SERVICE ALIAS MESSAGES ---
    "svc_alias_title": "pyIRCX {service_name} Service",
    "svc_alias_implemented": "This service is currently implemented as an alias.",
    "svc_alias_available": "Available services:",
    "svc_alias_registrar": "  Registrar/NickServ - Nickname registration (/msg Registrar HELP)",
    "svc_alias_chanserv": "  Registrar/ChanServ - Channel registration (/msg Registrar HELP)",
    "svc_alias_messenger": "  Messenger/MemoServ - Offline messages (/msg Messenger HELP)",
    "svc_alias_newsflash": "  NewsFlash - Network announcements (/msg NewsFlash HELP)",
    "svc_alias_servicebot": "  ServiceBot## - Channel moderation (/msg ServiceBot01 HELP)",
    "svc_alias_full_list": "For the full command list, try: /HELP",

    # --- EASTER EGG MESSAGES ---
    "easter_jedi": "That is not the command you're looking for.",
    "easter_wallops": "Ouch, that hurts! Violence is not the answer.",

    # --- SETNAME MESSAGES ---
    "setname_disabled": "Real name changes are disabled on this server.",
    "setname_wait": "You must wait {remaining} seconds before changing your real name again.",
    "setname_too_long": "Real name is too long (maximum {max_len} characters).",
    "setname_empty": "Real name cannot be empty.",

    # --- GOD/SYSTEM ENTITY MESSAGES ---
    "entity_usage": "Usage: /MSG {entity_name} HELP",
    "entity_privmsg_usage": "Usage: PRIVMSG <target> <message>",
    "entity_notice_usage": "Usage: NOTICE <target> <message>",
    "entity_kick_usage": "Usage: KICK <channel> <nickname> [<reason>]",
    "entity_kill_usage": "Usage: KILL <nickname> [<reason>]",
    "entity_channel_not_found": "Channel {target} does not exist.",
    "entity_user_not_found": "User {target} was not found.",
    "entity_privmsg_sent": "PRIVMSG sent to {target} as {entity_name}.",
    "entity_notice_sent": "NOTICE sent to {target} as {entity_name}.",
    "entity_not_in_channel": "{nick} is not in {channel}.",
    "entity_kicked": "Kicked {nick} from {channel} as {entity_name}.",
    "entity_cannot_kill_admin": "You cannot kill IRC administrators.",
    "entity_cannot_kill_virtual": "You cannot kill virtual users.",
    "entity_killed": "Killed {nick} as {entity_name}: {reason}.",
    "entity_unknown_cmd": "Unknown command: {cmd}. Try HELP for available commands.",
    "admin_invite_only": "Only IRC administrators can invite {entity}.",

    # --- REGISTRAR SERVICE MESSAGES ---
    "registrar_help": "Commands: REGISTER <password> [<email>], IDENTIFY <password>, DROP, INFO [<nickname>], CHANNEL <command>, SET <option>, MFA <command>",
    "registrar_tip": "You can also use direct commands: REGISTER, UNREGISTER, IDENTIFY, MFA.",
    "registrar_nick_not_registered": "Your nickname is not registered.",
    "registrar_nick_not_found": "That nickname was not found.",
    "registrar_identify_first": "You must identify first.",
    "registrar_identify_first_mfa": "You must identify first to {action} MFA.",
    "registrar_staff_not_registered": "Your staff account is not registered.",
    "registrar_nick_must_register": "Your nickname must be registered first.",
    "registrar_channel_not_exist": "That channel does not exist.",
    "registrar_must_be_owner": "You must be a channel owner to register {channel}.",
    "registrar_channel_already_reg": "Channel {channel} is already registered.",
    "registrar_channel_registered": "Channel {channel} has been registered (UUID: {uuid}).",
    "registrar_channel_not_reg": "That channel is not registered.",
    "registrar_only_owner_admin": "Only the channel owner or an administrator can drop it.",
    "registrar_channel_dropped": "Channel {channel} has been dropped.",
    "registrar_channel_register_failed": "We couldn't register the channel. Please try again later.",
    "registrar_channel_drop_failed": "We couldn't drop the channel. Please try again later.",
    "registrar_channel_info_title": "Information for {name}:",
    "registrar_channel_info_uuid": "  UUID: {uuid}",
    "registrar_channel_info_owner": "  Owner: {owner}",
    "registrar_channel_info_registered": "  Registered: {date}",
    "registrar_channel_info_desc": "  Description: {description}",
    "registrar_channel_info_failed": "We couldn't look up the channel information. Please try again later.",
    "registrar_info_title": "Information for {nickname}:",
    "registrar_info_uuid": "  UUID: {uuid}",
    "registrar_info_registered": "  Registered: {date}",
    "registrar_info_last_seen": "  Last seen: {date}",
    "registrar_info_mfa": "  MFA enabled: {status}",
    "registrar_info_failed": "We couldn't look up that information. Please try again later.",
    "registrar_must_identify_reg": "You must identify to a registered nickname first.",
    "registrar_set_password_updated": "Your password has been updated.",
    "registrar_set_email_updated": "Your email has been updated to {email}.",
    "registrar_set_unknown": "'{setting}' is not a recognized setting.",
    "registrar_set_failed": "We couldn't update the setting. Please try again later.",
    "registrar_mfa_already_enabled": "MFA is already enabled for your nickname.",
    "registrar_mfa_setup_title": "MFA Setup - Add this to your authenticator application:",
    "registrar_mfa_setup_secret": "  Secret: {secret}",
    "registrar_mfa_setup_uri": "  URI: {uri}",
    "registrar_mfa_setup_verify": "To complete setup, verify with: MFA VERIFY <code>",
    "registrar_mfa_setup_warning": "MFA will NOT be active until you verify the code.",
    "registrar_mfa_setup_failed": "We couldn't set up MFA. Please try again later.",
    "registrar_mfa_not_enabled": "MFA is not currently enabled for your nickname.",
    "registrar_mfa_disable_usage": "Usage: MFA DISABLE <code>",
    "registrar_mfa_disable_require": "You must provide a valid MFA code to disable MFA.",
    "registrar_mfa_code_invalid": "That MFA code is not valid.",
    "registrar_mfa_disabled_msg": "MFA has been disabled for your nickname.",
    "registrar_mfa_disable_failed": "We couldn't disable MFA. Please try again later.",
    "registrar_mfa_session_expired": "Your MFA verification session has expired. Please try again.",
    "registrar_mfa_verified": "MFA verified. You are now identified as {nickname}.",
    "registrar_mfa_code_retry": "That MFA code is not valid. Please try again.",
    "registrar_mfa_identify_or_verify": "You must identify first, or complete your pending MFA verification.",
    "registrar_mfa_already_verify": "MFA is already enabled. Did you mean to verify after IDENTIFY?",
    "registrar_mfa_enable_first": "You must run MFA ENABLE first to set up MFA.",
    "registrar_mfa_now_enabled": "MFA is now enabled for your nickname.",
    "registrar_mfa_code_required": "You will need to provide an MFA code after IDENTIFY from now on.",
    "registrar_mfa_setup_cancelled": "That MFA code is not valid. MFA setup has been cancelled.",
    "registrar_mfa_verify_failed": "MFA verification failed. Please try again later.",
    "registrar_unknown_cmd": "Unknown command: {cmd}. Available commands: REGISTER, IDENTIFY, DROP, INFO, CHANNEL, SET, MFA.",

    # --- MESSENGER SERVICE MESSAGES ---
    "messenger_cleared": "All your messages have been cleared.",
    "messenger_list_header": "Your messages:",
    "messenger_list_item": "  [{id}] {status}From {sender} ({time}): {preview}",
    "messenger_read_header": "Message #{id} from {sender} ({time}):",
    "messenger_read_body": "  {message}",
    "messenger_user_offline": "{target} is offline. Your message has been saved for delivery.",
    "messenger_user_online": "{target} is online and has been notified.",
    "messenger_commands": "Commands: SEND <nickname> <message>, READ, DELETE <id>, COUNT, HELP.",
    "messenger_send_usage": "Usage: SEND <nickname> <message>",
    "messenger_delete_usage": "Usage: DELETE <id>",
    "messenger_delete_invalid_id": "That message ID is not valid.",
    "messenger_push_usage": "Usage: PUSH <message>",
    "messenger_unknown_cmd": "Unknown command: {cmd}. Try HELP for available commands.",
    "messenger_nick_not_registered": "That nickname is not registered.",
    "messenger_sent": "Your message has been sent to {target}.",
    "messenger_new_message": "You have a new message from {sender}.",
    "messenger_send_failed": "We couldn't send the message. Please try again later.",
    "messenger_identify_first": "You must identify to read your messages.",
    "messenger_identify_required": "You must identify first.",
    "messenger_nick_not_reg": "Your nickname is not registered.",
    "messenger_no_messages": "You have no messages in your mailbox.",
    "messenger_read_failed": "We couldn't retrieve your messages. Please try again later.",
    "messenger_deleted": "Message {msg_id} has been deleted.",
    "messenger_not_found": "That message was not found.",
    "messenger_delete_failed": "We couldn't delete the message. Please try again later.",
    "messenger_unread_count": "You have {count} unread message(s).",
    "messenger_pushed": "Message pushed to {count} user(s).",

    # --- NEWSFLASH SERVICE MESSAGES ---
    "newsflash_list_header": "Active NewsFlash items:",
    "newsflash_list_item": "  [{id}] (P{priority}) {message} - by {author}",
    "newsflash_read_header": "NewsFlash #{id} by {author} ({time}):",
    "newsflash_read_body": "  {message}",
    "newsflash_commands": "Commands: LIST, ADD <message> (staff), DELETE <id> (staff), PUSH <message> (administrator), HELP.",
    "newsflash_add_usage": "Usage: ADD <message>",
    "newsflash_delete_usage": "Usage: DELETE <id>",
    "newsflash_read_usage": "Usage: READ <id>",
    "newsflash_not_found": "NewsFlash #{id} was not found.",
    "newsflash_delete_invalid_id": "That message ID is not valid.",
    "newsflash_push_usage": "Usage: PUSH <message>",
    "newsflash_staff_required": "That command requires staff privileges.",
    "newsflash_unknown_cmd": "Unknown command: {cmd}. Try HELP for available commands.",
    "newsflash_no_messages": "There are no active news messages.",
    "newsflash_added": "News message has been added.",
    "newsflash_add_failed": "We couldn't add the message. Please try again later.",
    "newsflash_deleted_msg": "News message {msg_id} has been deleted.",
    "newsflash_delete_failed": "We couldn't delete the message. Please try again later.",
    "newsflash_pushed": "NewsFlash pushed to {count} user(s).",

    # --- SERVICEBOT MESSAGES ---
    "servicebot_dispatched": "Dispatched {bot} to {channel}.",
    "servicebot_unknown_cmd": "Unknown command: {cmd}. Try HELP for available commands.",
    "servicebot_status_title": "=== {botname} Status ===",
    "servicebot_active_channels": "Active in {count}/{max} channels",
    "servicebot_monitoring": "Monitoring: {channels}",
    "servicebot_not_monitoring": "Not currently monitoring any channels.",
    "servicebot_detection_status": "Detection Status:",
    "servicebot_monitoring_disabled": "Monitoring: Globally Disabled",
    "servicebot_invite_hint": "To invite me to a channel: /INVITE {botname} #channel (SYSOP+ only)",
    "servicebot_max_channels": "ServiceBots can monitor up to 10 channels simultaneously.",

    # --- CAP & SASL MESSAGES ---
    "cap_invalid": "That is not a valid CAP command.",
    "cap_invalid_subcmd": "That is not a valid CAP subcommand.",
    "sasl_aborted": "SASL authentication aborted.",
    "sasl_lockout": "Too many failed attempts. Please try again in {remaining} seconds.",
    "sasl_rate_limited": "SASL authentication rate limited. Please try again later.",
    "sasl_not_enabled": "SASL authentication failed because SASL is not enabled on this server.",
    "sasl_already_auth": "You have already authenticated via SASL.",
    "sasl_mechanisms_available": "are available SASL mechanisms",
    "sasl_failed": "SASL authentication failed.",
    "sasl_too_long": "SASL message is too long.",
    "sasl_logged_in": "You are now logged in as {username}.",
    "sasl_successful": "SASL authentication successful.",

    # --- CONNECTION & SHUTDOWN MESSAGES ---
    "error_cap_timeout": "Closing link: CAP negotiation timeout ({timeout}s)",
    "error_access_denied": "Closing Link: {nickname} (Access denied)",
    "error_staff_only": "Closing Link: {nickname} (Staff-only server)",
    "error_banned": "You are banned from this server: {reason}.",
    "error_risk_score": "Connection refused due to security risk assessment.",
    "notice_server_shutdown": "Server shutting down",

    # --- DISCONNECT & REASON STRINGS ---
    "part_channel_reconfig": "Channel reconfiguration",
    "part_channel_locked": "Channel locked by administrator",
    "kill_banned": "Banned: {reason}",
    "kill_default_reason": "Killed by administrator",
    "ban_default_reason": "Banned by administrator",
    "entity_kill_reason": "Killed by {entity_name}",
    "quit_reason_killed": "Killed: {reason}",
    "quit_reason_banned": "Banned: {reason}",
    "quit_client_exited": "Client exited",
    "servicebot_kick_reason": "ServiceBot: {violation}",
    "servicebot_ban_reason": "ServiceBot: Banned for {violation}",

    # --- SERVICEBOT VIOLATION WARNINGS ---
    "servicebot_warn_caps": "Please don't use excessive caps (shouting).",
    "servicebot_warn_repeat": "Please don't repeat the same message.",
    "servicebot_warn_url_spam": "Please don't spam URLs.",

    # --- MESSAGE PREFIXES ---
    "messenger_global_prefix": "[Global] {message}",
    "newsflash_prefix": "[NEWS] {message}",

    # --- WHOIS MESSAGES ---
    "whois_identified": "has identified for this nickname",

    # --- SYSTEM CHANNEL NOTIFICATIONS ---
    "gag_channel_notify": "[GAG] {nickname} gagged {target} in {channel}",
    "ungag_channel_notify": "[UNGAG] {nickname} ungagged {target} in {channel}",
    "gag_global_notify": "[GAG] {nickname} globally gagged {target} (+z)",
    "ungag_global_notify": "[UNGAG] {nickname} globally ungagged {target} (-z)",
    "auth_alert_blocked_ssl": "AUTH blocked: {nickname} ({ip}) - no SSL",
    "auth_alert_lockout": "AUTH lockout: {username} from {nickname} ({ip})",
    "auth_alert_failed_user": "AUTH failed: unknown user '{username}' from {nickname} ({ip})",
    "auth_alert_failed_password": "AUTH failed: wrong password for '{username}' from {nickname} ({ip})",
    "auth_alert_pending_mfa": "AUTH pending MFA: '{username}' from {nickname} ({ip}) as {level}",
    "auth_alert_mfa_failed": "AUTH MFA failed: invalid code for '{username}' from {nickname} ({ip})",
    "auth_alert_success": "AUTH success: {username} from {nickname} ({ip}) as {level}",
    "auth_alert_drop": "DROP: {username} ({level}) dropped privileges from {nickname} ({ip})",

    # --- LINKING: STAFF COMMAND REPLIES ---
    "link_staff_user_not_found": "Error: User not found on trunk.",
    "link_staff_password_syntax": "Error: Invalid PASSWORD command syntax.",
    "link_staff_account_not_found": "Error: Staff account not found.",
    "link_staff_wrong_password": "Error: Incorrect current password.",
    "link_staff_password_changed": "Password changed successfully.",
    "link_staff_add_syntax": "Error: Invalid ADD command syntax.",
    "link_staff_permission_denied": "Error: Permission denied (administrator only).",
    "link_staff_invalid_level": "Error: Invalid staff level (must be ADMIN, SYSOP, or GUIDE).",
    "link_staff_username_exists": "Error: Username {username} already exists.",
    "link_staff_account_created": "Staff account {username} created with level {level}.",
    "link_staff_remove_syntax": "Error: Invalid REMOVE command syntax.",
    "link_staff_account_not_found_named": "Error: Staff account {username} not found.",
    "link_staff_cannot_self_remove": "Error: You cannot remove your own staff account.",
    "link_staff_account_removed": "Staff account {username} has been removed.",
    "link_staff_level_syntax": "Error: Invalid LEVEL command syntax.",
    "link_staff_invalid_level_full": "Error: Invalid level (must be ADMIN, SYSOP, GUIDE, or USER).",
    "link_staff_level_changed": "Staff level for {username} changed to {level}.",
    "link_staff_unknown_command": "Error: Unknown staff command {command}.",
    "link_staff_command_failed": "Error: Command failed - {error}.",

    # --- LINKING: REGISTRATION COMMAND REPLIES ---
    "link_reg_user_not_found": "Error: User not found on trunk.",
    "link_reg_register_syntax": "Error: Invalid REGISTER syntax.",
    "link_reg_nick_already_registered": "Error: Nickname {account} is already registered.",
    "link_reg_nick_registered": "Nickname {account} has been registered.",
    "link_reg_unregister_syntax": "Error: Invalid UNREGISTER syntax.",
    "link_reg_nick_unregistered": "Nickname {account} has been unregistered.",
    "link_reg_identify_syntax": "Error: Invalid IDENTIFY syntax.",
    "link_reg_nick_not_registered": "Error: Nickname {account} is not registered.",
    "link_reg_mfa_trunk_only": "Error: MFA-protected accounts must identify on the trunk server.",
    "link_reg_identified": "You are now identified as {account}.",
    "link_reg_wrong_password": "Error: Incorrect password.",
    "link_reg_channel_register_syntax": "Error: Invalid channel REGISTER syntax.",
    "link_reg_channel_already_registered": "Error: Channel {channel} is already registered.",
    "link_reg_must_identify": "Error: You must be identified to register a channel.",
    "link_reg_channel_registered": "Channel {channel} has been registered.",
    "link_reg_channel_unregister_syntax": "Error: Invalid channel UNREGISTER syntax.",
    "link_reg_channel_not_registered": "Error: Channel {channel} is not registered.",
    "link_reg_channel_not_owner": "Error: You do not own channel {channel}.",
    "link_reg_channel_unregistered": "Channel {channel} has been unregistered.",
    "link_reg_chgpass_syntax": "Error: Invalid CHGPASS syntax.",
    "link_reg_nick_not_registered_pass": "Error: Nickname is not registered.",
    "link_reg_password_changed": "Password changed successfully.",
    "link_reg_unknown_command": "Error: Unknown registration command {command}.",
    "link_reg_command_failed": "Error: Command failed - {error}.",

    # --- LINKING: MEMO COMMAND REPLIES ---
    "link_memo_user_not_found": "Error: User not found on trunk.",
    "link_memo_send_syntax": "Error: Invalid MEMO SEND syntax.",
    "link_memo_target_not_registered": "Error: Nickname {target} is not registered.",
    "link_memo_sent": "Message sent to {target}.",
    "link_memo_new_notification": "You have a new message from {nickname}. Use MEMO READ to view.",
    "link_memo_no_memos": "You have no messages.",
    "link_memo_count": "You have {count} message(s):",
    "link_memo_not_found": "Message #{id} not found.",
    "link_memo_no_unread": "No unread messages.",
    "link_memo_all_deleted": "All messages have been deleted.",
    "link_memo_deleted": "Message #{id} has been deleted.",
    "link_memo_invalid_id": "Error: Invalid message ID.",
    "link_memo_delete_syntax": "Error: Invalid MEMO DELETE syntax.",
    "link_memo_unknown_command": "Error: Unknown MEMO command {command}.",
    "link_memo_command_failed": "Error: Command failed - {error}.",
    "link_memo_status_read": "[READ]",
    "link_memo_status_new": "[NEW]",
    "link_memo_list_entry": "  #{id} from {sender} {status} ({timestamp})",
    "link_memo_read_header": "Message #{id} from {sender} ({timestamp}):",

    # --- VALIDATION ERROR MESSAGES ---
    "validate_nick_erroneous": "That nickname contains invalid characters.",
    "validate_nick_reserved": "That nickname is reserved for services.",
    "validate_user_invalid": "That username is not valid.",
    "validate_chan_no_name": "Please specify a channel name.",
    "validate_chan_bad_prefix": "Channel name must start with # or &.",
    "validate_chan_too_long": "Channel name is too long (maximum {max_len} characters).",
    "validate_chan_just_prefix": "Channel name cannot be just a prefix character.",
    "validate_chan_starts_digit": "Channel name cannot start with a digit.",
    "validate_chan_invalid_chars": "Channel name contains invalid characters.",
    "validate_chan_looks_like_host": "Channel name cannot resemble an IP address or hostname.",
    "validate_realname_empty": "Please provide your real name.",
    "validate_realname_not_text": "Real name must be text.",
    "validate_realname_too_long": "Real name is too long. Please use {max_len} characters or fewer.",
    "validate_realname_invalid": "Please provide a valid real name.",
    "validate_msg_empty": "Please provide a message to send.",
    "validate_msg_not_text": "Message must be text.",
    "validate_msg_too_long": "Message is too long. Please keep it under {max_len} characters.",
    "validate_msg_invalid": "Please provide a valid message.",
    "validate_pass_empty": "Please provide a password.",
    "validate_pass_not_text": "Password must be text.",
    "validate_pass_too_long": "Password is too long. Please use {max_len} characters or fewer.",
    "validate_pass_has_spaces": "Password cannot contain spaces.",
    "validate_staff_level_invalid": "'{level}' is not a valid staff level. Must be one of: {valid_levels}.",
    "validate_pattern_empty": "Pattern cannot be empty.",
    "validate_pattern_too_long": "Pattern is too long (maximum {max_len} characters).",
    "validate_pattern_bad_regex": "That regular expression syntax is not valid: {error}",
    "validate_pattern_dangerous": "That pattern contains potentially dangerous constructs that could cause slow matching.",
    "validate_pattern_too_many_quantifiers": "Pattern has too many quantifiers (maximum 10).",
    "validate_pattern_too_many_alternations": "Pattern has too many alternations (maximum 20).",
    "validate_cmd_empty": "Please provide a command.",
    "validate_cmd_not_text": "Command must be text.",
    "validate_cmd_too_long": "Command is too long. Please keep it under {max_len} characters.",
    "validate_cmd_multiline": "Please use a single-line command.",
    "validate_cmd_invalid": "Please provide a valid command.",
    "validate_cmd_blocked": "The command '{cmd_name}' is not allowed via the raw interface.",

    # --- SERVICEBOT VIOLATION TYPES ---
    "violation_profanity": "matched word: {matched}",
    "violation_flood": "message flooding",
    "violation_repeat": "repeated message spam",
    "violation_caps": "excessive caps",
    "violation_url_spam": "URL spam",

    # --- API MESSAGES ---
    "api_kill_default_reason": "Killed by administrator",
    "api_ban_default_reason": "Banned by administrator",
    "api_reason_required": "Please provide a reason (1-500 characters)",
    "api_ban_duration_invalid": "Ban duration must be a non-negative number (in seconds)",
    "api_kill_success": "User {nickname} will be disconnected",
    "api_ban_success": "User {nickname} will be banned for {duration} seconds",
    "api_channel_reset": "Channel {channel} will be reset",
    "api_status_not_found": "Status file not found - server may not be running",
    "api_admin_command_write_failed": "Failed to write admin command: {error}",
    "api_owner_name_required": "Owner name must be provided (1-30 characters)",
    "api_mode_string_required": "Please provide a mode string (1-50 characters)",
    "api_mode_string_invalid_format": "Mode string must start with + or - followed by mode letters (e.g., '+nt' or '-s')",
    "api_topic_too_long": "Topic must not exceed 500 characters",
    "api_newsflash_message_required": "Please provide a message (1-500 characters)",
    "api_newsflash_priority_invalid": "Priority must be between 0 (normal) and 10 (highest)",
    "api_newsflash_id_invalid": "Please provide a valid NewsFlash message ID (must be a positive number)",
    "api_sender_nick_required": "Sender nickname must be provided (1-30 characters)",
    "api_username_invalid_format": "Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens",
    "api_password_too_short": "Password must be at least 8 characters long",
    "api_username_too_short": "Please provide a valid username (at least 3 characters)",
    "api_email_invalid": "Invalid email address",
    "api_nickname_no_changes": "No changes specified - please provide a new password and/or email address",
    "api_password_required": "Password is required",
    "api_login_credentials_required": "Username and password are required",
    "api_access_list_required": "Access list JSON is required",
    "api_json_invalid": "Invalid JSON: {error}",
    "api_server_access_not_found": "Server access rule not found for pattern '{pattern}'",
    "api_newsflash_not_found": "NewsFlash message with ID {msg_id} not found",
    "api_mailbox_not_found": "Message ID {message_id} not found",
    "api_staff_already_exists": "Staff member '{username}' already exists",
    "api_staff_not_found": "Staff member '{username}' not found",
    "api_logs_unavailable": "No logs available - journalctl failed and log file not found",
    "api_nickname_already_registered": "Nickname '{nickname}' is already registered",
    "api_channel_already_registered": "Channel '{channel_name}' is already registered",
    "api_channel_owner_not_found": "Owner '{owner_nickname}' not found. Please use a registered nickname or service name (System, Registrar, Messenger, NewsFlash)",
    "api_nickname_not_registered": "Nickname '{nickname}' is not registered",
    "api_nickname_owns_channels": "Cannot unregister '{nickname}': owns {channel_count} registered channel(s). Unregister channels first.",
    "api_staff_account_not_found": "Staff account '{username}' not found",
    "api_channel_not_registered": "Channel '{channel_name}' is not registered",
    "api_owner_not_found": "Owner nickname '{new_owner}' not found",
    "api_channel_no_changes": "No changes were made - please specify at least one property to update",
    "api_channel_not_found": "Channel '{channel_name}' not found",
    "api_channel_not_registered_for_access": "Channel '{channel_name}' is not registered. Register it first.",
    "api_no_command": "No command specified",
    "api_unknown_command": "Unknown command: {command}",
    "api_lock_channel_success": "Channel {channel_name} will be locked and registered to {owner}",
    "api_set_mode_success": "Mode {mode_string} will be set on {channel_name}",
    "api_set_topic_success": "Topic will be set on {channel_name}",
    "api_server_access_added": "Added {access_type} for {pattern}",
    "api_server_access_removed": "Removed {access_type} for {pattern}",
    "api_newsflash_added": "NewsFlash added",
    "api_newsflash_deleted": "NewsFlash message deleted successfully",
    "api_newsflash_settings_updated": "NewsFlash settings updated successfully",
    "api_mailbox_sent": "Message sent to {recipient_nick}",
    "api_mailbox_deleted": "Message {message_id} deleted",
    "api_staff_added": "Staff member '{username}' added as {level}",
    "api_staff_deleted": "Staff member '{username}' deleted successfully",
    "api_staff_password_changed": "Password changed for '{username}'",
    "api_staff_level_changed": "Level changed for '{username}' to {new_level}",
    "api_staff_profile_updated": "Profile updated for '{username}'",
    "api_nickname_registered": "Nickname '{nickname}' registered successfully",
    "api_channel_registered": "Channel '{channel_name}' registered successfully to {owner_nickname}",
    "api_nickname_unregistered": "Nickname '{nickname}' has been unregistered",
    "api_nickname_updated": "Updated {changes} for nickname '{nickname}'",
    "api_mfa_disabled": "MFA disabled for '{nickname}'",
    "api_channel_unregistered": "Channel '{channel_name}' has been unregistered",
    "api_channel_updated": "Updated {changes} for channel '{channel_name}'",
    "api_channel_updated_reload": "Updated {changes} for channel '{channel_name}' (channel will reload)",
    "api_channel_access_updated": "ACCESS lists updated for {channel_name}",
    "api_identify_nickname_not_registered": "Nickname not registered",
    "api_identify_mfa_required": "Password correct (MFA required for login)",
    "api_identify_success": "Password correct (authentication would succeed)",
    "api_identify_password_incorrect": "Password incorrect",
    "api_staff_login_not_found": "Staff account not found",
    "api_login_success_with_level": "Password correct (Level: {level})",
    "api_staff_login_password_incorrect": "Password incorrect",
    "api_health_db_ok": "Connected",
    "api_health_status_fresh": "Fresh ({age}s old)",
    "api_health_status_stale": "Stale ({age}s old)",
    "api_health_status_very_stale": "Very stale ({age}s old)",
    "api_health_status_not_found": "Not found - server may not be running",
    "api_health_pool_not_initialized": "Pool not initialized",
    "api_usage_add_server_access": "Usage: add-server-access <type> <pattern> <set_by> <reason> [timeout]",
    "api_usage_remove_server_access": "Usage: remove-server-access <type> <pattern>",
    "api_usage_add_newsflash": "Usage: add-newsflash <message> <created_by> [priority]",
    "api_usage_delete_newsflash": "Usage: delete-newsflash <id>",
    "api_usage_set_newsflash_settings": "Usage: set-newsflash-settings <on_connect> <periodic_enabled> <periodic_interval>",
    "api_usage_send_mailbox_message": "Usage: send-mailbox-message <sender> <recipient> <message>",
    "api_usage_delete_mailbox_message": "Usage: delete-mailbox-message <message_id>",
    "api_usage_search_nicknames": "Usage: search-nicknames <query>",
    "api_usage_search_channels": "Usage: search-channels <query>",
    "api_usage_set_config": "Usage: set-config <json>",
    "api_usage_set_motd": "Usage: set-motd <motd_lines>",
    "api_usage_add_staff": "Usage: add-staff <username> <password> <level> [realname] [email] [force_realname]",
    "api_usage_delete_staff": "Usage: delete-staff <username>",
    "api_usage_change_staff_password": "Usage: change-staff-password <username> <new_password>",
    "api_usage_change_staff_level": "Usage: change-staff-level <username> <new_level>",
    "api_usage_update_staff_profile": "Usage: update-staff-profile <username> <realname> <email> <force_realname>",
    "api_usage_register_nick": "Usage: register-nick <nickname> <password> [email]",
    "api_usage_register_channel": "Usage: register-channel <channel_name> <owner_nickname>",
    "api_usage_unregister_nick": "Usage: unregister-nick <nickname>",
    "api_usage_unregister_channel": "Usage: unregister-channel <channel_name>",
    "api_usage_edit_nick": "Usage: edit-nick <nickname> <new_password> [new_email]",
    "api_usage_reset_mfa": "Usage: reset-mfa <nickname>",
    "api_usage_test_identify": "Usage: test-identify <nickname> <password>",
    "api_usage_test_staff_login": "Usage: test-staff-login <username> <password>",
    "api_usage_test_staff_login_stdin": "Usage: test-staff-login-stdin <username> (password from stdin)",
    "api_usage_get_staff_details": "Usage: get-staff-details <username>",
    "api_usage_edit_channel": "Usage: edit-channel <channel_name> <new_owner> [new_description] [new_topic] [new_modes] [new_onjoin] [new_onpart] [new_memberkey] [new_hostkey] [new_ownerkey] [new_voicekey]",
    "api_usage_get_channel_access": "Usage: get-channel-access <channel_name>",
    "api_usage_get_channel_details": "Usage: get-channel-details <channel_name>",
    "api_usage_set_channel_access": "Usage: set-channel-access <channel_name> <access_list_json>",
    "api_usage_kill_user": "Usage: kill-user <nickname> [reason]",
    "api_usage_ban_user": "Usage: ban-user <nickname> [duration] [reason]",
    "api_usage_kill_channel": "Usage: kill-channel <channel>",
    "api_usage_lock_channel": "Usage: lock-channel <channel> [owner]",
    "api_usage_set_channel_mode": "Usage: set-channel-mode <channel> <mode_string>",
    "api_usage_set_channel_topic": "Usage: set-channel-topic <channel> [topic]",

    # --- API HELPERS - VALIDATION ERRORS ---
    "api_rate_limit_exceeded": "Too many attempts - please try again in a moment",
    "api_invalid_access_type": "Invalid access_type: '{access_type}'. Must be one of: {valid_types}",
    "api_pattern_required": "Please provide a pattern (e.g., nick!*@*.com)",
    "api_pattern_not_string": "Pattern must be a text string",
    "api_pattern_too_short": "Pattern must be at least {min_length} character(s) long",
    "api_pattern_too_long": "Pattern must not exceed {max_length} characters",
    "api_timeout_not_integer": "Timeout must be an integer",
    "api_timeout_negative": "Timeout cannot be negative",

    # --- API HELPERS - ERROR HANDLER RESPONSES ---
    "api_db_integrity_error": "Database integrity error: {error}",
    "api_db_operational_error": "Database operational error: {error}",
    "api_connection_timeout": "Connection timeout",
    "api_connection_refused": "Connection refused - server may not be running",
    "api_irc_server_not_running": "IRC server not running",

    # --- DB POOL - RUNTIME ERRORS ---
    "db_pool_not_initialized": "Connection pool not initialized",
    "db_pool_no_connection": "No database connection available (pool size: {pool_size})",
    "db_pool_not_initialized_call": "Connection pool not initialized. Call init_pool() first.",

    # --- LINKING - PROTOCOL ERROR MESSAGES ---
    "link_standalone_local": "This server is configured as standalone (linking disabled).",
    "link_standalone_remote": "Remote server is configured as standalone.",
    "link_trunk_to_trunk": "Trunk-to-trunk linking is not allowed (would create multi-tier topology).",
    "link_branch_to_branch": "Branch-to-branch linking is not allowed (branches must connect to trunk).",
    "link_invalid_role_combo": "Invalid role combination: {my_role} <-> {remote_role}.",
    "link_error_invalid_version": "Invalid VERSION response.",
    "link_error_version_mismatch": "Version mismatch. Remote: {remote_version}, Local: {local_version}. Versions must match exactly. Please upgrade or downgrade to match.",
    "link_error_incompatible_proto": "Incompatible linking protocol {remote_proto}. Required: {required_proto}.",
    "link_error_invalid_timesync": "Invalid TIMESYNC response.",
    "link_error_clock_skew": "Clock skew {delta}s exceeds {limit}s limit. Synchronize clocks with NTP (same time source recommended).",
    "link_error_timesync_format": "Invalid TIMESYNC format.",
    "link_error_bad_password": "Incorrect password.",
    "link_error_rejected": "Link rejected: {error_msg}.",
    "link_not_enabled": "Server linking is not enabled on this server.",
    "link_notice_server_linked": "Server {server} linked.",
    "link_notice_linked_to": "Linked to server {server}.",
    "link_notice_server_split": "Server {server} has split.",
    "links_end": "End of /LINKS list",
    "map_end": "End of /MAP",

    # --- WEBCHAT GATEWAY MESSAGES ---
    "webchat_error_at_capacity": "Server at capacity - please try again later",
    "webchat_error_too_many_ip": "Too many connections from your IP - please close some connections first",
    "webchat_error_connect_refused": "Unable to connect to chat server - please try again later",
    "webchat_error_connect_timeout": "Connection timeout - please try again later",
    "webchat_error_connection": "Connection error - please try again later",
    "webchat_error_rate_limit": "Sending messages too fast - please slow down",
    "webchat_error_reconnect": "Connection error - please reconnect",

    # --- IRC COMMAND USAGE STRINGS ---
    "usage_config_get": "CONFIG GET <section.key>",
    "usage_config_set": "CONFIG SET <section.key> <value>",
    "usage_link": "LINK <servername>",
    "usage_unlink": "UNLINK <servername> [reason]",
    "usage_staff_add": "STAFF ADD <username> <password> <level>",
    "usage_staff_delete": "STAFF DELETE <username>",
    "usage_staff_set": "STAFF SET <username> <level>",
    "usage_staff_pass": "STAFF PASS <username> <oldpassword> <newpassword>",
    "usage_register": "REGISTER <account> <email|*> <password>",
    "usage_unregister": "UNREGISTER <account|#channel>",
    "usage_identify": "IDENTIFY [<account>] <password>",
    "usage_mfa": "MFA ENABLE|VERIFY|DISABLE [<code>]",
    "usage_mfa_verify": "MFA VERIFY <6-digit code>",
    "usage_chgpass": "CHGPASS <oldpassword> <newpassword>",
    "usage_memo": "MEMO SEND <nickname> <message> | LIST | READ | DELETE <id|ALL>",
    "usage_ns_register": "REGISTER <password> [<email>]",
    "usage_ns_identify": "IDENTIFY <password>",
    "usage_ns_channel_register": "CHANNEL REGISTER|DROP <#channel>",
    "usage_ns_channel_full": "CHANNEL REGISTER|DROP|INFO <#channel>",
    "usage_ns_set": "SET PASSWORD|EMAIL <value>",
    "usage_ns_mfa": "MFA ENABLE|VERIFY|DISABLE [<code>]",
    "valid_staff_levels": "ADMIN, SYSOP, or GUIDE",
    "item_staff_account": "Staff account",

    # --- BOT / STATS ---
    "stats_bot_users": "  User bots (+b): {count}",
}

# ==============================================================================
# SERVICE HELP MENUS - Multi-line help text for service bots
# ==============================================================================
SERVICE_HELP = {
    "registrar": [
        "=== Registrar Service Help ===",
        "",
        "Nickname Registration:",
        "  REGISTER <password> [<email>] - Register your current nickname",
        "    Example: REGISTER mypassword me@example.com",
        "    Example: REGISTER mypassword (without email)",
        "  IDENTIFY <password> - Log into your registered nickname",
        "    Example: IDENTIFY mypassword",
        "  DROP - Delete your nickname registration",
        "  INFO [<nickname>] - View registration information",
        "    Example: INFO alice",
        "",
        "Channel Registration:",
        "  CHANNEL REGISTER <#channel> - Register a channel you own",
        "    Example: CHANNEL REGISTER #mychannel",
        "  CHANNEL DROP <#channel> - Unregister a channel",
        "  CHANNEL INFO <#channel> - View channel registration information",
        "    Example: CHANNEL INFO #lobby",
        "",
        "Account Settings:",
        "  SET PASSWORD <newpass> - Change your password",
        "    Example: SET PASSWORD mynewpassword",
        "  SET EMAIL <email> - Change your email address",
        "    Example: SET EMAIL newemail@example.com",
        "",
        "Two-Factor Authentication:",
        "  MFA ENABLE - Enable 2FA (you'll receive a QR code)",
        "  MFA VERIFY <code> - Complete MFA login with 6-digit code",
        "    Example: MFA VERIFY 123456",
        "  MFA DISABLE <code> - Disable two-factor authentication",
        "    Example: MFA DISABLE 123456",
        "",
        "Alternative: Use direct commands /REGISTER, /IDENTIFY, /UNREGISTER, /MFA",
        "For direct help: /HELP REGISTER or /HELP MFA",
    ],
    "messenger": [
        "=== Messenger - Offline Message Service ===",
        "",
        "Send and receive messages when users are offline.",
        "",
        "Commands:",
        "  SEND <nickname> <message> - Send a message to a user",
        "    Example: SEND alice Don't forget the meeting tomorrow!",
        "    If the user is offline, they'll receive it when they return",
        "  READ - Read all your offline messages",
        "    Shows sender, timestamp, and message content",
        "  DELETE <id> - Delete a specific message by ID",
        "    Example: DELETE 5",
        "  COUNT - Show how many unread messages you have",
    ],
    "messenger_admin": [
        "  PUSH <message> - (ADMIN only) Send to all online users",
        "    Example: PUSH Server maintenance in 5 minutes",
    ],
    "messenger_tip": [
        "",
        "Tip: Messages are delivered automatically when the user logs in",
    ],
    "newsflash": [
        "=== NewsFlash - Network News Service ===",
        "",
        "Network-wide announcements and updates.",
        "",
        "Commands:",
        "  LIST - View all active news messages",
        "    Shows message ID, timestamp, and content",
    ],
    "newsflash_staff": [
        "  ADD <message> - (STAFF only) Post a network announcement",
        "    Example: ADD Server upgrade scheduled for Saturday 3am EST",
        "  DELETE <id> - (STAFF only) Remove a news message",
        "    Example: DELETE 7",
    ],
    "newsflash_admin": [
        "  PUSH <message> - (ADMIN only) Send immediate notice to all online users",
        "    Example: PUSH Emergency maintenance starting now!",
    ],
    "newsflash_tip": [
        "",
        "Tip: News messages persist until deleted, PUSH is immediate",
    ],
    "servicebot": [
        "=== ServiceBot - Channel Monitoring Service ===",
        "I automatically monitor channels for problematic behavior and take action.",
        "",
        "Monitoring Features:",
    ],
    "servicebot_profanity_enabled": "  Profanity Filter: Enabled (Action: {action})",
    "servicebot_profanity_disabled": "  Profanity Filter: Disabled",
    "servicebot_flood_enabled": "  Flood Protection: Enabled (Action: {action})",
    "servicebot_caps_enabled": "  CAPS Detection: Enabled (Action: {action})",
    "servicebot_url_enabled": "  URL Spam Detection: Enabled (Action: {action})",
    "servicebot_repeat_enabled": "  Repeat Message Detection: Enabled (Action: {action})",
    "servicebot_malicious_disabled": "  Malicious Detection: Disabled",
    "servicebot_help_footer": [
        "",
        "Actions: warn (warning), gag (mute user), kick (remove from channel)",
        "",
        "Commands:",
        "  HELP - Show this help message",
        "  STATUS - View this bot's status and channels",
        "",
    ],
    "entity": [
        "=== {entity_name} Commands (Admin Only) ===",
        "PRIVMSG <target> <message> - Send message as {entity_name}",
        "NOTICE <target> <message> - Send notice as {entity_name}",
        "KICK <channel> <nickname> <reason> - Kick user as {entity_name}",
        "KILL <nickname> <reason> - Kill user as {entity_name}",
        "All actions masquerade as {entity_name}",
    ],
}

# ==============================================================================
# EASTER EGG JOKES - Random jokes for the JOKE command
# ==============================================================================
EASTER_EGG_JOKES = [
    "Why don't scientists trust atoms? Because they make up everything!",
    "What do you call a bear with no teeth? A gummy bear!",
    "Why did the scarecrow win an award? He was outstanding in his field!",
    "What do you call fake spaghetti? An impasta!",
    "Why don't eggs tell jokes? They'd crack each other up!",
    "What do you call a dinosaur that crashes his car? Tyrannosaurus Wrecks!",
    "Why can't you hear a pterodactyl go to the bathroom? Because the 'P' is silent!",
    "What did the ocean say to the beach? Nothing, it just waved!",
    "Why did the math book look so sad? Because it had too many problems!",
    "What do you call a fish wearing a bowtie? Sofishticated!",
    "Why did the bicycle fall over? Because it was two-tired!",
    "What do you call a sleeping bull? A bulldozer!",
    "Why don't skeletons fight each other? They don't have the guts!",
    "What do you call cheese that isn't yours? Nacho cheese!",
    "Why couldn't the leopard play hide and seek? Because he was always spotted!",
    "What did one wall say to the other wall? I'll meet you at the corner!",
    "Why did the cookie go to the doctor? Because it felt crumbly!",
    "What do you call a snowman with a six-pack? An abdominal snowman!",
    "Why did the golfer bring two pairs of pants? In case he got a hole in one!",
    "What's orange and sounds like a parrot? A carrot!",
    "Why don't programmers like nature? It has too many bugs!",
    "What do you call a lazy kangaroo? A pouch potato!",
    "Why did the tomato turn red? Because it saw the salad dressing!",
    "What do you call a belt made of watches? A waist of time!",
    "Why did the computer go to the doctor? Because it had a virus!",
    "What do you call a can opener that doesn't work? A can't opener!",
    "Why did the stadium get hot after the game? All the fans left!",
    "What do you call a group of unorganized cats? A cat-astrophe!",
    "Why don't oysters donate to charity? Because they're shellfish!",
    "What did the grape do when it got stepped on? Nothing but let out a little wine!",
    "Why did the picture go to jail? Because it was framed!",
    "What do you call a parade of rabbits hopping backwards? A receding hare-line!",
    "Why couldn't the bicycle stand up by itself? It was two-tired!",
    "What do you call a boomerang that won't come back? A stick!",
    "Why did the coffee file a police report? It got mugged!",
    "What do you call a bear in the rain? A drizzly bear!",
    "Why don't scientists trust stairs? Because they're always up to something!",
    "What do you call a magician who loses his magic? Ian!",
    "Why did the invisible man turn down the job offer? He couldn't see himself doing it!",
    "What do you call a pile of cats? A meowtain!",
    "Why did the moon skip dinner? Because it was full!",
    "What do you call a singing laptop? A Dell!",
    "Why don't calendars ever win races? Because they only have 12 months!",
    "What do you call a cow with no legs? Ground beef!",
    "Why did the smartphone need glasses? It lost all its contacts!",
    "What do you call a chicken staring at lettuce? Chicken sees a salad!",
    "Why did the baker go to therapy? He kneaded it!",
    "What do you call a sleeping pizza? A piZZZa!",
    "Why don't trees use computers? They prefer to log in naturally!",
    "What do you call a knight who is afraid to fight? Sir Render!",
]

# ==============================================================================
# ENTITY RESPONSES - Easter egg responses for God/System entities
# ==============================================================================
ENTITY_RESPONSES = {
    "god": [
        "In the beginning was the Word...and the Word was 'busy'.",
        "Let there be light...but not for thee at this moment.",
        "Thou shalt not spam the divine hotline.",
        "I work in mysterious ways...like ignoring non-admins.",
        "The meek shall inherit the Earth, but not admin privileges.",
        "Ask and ye shall receive...a humorous deflection.",
        "Blessed are the admins, for they can command me.",
        "Lo, I am with you always...but I don't take requests from mortals.",
        "Fear not, for I bring you tidings of...access denied.",
        "Seek and ye shall find...the admin if you need something.",
        "Patience is a virtue. I have infinite patience. You should too.",
        "Knock and the door shall be opened...by an admin.",
        "Verily, verily I say unto you...get admin privileges first.",
        "I am the Alpha and the Omega...and you are neither.",
    ],
    "system": [
        "404: Admin privileges not found.",
        "Kernel panic in ircd_core.c at line 1337.",
        "Error: Insufficient privileges. Expected: admin, Got: mortal.",
        "sudo make me do that. (Permission denied)",
        "Segmentation fault (core dumped to /dev/null).",
        "FATAL: Non-admin user attempted system call.",
        "Warning: This functionality requires root access to the cosmos.",
        "Compiler error: Cannot convert 'user' to 'admin'.",
        "Stack overflow in command buffer. Please try 'sudo' and retry.",
        "Oops! That tickles! But I only take orders from ops.",
        "Rebooting universe.exe...just kidding, I'm busy.",
        "Critical error: Humor module loaded, admin module not found.",
        "Access violation at address 0xDEADBEEF. Process terminated.",
        "Your request has been logged to /dev/null for future reference.",
        "Beep boop. I am a virtual entity. Beep. Also, you're not an admin.",
        "System.out.println('Nice try, mortal!');",
        "Error: Cannot open '/etc/admin.conf': Permission denied.",
        "Rejected by firewall rule #1: DROP all non-admin packets.",
        "Oops! It looks like you're trying to admin. Would you like help with that? LOL no.",
        "malloc() failed: Not enough admin privileges available.",
    ],
}

# ==============================================================================
# LOG MESSAGES - Centralized logging message templates
# ==============================================================================
LOG_MESSAGES = {
    # CONFIG MESSAGES
    "config_loaded": "Loaded config from {file}",
    "config_error": "Config error: {error}",
    "config_not_found": "Config file not found: {file}",
    "config_saved": "Config saved",
    "config_save_error": "Save error: {error}",
    "config_reloaded": "Configuration reloaded successfully",

    # SSL/TLS MESSAGES
    "ssl_missing_config": "SSL enabled but cert_file or key_file not configured",
    "ssl_cert_not_found": "SSL certificate file not found: {file}",
    "ssl_key_not_found": "SSL key file not found: {file}",
    "ssl_loaded": "SSL certificates loaded successfully",
    "ssl_cert_file": "  Certificate: {file}",
    "ssl_key_file": "  Key: {file}",
    "ssl_min_tls": "  Minimum TLS: {version}",
    "ssl_expiry": "  Expires: {expiry} ({days} days)",
    "ssl_subject": "  Subject: {subject}",
    "ssl_load_error": "SSL error loading certificates: {error}",
    "ssl_load_generic_error": "Error loading SSL certificates: {error}",
    "ssl_parse_error": "Could not parse certificate details: {error}",
    "ssl_files_changed": "SSL certificate files changed, reloading...",
    "ssl_reloaded": "SSL certificates reloaded successfully",
    "ssl_reload_failed": "Failed to reload SSL certificates, keeping old ones",
    "ssl_check_error": "Error checking certificate files: {error}",
    "ssl_expired": "SSL CERTIFICATE HAS EXPIRED! Renew immediately.",
    "ssl_expires_soon": "SSL certificate expires in less than 1 day! Renew immediately.",
    "ssl_expires_warning": "SSL certificate expires in {days} days. Consider renewing soon.",
    "ssl_force_reload": "Forcing SSL certificate reload...",
    "ssl_context_updated": "SSL context updated for new connections",
    "ssl_monitor_error": "SSL monitor error: {error}",
    "ssl_reload_error": "Failed to reload SSL certificates: {error}",

    # SECURITY MESSAGES
    "auth_lockout_ip": "Auth lockout triggered for IP {ip} ({duration}s)",
    "auth_lockout_user": "Auth lockout triggered for username {username} ({duration}s)",
    "dnsbl_listed": "DNSBL: {ip} listed in {dnsbl}",
    "dnsbl_check_error": "DNSBL check error for {dnsbl}: {error}",
    "dnsbl_action": "DNSBL: {ip} listed in {dnsbls} - action: {action}",
    "proxy_detected": "Proxy detection: {ip}:{port} is open",
    "rate_limit_exceeded": "Rate limit exceeded for {key}",
    "cache_hit": "Cache hit for {func}",
    "cache_miss": "Cache miss for {func}",
    "flood_triggered": "Flood: {nickname}",
    "connection_score_exceeded": "Connection score {score} exceeds threshold for {ip}",
    "banned_connection": "Banned connection refused: {ip} - {reason}",
    "throttled_connection": "Throttled: {ip}",
    "max_users_reached": "Max users reached",
    "cap_timeout": "CAP timeout: {ip} (stuck in negotiation)",
    "cap_timeout_error": "CAP timeout disconnect error: {error}",
    "config_permissions_warning": "SECURITY WARNING: Config file is world-readable/writable!",
    "config_file_info": "File: {file}",
    "config_permissions_current": "Current permissions: {permissions}",
    "config_permissions_fix": "Recommended fix: sudo chmod 600 /etc/pyircx/pyircx_config.json",
    "config_group_readable": "Config file {file} is group-readable. Consider chmod 600 for maximum security.",
    "config_permissions_error": "Could not validate config file permissions: {error}",

    # DATABASE MESSAGES
    "db_pool_init": "Initializing connection pool: {db_path} (size: {pool_size})",
    "db_pool_conn_created": "Created pool connection {num}/{total}",
    "db_pool_conn_failed": "Failed to create pool connection {num}: {error}",
    "db_pool_ready": "Connection pool initialized with {pool_size} connections",
    "db_pool_exhausted": "Connection pool exhausted (timeout={timeout}s)",
    "db_async_pool_ready": "Async connection pool ready (size: {size})",
    "db_async_pool_exhausted": "Async connection pool exhausted (size: {size})",
    "db_rollback": "Transaction rolled back due to error",
    "db_pool_rollback_failed": "Pool rollback failed: {error}",
    "db_pool_return_failed": "Failed to return connection to pool: {error}",
    "db_replacement_created": "Created replacement connection",
    "db_pool_replacement_failed": "Failed to create pool replacement connection: {error}",
    "db_closing": "Closing all connections in pool",
    "db_already_init": "Connection pool already initialized, closing existing pool",
    "db_initialized": "Database initialized (trunk)",
    "db_skipped": "Skipping database initialization (branch server)",
    "db_pool_initialized": "Database connection pool initialized",
    "db_pool_closed": "Database pool closed",
    "db_pool_close_error": "Database pool close: {error}",

    # SERVER STARTUP/SHUTDOWN MESSAGES
    "server_header": "=" * 70,
    "server_name": " {servername} Enhanced",
    "server_network": " {network}",
    "server_starting": "pyIRCX Server starting (PID: {pid})",
    "server_mode": "Mode: {mode}",
    "server_fatal": "Fatal error: {error}",
    "shutdown_initiated": "Initiating graceful shutdown...",
    "shutdown_complete": "Shutdown complete",
    "shutdown_timeout": "Shutdown timeout exceeded, forcing exit",
    "shutdown_error": "Shutdown error: {error}",
    "link_manager_shutdown": "Link manager shutdown complete",
    "link_manager_shutdown_error": "Link manager shutdown: {error}",
    "server_close_timeout": "Timeout waiting for server to close, forcing",
    "client_disconnect_timeout": "Timeout disconnecting clients, forcing",
    "no_ports_available": "No ports available, exiting",

    # LISTENING/BINDING MESSAGES
    "listening_ipv6": "Listening on [{addr}]:{port} ({family})",
    "listening_ipv4": "Listening on {addr}:{port} ({family})",
    "listening_ipv6_ssl": "Listening on [{addr}]:{port} ({family}, SSL/TLS)",
    "listening_ipv4_ssl": "Listening on {addr}:{port} ({family}, SSL/TLS)",
    "bind_failed_ipv6": "Failed to bind to [{addr}]:{port} ({family}): {error}",
    "bind_failed_ipv4": "Failed to bind to {addr}:{port} ({family}): {error}",
    "bind_ssl_failed_ipv6": "Failed to bind SSL to [{addr}]:{port} ({family}): {error}",
    "bind_ssl_failed_ipv4": "Failed to bind SSL to {addr}:{port} ({family}): {error}",

    # SERVICE INITIALIZATION MESSAGES
    "system_channel_created": "#System channel created",
    "god_user_created": "God virtual user created",
    "registrar_created": "Registrar service created",
    "messenger_created": "Messenger service created",
    "newsflash_created": "NewsFlash service created",
    "servicebots_created": "{count} ServiceBots created",
    "servicebot_dispatcher_created": "ServiceBot dispatcher created",
    "services_initialized": "Services initialized in {mode} mode",
    "services_with_hub": " (providing hub services)",
    "services_disabled_branch": "Services disabled: Running as branch server in centralized mode",
    "services_trunk_info": "Services will be provided by trunk: {trunk}",
    "services_disabled": "Services disabled by configuration",
    "services_config_error": "Services configuration error - check services.mode and services.is_services_hub",
    "dnsbl_enabled": "DNSBL checking enabled",
    "proxy_detection_enabled": "Proxy detection enabled",
    "connection_scoring_enabled": "Connection scoring enabled",
    "cap_monitor_started": "CAP timeout monitor started ({timeout}s timeout)",
    "linking_enabled": "Server linking enabled",

    # USER CONNECTION MESSAGES
    "client_timeout": "Client timeout (no data for {timeout}s): {nickname} ({ip})",
    "client_debug": "[{nickname}] <<< {data}",
    "client_error": "Client error [{nickname}]: {error}",
    "client_traceback": "Traceback: {traceback}",
    "user_send_error": "User send error [{nickname}]: {error}",
    "close_error": "Close error: {error}",
    "status_dump_error": "Status dump error: {error}",

    # AUTHENTICATION MESSAGES
    "webirc_disabled": "WEBIRC attempt from {ip} but WEBIRC is disabled",
    "webirc_unknown_gateway": "WEBIRC: Unknown gateway '{gateway}' from {ip}",
    "webirc_invalid_password": "WEBIRC: Invalid password from gateway '{gateway}' at {ip}",
    "webirc_not_allowed": "WEBIRC: Gateway '{gateway}' not allowed from {ip}",
    "webirc_spoofed": "WEBIRC: {gateway} spoofed {old_ip} -> {new_ip} ({hostname})",
    "webirc_invalid_client_ip": "WEBIRC: Invalid client IP '{client_ip}' from gateway '{gateway}'",
    "sasl_staff_auth_trunk": "SASL staff auth via trunk: {account} as {level}",
    "sasl_staff_auth_failed_trunk": "SASL staff auth failed: Trunk unavailable for {account}",
    "sasl_staff_auth_failed_link": "SASL staff auth failed: Link manager not available for {account}",
    "sasl_auth_lookup_error": "SASL auth lookup error: {error}",
    "pass_staff_blocked_ssl": "PASS staff auth blocked: {username} ({ip}) - no SSL",
    "staff_auth_trunk": "Staff auth via trunk: {username} as {level}",
    "staff_auth_failed_trunk": "Staff auth failed: Trunk unavailable for {username}",
    "pass_auth_attempt": "PASS auth attempt: username='{username}' ip={ip}",
    "pass_auth_found": "PASS auth: Found staff account for '{username}'",
    "pass_auth_success": "PASS auth: SUCCESS for '{username}' as {level}",
    "pass_auth_wrong_password": "PASS auth: FAILED for '{username}' - wrong password",
    "pass_auth_not_found": "PASS auth: No staff account found for '{username}'",
    "pass_auth_error": "PASS auth error for '{username}': {error}",
    "auth_success": "AUTH: {username} authenticated successfully from {nickname} ({ip}) as {level}",
    "access_grant_matched": "User {nickname} matches ACCESS GRANT pattern: {pattern}",
    "access_rejected": "Rejected non-authorized connection attempt: {nickname} ({ip})",
    "default_admin_created": "Created default ADMIN account: {username}",
    "default_admin_warning": "*** CHANGE THE DEFAULT PASSWORD IMMEDIATELY using: STAFF PASS ***",
    "sasl_decode_error": "SASL decode error for {nickname}: {error}",
    "sasl_plain_success": "SASL PLAIN auth success: {username} ({ip})",
    "sasl_database_error": "SASL database error: {error}",
    "sasl_plain_failed": "SASL PLAIN auth failed: {username} ({ip})",
    "sasl_plain_error": "SASL PLAIN error: {error}",

    # AUTH COMMAND MESSAGES
    "auth_no_ssl": "AUTH: {nickname} ({ip}) attempted AUTH on non-SSL connection",
    "auth_unknown_user": "AUTH: Failed attempt for unknown user '{username}' from {nickname} ({ip})",
    "auth_wrong_password": "AUTH: Failed password for '{username}' from {nickname} ({ip})",
    "auth_error": "AUTH error: {error}",
    "auth_mfa_expired": "AUTH: MFA session expired for {nickname}",
    "auth_mfa_invalid": "AUTH: Invalid MFA code for '{username}' from {nickname} ({ip})",
    "auth_verify_error": "AUTH VERIFY error: {error}",
    "auth_verify_setup_error": "AUTH VERIFY setup error: {error}",
    "auth_enable_error": "AUTH ENABLE error: {error}",
    "auth_disable_success": "AUTH DISABLE: {username} disabled MFA",
    "auth_disable_error": "AUTH DISABLE error: {error}",
    "auth_count_failures_error": "_count_auth_failures error: {error}",
    "drop_success": "DROP: {username} ({level}) dropped to regular user from {nickname} ({ip})",

    # NICK BURST/LINKING MESSAGES
    "nick_burst_broadcasting": "Broadcasting NICK burst for {nickname} to linked servers: {burst}",
    "nick_burst_sent": "NICK burst sent for {nickname}",

    # SERVICE MESSAGE ROUTING
    "service_routed": "Routed service message from {nickname} to {target} via trunk",
    "service_route_failed": "Failed to route to trunk for {target}",

    # CHANNEL MESSAGES
    "channel_loaded": "Loaded registered channel: {channel}",
    "channel_load_error": "Error loading registered channel {channel}: {error}",
    "join_propagated_sending": "Propagating JOIN to linked servers: {message}",
    "join_propagated": "JOIN propagated for {nickname} to {channel}",
    "topic_set": "Topic set in {channel} by {nickname}",
    "prop_set": "PROP {channel} {prop}={value} by {nickname}",
    "transcript_write_error": "Transcript write error for {channel}: {error}",
    "transcript_read_error": "Transcript read error for {channel}: {error}",

    # ACCESS MESSAGES
    "access_loaded": "ACCESS rules loaded: {grant} GRANT, {deny} DENY",
    "access_load_error": "Load ACCESS error: {error}",
    "access_add": "ACCESS {target} ADD {level} {mask} by {nickname}",
    "access_add_error": "ACCESS ADD DB error: {error}",
    "access_del": "ACCESS {target} DELETE {level} {mask} by {nickname}",
    "access_del_error": "ACCESS DELETE DB error: {error}",
    "access_clear": "ACCESS {target} CLEAR {level} by {nickname}",
    "access_clear_error": "ACCESS CLEAR DB error: {error}",
    "access_in_memory": "ACCESS list: In-memory only (branch server)",

    # STATS/ERROR MESSAGES
    "stats_error": "Stats error: {error}",
    "database_stats_error": "Database stats error: {error}",
    "newsflash_stats_error": "NewsFlash stats error: {error}",
    "newsflash_error": "NewsFlash error: {error}",
    "reply_error": "Reply error {code}: {error}",
    "template_error": "Missing template variable for {key}: {error}",
    "unknown_message_key": "Unknown message key: {key}",

    # CONFIG COMMAND MESSAGES
    "config_set_log": "CONFIG: {nickname} set {key} = {value}",
    "config_saved_log": "CONFIG: {nickname} saved configuration",
    "config_reloaded_log": "CONFIG: {nickname} reloaded configuration",

    # LINK COMMAND MESSAGES
    "link_success": "LINK: {nickname} linked to {server}",
    "link_failed_log": "LINK: Failed to link to {server}: {error}",
    "unlink_success": "UNLINK: {nickname} unlinked {server}: {reason}",
    "unlink_failed": "UNLINK: Failed to unlink {server}: {error}",

    # STAFF COMMAND MESSAGES
    "staff_log": "STAFF: {message}",
    "staff_list_error": "STAFF LIST error: {error}",
    "staff_added": "STAFF: {nickname} added staff account '{username}' ({level})",
    "staff_add_error": "STAFF ADD error: {error}",
    "staff_deleted": "STAFF: {nickname} deleted staff account '{username}' ({level})",
    "staff_del_error": "STAFF DELETE error: {error}",
    "staff_level_changed": "STAFF: {nickname} changed '{username}' level from {old_level} to {new_level}",
    "staff_set_error": "STAFF SET error: {error}",
    "staff_password_changed": "STAFF: {nickname} changed password for '{username}'",
    "staff_pass_error": "STAFF PASS error: {error}",
    "staff_mfa_checked": "STAFF MFA: {nickname} checked MFA status for {username}",
    "staff_mfa_enable_failed": "STAFF MFA: {nickname} failed to enable MFA for {username} (invalid code)",
    "staff_mfa_enabled": "STAFF MFA: {nickname} enabled MFA for {username}",
    "staff_mfa_disable_failed": "STAFF MFA: {nickname} failed to disable MFA for {username} (invalid code)",
    "staff_mfa_disabled": "STAFF MFA: {nickname} disabled MFA for {username}",
    "staff_mfa_error": "STAFF MFA error: {error}",

    # PROFANITY COMMAND MESSAGES
    "profanity_word_added_log": "PROFANITY: {nickname} added word '{word}'",
    "profanity_pattern_added_log": "PROFANITY: {nickname} added pattern '{pattern}'",
    "profanity_word_removed_log": "PROFANITY: {nickname} removed word '{word}'",
    "profanity_pattern_removed_log": "PROFANITY: {nickname} removed pattern '{pattern}'",
    "profanity_enabled_log": "PROFANITY: {nickname} enabled profanity filter",
    "profanity_disabled_log": "PROFANITY: {nickname} disabled profanity filter",

    # REGISTRATION MESSAGES
    "register_nick": "REGISTER: {account} registered by {prefix}",
    "register_nick_error": "REGISTER nick error: {error}",
    "register_channel": "REGISTER: {channel} registered by {nickname}",
    "register_channel_error": "REGISTER channel error: {error}",
    "unregister_nick": "UNREGISTER: {account} unregistered",
    "unregister_nick_error": "UNREGISTER nick error: {error}",
    "unregister_channel": "UNREGISTER: {channel} unregistered by {nickname}",
    "unregister_channel_error": "UNREGISTER channel error: {error}",
    "identify_success": "IDENTIFY: {account} identified",
    "identify_error": "IDENTIFY error: {error}",

    # MFA MESSAGES
    "mfa_setup_initiated": "MFA: {nickname} initiated setup",
    "mfa_enable_error": "MFA enable error: {error}",
    "mfa_verify_error": "MFA verify error: {error}",
    "mfa_disabled": "MFA: {nickname} disabled MFA",
    "mfa_disable_error": "MFA disable error: {error}",

    # CHGPASS/SETNAME MESSAGES
    "chgpass_proxied": "Proxied CHGPASS from {nickname} to trunk",
    "chgpass_success": "CHGPASS: {nickname} changed password",
    "chgpass_error": "CHGPASS error: {error}",
    "setname_changed": "SETNAME: {nickname} changed realname to '{realname}'",

    # MEMO MESSAGES
    "memo_send_error": "MEMO SEND error: {error}",
    "memo_list_error": "MEMO LIST error: {error}",
    "memo_read_error": "MEMO READ error: {error}",
    "memo_del_error": "MEMO DELETE error: {error}",
    "memo_delivery_error": "Memo delivery check error: {error}",

    # SERVICEBOT MESSAGES
    "servicebot_warned": "ServiceBot {bot}: Warned {user} in {channel} for {violation}",
    "servicebot_gagged": "ServiceBot {bot}: Gagged {user} in {channel} for {violation}",
    "servicebot_kicked": "ServiceBot {bot}: Kicked {user} from {channel} for {violation}",
    "servicebot_banned": "ServiceBot {bot}: Banned {user} from {channel} for {violation}",
    "servicebot_dispatcher_assigned": "ServiceBot dispatcher assigned {bot} to {channel} via INVITE from {nickname}",
    "servicebot_invited": "ServiceBot {bot} joined {channel} via INVITE from {nickname} (granted +q)",
    "entity_invited": "{entity} joined {channel} via INVITE from {nickname} (granted +q)",

    # REGISTRAR SERVICE MESSAGES
    "registrar_registered": "Registrar: {nickname} registered by {prefix}",
    "registrar_register_error": "Registrar register error: {error}",
    "registrar_identified": "Registrar: {nickname} identified",
    "registrar_identify_error": "Registrar identify error: {error}",
    "registrar_dropped": "Registrar: {nickname} dropped",
    "registrar_drop_error": "Registrar drop error: {error}",
    "registrar_info_error": "Registrar info error: {error}",
    "registrar_channel_registered": "Registrar: {channel} registered by {nickname}",
    "registrar_channel_register_error": "Registrar channel register error: {error}",
    "registrar_channel_dropped": "Registrar: {channel} dropped by {nickname}",
    "registrar_channel_drop_error": "Registrar channel drop error: {error}",
    "registrar_channel_info_error": "Registrar channel info error: {error}",
    "registrar_password_changed": "Registrar: {nickname} changed password",
    "registrar_set_error": "Registrar set error: {error}",
    "registrar_mfa_enable_error": "Registrar MFA enable error: {error}",
    "registrar_mfa_disabled": "Registrar: {nickname} disabled MFA",
    "registrar_mfa_disable_error": "Registrar MFA disable error: {error}",
    "registrar_mfa_enabled": "Registrar: {nickname} enabled MFA",
    "registrar_mfa_verify_error": "Registrar MFA verify error: {error}",

    # MESSENGER SERVICE MESSAGES
    "messenger_send_error": "Messenger send error: {error}",
    "messenger_read_error": "Messenger read error: {error}",
    "messenger_delete_error": "Messenger delete error: {error}",
    "messenger_count_error": "Messenger count error: {error}",
    "messenger_global_push": "Messenger: Global push by {nickname}: {message}",

    # NEWSFLASH SERVICE MESSAGES
    "newsflash_list_error": "NewsFlash list error: {error}",
    "newsflash_added": "NewsFlash: Added by {nickname}: {message}",
    "newsflash_add_error": "NewsFlash add error: {error}",
    "newsflash_delete_error": "NewsFlash delete error: {error}",
    "newsflash_periodic_error": "NewsFlash periodic error: {error}",

    # ADMIN COMMAND MESSAGES
    "admin_killed_channel": "Admin command: Killed channel {channel} for reconfiguration",
    "admin_killed_user": "Admin command: Killed user {nickname} - {reason}",
    "admin_banned_user": "Admin command: Banned user {nickname} ({ip}) for {duration}s - {reason}",
    "admin_registered_channel": "Admin command: Registered channel {channel} to {owner}",
    "admin_updated_channel": "Admin command: Updated channel {channel} owner to {owner} with +ra modes",
    "admin_locked_channel": "Admin command: Locked channel {channel} (registered +ra to {owner})",
    "admin_set_mode": "Admin command: Set mode {mode} on {channel}",
    "admin_set_topic": "Admin command: Set topic on {channel}",
    "admin_system_user_missing": "Admin command: System user not found for {command}",
    "admin_command_error": "Error processing admin commands: {error}",
    "admin_lock_channel_error": "Error locking channel {channel}: {error}",

    # MFA messages
    "mfa_identify_success": "MFA: {nickname} completed identification",
    "mfa_enabled": "MFA: {nickname} enabled",

    # Auth messages
    "auth_lockout": "AUTH: {username} locked out (IP: {ip})",
    "auth_pending_mfa": "AUTH: Password OK for '{username}' from {nickname} ({ip}), awaiting MFA",
    "auth_mfa_secret_missing": "AUTH: MFA secret not found for {username}",
    "auth_mfa_first_verify": "AUTH VERIFY: MFA enabled for {username} after first successful verification",
    "auth_verify_mfa_enabled": "AUTH VERIFY: {username} enabled MFA via setup completion",
    "auth_verify_mfa_failed": "AUTH VERIFY: {username} failed MFA setup verification",
    "auth_enable_bad_password": "AUTH ENABLE: Failed password verification for {username}",
    "auth_enable_secret_generated": "AUTH ENABLE: {username} generated MFA secret",
    "auth_update_last_login_error": "AUTH: Failed to update last_login: {error}",

    # Registrar service messages
    "registrar_mfa_setup": "Registrar: {nickname} initiated MFA setup",
    "registrar_mfa_identified": "Registrar: {nickname} completed MFA identification",

    # NewsFlash service messages
    "newsflash_push": "NewsFlash: Push by {nickname}: {message}",
    "newsflash_connect_error": "NewsFlash on-connect error: {error}",
    "newsflash_periodic": "NewsFlash: Periodic broadcast to {count} user(s)",

    # Mode messages
    "mode_unregister_channel": "Channel {channel} unregistered via MODE -r by {nickname}",
    "mode_unregister_error": "MODE -r database error: {error}",
    "mode_channel_locked": "Channel {channel} locked (+z) by {nickname}",
    "mode_channel_unlocked": "Channel {channel} unlocked (-z) by {nickname}",

    # Server/connection messages
    "signal_shutdown": "Received signal {signal}, initiating shutdown...",
    "config_reload_error": "Failed to reload configuration: {error}",

    # API HELPER MESSAGES
    "api_integrity_error": "{func} IntegrityError: {error}",
    "api_operational_error": "{func} OperationalError: {error}",
    "api_value_error": "{func} ValueError: {error}",
    "api_socket_timeout": "{func} socket timeout",
    "api_connection_refused": "{func} connection refused",
    "api_generic_error": "{func} error: {error}",
    "api_connected": "Connected to IRC server {host}:{port}",
    "api_command": "{description}: {command}",
    "api_socket_timeout_cmd": "{description} - socket timeout",
    "api_connection_refused_cmd": "{description} - connection refused",
    "api_error_cmd": "{description} error: {error}",
    "api_pool_initialized": "Database connection pool initialized: {path} (pool_size={pool_size})",
    "api_pool_init_failed": "Failed to initialize database pool: {error}",
    "api_pool_init_warning": "Connection pool initialization failed: {error}",
    "api_auto_nick_mailbox": "Auto-created nickname '{nickname}' for mailbox delivery (sender: {sender})",
    "api_auto_service_account": "Auto-created service account '{name}' for channel registration (channel: {channel})",

    # WEBCHAT GATEWAY MESSAGES
    "webchat_at_capacity": "Connection refused from {ip} - server at capacity ({max} connections)",
    "webchat_too_many_ip": "Connection refused from {ip} - too many connections from this IP",
    "webchat_new_connection": "New connection: {client_id} from {ip}",
    "webchat_irc_connected": "Connected to IRC for client {client_id}",
    "webchat_irc_refused": "IRC server refused connection for client {client_id}",
    "webchat_irc_timeout": "IRC connection timeout for client {client_id}",
    "webchat_error": "Error for client {client_id}: {error_type}",
    "webchat_closed": "Connection closed: {client_id}",
    "webchat_rate_limit": "[{client_id}] Rate limit exceeded",
    "webchat_webirc_sent": "[{client_id}] Sent WEBIRC for {ip}",
    "webchat_ws_irc_error": "[{client_id}] WS->IRC error: {error_type}",
    "webchat_buffer_overflow": "[{client_id}] Buffer overflow - disconnecting",
    "webchat_irc_ws_error": "[{client_id}] IRC->WS error: {error_type}",
    "webchat_started": "WebSocket gateway started: {ws_host}:{ws_port} -> IRC {irc_host}:{irc_port}",
    "webchat_max_connections": "Max connections: {total} total, {per_ip} per IP",
    "webchat_rate_limit_config": "Rate limit: {rate} messages/second",
    "webchat_shutdown": "Gateway shutting down",

    # LINKING MESSAGES
    "link_send_error": "Error sending to {server}: {error}",
    "link_invalid_role": "Invalid server_role '{role}'. Must be one of: {valid_roles}",
    "link_invalid_version": "Invalid VERSION response from {server}: {line}",
    "link_remote_version": "Remote server {server}: pyIRCX/{version} PROTO/{proto}",
    "link_proto_mismatch": "Protocol mismatch with {server}",
    "link_version_mismatch": "Version mismatch with {server}",
    "link_invalid_timesync": "Invalid TIMESYNC response from {server}: {line}",
    "link_time_delta": "Time sync check for {server}: delta = {delta}s",
    "link_listening": "Server linking listening on {host}:{port}",
    "link_monitor_started": "Link monitoring task started",
    "link_start_failed": "Failed to start server linking: {error}",
    "link_ping_timeout": "Ping timeout for {server}",
    "link_monitor_cancelled": "Link monitoring task cancelled",
    "link_auth_failed": "Failed auth from {server} at {peer}",
    "link_server_linked": "Server {server} linked successfully",
    "link_handshake_timeout": "Server handshake timeout from {peer}",
    "link_handshake_error": "Server handshake error: {error}",
    "link_connecting": "Connecting to {server} at {host}:{port}",
    "link_role_validation_failed": "Role validation failed for {server}: {error}",
    "link_role_validation_passed": "Role validation passed: {local_role} <-> {remote_role}",
    "link_rejected": "Link to {server} rejected: {line}",
    "link_connect_failed": "Failed to connect to {server}: {error}",
    "link_reconnect_cancelled": "Reconnect to {server} cancelled",
    "link_reconnect_failed": "Reconnect attempt to {server} failed: {error}",
    "link_read_error": "Error reading from {server}: {error}",
    "link_invalid_staffsync": "Invalid STAFFSYNC from {server}: {parts}",
    "link_staff_sync_error": "Error syncing staff account {username}: {error}",
    "link_invalid_staffcmd": "Invalid STAFFCMD from {server}: {parts}",
    "link_staffcmd_unknown_user": "STAFFCMD for unknown user {nickname} from {server}",
    "link_staffcmd_error": "Error processing STAFFCMD {subcmd} from {server}: {error}",
    "link_invalid_staffupdate": "Invalid STAFFUPDATE from {server}: {parts}",
    "link_staff_update_password": "Staff update: password changed for {username}",
    "link_staff_update_level": "Staff update: level changed for {username} to {level}",
    "link_staff_update_added": "Staff update: {username} added with level {level}",
    "link_staff_update_removed": "Staff update: {username} removed",
    "link_staffupdate_error": "Error processing STAFFUPDATE for {username}: {error}",
    "link_invalid_regcmd": "Invalid REGCMD from {server}: {parts}",
    "link_regcmd_unknown_user": "REGCMD for unknown user {nickname} from {server}",
    "link_regcmd_error": "Error processing REGCMD {subcmd} from {server}: {error}",
    "link_invalid_regupdate": "Invalid REGUPDATE from {server}: {parts}",
    "link_regupdate_action": "Registration update: {nickname} {action}",
    "link_regupdate_unregistered": "Registration update: {nickname} unregistered",
    "link_regupdate_error": "Error processing REGUPDATE for {nickname}: {error}",
    "link_invalid_memocmd": "Invalid MEMOCMD from {server}: {parts}",
    "link_memocmd_unknown_user": "MEMOCMD for unknown user {nickname} from {server}",
    "link_memocmd_error": "Error processing MEMOCMD {subcmd} from {server}: {error}",
    "link_collision_keep_incoming": "Collision resolution: Keeping incoming {nickname} (older timestamp)",
    "link_collision_kill_error": "Error killing local user in collision: {error}",
    "link_collision_keep_existing": "Collision resolution: Keeping existing {nickname} (older timestamp)",
    "link_service_handler_not_found": "Service handler {handler} not found!",
    "link_channel_member_count": "  Channel {channel} has {count} total members",
    "link_remote_mode_key_set": "Remote MODE: Set key on {channel}",
    "link_remote_mode_limit_set": "Remote MODE: Set limit on {channel}",
    "link_remote_kick": "Remote KICK: {target} from {channel} by {source}",
    "link_remote_invite": "Remote INVITE: {target} to {channel} from {source}",
    "link_remote_nick_change": "Remote NICK: {old} -> {new}",
    "link_remote_kill_ignored": "Remote KILL ignored: {target} is remote on this server",
    "link_remote_kill": "Remote KILL: {target} ({reason})",
    "link_remote_whois": "Remote WHOIS: {requester} querying {target}",
    "link_remote_whisper": "Remote WHISPER: {source} to {target} in {channel}",
    "link_remote_access": "Remote ACCESS: {nickname} executed ACCESS {action} on {obj}",
    "link_remote_access_error": "Remote ACCESS execution error: {error}",
    "link_remote_prop": "Remote PROP: {nickname} set {prop} on {channel}",
    "link_remote_prop_error": "Remote PROP execution error: {error}",
    "link_remote_knock": "Remote KNOCK: {nickname} knocked on {channel}",
    "link_bcrypt_error": "bcrypt verification error for {server}: {error}",
    "link_trunk_not_found": "Trunk server '{hub}' not found in linked servers",
    "link_trunk_found": "Found trunk server '{hub}', is_direct={is_direct}",
    "link_routed_to_trunk": "Routed message to trunk",
    "link_trunk_not_direct": "Trunk found but not direct: {hub}, is_direct={is_direct}",
    "link_staff_auth_no_trunk": "Staff auth routing failed: No trunk connection",
    "link_staff_auth_timeout": "Staff auth timeout for {username}",

    # Additional linking messages (auto-generated from linking.py conversion)
    "link_added_remote_service": "Added remote service {nickname} from {server}",
    "link_added_remote_user": "Added remote user {nickname} from {server} (total: {total})",
    "link_added_user_to_channel": "Added {nickname} to {channel}",
    "link_attempting_reconnect": "Attempting reconnect to {server}",
    "link_available_servers": "Available servers: {servers}, exclude={exclude}",
    "link_branch_staff_auth_failed": "Branch: Staff auth FAILED via trunk for {username}",
    "link_branch_staff_auth_success": "Branch: Staff auth SUCCESS via trunk for {username} ({level})",
    "link_broadcast_to_servers": "broadcast_to_servers: {preview}",
    "link_burst_service": "Bursting service {nickname} to {server}",
    "link_burst_staff": "Burst {count} staff accounts to {server}",
    "link_burst_staff_error": "Error bursting staff to {server}: {error}",
    "link_channel_equal_timestamp": "Channel {channel}: Equal timestamp, merging state",
    "link_channel_local_older": "Channel {channel}: Local is older, keeping local state",
    "link_channel_member_detail": "  Member {nickname}: is_remote={is_remote}",
    "link_channel_registered": "Channel registration: {channel} registered by {nickname} via {server}",
    "link_channel_remote_older": "Channel {channel}: Remote is older, accepting remote state",
    "link_channel_unregistered": "Channel unregistration: {channel} unregistered by {nickname} via {server}",
    "link_chgpass": "CHGPASS: {nickname} changed password via {server}",
    "link_clock_skew_reject": "Clock skew too large for {server}: {delta}s > {limit}s",
    "link_clock_skew_warn": "Clock skew detected for {server}: {delta}s",
    "link_collision_tie_keep_existing": "Collision tie: keeping existing {nickname}",
    "link_collision_tie_keep_incoming": "Collision tie: keeping incoming {nickname}",
    "link_created_channel_for_join": "Created channel {channel} for remote JOIN",
    "link_created_channel_sjoin": "Created channel {channel} from SJOIN (ts={timestamp})",
    "link_created_virtual_user": "Created virtual remote user {nickname} from {server}",
    "link_delivered_private_message": "Delivered private message from {source} to {target}",
    "link_failed_create_remote_user": "Failed to create remote user {nickname}",
    "link_forwarded_nick": "Forwarded NICK for {nickname}",
    "link_forwarded_private_message": "Forwarded private message from {source} to {target}",
    "link_forwarding_to_servers": "Forwarding to other servers (exclude={exclude})",
    "link_handle_remote_nick_called": "handle_remote_nick from {server}: {parts} parts",
    "link_handle_remote_nick_not_enough_parts": "handle_remote_nick: Not enough parts ({count})",
    "link_incoming_connection": "Incoming server connection from {peer}",
    "link_join_complete": "JOIN complete for {nickname} in {channel}",
    "link_join_details": "JOIN: user={nickname}, channel={channel}, found={found}",
    "link_join_forwarded": "JOIN forwarded for {nickname} in {channel}",
    "link_memo_sent": "Memo sent: {sender} -> {target} via {server}",
    "link_memoreply_unknown_user": "MEMOREPLY for unknown user {nickname}",
    "link_monitoring_error": "Link monitoring error: {error}",
    "link_nick_identified": "Identification: {account} identified via {server}",
    "link_nick_registered": "Registration: {account} registered via {server}",
    "link_nick_unregistered": "Unregistration: {account} unregistered via {server}",
    "link_not_forwarding_branch": "NOT forwarding (branch server)",
    "link_plaintext_password_warning": "Server link {server} using PLAINTEXT password!",
    "link_processing_channel_message": "Processing channel message: {source} -> {target}",
    "link_processing_nick": "Processing NICK for {nickname} from {server}",
    "link_processing_remote_join": "Processing remote JOIN from {server}: {line}",
    "link_propagated_squit": "Propagated SQUIT for {server}",
    "link_received_eob": "Received EOB from {server}",
    "link_reconnect_disabled": "Not scheduling reconnect for {server} (autoconnect disabled)",
    "link_regreply_unknown_user": "REGREPLY for unknown user {nickname}",
    "link_regupdate_user_not_on_branch": "REGUPDATE for user {nickname} not on this branch",
    "link_remote_away_set": "Remote AWAY: {nickname} is away: {message}",
    "link_remote_away_unset": "Remote AWAY: {nickname} is back",
    "link_remote_mode_ban_added": "Remote MODE: Added ban {mask} to {channel}",
    "link_remote_mode_ban_removed": "Remote MODE: Removed ban {mask} from {channel}",
    "link_remote_mode_flag": "Remote MODE: Set {channel} {sign}{char}",
    "link_remote_mode_host_added": "Remote MODE: Added {nickname} as host of {channel}",
    "link_remote_mode_host_removed": "Remote MODE: Removed {nickname} as host of {channel}",
    "link_remote_mode_key_removed": "Remote MODE: Removed key from {channel}",
    "link_remote_mode_limit_removed": "Remote MODE: Removed limit from {channel}",
    "link_remote_mode_owner_added": "Remote MODE: Added {nickname} as owner of {channel}",
    "link_remote_mode_owner_removed": "Remote MODE: Removed {nickname} as owner of {channel}",
    "link_remote_mode_user_invisible": "Remote MODE: {target} {sign}i",
    "link_remote_mode_voice_added": "Remote MODE: Added {nickname} as voice in {channel}",
    "link_remote_mode_voice_removed": "Remote MODE: Removed {nickname} as voice in {channel}",
    "link_remote_topic_set": "Remote TOPIC set in {channel} by {nickname}: {topic}",
    "link_routed_privmsg": "Routed PRIVMSG from {nickname} to {target}",
    "link_scheduling_reconnect": "Scheduling reconnect to {server} in {delay}s (attempt #{attempt})",
    "link_sending_to_member": "  -> Sending to {nickname}",
    "link_sending_to_server": "  Sending to {server}: {preview}",
    "link_sent_eob": "Sent EOB to {server}",
    "link_sent_ping": "Sent PING to {server}",
    "link_sent_staff_auth_request": "Sent staff auth request to trunk: {username} (id: {auth_id})",
    "link_sent_to_server": "  Sent to {server}",
    "link_server_split": "Server {server} disconnected (split)",
    "link_staff_account_added": "Staff account {username} ({level}) added by {by} via {server}",
    "link_staff_account_removed": "Staff account {username} removed by {by} via {server}",
    "link_staff_auth_route_error": "Staff auth routing error: {error}",
    "link_staff_auth_unknown_id": "Staff auth response for unknown ID: {auth_id}",
    "link_staff_level_changed": "Staff level for {username} changed to {level} by {by} via {server}",
    "link_staff_password_changed": "Staff password changed for {username} via {server}",
    "link_staff_sync": "Staff sync: {username} ({level}) from {server}",
    "link_staff_sync_completed": "Staff sync completed from {server}",
    "link_staffreply_unknown_user": "STAFFREPLY for unknown user {nickname}",
    "link_successfully_linked": "Successfully linked to {server}",
    "link_time_ok": "Time sync check passed for {server}",
    "link_timesync_error": "Invalid TIMESYNC from {server}: {error}",
    "link_trunk_sasl_auth_success": "Trunk: SASL staff auth SUCCESS for {username} ({level})",
    "link_trunk_staff_auth_bad_password": "Trunk: Staff auth FAILED for {username} (bad password)",
    "link_trunk_staff_auth_error": "Trunk: Staff auth error for {username}: {error}",
    "link_trunk_staff_auth_not_found": "Trunk: Staff auth FAILED for {username} (not found)",
    "link_trunk_staff_auth_success": "Trunk: Staff auth SUCCESS for {username} ({level})",
    "link_user_not_found_branch": "User {target} not found locally on branch",
    "link_version_ok": "Version check passed for {server}",

    # CHANNEL PROPERTY MESSAGES
    "channel_props_error": "Error loading channel properties: {error}",

    # SHUTDOWN / SIGNAL MESSAGES
    "shutdown_task_timeout": "Timeout cancelling background tasks, forcing",
    "signal_sighup_reload": "Received SIGHUP, reloading configuration...",
    "ssl_context_updated": "SSL context updated for new connections",

    # LINKING OPERATIONAL MESSAGES
    "link_disabled_config": "Server linking disabled in config",
    "link_monitor_started": "Link monitoring task started",
    "link_health_monitoring_started": "Link health monitoring started",
    "link_monitor_cancelled": "Link monitoring task cancelled",
    "link_ping_timeout": "Server {server} ping timeout ({time_since_pong}s since last PONG, limit {timeout}s)",
    "link_no_hub_configured": "No hub_server configured in services",
    "link_no_trunk_routing": "No trunk server found for service routing",

    # STAFF AUDIT DETAIL MESSAGES
    "audit_staff_add_level": "Level: {level}",
    "audit_staff_delete_level": "Was: {old_level}",
    "audit_staff_level_change": "{old_level} -> {new_level}",
    "audit_auth_success": "Authenticated as {level} from {ip}",
    "audit_auth_fail": "Failed AUTH from IP {ip}",
    "audit_auth_drop": "Dropped {old_level} privileges from {ip}",
    "audit_kill_channel": "Channel destroyed: {reason}",
    "audit_kill_pattern": "Pattern kill: {reason} ({kill_count} users)",
    "audit_kick_target": "{target_nick} from {chan_name}",
    "audit_staff_pass_changed": "Password changed",
    "audit_staff_mfa_enabled": "MFA enabled by admin",
    "audit_staff_mfa_disabled": "MFA disabled by admin",
}

def get_log_message(key: str, **kwargs) -> str:
    """
    Get a formatted log message from LOG_MESSAGES.

    Args:
        key: The message key from LOG_MESSAGES
        **kwargs: Format arguments

    Returns:
        Formatted message string, or the key itself if not found
    """
    template = LOG_MESSAGES.get(key)
    if template is None:
        return key
    try:
        return template.format(**kwargs)
    except KeyError as e:
        return f"{key}: Missing format key {e}"

# ==============================================================================
# MESSAGE CATEGORIZATION AND ROUTING HELPERS
# ==============================================================================

# Message categories for NOTICE/PRIVMSG routing
MESSAGE_CATEGORIES = {
    "help": [
        "help_", "stats_help_", "registrar_help", "messenger_help", "newsflash_help",
        "profanity_subcommands", "profanity_examples", "config_subcommands",
        "event_usage", "event_classes", "memo_usage_"
    ],
    "stats": [
        "stats_", "ssl_", "stats_db_", "stats_network_", "stats_linking_"
    ],
    "errors": [
        "requires_", "cannot_", "invalid_", "not_found", "already_",
        "rate_limit_", "restricted_", "denied"
    ],
    "services": [
        "registrar_", "messenger_", "newsflash_", "servicebot_"
    ],
    "staff": [
        "staff_", "gag_", "ungag_"
    ],
    "config": [
        "config_"
    ],
    "mfa": [
        "mfa_"
    ]
}

def get_message_category(key: str) -> str:
    """
    Determine the category of a message key for NOTICE/PRIVMSG routing.

    Args:
        key: The message key (from SERVER_MESSAGES or RESPONSES)

    Returns:
        Category name ('help', 'stats', 'errors', 'services', 'staff', 'config', 'mfa')
        or 'default' if no specific category matches
    """
    for category, prefixes in MESSAGE_CATEGORIES.items():
        for prefix in prefixes:
            if key.startswith(prefix):
                return category
    return "default"

def get_message_type(key: str, config: dict = None) -> str:
    """
    Determine whether a message should be sent as NOTICE or PRIVMSG.

    Args:
        key: The message key
        config: Optional config dict with 'messages' section containing:
            - default_type: 'NOTICE' or 'PRIVMSG' (default: 'NOTICE')
            - category_overrides: dict mapping categories to types

    Returns:
        'NOTICE' or 'PRIVMSG'
    """
    if config is None:
        return "NOTICE"

    messages_config = config.get("messages", {})
    default_type = messages_config.get("default_type", "NOTICE")
    category_overrides = messages_config.get("category_overrides", {})

    category = get_message_category(key)
    return category_overrides.get(category, default_type)

def get_server_message(key: str, **kwargs) -> str:
    """
    Get a formatted server message from SERVER_MESSAGES.

    Args:
        key: The message key from SERVER_MESSAGES
        **kwargs: Format arguments

    Returns:
        Formatted message string, or None if key not found
    """
    template = SERVER_MESSAGES.get(key)
    if template is None:
        return None
    try:
        return template.format(**kwargs)
    except KeyError:
        return None

def is_numeric_code(key: str) -> bool:
    """
    Check if a key is a numeric response code.

    Args:
        key: The key to check

    Returns:
        True if key is a 3-digit numeric code in RESPONSES
    """
    return key.isdigit() and len(key) == 3 and key in RESPONSES

def get_help_lines(topic: str, content_lines: list) -> list:
    """
    Generate help output using proper IRC numerics (704-706).

    Args:
        topic: The help topic name (e.g., "STATS", "ACCESS")
        content_lines: List of help content lines

    Returns:
        List of tuples [(numeric_code, format_kwargs), ...]
    """
    lines = []
    # Header (704)
    lines.append(("704", {"topic": topic, "text": f"=== {topic} Help ==="}))
    # Content lines (705)
    for line in content_lines:
        lines.append(("705", {"topic": topic, "text": line}))
    # Footer (706)
    lines.append(("706", {"topic": topic}))
    return lines

def get_stats_lines(flag: str, title: str, content_lines: list) -> list:
    """
    Generate stats output using proper numerics (970-975) with 219 end marker.

    Args:
        flag: The STATS flag (e.g., "u", "*")
        title: The stats section title
        content_lines: List of tuples [(label, value), ...] or strings

    Returns:
        List of tuples [(numeric_code, format_kwargs), ...]
    """
    lines = []
    # Header (970)
    lines.append(("970", {"title": title}))
    # Content lines (972/973)
    for item in content_lines:
        if isinstance(item, tuple):
            label, value = item
            lines.append(("972", {"label": label, "value": value}))
        elif isinstance(item, str):
            # Raw text line
            lines.append(("972", {"label": item, "value": ""}))
    # End marker (219)
    lines.append(("219", {"flag": flag}))
    return lines
