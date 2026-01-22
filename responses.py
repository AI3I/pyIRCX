#!/usr/bin/env python3
"""
IRC Response Templates for pyIRCX Server

This module contains the numeric response templates (RESPONSES) and
server message templates (SERVER_MESSAGES) used by the IRC server.
"""

# ==============================================================================
# RESPONSE TABLE - IRC numeric replies
# ==============================================================================
RESPONSES = {
    "001": "Welcome to the {network}, {nick}!",
    "002": "Your host is {servername}, running version {version_label} {version}",
    "003": "This server was created {created_date}",
    "004": "{servername} {version_label} {version} {usermodes} {chanmodes}",
    "005": "CHANTYPES=#& PREFIX=(qov).@+ CHANMODES={chanmodes_param} NICKLEN={nicklen} MAXNICKLEN={nicklen} USERLEN={userlen} CHANNELLEN={chanlen} TOPICLEN={topiclen} MODES={max_modes} CASEMAPPING=rfc1459 STATUSMSG=.@+ NETWORK={network_name} IRCX ACCESS PROPS :are supported",
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
    "324": "{channel} +{modes}",
    "331": "{channel} :No topic is set",
    "332": "{channel} :{topic}",
    "333": "{channel} {nick} {timestamp}",
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
    "382": "{config_file} :Rehashing",  # RPL_REHASHING
    "386": "{staff_login_message}",
    "391": ":Local time is {time}",
    "401": "{target} :That nickname or channel doesn't exist",
    "403": "{target} :That channel doesn't exist",
    "404": "{channel} :You cannot send to channel (check channel modes or your permissions)",
    "407": "{target} :You specified too many recipients",
    "421": "{command} :This command is not recognized",
    "432": "{target} :That nickname is not valid (must be 1-{nicklen} characters, start with a letter, and contain only letters, numbers, -, _, [, ], {{, }}, \\, or |)",
    "433": "{target} :Nickname is already in use",
    "441": "{target} {channel} :They aren't on that channel",
    "442": "{target} :You're not on that channel",
    "443": "{target} {channel} :They are already on that channel",
    "451": "You have not registered (use NICK and USER commands)",
    "461": "{command} :You did not provide enough parameters. See /HELP {command} for usage.",
    "462": "You may not reregister",
    "468": ":That username is not valid (must start with a letter and contain only letters, numbers, -, _, or .)",
    "471": "{target} :You cannot join channel (channel is full - user limit reached)",
    "473": "{target} :You cannot join channel (invite-only - you must be invited)",
    "474": "{target} :You cannot join channel (you are banned from this channel)",
    "475": "{target} :You cannot join channel (incorrect channel key/password)",
    "481": "You do not have permission - IRC operator or administrator privileges are required",
    "482": "{target} :You're not a channel owner or host (+q or +o required)",
    "696": "{target} {mode} :You must specify a parameter for the {mode} mode",
    "710": "{channel} {nick} {host} :has asked for an invite",
    "711": "{target} :Your knock request has been sent",
    "712": "{target} :You have sent too many knock requests. Please wait before trying again.",
    "713": "{target} :Channel is open",
    "714": "{target} :You are already on that channel",
    "716": "{target} :You cannot knock on this channel (+u mode)",
    "800": "1 0 {auth_status} 512 *",
    "804": "Authentication successful",
    "805": "{target} :Access list",
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
    "854": "{target} :ACCESS {level} added: {mask}",
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
    "874": ":Your nickname {nick} has been registered (UUID: {uuid})",
    "875": ":Your nickname {nick} has been dropped",
    "876": ":You are now identified as {nick}",
    "877": ":Password accepted. MFA is enabled - please verify with: MFA VERIFY <code>",
    "878": ":MFA enabled. Save this secret: {secret}. Scan the QR code or enter manually in your authenticator app.",
    "879": ":Your MFA has been disabled",
    # IRCX Staff Management (880-889)
    "880": ":The staff account {username} was created with level {level}",
    "881": ":The staff account {username} was deleted",
    "882": ":The staff account {username} was changed to level {level}",
    "883": ":The password was changed for staff account {username}",
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
    # IRCX Database/System (900-909)
    "900": ":Registration failed. Please try again later. If the problem persists, contact an administrator.",
    "901": ":Identification failed - please try again later",
    "902": ":Drop failed - please try again later",
    "903": ":Database error. Please try again later. If the problem persists, contact an administrator.",
    "904": ":System error - please contact an administrator",
    "905": ":Operation failed. Please try again. If the problem persists, contact an administrator.",
    "906": ":Channel registration failed. The channel may already be registered or you may not be the owner.",
    "907": ":Channel drop failed",
    "908": ":Info lookup failed",
    "909": ":Memo operation failed. Please check your parameters and try again.",
    # IRCX Service Messages (910-919)
    "910": ":Commands: {commands}",
    "911": ":That command is not recognized: {cmd}. Try: {suggestions}",
    "912": ":{service} service is temporarily unavailable",
    "913": ":No memos waiting",
    "914": ":You have {count} memo(s) waiting",
    "915": ":Memo sent to {target}",
    "916": ":Memo {id} deleted",
    "917": ":All memos cleared",
    "918": ":Channel {channel} is already registered",
    "919": ":Channel {channel} is not registered",
    # WATCH numerics
    "600": "{nick} {user} {host} {signon} :logged on",
    "601": "{nick} {user} {host} {signon} :logged off",
    "602": "{nick} {user} {host} {signon} :stopped watching",
    "604": "{nick} {user} {host} {signon} :is online",
    "605": "{nick} * * 0 :is offline",
    "606": ":{nicks}",  # List of watched nicks
    "607": ":End of WATCH list",
    # SILENCE numerics
    "271": "{nick} {mask}",
    "272": ":End of Silence List",
    # HELP numerics (704-706)
    "704": "{topic} :{text}",  # RPL_HELPSTART - Start of help section
    "705": "{topic} :{text}",  # RPL_HELPTXT - Help content line
    "706": "{topic} :End of {topic}",  # RPL_ENDOFHELP - End of help section
    # ERR_NOPRIVS (723)
    "723": "{priv} :Insufficient oper privileges",  # ERR_NOPRIVS
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
    # IRCX Memo System Output (960-969)
    "960": ":--- Memo List ({count} memo(s)) ---",  # Memo list header
    "961": ":{status}#{id} from {sender} at {time}: {preview}",  # Memo list entry
    "962": ":--- End of Memo List ---",  # Memo list footer
    "963": ":--- Memo #{id} from {sender} at {time} ---",  # Memo read header
    "964": ":{text}",  # Memo body line
    "965": ":--- End of Memo ---",  # Memo read footer
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
    # Gag/Ungag confirmations (sent to staff, not target - shadow ban)
    "gag_channel": "{target} has been gagged in {channel}",
    "ungag_channel": "{target} has been ungagged in {channel}",
    "gag_global": "{target} has been globally gagged (+z)",
    "ungag_global": "{target} has been globally ungagged (-z)",

    # WHO/LIST restrictions
    "who_requires_staff": "WHO * requires IRC operator or administrator privileges. Try using a pattern like *nick* or *@host* instead",

    # Message handling
    "system_no_messages": "The System service does not accept direct messages. Use /HELP for available services, or /msg Registrar for help.",
    "mfa_pending": "MFA verification pending. Send your 6-digit code: /msg Registrar MFA VERIFY <code>",
    "access_denied": "You do not have access: {reason}",

    # User killed
    "user_killed": "{target} KILLED",

    # Registrar service
    "registrar_help": "Commands: REGISTER <password> [email], IDENTIFY <password>, DROP, INFO [nick], CHANNEL <cmd>, SET <option>, MFA <cmd>",
    "registrar_tip": "TIP: You can also use direct commands: REGISTER, UNREGISTER, IDENTIFY, MFA",
    "registrar_info_header": "Info for {nickname}:",
    "registrar_info_uuid": "  UUID: {uuid}",
    "registrar_info_registered": "  Registered: {time}",
    "registrar_info_lastseen": "  Last seen: {time}",
    "registrar_info_mfa": "  MFA enabled: {status}",
    "registrar_channel_registered": "Channel {channel} is now registered to you",
    "registrar_channel_dropped": "Channel {channel} has been unregistered",
    "registrar_channel_info": "Channel {channel} - Owner: {owner}, Registered: {time}",
    "registrar_email_updated": "Your email address has been updated",
    "registrar_password_updated": "Your password has been updated",
    "registrar_mfa_verify_prompt": "Please enter the 6-digit MFA code from your authenticator app",
    "registrar_mfa_verify_success": "MFA verification successful!",

    # Messenger service
    "messenger_help": "Commands: SEND <nick> <message>, LIST, READ <id>, DELETE <id>, CLEAR, COUNT, PUSH <message> (IRC administrator only)",
    "messenger_sent": "Message sent to {target}",
    "messenger_deleted": "Your memo {id} has been deleted",
    "messenger_cleared": "All your memos have been cleared",
    "messenger_count": "You have {count} memo(s) waiting",
    "messenger_no_memos": "You have no memos waiting",
    "messenger_list_header": "Your memos:",
    "messenger_list_item": "  [{id}] From {from} at {time}: {preview}",
    "messenger_read_header": "Memo {id} from {from} at {time}:",
    "messenger_read_body": "  {message}",
    "messenger_user_offline": "{target} is offline. Your message has been queued for delivery.",
    "messenger_user_online": "{target} is online",
    "messenger_push_sent": "Message pushed to {count} user(s)",

    # NewsFlash service
    "newsflash_help": "Commands: LIST, READ <id>, DELETE <id> (staff), PUSH <message> (IRC administrator only)",
    "newsflash_list_header": "Recent NewsFlash items:",
    "newsflash_list_item": "  [{id}] {time}: {preview}",
    "newsflash_read_header": "NewsFlash {id} from {time}:",
    "newsflash_read_body": "  {message}",
    "newsflash_deleted": "NewsFlash {id} has been deleted",
    "newsflash_pushed": "NewsFlash sent to {count} user(s)",
    "newsflash_no_items": "There are no NewsFlash items available",

    # ServiceBot messages
    "servicebot_warning": "Warning: {violation}",
    "servicebot_action": "Action taken: {action}",

    # IRCX PROP on-join/on-part (sent from channel entity, not server)
    # These are sent as channel!channel@server PRIVMSG/NOTICE

    # =========================================================================
    # PRIVILEGE/PERMISSION MESSAGES
    # =========================================================================
    "requires_admin": "{command} requires administrator privileges",
    "requires_oper_admin": "{command} requires operator or administrator privileges",
    "requires_staff": "{command} requires staff privileges",
    "requires_ircx": "{command} requires IRCX mode. Type /IRCX to enable it.",
    "requires_channel_owner": "You must be the channel owner to do that",
    "requires_channel_host": "You must be a channel host or owner to do that",
    "requires_identify": "You must identify first",
    "requires_identify_unregister": "You must identify first to unregister",
    "requires_identify_mfa": "You must identify first to enable MFA",
    "requires_identify_mfa_disable": "You must identify first to disable MFA",
    "requires_identify_mfa_pending": "You must identify first, or complete pending MFA verification",
    "requires_register": "You must register your nickname first",
    "restricted_to_staff": "{feature} is restricted to staff",
    "who_restricted": "WHO * is restricted to staff. Try a pattern like WHO *nick* instead.",
    "cannot_target_staff": "You cannot {action} staff members",
    "cannot_target_services": "You cannot {action} services",

    # =========================================================================
    # RATE LIMITING MESSAGES
    # =========================================================================
    "rate_limit_wait": "Please wait a moment before using {command} again.",
    "rate_limit_seconds": "Please wait {seconds} seconds before {action}",
    "rate_limit_flood": "You're sending messages too quickly. Please slow down.",
    "rate_limit_whisper": "Please wait a few seconds before sending another whisper.",
    "rate_limit_broadcast": "Please wait a moment before sending another broadcast.",
    "rate_limit_nick": "You must wait {seconds} seconds before changing nickname",
    "rate_limit_setname": "You must wait {seconds} seconds before changing your realname",
    "rate_limit_invite": "Please wait a moment before sending another invitation.",
    "rate_limit_topic": "Please wait a moment before changing the topic again.",
    "rate_limit_knock": "Please wait a moment before knocking again.",
    "rate_limit_transcript": "Please wait a moment before requesting another transcript.",

    # =========================================================================
    # SUCCESS MESSAGES
    # =========================================================================
    "success_header": "=== SUCCESS ===",
    "end_marker": "--- End ---",
    "operation_complete": "{operation} completed successfully",

    # =========================================================================
    # ERROR MESSAGES - General
    # =========================================================================
    "not_found": "{item} not found",
    "not_found_account": "Staff account '{username}' not found",
    "not_found_nick": "Nickname not found",
    "not_found_channel": "Channel {channel} does not exist",
    "not_found_memo": "Memo #{id} not found",
    "not_found_message": "That message was not found",
    "already_exists": "{item} already exists",
    "already_exists_account": "Staff account '{username}' already exists",
    "already_registered_nick": "Nickname {nick} is already registered",
    "already_registered_channel": "Channel {channel} is already registered",
    "invalid_subcommand": "That subcommand is not recognized: {subcmd}",
    "invalid_parameter": "That parameter is not valid: {param}",
    "invalid_mfa_code": "Invalid MFA code",
    "invalid_mfa_code_for": "Invalid MFA code for {username}",
    "incorrect_password": "Incorrect password",
    "auth_failed": "Authentication failed",
    "operation_failed": "{operation} failed - please try again later",
    "internal_error": "An internal error occurred",
    "database_error": "A database error occurred. Please try again later.",

    # =========================================================================
    # STAFF MANAGEMENT MESSAGES
    # =========================================================================
    "staff_created_header": "Staff account created:",
    "staff_deleted_header": "Staff account deleted:",
    "staff_changed_header": "Staff account updated:",
    "staff_username": "  Username: {username}",
    "staff_level": "  Level: {level}",
    "staff_created_by": "  Created by: {by}",
    "staff_deleted_by": "  Deleted by: {by}",
    "staff_changed_by": "  Changed by: {by}",
    "staff_active_next_login": "The account will be active on next login.",
    "staff_levels_hint": "Levels: ADMIN, SYSOP, GUIDE",
    "staff_forwarded": "Staff command forwarded to trunk. Please wait...",
    "staff_password_min": "Your password must be at least 6 characters",
    "staff_password_updated": "Your password has been updated.",

    # =========================================================================
    # SERVICES AVAILABILITY
    # =========================================================================
    "services_unavailable": "Services are currently unavailable (the trunk server is not connected)",
    "trunk_unavailable": "The trunk server is not connected. Staff management is unavailable.",
    "service_temporarily_unavailable": "{service} is temporarily unavailable",

    # =========================================================================
    # MFA MESSAGES (Nickname MFA)
    # =========================================================================
    "mfa_setup_header": "MFA Setup - Add to your authenticator app:",
    "mfa_secret": "  Secret: {secret}",
    "mfa_uri": "  URI: {uri}",
    "mfa_already_enabled": "MFA is already enabled",
    "mfa_not_enabled": "MFA is not enabled",
    "mfa_verify_failed": "MFA verification failed - internal error",
    "mfa_config_error": "MFA configuration error",
    "mfa_required_hint": "You will need to provide an MFA code when using AUTH from now on",
    "mfa_password_required": "Your password is required to enable MFA",
    "mfa_verify_prompt": "Please enter the 6-digit MFA code from your authenticator app",
    "mfa_setup_complete_hint": "Complete setup with: MFA VERIFY <6-digit code>",
    "mfa_setup_failed": "MFA setup failed",
    "mfa_session_expired": "MFA session expired",
    "mfa_verify_success": "MFA verified. You are now identified as {nickname}",
    "mfa_enable_first": "Run MFA ENABLE first",
    "mfa_enabled_success": "MFA is now enabled",
    "mfa_code_invalid_cancelled": "That code is not valid - MFA setup cancelled",
    "mfa_disable_usage": "Usage: MFA DISABLE <6-digit code>",
    "mfa_disabled_success": "MFA has been disabled",
    "mfa_disable_failed": "MFA disable failed",

    # =========================================================================
    # REGISTRATION MESSAGES
    # =========================================================================
    "reg_must_use_nickname": "You must be using the nickname to register it",
    "reg_already_identified": "You are already identified to a registered nickname",
    "reg_request_sent": "Registration request sent to services. Please wait...",
    "reg_nick_success": "Your nickname {account} has been registered",
    "reg_failed": "Registration failed - please try again later",
    "reg_requires_identify": "You must identify to a registered nickname first",
    "reg_channel_not_owner": "You must be a channel owner to register {channel}",
    "reg_channel_request_sent": "Channel registration request sent to services. Please wait...",
    "reg_nick_required": "Your nickname must be registered first",
    "reg_channel_success": "Your channel {channel} has been registered",
    "reg_usage_alt": "   or: REGISTER <#channel> [<password>]",

    # =========================================================================
    # UNREGISTRATION MESSAGES
    # =========================================================================
    "unreg_must_be_owner": "You can only unregister your own nickname",
    "unreg_request_sent": "Unregistration request sent to services. Please wait...",
    "unreg_nick_success": "Your nickname {account} has been unregistered",
    "unreg_failed": "Unregistration failed - please try again later",
    "unreg_channel_request_sent": "Channel unregistration request sent to services. Please wait...",
    "unreg_channel_not_registered": "Channel {channel} is not registered",
    "unreg_staff_not_registered": "Your staff account is not registered",
    "unreg_nick_not_registered": "Your nickname is not registered",
    "unreg_channel_success": "Your channel {channel} has been unregistered",

    # =========================================================================
    # IDENTIFY MESSAGES
    # =========================================================================
    "identify_must_use_nickname": "You must be using the nickname to identify to it",
    "identify_in_progress": "Identifying...",
    "identify_nick_not_registered": "Nickname {account} is not registered",
    "identify_mfa_required": "Password accepted. MFA required - use: MFA VERIFY <code>",
    "identify_success": "You are now identified as {account}",
    "identify_failed": "Identification failed - please try again later",

    # =========================================================================
    # AUTH COMMAND MESSAGES (Staff Authentication)
    # =========================================================================
    "auth_usage_full": "Usage: AUTH <username> <password> | AUTH VERIFY <code> | AUTH ENABLE <password> | AUTH DISABLE <password> <code>",
    "auth_usage_basic": "Usage: AUTH <username> <password>",
    "auth_requires_ssl": "AUTH command requires an SSL/TLS connection (port 6697)",
    "auth_plaintext_warning": "Your credentials would be transmitted in plaintext",
    "auth_too_many_failures": "Too many failed authentication attempts",
    "auth_account_locked": "Account locked. Try again in {remaining}s",
    "auth_mfa_required": "Password accepted. MFA verification required.",
    "auth_enter_code": "Enter code: /AUTH VERIFY <6-digit code>",
    "auth_verify_usage": "Usage: AUTH VERIFY <6-digit code>",
    "auth_session_expired": "Authentication session expired. Please AUTH again.",
    "auth_mfa_config_error": "MFA configuration error",
    "auth_mfa_invalid": "Invalid MFA code",
    "auth_enable_first": "Run AUTH ENABLE first to set up MFA",
    "auth_mfa_enabled": "MFA is now enabled for your account",
    "auth_mfa_required_hint": "You will need to provide an MFA code when using AUTH from now on",
    "auth_mfa_setup_cancelled": "Invalid MFA code. Setup cancelled.",
    "auth_no_pending": "No pending authentication. Use: AUTH <username> <password>",
    "auth_or_enable": "Or run AUTH ENABLE first to set up MFA",
    "auth_enable_usage": "Usage: AUTH ENABLE <your-password>",
    "auth_must_be_staff": "You must be authenticated as staff to enable MFA",
    "auth_mfa_already_enabled": "MFA is already enabled for your account",
    "auth_setup_complete_hint": "Complete setup with: AUTH VERIFY <6-digit code>",
    "auth_setup_failed": "MFA setup failed - internal error",
    "auth_disable_usage": "Usage: AUTH DISABLE <your-password> <6-digit-code>",
    "auth_disable_requires_both": "Both password and current MFA code required to disable MFA",
    "auth_staff_required": "You must be authenticated as staff",
    "auth_mfa_disabled": "MFA has been disabled for your account",
    "auth_mfa_disable_failed": "MFA disable failed - internal error",

    # =========================================================================
    # CONFIGURATION MESSAGES
    # =========================================================================
    "config_subcommands": "CONFIG subcommands: LIST, GET, SET, SAVE, RELOAD",
    "config_set": "Set {key} = {value}",
    "config_previous": "Previous value: {value}",
    "config_save_hint": "Use CONFIG SAVE to persist changes",
    "config_saved": "Configuration saved to {file}",
    "config_reloaded": "Configuration reloaded from {file}",
    "config_restart_note": "Note: Some settings require server restart to take effect",
    "config_set_failed": "We couldn't set the value",
    "config_value_too_large": "Configuration value too large (max {max_size})",

    # =========================================================================
    # MEMO SYSTEM MESSAGES
    # =========================================================================
    "memo_send_usage": "Usage: MEMO SEND <nick> <message>",
    "memo_del_usage": "Usage: MEMO DEL <id|ALL>",
    "memo_request_sent": "Memo request sent to services. Please wait...",
    "memo_sent": "Memo sent to {target}",
    "memo_new_notification": "You have a new memo from {sender}. Use MEMO READ to view.",
    "memo_send_failed": "We couldn't send the memo",
    "memo_nick_not_registered": "Nickname {target} is not registered",
    "memo_no_memos": "You have no memos",
    "memo_list_header": "--- Memo List ---",
    "memo_list_entry": "{status}#{id} from {sender} at {timestamp}",
    "memo_list_footer": "--- End of Memo List ---",
    "memo_list_failed": "We couldn't list the memos",
    "memo_not_found": "Memo #{id} not found",
    "memo_no_unread": "No unread memos",
    "memo_header": "Memo #{id} from {sender} ({timestamp}):",
    "memo_read_failed": "We couldn't read the memos",
    "memo_del_request_sent": "Memo deletion request sent to services. Please wait...",
    "memo_all_deleted": "All memos deleted",
    "memo_deleted": "Memo #{id} deleted",
    "memo_delete_failed": "We couldn't delete the memo",
    "memo_unread_count": "You have {count} unread memo(s). Use MEMO READ to view.",

    # =========================================================================
    # HELP SYSTEM MESSAGES
    # =========================================================================
    "help_header": "=== {topic} Help ===",
    "help_footer": "=== End of {topic} Help ===",
    "help_not_found": "No help available for: {topic}",
    "help_suggestions": "Did you mean: {suggestions}?",
    "help_available_topics": "Available topics: COMMANDS CHANNEL REGISTER IRCX USERMODES CHANMODES SERVICES ALIASES",
    "help_staff_topic": "Staff topic: STAFF",
    "help_try_command": "Try /HELP <command> for specific commands (e.g., /HELP JOIN)",

    # =========================================================================
    # RATE LIMITING MESSAGES
    # =========================================================================
    "nick_change_cooldown": "You must wait {remaining} seconds before changing nickname",
    "topic_change_cooldown": "Please wait a moment before changing the topic again.",
    "transcript_cooldown": "Please wait a moment before requesting another transcript.",
    "knock_cooldown": "Please wait a moment before knocking again.",

    # =========================================================================
    # ACCESS/PERMISSION ERRORS
    # =========================================================================
    "access_denied_with_reason": "Access denied{reason}",
    "server_restricted": "This server is restricted to authenticated staff and authorized users only",
    "server_use_branch": "You should connect to a branch server",
    "services_trunk_offline": "Services temporarily unavailable (trunk offline)",
    "tag_channel_only": "Tag prefix {prefix}* can only be used with channel targets",
    "tag_requires_owner": "Tag prefix OWN.* requires channel owner status (+q) in {channel}",
    "tag_requires_host": "The HST.* tag prefix requires channel host status in {channel}.",
    "who_truncated": "WHO results truncated at {max}",
    "ownerkey_owners_only": "Only channel owners can view OWNERKEY",
    "property_readonly": "Property {property} is read-only",
    "servicebots_capacity": "All ServiceBots are at maximum capacity. Try /INVITE ServiceBotXX #channel directly.",
    "servicebot_dispatched": "Dispatched {bot} to {channel}",
    "user_max_channels": "{nickname} has reached max channels ({max})",
    "admin_invite_only": "Only IRC administrators can invite {entity}",
    "mode_changes_limit": "You specified too many mode changes (max {max} per command)",

    # =========================================================================
    # TRANSCRIPT MESSAGES
    # =========================================================================
    "transcript_not_enabled": "{channel} does not have transcript mode (+y) enabled",
    "transcript_unavailable": "No transcript available for {channel}",
    "transcript_header": "=== Transcript for {channel} ({count} lines) ===",
    "transcript_footer": "=== End of transcript ===",

    # =========================================================================
    # LINK COMMAND MESSAGES
    # =========================================================================
    "link_config_not_found": "No link configuration found for {server}",
    "link_connecting": "Linking to {server}...",
    "link_success": "Successfully linked to {server}",
    "link_failed": "Unable to establish link to {server}. Check server logs for details.",
    "link_not_connected": "Not linked to {server}",
    "unlink_in_progress": "Unlinking from {server}...",
    "unlink_success": "Unlinked from {server}",
    "unlink_failed": "Unable to unlink {server}. Check server logs for details.",

    # =========================================================================
    # AUTH/DROP MESSAGES
    # =========================================================================
    "auth_success_as": "You are now authenticated as {level}",
    "drop_success": "Staff privileges dropped. You are now a regular user.",
    "drop_reauth_hint": "Use AUTH to re-authenticate if needed.",

    # =========================================================================
    # WATCH/SILENCE MESSAGES
    # =========================================================================
    "watch_cleared": "Watch list cleared",
    "silence_added": "Added {mask} to silence list",
    "silence_removed": "Removed {mask} from silence list",

    # =========================================================================
    # PASS COMMAND MESSAGES
    # =========================================================================
    "pass_too_short": "Password must be at least 6 characters",
    "pass_service_unavailable_trunk": "Service unavailable (trunk not connected)",
    "pass_service_unavailable": "Service unavailable",
    "pass_nick_not_registered": "Nickname not registered. Staff accounts use: STAFF PASS <username> <newpassword>",
    "pass_changed": "Password changed successfully",
    "pass_failed": "Password change failed",

    # =========================================================================
    # EVENT COMMAND MESSAGES
    # =========================================================================
    "event_add_usage": "Usage: EVENT ADD <class> [<mask>]",
    "event_delete_usage": "Usage: EVENT DELETE <class> [<mask>]",
    "event_trap_not_found": "No matching event trap found",

    # =========================================================================
    # STAFF KILL/GAG MESSAGES
    # =========================================================================
    "kill_success": "*** User {target} has been killed ({reason})",
    "killchan_success": "Channel {channel} destroyed ({count} users removed)",
    "killmask_success": "Pattern {pattern} matched {count} user(s)",
    "channel_unreg_failed": "We couldn't unregister the channel",
    "gag_channel_success": "{target} has been gagged in {channel}",
    "ungag_channel_success": "{target} has been ungagged in {channel}",
    "gag_global_success": "{target} has been globally gagged (+z)",
    "ungag_global_success": "{target} has been globally ungagged (-z)",

    # =========================================================================
    # STATISTICS HEADERS
    # =========================================================================
    "stats_header": "=== {title} ===",
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
    "stats_flood_threshold": "  Threshold: {msgs} msgs per {window}s",
    "stats_message_privmsg": "  PRIVMSGs sent: {count}",
    "stats_message_notice": "  NOTICEs sent: {count}",
    "stats_all_header": "=== STATS * - Full Statistics ===",
    "stats_all_footer": "=== End of STATS * ===",
    "stats_unknown_flag": "That STATS flag is not recognized: {flag}",
    # Database statistics
    "stats_db_pool_size": "  Pool size: {size}",
    "stats_db_active": "  Active connections: {count}",
    "stats_db_available": "  Available connections: {count}",
    "stats_db_size": "  Database size: {size}",
    "stats_db_tables": "  Tables: {tables}",
    "stats_db_registered_nicks": "  Registered nicknames: {count}",
    "stats_db_registered_channels": "  Registered channels: {count}",
    "stats_db_memos": "  Memos: {count}",
    # Network statistics
    "stats_network_header": "--- Network Statistics ---",
    "stats_network_local_users": "  Local users: {count}",
    "stats_network_remote_users": "  Remote users: {count}",
    "stats_network_servers": "  Linked servers: {count}",
    "stats_network_services": "  Services online: {count}",
    # Linking statistics
    "stats_linking_header": "--- Server Linking ---",
    "stats_linking_status": "  Status: {status}",
    "stats_linking_role": "  Server role: {role}",
    "stats_linking_server": "  {server}: {status}",
    # STATS misc content
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
    "stats_db_unavailable": "  Database statistics temporarily unavailable",
    "stats_db_not_configured": "  Database not configured",
    "stats_unavailable": "  Statistics temporarily unavailable",
    "stats_version": "  Version: {version} ({label})",
    "stats_dnsbl": "  DNSBL: {status}",
    "stats_ssl_cert": "Certificate: {file}",
    "stats_ssl_expires": "Expires: {expiry} ({days:.0f} days) [{status}]",
    "stats_ssl_subject": "Subject: {subject}",
    "stats_ssl_not_init": "SSL: not initialized",
    # Performance metrics
    "stats_perf_header": "--- Performance Metrics ---",
    "stats_config_reloads": "  Config cache reloads: {count}",
    "stats_channel_monitors": "  Active channel monitors: {count}",
    "stats_avg_msg_reload": "  Avg messages/reload: {count:,}",
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
    "stats_staff_guide_entry": "{nickname} (IRC Guide)",
    "stats_no_staff": "No staff currently online",
    "stats_end_staff": "--- End of Staff ---",
    # Individual flag stats
    "stats_admins_header": "=== Online IRC administrators ({count}) ===",
    "stats_no_admins": "No IRC administrators currently online",
    "stats_admin_entry": "  {prefix} (idle: {idle})",
    "stats_admins_footer": "=== End of IRC administrators ===",
    "stats_opers_header": "=== Online IRC operators ({count}) ===",
    "stats_no_opers": "No IRC operators currently online",
    "stats_oper_entry": "  {prefix} (idle: {idle})",
    "stats_opers_footer": "=== End of IRC operators ===",
    "stats_guides_header": "=== Online IRC Guides ({count}) ===",
    "stats_no_guides": "No IRC guides currently online",
    "stats_guide_entry": "  {prefix} (idle: {idle})",
    "stats_guides_footer": "=== End of IRC Guides ===",
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
    "stats_chan_modes": "Chan Modes: {modes}",
    "stats_flood_enabled": "Flood Protection: {status}",
    "stats_db_nicks": "Registered nicks: {count}",
    "stats_db_channels": "Registered channels: {count}",
    "stats_db_messages": "Offline messages: {count}",
    "stats_db_news": "Active news: {count}",
    "stats_news_unavailable": "News statistics temporarily unavailable",
    "stats_news_temp_unavailable": "News temporarily unavailable",
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
    "stats_no_message_data": "No message data available",
    "stats_active_channels": "Active channels: {count}",
    "stats_servicebots_enabled": "ServiceBots enabled: {status}",
    "stats_violations_detected": "Violations detected:",
    "stats_no_violations": "No violations detected",
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
    "stats_no_command_data": "No command usage data available",
    "stats_total_commands": "Total commands: {count}",
    # STAFF management messages
    "staff_subcommands": "STAFF subcommands: LIST, ADD, DEL, SET, PASS, MFA",
    "staff_levels": "Staff levels: ADMIN, SYSOP, GUIDE",
    "staff_list_header": "=== Staff Accounts ({count}) ===",
    "staff_list_none": "No staff accounts configured",
    "staff_list_blank": "",
    "staff_list_level_header": "{level} ({count}):",
    "staff_list_entry": "  {username}{status}",
    "staff_list_footer": "=== End of Staff Accounts ===",
    "staff_already_level": "'{username}' is already {level}",
    "staff_level_changed_header": "Staff level changed:",
    "staff_previous_level": "  Previous: {level}",
    "staff_new_level": "  New level: {level}",
    "staff_change_next_login": "Change will take effect on next login.",
    "staff_pass_old_required": "Your old password is required to change your password",
    "staff_pass_admin_hint": "Admins changing others: STAFF PASS <username> <newpassword>",
    "staff_pass_forwarded": "Password change request forwarded to trunk. Please wait...",
    "staff_pass_not_self": "Cannot change another's password (only their own)",
    "staff_pass_not_allowed": "You cannot change password for '{username}'",
    "staff_pass_invalid_old": "Invalid old password",
    "staff_pass_changed_header": "Password changed:",
    "staff_pass_changed_by": "  Changed by: {by}",
    "staff_pass_changed_note": "New password is now active.",
    "staff_mfa_status_header": "MFA Status for {username}:",
    "staff_mfa_enabled": "  MFA: Enabled",
    "staff_mfa_disabled": "  MFA: Disabled",
    "staff_mfa_secret_hint": "  Use STAFF MFA ENABLE to set up",
    "staff_mfa_enabled_success": "MFA enabled for {username}",
    "staff_mfa_secret": "  Secret: {secret}",
    "staff_mfa_setup_hint": "  Add this secret to your authenticator app",
    "staff_mfa_required_next_login": "  MFA will be required on next login",
    "staff_mfa_disabled_success": "MFA disabled for {username}",
    "staff_mfa_already_enabled": "MFA is already enabled for {username}",
    "staff_mfa_not_enabled": "MFA is not enabled for {username}",
    "staff_mfa_invalid_code": "Invalid MFA code",
    "staff_mfa_verified": "MFA code verified successfully",
    "trunk_only_format": "This format only works on trunk server",
    "staff_pass_self_only": "You can only change your own staff password",
    "staff_pass_changed_success": "Staff password changed:",
    "staff_pass_updated_other": "Password updated. User must login with new credentials.",
    "staff_mfa_own_hint": "Use AUTH ENABLE to manage your own MFA",
    "staff_mfa_usage": "Usage: STAFF MFA <username> ENABLE <code> | DISABLE <code> | STATUS",
    "staff_mfa_status": "MFA status for {username}: {status}",
    "staff_mfa_secret_pending": "Secret exists but awaiting first verification",
    "staff_mfa_enable_usage": "Usage: STAFF MFA {username} ENABLE <6-digit code>",
    "staff_mfa_user_needs_secret": "The user must run AUTH ENABLE first to generate their secret",
    "staff_mfa_user_enable_first": "User {username} must run AUTH ENABLE first to generate MFA secret",
    "staff_mfa_invalid_code_for_user": "Invalid MFA code for {username}",
    "staff_mfa_enabled_for_user": "MFA enabled for {username}",
    "staff_mfa_disable_usage": "Usage: STAFF MFA {username} DISABLE <6-digit code>",
    "staff_mfa_disable_code_required": "Current valid code required to disable MFA",
    "staff_mfa_config_error_for_user": "MFA configuration error for {username}",
    "staff_mfa_disabled_for_user": "MFA disabled for {username}",
    "staff_mfa_invalid_action": "Invalid MFA action: {action}",
    "staff_mfa_available_actions": "Use: ENABLE, DISABLE, or STATUS",
    "staff_mfa_op_failed": "MFA operation failed - internal error",
    "staff_unknown_subcommand": "Unknown STAFF subcommand: {subcmd}",
    "mfa_pending_registrar": "MFA verification pending. Use: PRIVMSG Registrar :MFA VERIFY <code>",
    # CONFIG command messages
    "config_section_unknown": "That section is not recognized: {section}",
    "config_section_header": "--- Config [{section}] ---",
    "config_key_value": "{key} = {value}",
    "config_sections_header": "--- Config Sections ---",
    "config_section_summary": "[{section}] ({count} keys)",
    "config_sections_footer": "--- End (use CONFIG LIST <section> for details) ---",
    "config_not_set": "{key} = (not set)",
    "config_set_success": "Set {key} = {value}",
    "config_previous_value": "Previous value: {value}",
    "config_subcmd_unknown": "That subcommand is not recognized: {subcmd}",
    # ACCESS command messages
    "access_added": "ACCESS {level} added to {target}: {mask}{timeout}",
    "access_not_found": "This mask {mask} is not in the {level} list",
    "access_deleted": "ACCESS {level} removed from {target}: {mask}",
    "access_cleared": "Cleared {count} entries from {target} ({level})",
    # PROFANITY filter messages
    "profanity_examples": "Examples: PROFANITY LIST, PROFANITY ADD WORD badword, PROFANITY ADD PATTERN (bad|terrible)",
    "profanity_header": "=== Profanity Filter Configuration ===",
    "profanity_status": "Status: {status}",
    "profanity_action": "Action: {action} (warn/gag/kick)",
    "profanity_case": "Case Sensitive: {status}",
    "profanity_words_header": "Filtered Words ({count}):",
    "profanity_words_none": "Filtered Words: (none)",
    "profanity_word_entry": "  - {word}",
    "profanity_patterns_header": "Regex Patterns ({count}):",
    "profanity_patterns_none": "Regex Patterns: (none)",
    "profanity_pattern_entry": "  - {pattern}",
    "profanity_add_usage": "Usage: PROFANITY ADD WORD <word> or PROFANITY ADD PATTERN <pattern>",
    "profanity_word_exists": "Word '{word}' is already in the filter",
    "profanity_word_added": "Added word '{word}' to profanity filter",
    "profanity_pattern_exists": "Pattern '{pattern}' is already in the filter",
    "profanity_pattern_added": "Added pattern '{pattern}' to profanity filter",
    "profanity_type_unknown": "That type '{type}' is not recognized. Use WORD or PATTERN",
    "profanity_del_usage": "Usage: PROFANITY DEL WORD <word> or PROFANITY DEL PATTERN <pattern>",
    "profanity_word_not_found": "Word '{word}' is not in the filter",
    "profanity_word_removed": "Removed word '{word}' from profanity filter",
    "profanity_pattern_not_found": "Pattern '{pattern}' is not in the filter",
    "profanity_pattern_removed": "Removed pattern '{pattern}' from profanity filter",
    "profanity_enabled": "Profanity filter enabled",
    "profanity_disabled": "Profanity filter disabled",
    "profanity_test_usage": "Usage: PROFANITY TEST <text to check>",
    "profanity_test_would_catch": "TEST RESULT: Would be caught - matched: {matched}",
    "profanity_test_clean": "TEST RESULT: Would NOT be caught",
    "profanity_unknown_subcommand": "That subcommand is not recognized: {subcmd}",
    "profanity_available_subcommands": "Available: LIST, ADD, DEL, ENABLE, DISABLE, TEST",
    "profanity_blank_line": "",

    # =========================================================================
    # SSL/TLS MESSAGES
    # =========================================================================
    "ssl_enabled": "SSL: enabled",
    "ssl_disabled": "SSL: disabled",
    "ssl_no_certs": "SSL: enabled but no certificates loaded",
    "ssl_server": "Server: {server}",
    "ssl_network": "Network: {network}",
    "ssl_certificate": "Certificate: {file}",
    "ssl_subject": "Subject: {subject}",
    "ssl_expiry": "Expires: {expiry} ({days} days) [{status}]",

    # =========================================================================
    # CHANNEL MESSAGES
    # =========================================================================
    "channel_not_owner": "You are not the owner of {channel}",
    "channel_whispers_disabled": "You cannot send whispers in {channel} (+w)",
    "channel_invites_disabled": "You cannot send invitations in {channel} (+j)",
    "channel_no_external": "You cannot send to {channel} (not a member)",
    "channel_moderated": "You cannot speak in {channel} (moderated)",
    "channel_registered": "Channel {channel} is now registered",
    "channel_dropped": "Channel {channel} has been unregistered",
    "channel_local_no_register": "You cannot register local channels (&)",

    # =========================================================================
    # USER MODE MESSAGES
    # =========================================================================
    "mode_cannot_set": "You cannot manually set or unset mode +{mode}",
    "mode_cannot_unset_x": "You cannot unset +x mode",
    "mode_z_staff_controlled": "You cannot manually set or unset +z mode (staff-controlled)",
    "mode_too_many": "You specified too many mode changes (max {max} per command)",

    # =========================================================================
    # LINKING MESSAGES (additional)
    # =========================================================================
    "link_not_enabled": "Server linking is not enabled",
    "link_already_connected": "Already connected to {server}",
    "link_connected": "Connected to {server}",
    "link_disconnected": "Disconnected from {server}",

    # =========================================================================
    # EVENT MESSAGES
    # =========================================================================
    "event_classes": "Invalid event class. Valid: CONNECT, MEMBER, CHANNEL, USER, SERVER, SOCKET",
    "event_usage": "Usage: EVENT [ADD|DELETE|LIST] <class> [<mask>]",

    # =========================================================================
    # ADDITIONAL UNIQUE MESSAGES
    # =========================================================================
    "profanity_subcommands": "PROFANITY subcommands: LIST, ADD, DEL, ENABLE, DISABLE, TEST",
    "profanity_test_caught": "Text WOULD be caught by filter",
    "profanity_test_ok": "Text would NOT be caught by filter",
    "access_mask_not_found": "Mask {mask} was not found in the {level} list",
    "access_denied_reason": "Access denied{reason}",
    "broadcast_sent": "Server-wide {type} sent to {count} user(s) on {server}",
    "broadcast_restricted": "Server-wide messaging is restricted to staff.",
    "data_target_no_ircx": "{target} does not support IRCX",
    "tag_invalid_length": "Invalid tag: must be 1-15 characters",
    "tag_invalid_start": "Invalid tag: must start with a letter",
    "tag_invalid_chars": "Invalid tag: only letters, numbers, and periods allowed",
    "tag_reserved_adm": "The ADM.* tag prefix is reserved for administrators.",
    "tag_reserved_sys": "The SYS.* tag prefix is reserved for operators.",
    "tag_reserved_gde": "The GDE.* tag prefix is reserved for guides.",
    "kill_cannot_system": "You cannot kill #System channel",
    "kill_cannot_admin": "Cannot kill IRC administrators",
    "kill_cannot_virtual": "Cannot kill virtual users",
    "memo_usage_del": "Usage: MEMO DEL <id|ALL>",
    "memo_usage_read": "Usage: MEMO READ <id>",
    "memo_usage_send": "Usage: MEMO SEND <nick> <message>",
    "server_branch_hint": "You should connect to a branch server",
    "not_authenticated": "You are not authenticated as staff",
}


# ==============================================================================
# LOG MESSAGES - Centralized logging message templates
# ==============================================================================
LOG_MESSAGES = {
    # =========================================================================
    # CONFIG MESSAGES
    # =========================================================================
    "config_loaded": "Loaded config from {file}",
    "config_error": "Config error: {error}",
    "config_not_found": "Config file not found: {file}",
    "config_saved": "Config saved",
    "config_save_error": "Save error: {error}",
    "config_reloaded": "Configuration reloaded successfully",
    "config_reload_failed": "Failed to reload configuration: {error}",

    # =========================================================================
    # SSL/TLS MESSAGES
    # =========================================================================
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

    # =========================================================================
    # SECURITY MESSAGES
    # =========================================================================
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

    # =========================================================================
    # DATABASE MESSAGES
    # =========================================================================
    "db_pool_init": "Initializing connection pool: {db_path} (size: {pool_size})",
    "db_connection_created": "Created connection {current}/{total}",
    "db_connection_failed": "Failed to create connection {current}: {error}",
    "db_pool_ready": "Connection pool initialized with {pool_size} connections",
    "db_pool_exhausted": "Connection pool exhausted (timeout={timeout}s)",
    "db_pool_warning": "Database pool exhausted ({pool_size} connections in use). Consider increasing pool_size.",
    "db_rollback": "Transaction rolled back due to error",
    "db_rollback_failed": "Rollback failed: {error}",
    "db_return_failed": "Failed to return connection to pool: {error}",
    "db_replacement_created": "Created replacement connection",
    "db_replacement_failed": "Failed to create replacement connection: {error}",
    "db_closing": "Closing all connections in pool",
    "db_close_error": "Error closing connection: {error}",
    "db_closed": "Closed {count} connections",
    "db_already_init": "Connection pool already initialized, closing existing pool",
    "db_init_success": "Database connection pool initialized: {db_path} (pool_size={pool_size})",
    "db_init_failed": "Failed to initialize database pool: {error}",
    "db_init_warning": "Connection pool initialization failed: {error}",
    "db_initialized": "Database initialized (trunk)",
    "db_skipped": "Skipping database initialization (branch server)",
    "db_pool_initialized": "Database connection pool initialized",
    "db_pool_closed": "Database pool closed",
    "db_pool_close_error": "Database pool close: {error}",

    # =========================================================================
    # SERVER STARTUP/SHUTDOWN MESSAGES
    # =========================================================================
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
    "signal_received": "Received signal {signal}, initiating shutdown...",
    "sighup_received": "Received SIGHUP, reloading configuration...",
    "link_manager_shutdown": "Link manager shutdown complete",
    "link_manager_shutdown_error": "Link manager shutdown: {error}",
    "server_close_timeout": "Timeout waiting for server to close, forcing",
    "client_disconnect_timeout": "Timeout disconnecting clients, forcing",
    "cancel_tasks_timeout": "Timeout cancelling background tasks, forcing",
    "no_ports_available": "No ports available, exiting",

    # =========================================================================
    # LISTENING/BINDING MESSAGES
    # =========================================================================
    "listening_ipv6": "Listening on [{addr}]:{port} ({family})",
    "listening_ipv4": "Listening on {addr}:{port} ({family})",
    "listening_ipv6_ssl": "Listening on [{addr}]:{port} ({family}, SSL/TLS)",
    "listening_ipv4_ssl": "Listening on {addr}:{port} ({family}, SSL/TLS)",
    "bind_failed_ipv6": "Failed to bind to [{addr}]:{port} ({family}): {error}",
    "bind_failed_ipv4": "Failed to bind to {addr}:{port} ({family}): {error}",
    "bind_ssl_failed_ipv6": "Failed to bind SSL to [{addr}]:{port} ({family}): {error}",
    "bind_ssl_failed_ipv4": "Failed to bind SSL to {addr}:{port} ({family}): {error}",

    # =========================================================================
    # SERVICE INITIALIZATION MESSAGES
    # =========================================================================
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

    # =========================================================================
    # USER CONNECTION MESSAGES
    # =========================================================================
    "client_timeout": "Client timeout (no data for {timeout}s): {nickname} ({ip})",
    "client_debug": "[{nickname}] <<< {data}",
    "client_error": "Client error [{nickname}]: {error}",
    "client_traceback": "Traceback: {traceback}",
    "send_error": "Send error {nickname}: {error}",
    "close_error": "Close error: {error}",
    "status_dump_error": "Status dump error: {error}",

    # =========================================================================
    # AUTHENTICATION MESSAGES
    # =========================================================================
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

    # =========================================================================
    # AUTH COMMAND MESSAGES
    # =========================================================================
    "auth_no_ssl": "AUTH: {nickname} ({ip}) attempted AUTH on non-SSL connection",
    "auth_locked_out": "AUTH: {username} locked out (IP: {ip})",
    "auth_unknown_user": "AUTH: Failed attempt for unknown user '{username}' from {nickname} ({ip})",
    "auth_wrong_password": "AUTH: Failed password for '{username}' from {nickname} ({ip})",
    "auth_mfa_pending": "AUTH: Password OK for '{username}' from {nickname} ({ip}), awaiting MFA",
    "auth_error": "AUTH error: {error}",
    "auth_mfa_expired": "AUTH: MFA session expired for {nickname}",
    "auth_mfa_secret_not_found": "AUTH: MFA secret not found for {username}",
    "auth_mfa_invalid": "AUTH: Invalid MFA code for '{username}' from {nickname} ({ip})",
    "auth_mfa_enabled_first": "AUTH VERIFY: MFA enabled for {username} after first successful verification",
    "auth_verify_error": "AUTH VERIFY error: {error}",
    "auth_mfa_setup_complete": "AUTH VERIFY: {username} enabled MFA via setup completion",
    "auth_mfa_setup_failed": "AUTH VERIFY: {username} failed MFA setup verification",
    "auth_verify_setup_error": "AUTH VERIFY setup error: {error}",
    "auth_enable_wrong_password": "AUTH ENABLE: Failed password verification for {username}",
    "auth_enable_generated": "AUTH ENABLE: {username} generated MFA secret",
    "auth_enable_error": "AUTH ENABLE error: {error}",
    "auth_disable_success": "AUTH DISABLE: {username} disabled MFA",
    "auth_disable_error": "AUTH DISABLE error: {error}",
    "auth_complete": "AUTH: {username} authenticated successfully from {nickname} ({ip}) as {level}",
    "auth_update_login_failed": "AUTH: Failed to update last_login: {error}",
    "auth_count_failures_error": "_count_auth_failures error: {error}",
    "drop_success": "DROP: {username} ({level}) dropped to regular user from {nickname} ({ip})",

    # =========================================================================
    # NICK BURST/LINKING MESSAGES
    # =========================================================================
    "nick_burst_broadcasting": "Broadcasting NICK burst for {nickname} to linked servers: {burst}",
    "nick_burst_sent": "NICK burst sent for {nickname}",

    # =========================================================================
    # SERVICE MESSAGE ROUTING
    # =========================================================================
    "service_routed": "Routed service message from {nickname} to {target} via trunk",
    "service_route_failed": "Failed to route to trunk for {target}",

    # =========================================================================
    # CHANNEL MESSAGES
    # =========================================================================
    "channel_loaded": "Loaded registered channel: {channel}",
    "channel_load_error": "Error loading registered channel {channel}: {error}",
    "join_propagated_sending": "Propagating JOIN to linked servers: {message}",
    "join_propagated": "JOIN propagated for {nickname} to {channel}",
    "topic_set": "Topic set in {channel} by {nickname}",
    "prop_set": "PROP {channel} {prop}={value} by {nickname}",
    "channel_unregistered_mode": "Channel {channel} unregistered via MODE -r by {nickname}",
    "channel_unregister_error": "MODE -r database error: {error}",
    "channel_locked": "Channel {channel} locked (+z) by {nickname}",
    "channel_unlocked": "Channel {channel} unlocked (-z) by {nickname}",
    "transcript_write_error": "Transcript write error for {channel}: {error}",
    "transcript_read_error": "Transcript read error for {channel}: {error}",

    # =========================================================================
    # ACCESS MESSAGES
    # =========================================================================
    "access_loaded": "ACCESS rules loaded: {grant} GRANT, {deny} DENY",
    "access_load_error": "Load ACCESS error: {error}",
    "access_add": "ACCESS {target} ADD {level} {mask} by {nickname}",
    "access_add_error": "ACCESS ADD DB error: {error}",
    "access_del": "ACCESS {target} DEL {level} {mask} by {nickname}",
    "access_del_error": "ACCESS DEL DB error: {error}",
    "access_clear": "ACCESS {target} CLEAR {level} by {nickname}",
    "access_clear_error": "ACCESS CLEAR DB error: {error}",
    "access_in_memory": "ACCESS list: In-memory only (branch server)",

    # =========================================================================
    # STATS/ERROR MESSAGES
    # =========================================================================
    "stats_error": "Stats error: {error}",
    "database_stats_error": "Database stats error: {error}",
    "newsflash_stats_error": "NewsFlash stats error: {error}",
    "newsflash_error": "NewsFlash error: {error}",
    "reply_error": "Reply error {code}: {error}",
    "template_error": "Missing template variable for {key}: {error}",
    "unknown_message_key": "Unknown message key: {key}",

    # =========================================================================
    # CONFIG COMMAND MESSAGES
    # =========================================================================
    "config_set_log": "CONFIG: {nickname} set {key} = {value}",
    "config_saved_log": "CONFIG: {nickname} saved configuration",
    "config_reloaded_log": "CONFIG: {nickname} reloaded configuration",

    # =========================================================================
    # LINK COMMAND MESSAGES
    # =========================================================================
    "link_success": "LINK: {nickname} linked to {server}",
    "link_failed_log": "LINK: Failed to link to {server}: {error}",
    "unlink_success": "UNLINK: {nickname} unlinked {server}: {reason}",
    "unlink_failed": "UNLINK: Failed to unlink {server}: {error}",

    # =========================================================================
    # STAFF COMMAND MESSAGES
    # =========================================================================
    "staff_log": "STAFF: {message}",
    "staff_list_error": "STAFF LIST error: {error}",
    "staff_added": "STAFF: {nickname} added staff account '{username}' ({level})",
    "staff_add_error": "STAFF ADD error: {error}",
    "staff_deleted": "STAFF: {nickname} deleted staff account '{username}' ({level})",
    "staff_del_error": "STAFF DEL error: {error}",
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

    # =========================================================================
    # PROFANITY COMMAND MESSAGES
    # =========================================================================
    "profanity_word_added_log": "PROFANITY: {nickname} added word '{word}'",
    "profanity_pattern_added_log": "PROFANITY: {nickname} added pattern '{pattern}'",
    "profanity_word_removed_log": "PROFANITY: {nickname} removed word '{word}'",
    "profanity_pattern_removed_log": "PROFANITY: {nickname} removed pattern '{pattern}'",
    "profanity_enabled_log": "PROFANITY: {nickname} enabled profanity filter",
    "profanity_disabled_log": "PROFANITY: {nickname} disabled profanity filter",

    # =========================================================================
    # REGISTRATION MESSAGES
    # =========================================================================
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

    # =========================================================================
    # MFA MESSAGES
    # =========================================================================
    "mfa_setup_initiated": "MFA: {nickname} initiated setup",
    "mfa_enable_error": "MFA enable error: {error}",
    "mfa_identification_complete": "MFA: {nickname} completed identification",
    "mfa_enabled_log": "MFA: {nickname} enabled",
    "mfa_verify_error": "MFA verify error: {error}",
    "mfa_disabled_log": "MFA: {nickname} disabled",
    "mfa_disable_error": "MFA disable error: {error}",

    # =========================================================================
    # CHGPASS/SETNAME MESSAGES
    # =========================================================================
    "chgpass_proxied": "Proxied CHGPASS from {nickname} to trunk",
    "chgpass_success": "CHGPASS: {nickname} changed password",
    "chgpass_error": "CHGPASS error: {error}",
    "setname_changed": "SETNAME: {nickname} changed realname to '{realname}'",

    # =========================================================================
    # MEMO MESSAGES
    # =========================================================================
    "memo_send_error": "MEMO SEND error: {error}",
    "memo_list_error": "MEMO LIST error: {error}",
    "memo_read_error": "MEMO READ error: {error}",
    "memo_del_error": "MEMO DEL error: {error}",
    "memo_delivery_error": "Memo delivery check error: {error}",

    # =========================================================================
    # SERVICEBOT MESSAGES
    # =========================================================================
    "servicebot_warned": "ServiceBot {bot}: Warned {user} in {channel} for {violation}",
    "servicebot_gagged": "ServiceBot {bot}: Gagged {user} in {channel} for {violation}",
    "servicebot_kicked": "ServiceBot {bot}: Kicked {user} from {channel} for {violation}",
    "servicebot_banned": "ServiceBot {bot}: Banned {user} from {channel} for {violation}",
    "servicebot_dispatcher_assigned": "ServiceBot dispatcher assigned {bot} to {channel} via INVITE from {nickname}",
    "servicebot_invited": "ServiceBot {bot} joined {channel} via INVITE from {nickname} (granted +q)",
    "entity_invited": "{entity} joined {channel} via INVITE from {nickname} (granted +q)",

    # =========================================================================
    # REGISTRAR SERVICE MESSAGES
    # =========================================================================
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
    "registrar_mfa_initiated": "Registrar: {nickname} initiated MFA setup",
    "registrar_mfa_enable_error": "Registrar MFA enable error: {error}",
    "registrar_mfa_disabled": "Registrar: {nickname} disabled MFA",
    "registrar_mfa_disable_error": "Registrar MFA disable error: {error}",
    "registrar_mfa_completed": "Registrar: {nickname} completed MFA identification",
    "registrar_mfa_enabled": "Registrar: {nickname} enabled MFA",
    "registrar_mfa_verify_error": "Registrar MFA verify error: {error}",

    # =========================================================================
    # MESSENGER SERVICE MESSAGES
    # =========================================================================
    "messenger_send_error": "Messenger send error: {error}",
    "messenger_read_error": "Messenger read error: {error}",
    "messenger_delete_error": "Messenger delete error: {error}",
    "messenger_count_error": "Messenger count error: {error}",
    "messenger_global_push": "Messenger: Global push by {nickname}: {message}",

    # =========================================================================
    # NEWSFLASH SERVICE MESSAGES
    # =========================================================================
    "newsflash_list_error": "NewsFlash list error: {error}",
    "newsflash_added": "NewsFlash: Added by {nickname}: {message}",
    "newsflash_add_error": "NewsFlash add error: {error}",
    "newsflash_delete_error": "NewsFlash delete error: {error}",
    "newsflash_pushed": "NewsFlash: Push by {nickname}: {message}",
    "newsflash_on_connect_error": "NewsFlash on-connect error: {error}",
    "newsflash_periodic_broadcast": "NewsFlash: Periodic broadcast to {count} user(s)",
    "newsflash_periodic_error": "NewsFlash periodic error: {error}",

    # =========================================================================
    # AUTO-CREATION MESSAGES
    # =========================================================================
    "auto_create_nick": "Auto-created nickname '{nick}' for mailbox delivery (sender: {sender})",
    "auto_create_service": "Auto-created service account '{account}' for channel registration (channel: {channel})",

    # =========================================================================
    # ADMIN COMMAND MESSAGES
    # =========================================================================
    "admin_killed_channel": "Admin command: Killed channel {channel} for reconfiguration",
    "admin_killed_user": "Admin command: Killed user {nickname} - {reason}",
    "admin_banned_user": "Admin command: Banned user {nickname} ({ip}) for {duration}s - {reason}",
    "admin_registered_channel": "Admin command: Registered channel {channel} to {owner}",
    "admin_updated_channel": "Admin command: Updated channel {channel} owner to {owner} with +ra modes",
    "admin_locked_channel": "Admin command: Locked channel {channel} (registered +ra to {owner})",
    "admin_lock_error": "Error locking channel {channel}: {error}",
    "admin_set_mode": "Admin command: Set mode {mode} on {channel}",
    "admin_system_user_not_found_mode": "Admin command: System user not found for SET_CHANNEL_MODE",
    "admin_set_topic": "Admin command: Set topic on {channel}",
    "admin_system_user_not_found_topic": "Admin command: System user not found for SET_CHANNEL_TOPIC",
    "admin_error": "Error processing admin commands: {error}",
    "admin_system_user_missing": "Admin command: System user not found for {command}",
    "admin_command_error": "Error processing admin commands: {error}",
    "admin_lock_channel_error": "Error locking channel {channel}: {error}",

    # =========================================================================
    # ADDITIONAL PYIRCX MESSAGES
    # =========================================================================
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

    # =========================================================================
    # API HELPER MESSAGES
    # =========================================================================
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

    # =========================================================================
    # WEBCHAT GATEWAY MESSAGES
    # =========================================================================
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

    # =========================================================================
    # LINKING MESSAGES
    # =========================================================================
    "link_send_error": "Error sending to {server}: {error}",
    "link_invalid_role": "Invalid server_role '{role}'. Must be one of: {valid_roles}",
    "link_invalid_version": "Invalid VERSION response from {server}: {line}",
    "link_remote_version": "Remote server {server}: pyIRCX/{version} PROTO/{proto}",
    "link_proto_mismatch": "Protocol mismatch with {server}",
    "link_version_mismatch": "Version mismatch with {server}",
    "link_version_passed": "Version check passed for {server}",
    "link_invalid_timesync": "Invalid TIMESYNC response from {server}: {line}",
    "link_time_delta": "Time sync check for {server}: delta = {delta}s",
    "link_time_error": "Time sync error with {server}",
    "link_time_warning": "Time sync warning for {server}",
    "link_time_passed": "Time sync check passed for {server}",
    "link_timesync_parse_error": "Invalid TIMESYNC from {server}: {error}",
    "link_disabled": "Server linking disabled in config",
    "link_listening": "Server linking listening on {host}:{port}",
    "link_monitor_started": "Link monitoring task started",
    "link_start_failed": "Failed to start server linking: {error}",
    "link_health_started": "Link health monitoring started",
    "link_ping_sent": "Sent PING to {server}",
    "link_ping_timeout": "Ping timeout for {server}",
    "link_monitor_cancelled": "Link monitoring task cancelled",
    "link_monitor_error": "Link monitoring error: {error}",
    "link_incoming": "Incoming server connection from {peer}",
    "link_auth_failed": "Failed auth from {server} at {peer}",
    "link_role_failed": "Role validation failed for {server}: {error}",
    "link_role_passed": "Role validation passed: {local_role} <-> {remote_role}",
    "link_server_linked": "Server {server} linked successfully",
    "link_handshake_timeout": "Server handshake timeout from {peer}",
    "link_handshake_error": "Server handshake error: {error}",
    "link_connecting": "Connecting to {server} at {host}:{port}",
    "link_role_validation_failed": "Role validation failed for {server}: {error}",
    "link_role_validation_passed": "Role validation passed: {local_role} <-> {remote_role}",
    "link_connected": "Successfully linked to {server}",
    "link_rejected": "Link to {server} rejected: {line}",
    "link_connect_failed": "Failed to connect to {server}: {error}",
    "link_no_reconnect": "Not scheduling reconnect for {server} (autoconnect disabled)",
    "link_reconnect_scheduled": "Scheduling reconnect to {server} in {delay}s (attempt #{attempt})",
    "link_reconnect_attempting": "Attempting reconnect to {server}",
    "link_reconnect_cancelled": "Reconnect to {server} cancelled",
    "link_reconnect_failed": "Reconnect attempt to {server} failed: {error}",
    "link_staff_burst": "Burst {count} staff accounts to {server}",
    "link_staff_burst_error": "Error bursting staff accounts to {server}: {error}",
    "link_service_burst": "Bursting service {nickname} to {server}",
    "link_eob_sent": "Sent EOB (End of Burst) to {server}",
    "link_read_error": "Error reading from {server}: {error}",
    "link_staff_sync_complete": "Staff sync completed from {server}",
    "link_eob_received": "Received EOB from {server} - burst complete",
    "link_trunk_sasl_success": "Trunk: SASL staff auth SUCCESS for {username} ({level})",
    "link_trunk_staff_success": "Trunk: Staff auth SUCCESS for {username} ({level})",
    "link_trunk_staff_bad_password": "Trunk: Staff auth FAILED for {username} (bad password)",
    "link_trunk_staff_not_found": "Trunk: Staff auth FAILED for {username} (not found)",
    "link_trunk_staff_error": "Trunk: Staff auth error for {username}: {error}",
    "link_staff_reply_unknown": "Received staff auth response for unknown ID: {auth_id}",
    "link_branch_staff_success": "Branch: Staff auth SUCCESS via trunk for {username} ({level})",
    "link_branch_staff_failed": "Branch: Staff auth FAILED via trunk for {username}",
    "link_invalid_staffsync": "Invalid STAFFSYNC from {server}: {parts}",
    "link_staff_synced": "Staff sync: {username} ({level}) from {server}",
    "link_staff_sync_error": "Error syncing staff account {username}: {error}",
    "link_invalid_staffcmd": "Invalid STAFFCMD from {server}: {parts}",
    "link_staffcmd_unknown_user": "STAFFCMD for unknown user {nickname} from {server}",
    "link_staff_password_changed_via": "Staff password changed for {username} via {server}",
    "link_staff_added_via": "Staff account {username} ({level}) added by {by} via {server}",
    "link_staff_removed_via": "Staff account {username} removed by {by} via {server}",
    "link_staff_level_changed_via": "Staff level for {username} changed to {level} by {by} via {server}",
    "link_staffcmd_error": "Error processing STAFFCMD {subcmd} from {server}: {error}",
    "link_invalid_staffupdate": "Invalid STAFFUPDATE from {server}: {parts}",
    "link_staff_update_password": "Staff update: password changed for {username}",
    "link_staff_update_level": "Staff update: level changed for {username} to {level}",
    "link_staff_update_added": "Staff update: {username} added with level {level}",
    "link_staff_update_removed": "Staff update: {username} removed",
    "link_staffupdate_error": "Error processing STAFFUPDATE for {username}: {error}",
    "link_staffreply_unknown": "STAFFREPLY for unknown user {nickname}",
    "link_invalid_regcmd": "Invalid REGCMD from {server}: {parts}",
    "link_regcmd_unknown_user": "REGCMD for unknown user {nickname} from {server}",
    "link_registration_via": "Registration: {account} registered via {server}",
    "link_unregistration_via": "Unregistration: {account} unregistered via {server}",
    "link_identification_via": "Identification: {account} identified via {server}",
    "link_channel_registration_via": "Channel registration: {channel} registered by {nickname} via {server}",
    "link_channel_unregistration_via": "Channel unregistration: {channel} unregistered by {nickname} via {server}",
    "link_chgpass_via": "CHGPASS: {nickname} changed password via {server}",
    "link_regcmd_error": "Error processing REGCMD {subcmd} from {server}: {error}",
    "link_invalid_regupdate": "Invalid REGUPDATE from {server}: {parts}",
    "link_regupdate_not_local": "REGUPDATE for user {nickname} not on this branch",
    "link_regupdate_action": "Registration update: {nickname} {action}",
    "link_regupdate_unregistered": "Registration update: {nickname} unregistered",
    "link_regupdate_error": "Error processing REGUPDATE for {nickname}: {error}",
    "link_regreply_unknown": "REGREPLY for unknown user {nickname}",
    "link_invalid_memocmd": "Invalid MEMOCMD from {server}: {parts}",
    "link_memocmd_unknown_user": "MEMOCMD for unknown user {nickname} from {server}",
    "link_memo_sent_via": "Memo sent: {sender} -> {target} via {server}",
    "link_memocmd_error": "Error processing MEMOCMD {subcmd} from {server}: {error}",
    "link_memoreply_unknown": "MEMOREPLY for unknown user {nickname}",
    "link_service_added": "Added remote service {nickname} from trunk {server}",
    "link_remote_nick_called": "handle_remote_nick called from {server} with {parts} parts: {preview}",
    "link_remote_nick_not_enough_parts": "handle_remote_nick: Not enough parts ({count}), need 9+",
    "link_remote_nick_processing": "Processing NICK for {nickname} from {server}",
    "link_nick_collision": "Nick collision for {nickname}",
    "link_collision_keep_incoming": "Collision resolution: Keeping incoming {nickname} (older timestamp)",
    "link_collision_kill_error": "Error killing local user in collision: {error}",
    "link_collision_keep_existing": "Collision resolution: Keeping existing {nickname} (older timestamp)",
    "link_collision_tiebreak_incoming": "Collision resolution: Tie broken by server name, keeping incoming {nickname}",
    "link_collision_tiebreak_existing": "Collision resolution: Tie broken by server name, keeping existing {nickname}",
    "link_remote_user_added": "✓ Added remote user {nickname} from {server} (total users: {total})",
    "link_nick_forwarded": "Forwarded NICK for {nickname} to other servers",
    "link_channel_created_sjoin": "Created new channel {channel} from SJOIN (ts={timestamp})",
    "link_sjoin_info": "SJOIN for {channel}: local_ts={local_ts}, remote_ts={remote_ts}",
    "link_sjoin_accept_remote": "Channel {channel}: Remote is older, accepting remote state",
    "link_sjoin_keep_local": "Channel {channel}: Local is older, keeping local state",
    "link_sjoin_merge": "Channel {channel}: Equal timestamp, merging state",
    "link_virtual_user_created": "Created virtual remote user {nickname} from {server}",
    "link_privmsg_routed": "Routed PRIVMSG from {nickname} to {target}",
    "link_service_handler_not_found": "Service handler {handler} not found!",
    "link_remote_user_create_failed": "Failed to create/find remote user {nickname}",
    "link_channel_message_from": "Processing channel message from {server}: {source} -> {target}",
    "link_channel_member_count": "  Channel {channel} has {count} total members",
    "link_channel_member_info": "  Member {nickname}: is_remote={is_remote}",
    "link_channel_sending_to": "    -> Sending to {nickname}",
    "link_channel_forwarding": "  Forwarding to other servers (exclude={exclude})",
    "link_channel_not_forwarding": "  NOT forwarding (branch server)",
    "link_privmsg_delivered": "Delivered private message from {source} to {target}",
    "link_privmsg_forwarded": "Forwarded private message from {source} to {target}",
    "link_user_not_local": "User {target} not found locally on branch server",
    "link_remote_join_processing": "Processing remote JOIN from {server}: {line}",
    "link_remote_join_info": "JOIN: user={nickname}, channel={channel}, user_found={found}",
    "link_channel_created_join": "Created channel {channel} for remote JOIN",
    "link_remote_join_added": "Added {nickname} to {channel}, broadcasting to local users",
    "link_remote_join_forwarded": "JOIN forwarded to other servers for {nickname} in {channel}",
    "link_remote_join_complete": "JOIN processing complete for {nickname} in {channel}",
    "link_remote_topic": "Remote TOPIC set in {channel} by {nickname}: {topic}",
    "link_remote_mode_owner_add": "Remote MODE: Added {nickname} as owner of {channel}",
    "link_remote_mode_owner_del": "Remote MODE: Removed {nickname} as owner of {channel}",
    "link_remote_mode_host_add": "Remote MODE: Added {nickname} as host of {channel}",
    "link_remote_mode_host_del": "Remote MODE: Removed {nickname} as host of {channel}",
    "link_remote_mode_voice_add": "Remote MODE: Added {nickname} as voice in {channel}",
    "link_remote_mode_voice_del": "Remote MODE: Removed {nickname} as voice in {channel}",
    "link_remote_mode_ban_add": "Remote MODE: Added ban {mask} to {channel}",
    "link_remote_mode_ban_del": "Remote MODE: Removed ban {mask} from {channel}",
    "link_remote_mode_key_set": "Remote MODE: Set key on {channel}",
    "link_remote_mode_key_del": "Remote MODE: Removed key from {channel}",
    "link_remote_mode_limit_set": "Remote MODE: Set limit on {channel}",
    "link_remote_mode_limit_del": "Remote MODE: Removed limit from {channel}",
    "link_remote_mode_set": "Remote MODE: Set {channel} {sign}{char}",
    "link_remote_mode_user": "Remote MODE: {target} {sign}i",
    "link_remote_kick": "Remote KICK: {target} from {channel} by {source}",
    "link_remote_invite": "Remote INVITE: {target} to {channel} from {source}",
    "link_remote_nick_change": "Remote NICK: {old} -> {new}",
    "link_remote_kill_ignored": "Remote KILL ignored: {target} is remote on this server",
    "link_remote_kill": "Remote KILL: {target} ({reason})",
    "link_remote_whois": "Remote WHOIS: {requester} querying {target}",
    "link_remote_away": "Remote AWAY: {nickname} is away: {message}",
    "link_remote_back": "Remote AWAY: {nickname} is back",
    "link_remote_whisper": "Remote WHISPER: {source} to {target} in {channel}",
    "link_remote_access": "Remote ACCESS: {nickname} executed ACCESS {action} on {obj}",
    "link_remote_access_error": "Remote ACCESS execution error: {error}",
    "link_remote_prop": "Remote PROP: {nickname} set {prop} on {channel}",
    "link_remote_prop_error": "Remote PROP execution error: {error}",
    "link_remote_knock": "Remote KNOCK: {nickname} knocked on {channel}",
    "link_broadcast_called": "broadcast_to_servers called with message: {preview}...",
    "link_broadcast_servers": "Available servers: {servers}, exclude={exclude}",
    "link_broadcast_sending": "  Sending to {server}: {preview}...",
    "link_broadcast_sent": "  Sent to {server}",
    "link_server_disconnected": "Server {server} disconnected (split)",
    "link_squit_propagated": "Propagated SQUIT for {server} to all linked servers",
    "link_bcrypt_error": "bcrypt verification error for {server}: {error}",
    "link_plaintext_warning": "Server link {server} using PLAINTEXT password - UPDATE TO BCRYPT IMMEDIATELY",
    "link_no_hub_server": "No hub_server configured in services",
    "link_trunk_not_found": "Trunk server '{hub}' not found in linked servers",
    "link_trunk_found": "Found trunk server '{hub}', is_direct={is_direct}",
    "link_routed_to_trunk": "Routed message to trunk",
    "link_trunk_not_direct": "Trunk found but not direct: {hub}, is_direct={is_direct}",
    "link_no_trunk_for_service": "No trunk server found for service routing",
    "link_staff_auth_no_trunk": "Staff auth routing failed: No trunk connection",
    "link_staff_auth_sent": "Sent staff auth request to trunk: {username} (id: {auth_id})",
    "link_staff_auth_timeout": "Staff auth timeout for {username}",
    "link_staff_auth_error": "Staff auth error for {username}: {error}",

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

    # =========================================================================
    # CHANNEL PROPERTY MESSAGES
    # =========================================================================
    "channel_props_error": "Error loading channel properties: {error}",
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
