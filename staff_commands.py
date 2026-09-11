#!/usr/bin/env python3
"""
Staff and operator command handlers: STATS, CONFIG, STAFF, PROFANITY.

These are mixed into pyIRCXServer (see pyircx.py) and use its state through
self; they live here only to keep pyircx.py manageable.
"""

import json
import logging
import os
import time

from database import hash_password_async
from responses import SERVER_MESSAGES, get_log_message
from service_bot import ServiceBotMonitor
from validation import validate_regex_pattern, validate_username
from version import VERSION as __version__, VERSION_LABEL as __version_label__

logger = logging.getLogger('pyIRCX')

# Will be set by pyircx.py when module is imported
CONFIG = None


class StaffCommandsMixin:
    """STATS/CONFIG/STAFF/PROFANITY handlers for pyIRCXServer."""

    def _reload_all_monitor_configs(self):
        """Reload config cache for all channel monitors (called when PROFANITY config changes)"""
        for monitor in self.channel_monitors.values():
            monitor.reload_config()
        # Track config cache reloads for performance monitoring
        self.stats['config_cache_reloads'] += 1

    async def _get_db_stats(self):
        """Get database statistics. Returns dict with counts."""
        stats = {'nicks': 0, 'channels': 0, 'messages': 0}
        async with self.db_pool.connection() as db:
            async with db.execute("SELECT COUNT(*) FROM registered_nicks") as cursor:
                row = await cursor.fetchone()
                stats['nicks'] = row[0] if row else 0
            async with db.execute("SELECT COUNT(*) FROM registered_channels") as cursor:
                row = await cursor.fetchone()
                stats['channels'] = row[0] if row else 0
            async with db.execute("SELECT COUNT(*) FROM mailbox") as cursor:
                row = await cursor.fetchone()
                stats['messages'] = row[0] if row else 0
        return stats

    async def handle_stats(self, user, params):
        """
        STATS command implementation.
        Public flags (anyone):
          s: online staff listing
          u: system uptime
        Staff flags (GUIDE+):
          a: online ADMINs
          o: online SYSOPs
          g: online GUIDEs
          i: invisible users count
          k: ACCESS DENY list
          s: services/bots (mode +s)
          z: gagged users
          c: configuration
          d: database info
          l: links (placeholder)
          y: anonymous users count
          x: IRCX users count
          w: authenticated users count
        """
        # Rate limit STATS queries
        if not user.rate_limiter.check('STATS'):
            await user.send(self.get_reply("830", user))
            await user.send(self.get_reply("219", user, flag="*"))
            return
        if not params:
            await user.send(self.get_reply("219", user, flag="*"))
            return

        flag = params[0].lower() if params[0] not in ('?', '*') else params[0]
        is_staff = user.is_staff()

        # STATS ? - Help menu (also shown when no flag provided)
        if flag == '?' or not flag:
            await self.send_server_message(user, "stats_help_header")
            await self.send_server_message(user, "stats_help_general_header")
            await self.send_server_message(user, "stats_help_general_u")
            await self.send_server_message(user, "stats_help_general_s")
            await self.send_server_message(user, "stats_help_general_i")
            await self.send_server_message(user, "stats_help_general_x")
            await self.send_server_message(user, "stats_help_general_w")
            await self.send_server_message(user, "stats_help_general_y")
            await self.send_server_message(user, "stats_help_general_c")
            await self.send_server_message(user, "stats_help_general_f")
            await self.send_server_message(user, "stats_help_general_n")

            # Show guide/staff flags only if user is staff
            if user.is_staff() or user.is_high_staff():
                await self.send_server_message(user, "stats_help_staff_header")
                await self.send_server_message(user, "stats_help_staff_a")
                await self.send_server_message(user, "stats_help_staff_o")
                await self.send_server_message(user, "stats_help_staff_g")
                await self.send_server_message(user, "stats_help_staff_b")
                await self.send_server_message(user, "stats_help_staff_z")

            # Show operator/administrator flags only if user is operator or administrator
            if user.is_high_staff():
                await self.send_server_message(user, "stats_help_oper_header")
                await self.send_server_message(user, "stats_help_oper_d")
                await self.send_server_message(user, "stats_help_oper_k")
                await self.send_server_message(user, "stats_help_oper_l")
                await self.send_server_message(user, "stats_help_oper_m")
                await self.send_server_message(user, "stats_help_oper_p")
                await self.send_server_message(user, "stats_help_oper_t")
                await self.send_server_message(user, "stats_help_oper_v")
                await self.send_server_message(user, "stats_help_oper_star")

            await self.send_server_message(user, "stats_help_footer")
            await user.send(self.get_reply("219", user, flag=flag if flag else '?'))
            return

        # STATS * - All stats combined (Operator+ only)
        if flag == '*':
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="STATS *")))
                await user.send(self.get_reply("219", user, flag=flag))
                return

            await self.send_server_message(user, "stats_all_header")

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            await self.send_server_message(user, "stats_uptime", days=days, hours=hours, mins=mins, secs=secs)

            # User counts - Single iteration for performance
            user_stats = {
                'total': 0, 'invisible': 0, 'ircx': 0, 'auth': 0,
                'anon': 0, 'gagged': 0, 'admins': 0, 'sysops': 0, 'guides': 0
            }

            for u in self.users.values():
                if u.is_virtual:
                    continue

                user_stats['total'] += 1
                if u.has_mode('i'):
                    user_stats['invisible'] += 1
                if u.is_ircx:
                    user_stats['ircx'] += 1
                if u.authenticated:
                    user_stats['auth'] += 1
                if u.username.startswith('~'):
                    user_stats['anon'] += 1
                if u.has_mode('z'):
                    user_stats['gagged'] += 1
                if u.has_mode('a'):
                    user_stats['admins'] += 1
                elif u.has_mode('o'):
                    user_stats['sysops'] += 1
                if u.has_mode('g'):
                    user_stats['guides'] += 1

            await self.send_server_message(user, "stats_users_header")
            await self.send_server_message(user, "stats_users_total", count=user_stats['total'])
            await self.send_server_message(user, "stats_users_invisible", count=user_stats['invisible'])
            await self.send_server_message(user, "stats_users_ircx", count=user_stats['ircx'])
            await self.send_server_message(user, "stats_users_auth", count=user_stats['auth'])
            await self.send_server_message(user, "stats_users_anon", count=user_stats['anon'])
            await self.send_server_message(user, "stats_users_gagged", count=user_stats['gagged'])

            # Staff counts (already collected above)

            await self.send_server_message(user, "stats_staff_header")
            await self.send_server_message(user, "stats_staff_admins", count=user_stats['admins'])
            await self.send_server_message(user, "stats_staff_sysops", count=user_stats['sysops'])
            await self.send_server_message(user, "stats_staff_guides", count=user_stats['guides'])

            # Channel stats - Single iteration for performance
            chan_stats = {'global': 0, 'local': 0, 'registered': 0}
            for c in self.channels.values():
                if c.name.startswith('&'):
                    chan_stats['local'] += 1
                else:
                    chan_stats['global'] += 1
                if c.registered:
                    chan_stats['registered'] += 1

            await self.send_server_message(user, "stats_channels_header")
            await self.send_server_message(user, "stats_channels_global", count=chan_stats['global'])
            await self.send_server_message(user, "stats_channels_local", count=chan_stats['local'])
            await self.send_server_message(user, "stats_channels_registered", count=chan_stats['registered'])

            # Access lists
            deny_count = len(self.access_list['DENY'])
            grant_count = len(self.access_list['GRANT'])

            await self.send_server_message(user, "stats_access_header")
            await self.send_server_message(user, "stats_access_deny", count=deny_count)
            await self.send_server_message(user, "stats_access_grant", count=grant_count)

            # Server stats
            await self.send_server_message(user, "stats_server_header")
            await self.send_server_message(user, "stats_server_commands", count=self.stats.get('commands_processed', 0))
            await self.send_server_message(user, "stats_server_connections", count=self.stats.get('total_connections', 0))
            await self.send_server_message(user, "stats_server_max_users", count=self.max_users_seen)

            # Command usage (all commands)
            if self.stats.get('command_usage'):
                await self.send_server_message(user, "stats_command_header")
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, count in sorted_cmds:
                    await self.send_server_message(user, "stats_command_entry", command=cmd, count=count)

            # Peak usage
            await self.send_server_message(user, "stats_peak_header")
            await self.send_server_message(user, "stats_peak_users", count=self.stats['peak_users'])
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await self.send_server_message(user, "stats_peak_time", time=peak_dt.strftime('%Y-%m-%d %H:%M:%S'))

            # Flood protection
            await self.send_server_message(user, "stats_flood_header")
            await self.send_server_message(user, "stats_flood_events", count=self.stats['flood_events'])
            flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
            flood_window = CONFIG.get('security', 'flood_window', default=2.0)
            await self.send_server_message(user, "stats_flood_threshold", msgs=flood_msgs, window=flood_window)

            # Message statistics
            await self.send_server_message(user, "stats_message_header")
            await self.send_server_message(user, "stats_total_messages", count=self.stats['messages_sent'])
            if self.stats.get('messages_by_channel'):
                await self.send_server_message(user, "stats_active_channels_by_msg")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, cnt in sorted_channels:
                    await self.send_server_message(user, "stats_channel_msg_entry", channel=channel, count=cnt)

            # ServiceBot statistics
            if self.servicebot_enabled:
                await self.send_server_message(user, "stats_servicebot_header")
                await self.send_server_message(user, "stats_active_bots", count=len(self.servicebots))
                if self.stats.get('servicebot_violations'):
                    total_violations = sum(self.stats['servicebot_violations'].values())
                    await self.send_server_message(user, "stats_total_violations", count=total_violations)
                    all_violations = sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True)
                    for vtype, cnt in all_violations:
                        await self.send_server_message(user, "stats_violation_entry", type=vtype, count=cnt)
                if self.stats.get('servicebot_actions'):
                    total_actions = sum(self.stats['servicebot_actions'].values())
                    await self.send_server_message(user, "stats_total_actions", count=total_actions)
                # User bots (+b mode, excluding services)
                bot_users = [u for u in self.users.values() if u.has_mode('b') and not u.has_mode('s')]
                await self.send_server_message(user, "stats_bot_users", count=len(bot_users))

            # Ban statistics
            await self.send_server_message(user, "stats_ban_header")
            await self.send_server_message(user, "stats_access_deny", count=len(self.access_list['DENY']))
            await self.send_server_message(user, "stats_server_bans", count=len(self.server_bans))

            # Database statistics
            await self.send_server_message(user, "stats_database_header")
            try:
                if os.path.exists(self.db_path):
                    size = os.path.getsize(self.db_path)
                    await self.send_server_message(user, "stats_db_path", path=self.db_path)
                    await self.send_server_message(user, "stats_db_size_bytes", size=size, kb=size / 1024)
                    try:
                        stats = await self._get_db_stats()
                        await self.send_server_message(user, "stats_db_nicks", count=stats['nicks'])
                        await self.send_server_message(user, "stats_db_channels", count=stats['channels'])
                        await self.send_server_message(user, "stats_db_messages", count=stats['messages'])
                    except Exception as e:
                        logger.error(get_log_message("database_stats_error", error=e))
                        await self.send_server_message(user, "stats_db_unavailable")
                else:
                    await self.send_server_message(user, "stats_db_not_configured")
            except Exception as e:
                logger.error(get_log_message("stats_error", error=e))
                await self.send_server_message(user, "stats_unavailable")

            # Configuration summary
            await self.send_server_message(user, "stats_config_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)
            dnsbl_status = 'enabled' if CONFIG.get('security', 'dnsbl', 'enabled', default=False) else 'disabled'
            await self.send_server_message(user, "stats_dnsbl", status=dnsbl_status)

            # SSL/TLS status
            if self.ssl_manager:
                ssl_info = self.ssl_manager.get_info()
                await self.send_server_message(user, "stats_ssl_header")
                if ssl_info.get('enabled'):
                    await self.send_server_message(user, "ssl_enabled")
                    if ssl_info.get('context_loaded'):
                        await self.send_server_message(user, "stats_ssl_cert", file=ssl_info.get('cert_file', 'N/A'))
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            status = "OK" if days_left > 14 else ("WARNING" if days_left > 3 else "CRITICAL")
                            await self.send_server_message(user, "stats_ssl_expires", expiry=ssl_info['expiry'], days=days_left, status=status)
                        if ssl_info.get('subject'):
                            await self.send_server_message(user, "stats_ssl_subject", subject=ssl_info['subject'])
                    else:
                        await self.send_server_message(user, "ssl_no_certs")
                else:
                    await self.send_server_message(user, "ssl_disabled")

            # Performance metrics (v2.0.0 optimizations)
            await self.send_server_message(user, "stats_perf_header")
            config_reloads = self.stats.get('config_cache_reloads', 0)
            await self.send_server_message(user, "stats_config_reloads", count=config_reloads)
            await self.send_server_message(user, "stats_channel_monitors", count=len(self.channel_monitors))
            if config_reloads > 0:
                messages_per_reload = self.stats['messages_sent'] // config_reloads if config_reloads else 0
                await self.send_server_message(user, "stats_avg_msg_reload", count=messages_per_reload)

            # Real-time metrics
            await self.send_server_message(user, "stats_realtime_header")
            # Calculate current rates
            if self.stats['commands_per_minute']:
                recent_cmds = list(self.stats['commands_per_minute'])[-5:]  # Last 5 minutes
                avg_cmd_rate = sum(recent_cmds) / len(recent_cmds) if recent_cmds else 0
                await self.send_server_message(user, "stats_cmd_rate_avg", rate=avg_cmd_rate)
                max_cmd_rate = max(self.stats['commands_per_minute']) if self.stats['commands_per_minute'] else 0
                await self.send_server_message(user, "stats_cmd_rate_peak", count=max_cmd_rate)

            # Current load
            current_load_pct = (user_stats['total'] / self.max_users) * 100
            await self.send_server_message(user, "stats_current_load", pct=current_load_pct, current=user_stats['total'], max=self.max_users)

            # Historical trends
            await self.send_server_message(user, "stats_history_header")
            if self.stats.get('busiest_channels'):
                top_channels = sorted(self.stats['busiest_channels'].items(), key=lambda x: x[1], reverse=True)
                await self.send_server_message(user, "stats_busiest_channels")
                for channel, cnt in top_channels:
                    await self.send_server_message(user, "stats_busiest_channel_entry", channel=channel, count=cnt)

            if self.stats.get('most_active_users'):
                top_users = sorted(self.stats['most_active_users'].items(), key=lambda x: x[1], reverse=True)
                await self.send_server_message(user, "stats_most_active_users")
                for username, cnt in top_users:
                    await self.send_server_message(user, "stats_most_active_user_entry", username=username, count=cnt)

            # Distributed/linking stats
            if hasattr(self, 'link_manager') and self.link_manager and self.link_manager.enabled:
                await self.send_server_message(user, "stats_distributed_header")
                server_role = CONFIG.get('linking', 'server_role', default='trunk')
                await self.send_server_message(user, "stats_server_role", role=server_role.upper())
                linked_count = len(self.link_manager.linked_servers)
                await self.send_server_message(user, "stats_linked_servers", count=linked_count)

                if linked_count > 0:
                    await self.send_server_message(user, "stats_connected_servers")
                    for server_name, linked_server in self.link_manager.linked_servers.items():
                        user_count = getattr(linked_server, 'user_count', 0)
                        await self.send_server_message(user, "stats_linked_server_entry", server=server_name, users=user_count)

                # Network divergence/convergence history
                if self.stats['network_divergence_history']:
                    await self.send_server_message(user, "stats_divergence_header", count=len(self.stats['network_divergence_history']))
                    import datetime
                    for timestamp, server, reason in self.stats['network_divergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await self.send_server_message(user, "stats_divergence_entry", server=server, time=dt.strftime('%H:%M:%S'), reason=reason)

                if self.stats['network_convergence_history']:
                    await self.send_server_message(user, "stats_convergence_header", count=len(self.stats['network_convergence_history']))
                    import datetime
                    for timestamp, server in self.stats['network_convergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await self.send_server_message(user, "stats_convergence_entry", server=server, time=dt.strftime('%H:%M:%S'))

            await self.send_server_message(user, "stats_all_footer")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Public stats - available to all users
        if flag == 'u':
            # System uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            await user.send(self.get_reply("242", user, days=days, hours=hours, mins=mins, secs=secs))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Define permission tiers for STATS flags
        # Public: u s i x w y c f n
        GUIDE_FLAGS = {'a', 'o', 'g', 'b', 'z'}
        OPERATOR_FLAGS = {'d', 'k', 'l', 'm', 'p', 't', 'v'}

        # Check permissions based on flag
        is_high_staff = user.is_high_staff()

        if flag in OPERATOR_FLAGS and not is_high_staff:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command=f"STATS {flag}")))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag in GUIDE_FLAGS and not is_staff:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_staff'].format(command=f"STATS {flag}")))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Staff listing - public for everyone (optimized single pass)
        if flag == 's':
            await self.send_server_message(user, "stats_online_staff")
            staff_found = False
            for u in self.users.values():
                if u.is_virtual:
                    continue
                if u.has_mode('a'):
                    await self.send_server_message(user, "stats_staff_admin_entry", nickname=u.nickname)
                    staff_found = True
                elif u.has_mode('o'):
                    await self.send_server_message(user, "stats_staff_oper_entry", nickname=u.nickname)
                    staff_found = True
                elif u.has_mode('g'):
                    await self.send_server_message(user, "stats_staff_guide_entry", nickname=u.nickname)
                    staff_found = True
            if not staff_found:
                await self.send_server_message(user, "stats_no_staff")
            await self.send_server_message(user, "stats_end_staff")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag == 'a':
            # Online IRC administrators
            admins = [u for u in self.users.values() if u.has_mode('a') and not u.is_virtual]
            await self.send_server_message(user, "stats_admins_header", count=len(admins))
            if not admins:
                await self.send_server_message(user, "stats_no_admins")
            else:
                for u in admins:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_admin_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_admins_footer")

        elif flag == 'o':
            # Online IRC operators
            sysops = [u for u in self.users.values() if u.has_mode('o') and not u.has_mode('a') and not u.is_virtual]
            await self.send_server_message(user, "stats_opers_header", count=len(sysops))
            if not sysops:
                await self.send_server_message(user, "stats_no_opers")
            else:
                for u in sysops:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_oper_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_opers_footer")

        elif flag == 'g':
            # Online IRC Guides
            guides = [u for u in self.users.values() if u.has_mode('g') and not u.is_virtual]
            await self.send_server_message(user, "stats_guides_header", count=len(guides))
            if not guides:
                await self.send_server_message(user, "stats_no_guides")
            else:
                for u in guides:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_guide_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_guides_footer")

        elif flag == 'i':
            # Invisible users count
            count = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
            await self.send_server_message(user, "stats_invisible_count", count=count)

        elif flag == 'k':
            # Ban statistics - ACCESS DENY + server bans
            await self.send_server_message(user, "stats_ban_header")

            # ACCESS DENY list
            await self.send_server_message(user, "stats_access_deny_entries", count=len(self.access_list['DENY']))
            if self.access_list['DENY']:
                for pattern, set_by, set_at, reason in self.access_list['DENY']:
                    reason_str = f" :{reason}" if reason else ""
                    await self.send_server_message(user, "stats_access_deny_entry", pattern=pattern, by=set_by, reason=reason_str)

            # Server bans
            await self.send_server_message(user, "stats_server_bans_count", count=len(self.server_bans))
            if self.server_bans:
                for ip, (expires_at, reason, set_by) in list(self.server_bans.items()):
                    if expires_at == 0:
                        duration = "permanent"
                    else:
                        remaining = expires_at - int(time.time())
                        if remaining > 0:
                            duration = f"{remaining}s remaining"
                        else:
                            duration = "expired"
                    await self.send_server_message(user, "stats_server_ban_entry", ip=ip, duration=duration, by=set_by)

            await self.send_server_message(user, "stats_end")

        elif flag == 's':
            # Services/bots (users with +s mode) - includes virtual services
            await self.send_server_message(user, "stats_services_bots_header")
            for u in self.users.values():
                if u.is_service():
                    await self.send_server_message(user, "stats_service_entry", prefix=f"{u.nickname}!{u.username}@{u.host}")
            await self.send_server_message(user, "stats_end")

        elif flag == 'z':
            # Gagged users
            await self.send_server_message(user, "stats_gagged_header")
            for u in self.users.values():
                if u.has_mode('z') and not u.is_virtual:
                    await self.send_server_message(user, "stats_gagged_entry", prefix=f"{u.nickname}!{u.username}@{u.host}")
            await self.send_server_message(user, "stats_end")

        elif flag == 'c':
            # Configuration
            await self.send_server_message(user, "stats_config_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)
            await self.send_server_message(user, "stats_max_users", count=self.max_users)
            await self.send_server_message(user, "stats_user_modes", modes=CONFIG.get('modes', 'user', default='agiorsxz'))
            await self.send_server_message(user, "stats_chan_modes", modes=CONFIG.get('modes', 'channel', default='adefghijklmnprstuwxyz'))
            await self.send_server_message(user, "stats_flood_enabled", status=CONFIG.get('security', 'enable_flood_protection', default=True))
            await self.send_server_message(user, "stats_end")

        elif flag == 'd':
            # Database statistics
            await self.send_server_message(user, "stats_database_header")
            await self.send_server_message(user, "stats_db_path", path=self.db_path)
            try:
                db_path = self.db_path
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    await self.send_server_message(user, "stats_db_size_bytes", size=size, kb=size / 1024)

                    try:
                        stats = await self._get_db_stats()
                        await self.send_server_message(user, "stats_db_nicks", count=stats['nicks'])
                        await self.send_server_message(user, "stats_db_channels", count=stats['channels'])
                        await self.send_server_message(user, "stats_db_messages", count=stats['messages'])
                        # News items (not in common stats)
                        async with self.db_pool.connection() as db:
                            async with db.execute("SELECT COUNT(*) FROM newsflash WHERE active = 1") as cursor:
                                row = await cursor.fetchone()
                                await self.send_server_message(user, "stats_db_news", count=row[0])
                    except Exception as e:
                        logger.error(get_log_message("newsflash_stats_error", error=e))
                        await self.send_server_message(user, "stats_news_unavailable")
                else:
                    await self.send_server_message(user, "stats_db_not_configured")
            except Exception as e:
                logger.error(get_log_message("newsflash_error", error=e))
                await self.send_server_message(user, "stats_news_temp_unavailable")
            await self.send_server_message(user, "stats_end")

        elif flag == 'l':
            # Server linking statistics
            await self.send_server_message(user, "stats_linking_header")
            linking_enabled = CONFIG.get('linking', 'enabled', default=False)
            await self.send_server_message(user, "stats_linking_enabled", status='enabled' if linking_enabled else 'disabled')
            if linking_enabled:
                bind_host = CONFIG.get('linking', 'bind_host', default='0.0.0.0')
                bind_port = CONFIG.get('linking', 'bind_port', default=7001)
                await self.send_server_message(user, "stats_linking_bind", host=bind_host, port=bind_port)
                links = CONFIG.get('linking', 'links', default=[])
                await self.send_server_message(user, "stats_linking_configured", count=len(links))
                if links:
                    for link in links:
                        await self.send_server_message(user, "stats_linking_name", name=link.get('name', 'unknown'))
                else:
                    await self.send_server_message(user, "stats_linking_none")
            await self.send_server_message(user, "stats_end")

        elif flag == 'y':
            # Anonymous users count (users with ~ prefix, not authenticated)
            count = sum(1 for u in self.users.values() if u.username.startswith('~') and not u.is_virtual)
            await self.send_server_message(user, "stats_anonymous_count", count=count)

        elif flag == 'x':
            # IRCX users count
            count = sum(1 for u in self.users.values() if u.is_ircx and not u.is_virtual)
            await self.send_server_message(user, "stats_ircx_count", count=count)

        elif flag == 'w':
            # Authenticated users count
            count = sum(1 for u in self.users.values() if u.authenticated and not u.is_virtual)
            await self.send_server_message(user, "stats_auth_count", count=count)

        elif flag == 't':
            # SSL/TLS status
            await self.send_server_message(user, "stats_ssl_header")
            if self.ssl_manager:
                ssl_info = self.ssl_manager.get_info()
                if ssl_info.get('enabled'):
                    await self.send_server_message(user, "ssl_enabled")
                    if ssl_info.get('context_loaded'):
                        await self.send_server_message(user, "stats_ssl_cert", file=ssl_info.get('cert_file', 'N/A'))
                        await self.send_server_message(user, "stats_ssl_key", file=ssl_info.get('key_file', 'N/A'))
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            if days_left <= 0:
                                status = "EXPIRED"
                            elif days_left <= 3:
                                status = "CRITICAL"
                            elif days_left <= 14:
                                status = "WARNING"
                            else:
                                status = "OK"
                            await self.send_server_message(user, "stats_ssl_expires", expiry=ssl_info['expiry'], days=days_left, status=status)
                        if ssl_info.get('subject'):
                            await self.send_server_message(user, "stats_ssl_subject", subject=ssl_info['subject'])
                        min_ver = CONFIG.get('ssl', 'min_version', default='TLSv1.2')
                        await self.send_server_message(user, "stats_ssl_min_tls", version=min_ver)
                        ssl_ports = CONFIG.get('ssl', 'ports', default=[6697])
                        await self.send_server_message(user, "stats_ssl_ports", ports=', '.join(map(str, ssl_ports)))
                    else:
                        await self.send_server_message(user, "ssl_no_certs")
                else:
                    await self.send_server_message(user, "ssl_disabled")
            else:
                await self.send_server_message(user, "stats_ssl_not_init")
            await self.send_server_message(user, "stats_end")

        elif flag == 'p':
            # Peak usage statistics
            await self.send_server_message(user, "stats_peak_header")
            await self.send_server_message(user, "stats_peak_users", count=self.stats['peak_users'])
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await self.send_server_message(user, "stats_peak_time", time=peak_dt.strftime('%Y-%m-%d %H:%M:%S'))
            await self.send_server_message(user, "stats_peak_current", count=sum(1 for u in self.users.values() if not u.is_virtual))
            await self.send_server_message(user, "stats_peak_max", count=self.max_users_seen)
            await self.send_server_message(user, "stats_end")

        elif flag == 'f':
            # Flood protection statistics
            await self.send_server_message(user, "stats_flood_header")
            flood_enabled = CONFIG.get('security', 'enable_flood_protection', default=True)
            await self.send_server_message(user, "stats_flood_status", status=flood_enabled)
            if flood_enabled:
                flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
                flood_window = CONFIG.get('security', 'flood_window', default=2.0)
                await self.send_server_message(user, "stats_flood_config", msgs=flood_msgs, window=flood_window)
                await self.send_server_message(user, "stats_flood_total", count=self.stats['flood_events'])
            await self.send_server_message(user, "stats_end")

        elif flag == 'm':
            # Message statistics
            await self.send_server_message(user, "stats_message_header")
            await self.send_server_message(user, "stats_total_messages", count=self.stats['messages_sent'])

            # Most active channels (all)
            if self.stats['messages_by_channel']:
                await self.send_server_message(user, "stats_most_active_channels")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, cnt in sorted_channels:
                    await self.send_server_message(user, "stats_active_channel_entry", channel=channel, count=cnt)
            else:
                await self.send_server_message(user, "stats_no_message_data")

            # Current channels
            total_channels = len([c for c in self.channels.values() if not c.name.startswith('&')])
            await self.send_server_message(user, "stats_active_channels", count=total_channels)
            await self.send_server_message(user, "stats_end")

        elif flag == 'b':
            # ServiceBot statistics
            await self.send_server_message(user, "stats_servicebot_header")
            await self.send_server_message(user, "stats_servicebots_enabled", status=self.servicebot_enabled)

            if self.servicebot_enabled:
                await self.send_server_message(user, "stats_active_bots", count=len(self.servicebots))

                # Violations
                if self.stats['servicebot_violations']:
                    await self.send_server_message(user, "stats_violations_detected")
                    for violation_type, cnt in sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True):
                        await self.send_server_message(user, "stats_violation_entry", type=violation_type, count=cnt)
                else:
                    await self.send_server_message(user, "stats_no_violations")

                # Actions taken
                if self.stats['servicebot_actions']:
                    await self.send_server_message(user, "stats_actions_taken")
                    for action, cnt in sorted(self.stats['servicebot_actions'].items(), key=lambda x: x[1], reverse=True):
                        await self.send_server_message(user, "stats_action_entry", action=action, count=cnt)

                # Configuration
                profanity_enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
                malicious_enabled = CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False)
                await self.send_server_message(user, "stats_profanity_status", status='enabled' if profanity_enabled else 'disabled')
                await self.send_server_message(user, "stats_malicious_status", status='enabled' if malicious_enabled else 'disabled')

            await self.send_server_message(user, "stats_end")

        elif flag == 'n':
            # Network statistics
            await self.send_server_message(user, "stats_network_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)

            # Totals
            total_users = sum(1 for u in self.users.values() if not u.is_virtual)
            total_channels = len(self.channels)
            await self.send_server_message(user, "stats_users_count", count=total_users)
            await self.send_server_message(user, "stats_channels_count", count=total_channels)
            await self.send_server_message(user, "stats_services_count", count=sum(1 for u in self.users.values() if u.is_virtual))

            # Server version
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            await self.send_server_message(user, "stats_uptime_short", days=days, hours=hours, mins=mins)

            await self.send_server_message(user, "stats_end")

        elif flag == 'v':
            # Command usage statistics (Operator+)
            await self.send_server_message(user, "stats_command_usage_header")
            if self.stats['command_usage']:
                # Sort by usage count (descending)
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, cnt in sorted_cmds:
                    await self.send_server_message(user, "stats_command_usage_entry", command=cmd, count=cnt)
                await self.send_server_message(user, "stats_total_commands", count=self.stats['commands_processed'])
            else:
                await self.send_server_message(user, "stats_no_command_data")
            await self.send_server_message(user, "stats_end")

        else:
            await self.send_server_message(user, "stats_unknown_flag", flag=flag)

        await user.send(self.get_reply("219", user, flag=flag))

    async def handle_config(self, user, params):
        """
        CONFIG command - In-band configuration management for administrators.

        Subcommands:
          CONFIG LIST [section]     - List all config or a specific section (SYSOP+)
          CONFIG GET <section.key>  - Get a specific value (SYSOP+)
          CONFIG SET <section.key> <value> - Set a value (ADMIN only)
          CONFIG SAVE               - Save config to disk (ADMIN only)
          CONFIG RELOAD             - Reload config from disk (ADMIN only)
        """
        is_admin = user.has_mode('a')
        is_sysop = user.has_mode('o')

        if not is_admin and not is_sysop:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG")))
            return

        if not params:
            await user.send(self.get_reply("461", user, command="CONFIG"))
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List configuration - SYSOP+ can view
            section = params[1].lower() if len(params) > 1 else None

            if section:
                # List specific section
                sect_data = CONFIG.get_section(section)
                if not sect_data:
                    await self.send_server_message(user, "config_section_unknown", section=section)
                    return
                await user.send(self.get_reply("940", user, section=section))
                for key, value in sect_data.items():
                    await user.send(self.get_reply("941", user, key=f"{section}.{key}", value=json.dumps(value)))
                await user.send(self.get_reply("943", user))
            else:
                # List all sections
                await user.send(self.get_reply("940", user, section="All"))
                for section in CONFIG.get_all_sections():
                    sect_data = CONFIG.get_section(section)
                    await user.send(self.get_reply("942", user, section=section, count=len(sect_data)))
                await user.send(self.get_reply("943", user))

        elif subcmd == "GET":
            # Get specific value - SYSOP+ can view
            if len(params) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_config_get']))
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            value = CONFIG.get(*path)
            if value is None:
                await user.send(self.get_reply("892", user, key=params[1]))
            else:
                await user.send(self.get_reply("890", user, key=params[1], value=json.dumps(value)))

        elif subcmd == "SET":
            # Set value - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG SET")))
                return

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_config_set']))
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            # Parse value - try JSON first, then string
            raw_value = ' '.join(params[2:])

            # Size limit to prevent DoS via large JSON
            if len(raw_value) > 10000:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['config_value_too_large'].format(max_size="10KB")))
                return

            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                # Treat as string if not valid JSON
                value = raw_value

            if CONFIG.set(*path, value=value):
                await user.send(self.get_reply("891", user, key=params[1], value=json.dumps(value)))
                logger.info(get_log_message("config_set_log", nickname=user.nickname, key=params[1], value=json.dumps(value)))
            else:
                await user.send(self.get_reply("893", user))

        elif subcmd == "SAVE":
            # Save to disk - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG SAVE")))
                return

            CONFIG.save()
            await user.send(self.get_reply("382", user, config_file=CONFIG.config_file, message="Configuration saved"))
            logger.info(get_log_message("config_saved_log", nickname=user.nickname))

        elif subcmd == "RELOAD":
            # Reload from disk - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG RELOAD")))
                return

            CONFIG.load()
            await user.send(self.get_reply("382", user, config_file=CONFIG.config_file, message="Configuration reloaded"))
            await self.send_server_message(user, "config_restart_note")
            logger.info(get_log_message("config_reloaded_log", nickname=user.nickname))

        else:
            await self.send_server_message(user, "config_subcmd_unknown", subcmd=subcmd)
            await user.send(self.get_reply("461", user, command="CONFIG"))

    async def handle_staff(self, user, params):
        """
        STAFF command - In-band staff account management.

        Staff accounts are associated with usernames (USER ident), not nicknames.
        Authentication happens via PASS username:password before USER command.

        Subcommands:
          STAFF LIST                          - List all staff accounts (SYSOP+)
          STAFF ADD <username> <password> <level> - Add staff account (ADMIN only)
          STAFF DELETE <username>             - Remove staff account (ADMIN only)
          STAFF SET <username> <level>        - Change staff level (ADMIN only)
          STAFF PASS <username> <newpass>     - Change password (ADMIN, or self)

        Levels: ADMIN, SYSOP, GUIDE
        """
        is_admin = user.has_mode('a')
        is_sysop = user.has_mode('o')

        if not is_admin and not is_sysop:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF")))
            return

        if not params:
            await self.send_server_message(user, "staff_subcommands")
            await self.send_server_message(user, "staff_levels")
            return

        subcmd = params[0].upper()

        if subcmd in ("LIST", "L"):
            # List all staff accounts - SYSOP+ can view
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} LIST")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT username, level FROM users ORDER BY level, username") as cursor:
                        rows = await cursor.fetchall()

                await user.send(self.get_reply("930", user, count=len(rows)))
                if not rows:
                    await self.send_notice(user, "staff_list_none")
                else:
                    # Build online staff map in single pass (performance optimization)
                    online_staff = {}
                    for u in self.users.values():
                        username = u.username.lstrip('~')
                        if u.has_mode('a'):
                            online_staff[username] = 'ADMIN'
                        elif u.has_mode('o'):
                            online_staff[username] = 'SYSOP'
                        elif u.has_mode('g'):
                            online_staff[username] = 'GUIDE'

                    # Group by level
                    admins = [r[0] for r in rows if r[1] == 'ADMIN']
                    sysops = [r[0] for r in rows if r[1] == 'SYSOP']
                    guides = [r[0] for r in rows if r[1] == 'GUIDE']

                    if admins:
                        await user.send(self.get_reply("931", user, level="ADMIN", count=len(admins)))
                        for admin in admins:
                            status = " [ONLINE]" if admin in online_staff and online_staff[admin] == 'ADMIN' else ""
                            await user.send(self.get_reply("932", user, username=admin, status=status))
                    if sysops:
                        await user.send(self.get_reply("931", user, level="SYSOP", count=len(sysops)))
                        for sysop in sysops:
                            status = " [ONLINE]" if sysop in online_staff and online_staff[sysop] == 'SYSOP' else ""
                            await user.send(self.get_reply("932", user, username=sysop, status=status))
                    if guides:
                        await user.send(self.get_reply("931", user, level="GUIDE", count=len(guides)))
                        for guide in guides:
                            status = " [ONLINE]" if guide in online_staff and online_staff[guide] == 'GUIDE' else ""
                            await user.send(self.get_reply("932", user, username=guide, status=status))

                await user.send(self.get_reply("933", user))
            except Exception as e:
                logger.error(get_log_message("staff_list_error", error=e))
                await user.send(self.get_reply("884", user))

        elif subcmd in ("ADD", "A"):
            # Add staff account - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF ADD")))
                return

            if len(params) < 4:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_add']))
                await self.send_notice(user, "staff_levels_hint")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} ADD {params[1]} {params[2]} {params[3]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]
            password = params[2]
            level = params[3].upper()

            if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await user.send(self.get_reply("862", user, levels=SERVER_MESSAGES['valid_staff_levels']))
                return

            if len(password) < 6:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['staff_password_min']))
                return

            # Validate username
            valid, error = validate_username(username)
            if not valid:
                await user.send(self.get_reply("863", user, error=error))
                return

            try:
                async with self.db_pool.connection() as db:
                    # Check if already exists
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if await cursor.fetchone():
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['already_exists_account'].format(username=username)))
                            return

                    # Hash password and insert
                    password_hash = await hash_password_async(password)
                    await db.execute("INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                                    (username, password_hash, level))
                    await db.commit()

                await user.send(self.get_reply("880", user, username=username, level=level))
                logger.info(get_log_message("staff_added", nickname=user.nickname, username=username, level=level))
                await self.log_staff(user.nickname, "STAFF ADD", username, get_log_message("audit_staff_add_level", level=level))

            except Exception as e:
                logger.error(get_log_message("staff_add_error", error=e))
                await user.send(self.get_reply("885", user))

        elif subcmd in ("DELETE", "DEL", "D"):
            # Remove staff account - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF DELETE")))
                return

            if len(params) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_delete']))
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} REMOVE {params[1]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]

            # Prevent self-deletion
            if username.lower() == user.username.lower().lstrip('~'):
                await user.send(self.get_reply("858", user))
                return

            try:
                async with self.db_pool.connection() as db:
                    # Check if exists
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return
                        old_level = row[0]

                    await db.execute("DELETE FROM users WHERE username = ?", (username,))
                    await db.commit()

                await user.send(self.get_reply("881", user, username=username))
                logger.info(get_log_message("staff_deleted", nickname=user.nickname, username=username, level=old_level))
                await self.log_staff(user.nickname, "STAFF DELETE", username, get_log_message("audit_staff_delete_level", old_level=old_level))

            except Exception as e:
                logger.error(get_log_message("staff_del_error", error=e))
                await user.send(self.get_reply("886", user))

        elif subcmd in ("SET", "S"):
            # Change staff level - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF SET")))
                return

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_set']))
                await self.send_notice(user, "staff_levels_hint")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} LEVEL {params[1]} {params[2]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]
            new_level = params[2].upper()

            if new_level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await user.send(self.get_reply("862", user, levels=SERVER_MESSAGES['valid_staff_levels']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return
                        old_level = row[0]

                    if old_level == new_level:
                        await self.send_server_message(user, "staff_already_level", username=username, level=new_level)
                        return

                    await db.execute("UPDATE users SET level = ? WHERE username = ?", (new_level, username))
                    await db.commit()

                await user.send(self.get_reply("882", user, username=username, level=new_level))
                logger.info(get_log_message("staff_level_changed", nickname=user.nickname, username=username, old_level=old_level, new_level=new_level))
                await self.log_staff(user.nickname, "STAFF SET", username, get_log_message("audit_staff_level_change", old_level=old_level, new_level=new_level))

            except Exception as e:
                logger.error(get_log_message("staff_set_error", error=e))
                await user.send(self.get_reply("887", user))

        elif subcmd in ("PASS", "P"):
            # Change staff password - ADMIN or self
            # Syntax: STAFF PASS <username> <oldpassword> <newpassword> (for own password)
            #         STAFF PASS <username> <newpassword> (ADMIN changing others - less secure, local only)

            own_username = user.username.lstrip('~')

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                await self.send_server_message(user, "staff_pass_old_required")
                await self.send_server_message(user, "staff_pass_admin_hint")
                return

            username = params[1]
            is_self = username.lower() == own_username.lower()

            # Determine if 2 or 3 parameter format
            if len(params) == 4:
                # STAFF PASS <username> <oldpass> <newpass> - secure format
                old_password = params[2]
                new_password = params[3]

                # Check if branch in centralized mode - proxy to trunk
                if not self.is_services_hub and \
                   self.services_mode == 'centralized':
                    if self.link_manager and self.link_manager.servers:
                        trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                        if trunk_server:
                            await trunk_server.send(f"STAFFCMD {user.nickname} PASSWORD {old_password} {new_password}")
                            await self.send_server_message(user, "staff_pass_forwarded")
                            return
                    await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                    return

            elif len(params) == 3:
                # STAFF PASS <username> <newpass> - ADMIN-only shorthand (trunk only)
                if not is_admin:
                    await self.send_server_message(user, "staff_pass_old_required")
                    await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                    return

                if not self.is_services_hub:
                    await self.send_server_message(user, "trunk_only_format")
                    await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                    return

                new_password = params[2]
                old_password = None  # Admin override, no validation
            else:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                return

            # Check permissions
            if not is_admin and not is_self:
                await self.send_server_message(user, "staff_pass_self_only")
                return

            if len(new_password) < 6:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['staff_password_min']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if not await cursor.fetchone():
                            await user.send(self.get_reply("889", user, username=username))
                            return

                    password_hash = await hash_password_async(new_password)
                    await db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                    (password_hash, username))
                    await db.commit()

                await user.send(self.get_reply("883", user, message=f"The password was changed for staff account {username}"))
                logger.info(get_log_message("staff_password_changed", nickname=user.nickname, username=username))
                if not is_self:
                    await self.log_staff(user.nickname, "STAFF PASS", username, get_log_message("audit_staff_pass_changed"))

            except Exception as e:
                logger.error(get_log_message("staff_pass_error", error=e))
                await user.send(self.get_reply("888", user))


        elif subcmd in ("MFA", "M"):
            # Manage MFA for staff accounts (ADMIN only)
            # Syntax: STAFF MFA <username> ENABLE <code>   - Enable MFA with verified code
            #         STAFF MFA <username> DISABLE <code>  - Disable MFA with verified code
            #         STAFF MFA <username> STATUS          - Show MFA status

            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF MFA")))
                await self.send_server_message(user, "staff_mfa_own_hint")
                return

            if len(params) < 3:
                await self.send_server_message(user, "staff_mfa_usage")
                return

            username = params[1]
            mfa_action = params[2].upper()

            try:
                async with self.db_pool.connection() as db:
                    # Check if user exists
                    async with db.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE username = ?",
                                         (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return

                        mfa_enabled, mfa_secret = row

                    if mfa_action == "STATUS":
                        # Show MFA status
                        status = "enabled" if mfa_enabled else ("setup pending" if mfa_secret else "disabled")
                        await self.send_server_message(user, "staff_mfa_status", username=username, status=status)
                        if mfa_secret and not mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_secret_pending")
                        logger.info(get_log_message("staff_mfa_checked", nickname=user.nickname, username=username))

                    elif mfa_action == "ENABLE":
                        # Enable MFA with code verification
                        if len(params) < 4:
                            await self.send_server_message(user, "staff_mfa_enable_usage", username=username)
                            await self.send_server_message(user, "staff_mfa_user_needs_secret")
                            return

                        code = params[3]

                        if mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_already_enabled", username=username)
                            return

                        if not mfa_secret:
                            await self.send_server_message(user, "staff_mfa_user_enable_first", username=username)
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await self.send_server_message(user, "staff_mfa_invalid_code_for_user", username=username)
                            logger.warning(get_log_message("staff_mfa_enable_failed", nickname=user.nickname, username=username))
                            return

                        # Enable MFA!
                        await db.execute("UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await self.send_server_message(user, "staff_mfa_enabled_for_user", username=username)
                        logger.info(get_log_message("staff_mfa_enabled", nickname=user.nickname, username=username))
                        await self.log_staff(user.nickname, "STAFF MFA ENABLE", username, get_log_message("audit_staff_mfa_enabled"))

                    elif mfa_action == "DISABLE":
                        # Disable MFA with code verification
                        if len(params) < 4:
                            await self.send_server_message(user, "staff_mfa_disable_usage", username=username)
                            await self.send_server_message(user, "staff_mfa_disable_code_required")
                            return

                        code = params[3]

                        if not mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_not_enabled", username=username)
                            return

                        if not mfa_secret:
                            await self.send_server_message(user, "staff_mfa_config_error_for_user", username=username)
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await self.send_server_message(user, "staff_mfa_invalid_code_for_user", username=username)
                            logger.warning(get_log_message("staff_mfa_disable_failed", nickname=user.nickname, username=username))
                            return

                        # Disable MFA
                        await db.execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await self.send_server_message(user, "staff_mfa_disabled_for_user", username=username)
                        logger.info(get_log_message("staff_mfa_disabled", nickname=user.nickname, username=username))
                        await self.log_staff(user.nickname, "STAFF MFA DISABLE", username, get_log_message("audit_staff_mfa_disabled"))

                    else:
                        await self.send_server_message(user, "staff_mfa_invalid_action", action=mfa_action)
                        await self.send_server_message(user, "staff_mfa_available_actions")

            except Exception as e:
                logger.error(get_log_message("staff_mfa_error", error=e))
                await self.send_server_message(user, "staff_mfa_op_failed")
        else:
            await self.send_server_message(user, "staff_unknown_subcommand", subcmd=subcmd)
            await self.send_server_message(user, "staff_subcommands")

    async def handle_profanity(self, user, params):
        """
        PROFANITY command - Manage profanity filter (ADMIN only).

        Subcommands:
          PROFANITY LIST                    - Show current words and patterns
          PROFANITY ADD WORD <word>         - Add a word to filter
          PROFANITY ADD PATTERN <pattern>   - Add a regex pattern
          PROFANITY DELETE WORD <word>      - Remove a word
          PROFANITY DELETE PATTERN <pattern> - Remove a pattern
          PROFANITY ENABLE                  - Enable profanity filter
          PROFANITY DISABLE                 - Disable profanity filter
          PROFANITY TEST <text>             - Test if text would be caught
        """
        if not user.is_high_staff():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="PROFANITY")))
            return

        if not params:
            await self.send_server_message(user, "profanity_subcommands")
            await self.send_server_message(user, "profanity_examples")
            return

        subcmd = params[0].upper()

        if subcmd in ("LIST", "L"):
            # Show current filter configuration
            enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
            words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
            patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
            case_sensitive = CONFIG.get('servicebot', 'profanity_filter', 'case_sensitive', default=False)
            action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')

            await self.send_server_message(user, "profanity_header")
            await self.send_server_message(user, "profanity_status", status='Enabled' if enabled else 'Disabled')
            await self.send_server_message(user, "profanity_action", action=action)
            await self.send_server_message(user, "profanity_case", status='Yes' if case_sensitive else 'No')
            await self.send_server_message(user, "profanity_blank_line")

            if words:
                await self.send_server_message(user, "profanity_words_header", count=len(words))
                for word in words:
                    await self.send_server_message(user, "profanity_word_entry", word=word)
            else:
                await self.send_server_message(user, "profanity_words_none")

            await self.send_server_message(user, "profanity_blank_line")

            if patterns:
                await self.send_server_message(user, "profanity_patterns_header", count=len(patterns))
                for pattern in patterns:
                    await self.send_server_message(user, "profanity_pattern_entry", pattern=pattern)
            else:
                await self.send_server_message(user, "profanity_patterns_none")

        elif subcmd in ("ADD", "A"):
            if len(params) < 3:
                await self.send_server_message(user, "profanity_add_usage")
                return

            add_type = params[1].upper()
            value = ' '.join(params[2:])

            if add_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value in current_words:
                    await self.send_server_message(user, "profanity_word_exists", word=value)
                    return
                current_words.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_word_added", word=value)
                logger.info(get_log_message("profanity_word_added_log", nickname=user.nickname, word=value))

            elif add_type == "PATTERN":
                # Validate regex with ReDoS protection
                valid, error = validate_regex_pattern(value)
                if not valid:
                    await self.send_raw_notice(user, error)
                    return

                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value in current_patterns:
                    await self.send_server_message(user, "profanity_pattern_exists", pattern=value)
                    return
                current_patterns.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_pattern_added", pattern=value)
                logger.info(get_log_message("profanity_pattern_added_log", nickname=user.nickname, pattern=value))

            else:
                await self.send_server_message(user, "profanity_type_unknown", type=add_type)

        elif subcmd in ("DELETE", "DEL", "D"):
            if len(params) < 3:
                await self.send_server_message(user, "profanity_del_usage")
                return

            del_type = params[1].upper()
            value = ' '.join(params[2:])

            if del_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value not in current_words:
                    await self.send_server_message(user, "profanity_word_not_found", word=value)
                    return
                current_words.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_word_removed", word=value)
                logger.info(get_log_message("profanity_word_removed_log", nickname=user.nickname, word=value))

            elif del_type == "PATTERN":
                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value not in current_patterns:
                    await self.send_server_message(user, "profanity_pattern_not_found", pattern=value)
                    return
                current_patterns.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_pattern_removed", pattern=value)
                logger.info(get_log_message("profanity_pattern_removed_log", nickname=user.nickname, pattern=value))

            else:
                await self.send_server_message(user, "profanity_type_unknown", type=del_type)

        elif subcmd in ("ENABLE", "E"):
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', True)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await self.send_server_message(user, "profanity_enabled")
            logger.info(get_log_message("profanity_enabled_log", nickname=user.nickname))

        elif subcmd == "DISABLE":
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', False)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await self.send_server_message(user, "profanity_disabled")
            logger.info(get_log_message("profanity_disabled_log", nickname=user.nickname))

        elif subcmd in ("TEST", "T"):
            if len(params) < 2:
                await self.send_server_message(user, "profanity_test_usage")
                return

            test_text = ' '.join(params[1:])
            monitor = ServiceBotMonitor()
            has_profanity, matched = monitor.check_profanity(test_text)

            if has_profanity:
                await self.send_server_message(user, "profanity_test_would_catch", matched=matched)
            else:
                await self.send_server_message(user, "profanity_test_clean")

        else:
            await self.send_server_message(user, "profanity_unknown_subcommand", subcmd=subcmd)
            await self.send_server_message(user, "profanity_available_subcommands")
