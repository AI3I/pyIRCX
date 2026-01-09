/*
 * pyIRCX Cockpit Module - Comprehensive Management Interface
 * No jQuery - Vanilla JavaScript only
 */

(function() {
    "use strict";

    const cockpit = window.cockpit;
    const currentUser = {name: 'admin'};

    // Helper functions
    function $(sel) { return document.querySelector(sel); }
    function $$(sel) { return document.querySelectorAll(sel); }

    function escapeHtml(unsafe) {
        return (unsafe || '').toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Toast notification system
    function showToast(title, message, type = 'info') {
        const container = $('#toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <div class="toast-title">${escapeHtml(title)}</div>
                <div class="toast-message">${escapeHtml(message)}</div>
            </div>
            <div class="toast-close">×</div>
        `;

        container.appendChild(toast);

        // Close button
        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        });

        // Auto dismiss after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    }

    function formatTimestamp(ts) {
        if (!ts) return 'Never';
        return new Date(ts * 1000).toLocaleString();
    }

    function timeAgo(ts) {
        if (!ts) return 'Never';
        const sec = Math.floor(Date.now() / 1000 - ts);
        if (sec < 60) return `${sec}s ago`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
        if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
        return `${Math.floor(sec / 86400)}d ago`;
    }

    function formatUptime(sec) {
        const d = Math.floor(sec / 86400);
        const h = Math.floor((sec % 86400) / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const parts = [];
        if (d > 0) parts.push(`${d}d`);
        if (h > 0) parts.push(`${h}h`);
        if (m > 0) parts.push(`${m}m`);
        return parts.join(' ') || '< 1m';
    }

    // API wrapper
    function callAPI(cmd, args = []) {
        // Use system-wide installation path
        const fullArgs = ['python3', '/usr/share/cockpit/pyircx/api.py', cmd].concat(args);
        return cockpit.spawn(fullArgs, { err: 'message', superuser: 'try' })
            .then(out => JSON.parse(out))
            .catch(err => ({ error: err.message || 'Unknown error' }));
    }

    // Service control
    function controlService(action) {
        const actionLabels = {
            start: '▶️ Starting',
            stop: '⏹️ Stopping',
            restart: '🔄 Restarting'
        };

        showToast('Service Control', `${actionLabels[action]} pyIRCX service...`, 'info');

        cockpit.spawn(['sudo', 'systemctl', action, 'pyircx.service'], { err: 'message', superuser: 'try' })
            .then(() => {
                showToast('Success', `Service ${action}ed successfully`, 'success');
                setTimeout(() => {
                    loadServiceStatus();
                    loadRealtimeStatus();
                    loadAll();
                }, 1000);
            })
            .catch(err => showToast('Error', `Failed to ${action}: ${err.message}`, 'error'));
    }

    // Load functions
    function loadServiceStatus() {
        cockpit.spawn(['systemctl', 'is-active', 'pyircx.service'], { err: 'ignore', superuser: 'try' })
            .then(out => {
                const status = out.trim();
                let html, dotClass;

                if (status === 'active') {
                    html = '<span class="label label-success"><span class="status-dot green"></span>Running</span>';
                } else if (status === 'inactive') {
                    html = '<span class="label label-default"><span class="status-dot yellow"></span>Stopped</span>';
                } else if (status === 'failed') {
                    html = '<span class="label label-danger"><span class="status-dot red"></span>Failed</span>';
                } else {
                    html = '<span class="label label-warning"><span class="status-dot yellow"></span>Unknown</span>';
                }

                $('#service-status').innerHTML = html;
            })
            .catch(() => {
                $('#service-status').innerHTML = '<span class="label label-warning"><span class="status-dot red"></span>Service not found or no permission</span>';
            });
    }

    function loadRealtimeStatus() {
        callAPI('realtime-status').then(data => {
            if (data.error) {
                $('#realtime-status').innerHTML = `<div class="alert alert-warning">${escapeHtml(data.error)}</div>`;
                $('#connected-users').innerHTML = '<div class="empty-state"><div class="empty-state-icon">💤</div><div class="empty-state-text">Server Not Running</div><div class="empty-state-subtext">Start the service to see connected users</div></div>';
                $('#active-channels').innerHTML = '<div class="empty-state"><div class="empty-state-icon">💤</div><div class="empty-state-text">Server Not Running</div><div class="empty-state-subtext">Start the service to see active channels</div></div>';
                $('#connected-count').textContent = '0';
                $('#channel-count').textContent = '0';
                $('#stat-users').textContent = '0';
                $('#stat-channels').textContent = '0';
                return;
            }

            const age = data.status_age || 0;
            const color = age < 30 ? 'success' : (age < 60 ? 'warning' : 'danger');
            $('#realtime-status').innerHTML = `<p>Last updated: <span class="label label-${color}">${Math.floor(age)}s ago</span></p>`;

            const users = data.connected_users || [];
            $('#connected-count').textContent = users.length;
            $('#stat-users').textContent = users.length;

            if (users.length === 0) {
                $('#connected-users').innerHTML = '<div class="empty-state"><div class="empty-state-icon">👤</div><div class="empty-state-text">No Users Connected</div><div class="empty-state-subtext">Waiting for users to join</div></div>';
            } else {
                let html = '<table class="table table-striped table-bordered table-condensed">';
                html += '<thead><tr><th>Nick</th><th>Host</th><th>Connected</th><th>Channels</th></tr></thead><tbody>';
                users.forEach(u => {
                    const chans = u.channels ? u.channels.join(', ') : 'None';
                    html += `<tr><td><strong>${escapeHtml(u.nickname)}</strong></td>`;
                    html += `<td>${escapeHtml(u.username)}@${escapeHtml(u.hostname)}</td>`;
                    html += `<td>${timeAgo(u.connected_at)}</td><td>${escapeHtml(chans)}</td></tr>`;
                });
                html += '</tbody></table>';
                $('#connected-users').innerHTML = html;
            }

            const chans = data.active_channels || [];
            $('#channel-count').textContent = chans.length;
            $('#stat-channels').textContent = chans.length;

            if (chans.length === 0) {
                $('#active-channels').innerHTML = '<div class="empty-state"><div class="empty-state-icon">💬</div><div class="empty-state-text">No Active Channels</div><div class="empty-state-subtext">Create a channel to get started</div></div>';
            } else {
                let html = '<table class="table table-striped table-bordered table-condensed">';
                html += '<thead><tr><th>Channel</th><th>Modes</th><th>Topic</th><th>Members</th></tr></thead><tbody>';
                chans.forEach(c => {
                    const topic = c.topic || '(No topic)';
                    const modes = c.modes ? `+${c.modes}` : '';
                    html += `<tr><td><strong>${escapeHtml(c.name)}</strong></td>`;
                    html += `<td><code style="font-size: 11px;">${escapeHtml(modes)}</code></td>`;
                    html += `<td>${escapeHtml(topic)}</td><td>${c.member_count}</td></tr>`;
                });
                html += '</tbody></table>';
                $('#active-channels').innerHTML = html;
            }

            // Get linked servers
            const servers = data.linked_servers || [];
            $('#linked-count').textContent = servers.length;

            if (servers.length === 0) {
                $('#linked-servers').innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔗</div><div class="empty-state-text">No Linked Servers</div><div class="empty-state-subtext">Server linking not active</div></div>';
            } else {
                let html = '<table class="table table-striped table-bordered table-condensed">';
                html += '<thead><tr><th>Server</th><th>Users</th><th>Hops</th><th>Status</th></tr></thead><tbody>';
                servers.forEach(s => {
                    const statusClass = s.status === 'ok' ? 'success' : 'warning';
                    const statusIcon = s.status === 'ok' ? '✓' : '⚠';
                    const direct = s.is_direct ? '<span class="label label-info" style="font-size:9px;">DIRECT</span> ' : '';
                    html += `<tr><td>${direct}<strong>${escapeHtml(s.name)}</strong></td>`;
                    html += `<td>${s.user_count}</td>`;
                    html += `<td>${s.hopcount}</td>`;
                    html += `<td><span class="label label-${statusClass}">${statusIcon} ${s.status.toUpperCase()}</span></td></tr>`;
                });
                html += '</tbody></table>';
                $('#linked-servers').innerHTML = html;
            }
        });
    }

    function loadStats() {
        callAPI('stats').then(data => {
            if (data.error) {
                $('#server-stats').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                $('#stat-registered').textContent = '0';
                $('#stat-staff').textContent = '0';
                return;
            }

            // Update stat cards
            $('#stat-registered').textContent = data.registered_nicks || 0;
            $('#stat-staff').textContent = data.staff.total || 0;

            // Update detailed stats
            let html = '<dl class="dl-horizontal" style="margin-bottom: 0;">';
            html += `<dt>Total Staff:</dt><dd><strong>${data.staff.total}</strong>`;
            if (data.staff.by_level) {
                const levels = [];
                if (data.staff.by_level.ADMIN) levels.push(`${data.staff.by_level.ADMIN} Admin`);
                if (data.staff.by_level.SYSOP) levels.push(`${data.staff.by_level.SYSOP} SysOp`);
                if (data.staff.by_level.GUIDE) levels.push(`${data.staff.by_level.GUIDE} Guide`);
                if (levels.length) html += ` <span style="font-size: 11px; color: #666;">(${levels.join(', ')})</span>`;
            }
            html += `</dd>`;
            html += `<dt>Registered Nicknames:</dt><dd><strong>${data.registered_nicks}</strong></dd>`;
            html += `<dt>Registered Channels:</dt><dd><strong>${data.registered_channels}</strong></dd>`;
            html += `<dt>Unread Mailbox:</dt><dd><strong>${data.unread_mailbox}</strong></dd>`;
            html += `<dt>Unread Memos:</dt><dd><strong>${data.unread_memos || 0}</strong></dd>`;
            html += `<dt>NewsFlash Items:</dt><dd><strong>${data.newsflash_count || 0}</strong></dd>`;
            if (data.server_access) {
                const denies = data.server_access.DENY || 0;
                const grants = data.server_access.GRANT || 0;
                html += `<dt>Access Rules:</dt><dd><strong>${denies + grants}</strong>`;
                if (denies || grants) html += ` <span style="font-size: 11px; color: #666;">(${denies} ban${denies !== 1 ? 's' : ''}, ${grants} grant${grants !== 1 ? 's' : ''})</span>`;
                html += `</dd>`;
            }
            html += '</dl>';
            $('#server-stats').innerHTML = html;
        });
    }

    function loadAccessList() {
        callAPI('server-access-list').then(data => {
            if (data.error) {
                $('#access-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#access-list').innerHTML = '<div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">No Access Rules</div><div class="empty-state-subtext">Add rules to control server access</div></div>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Type</th><th>Pattern</th><th>Reason</th><th>Set By</th><th>Set At</th><th>Expires</th><th>Actions</th></tr></thead><tbody>';
            const now = Date.now() / 1000;
            data.forEach(r => {
                const expires = r.timeout === 0 ? 'Never' : (r.expired ? '<span class="label label-danger">EXPIRED</span>' : formatTimestamp(r.timeout));
                html += '<tr>';
                html += `<td><span class="label label-${r.type === 'DENY' ? 'danger' : 'success'}">${r.type}</span></td>`;
                html += `<td>${escapeHtml(r.pattern)}</td>`;
                html += `<td>${escapeHtml(r.reason)}</td>`;
                html += `<td>${escapeHtml(r.set_by)}</td>`;
                html += `<td>${formatTimestamp(r.set_at)}</td>`;
                html += `<td>${expires}</td>`;
                html += `<td><button class="btn btn-danger btn-xs btn-remove-access" data-type="${r.type}" data-pattern="${escapeHtml(r.pattern)}">Remove</button></td>`;
                html += '</tr>';
            });
            html += '</tbody></table>';
            $('#access-list').innerHTML = html;

            $$('.btn-remove-access').forEach(btn => {
                btn.addEventListener('click', function() {
                    const type = this.getAttribute('data-type');
                    const pattern = this.getAttribute('data-pattern');
                    if (confirm(`Remove ${type} for ${pattern}?`)) {
                        callAPI('remove-server-access', [type, pattern]).then(res => {
                            if (res.error) showToast('Error', res.error, 'error');
                            else {
                                showToast('Success', 'Access rule removed', 'success');
                                loadAccessList();
                            }
                        });
                    }
                });
            });
        });
    }

    function loadNewsflash() {
        callAPI('newsflash-list').then(data => {
            if (data.error) {
                $('#newsflash-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#newsflash-list').innerHTML = '<p>No newsflash messages.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Priority</th><th>Message</th><th>Created By</th><th>Created At</th><th>Actions</th></tr></thead><tbody>';
            data.forEach(n => {
                const pLabel = n.priority === 2 ? 'danger' : (n.priority === 1 ? 'warning' : 'default');
                const pText = n.priority === 2 ? 'Critical' : (n.priority === 1 ? 'High' : 'Normal');
                html += '<tr>';
                html += `<td><span class="label label-${pLabel}">${pText}</span></td>`;
                html += `<td>${escapeHtml(n.message)}</td>`;
                html += `<td>${escapeHtml(n.created_by)}</td>`;
                html += `<td>${formatTimestamp(n.created_at)}</td>`;
                html += `<td><button class="btn btn-danger btn-xs btn-delete-newsflash" data-id="${n.id}">Delete</button></td>`;
                html += '</tr>';
            });
            html += '</tbody></table>';
            $('#newsflash-list').innerHTML = html;

            $$('.btn-delete-newsflash').forEach(btn => {
                btn.addEventListener('click', function() {
                    const id = this.getAttribute('data-id');
                    if (confirm('Delete this NewsFlash?')) {
                        callAPI('delete-newsflash', [id]).then(res => {
                            if (res.error) showToast('Error', res.error, 'error');
                            else {
                                showToast('Success', 'NewsFlash deleted', 'success');
                                loadNewsflash();
                            }
                        });
                    }
                });
            });
        });
    }

    function loadNewsflashSettings() {
        callAPI('newsflash-settings').then(data => {
            if (data.error) {
                console.error('Error loading newsflash settings:', data.error);
                return;
            }
            if ($('#newsflash-on-connect')) {
                $('#newsflash-on-connect').checked = data.on_connect;
            }
            if ($('#newsflash-periodic-enabled')) {
                $('#newsflash-periodic-enabled').checked = data.periodic_enabled;
            }
            if ($('#newsflash-interval')) {
                $('#newsflash-interval').value = data.periodic_interval;
            }
        });
    }

    function saveNewsflashSettings() {
        const onConnect = $('#newsflash-on-connect').checked;
        const periodicEnabled = $('#newsflash-periodic-enabled').checked;
        const interval = $('#newsflash-interval').value;
        
        callAPI('set-newsflash-settings', [onConnect.toString(), periodicEnabled.toString(), interval]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
                $('#newsflash-settings-status').innerHTML = '<span style="color: red;">Failed to save</span>';
            } else {
                showToast('Success', 'NewsFlash settings saved', 'success');
                $('#newsflash-settings-status').innerHTML = '<span style="color: green;">Settings saved!</span>';
                setTimeout(() => {
                    $('#newsflash-settings-status').innerHTML = '';
                }, 3000);
            }
        });
    }


    function loadMailbox() {
        callAPI('mailbox-list', ['30']).then(data => {
            if (data.error) {
                $('#mailbox-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#mailbox-list').innerHTML = '<p>No mailbox messages.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>From</th><th>To</th><th>Message</th><th>Sent</th><th>Status</th></tr></thead><tbody>';
            data.forEach(m => {
                html += '<tr>';
                html += `<td>${escapeHtml(m.sender)}</td>`;
                html += `<td>${escapeHtml(m.recipient)}</td>`;
                html += `<td>${escapeHtml(m.message)}</td>`;
                html += `<td>${formatTimestamp(m.sent_at)}</td>`;
                html += `<td>${m.read ? '<span class="label label-default">Read</span>' : '<span class="label label-success">Unread</span>'}</td>`;
                html += '</tr>';
            });
            html += '</tbody></table>';
            $('#mailbox-list').innerHTML = html;
        });
    }

    function loadStaff() {
        callAPI('staff').then(data => {
            if (data.error) {
                $('#staff-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#staff-list').innerHTML = '<p>No staff members.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Username</th><th>Level</th><th>Actions</th></tr></thead><tbody>';
            data.forEach(s => {
                const levelClass = {'SYSOP': 'danger', 'ADMIN': 'warning', 'GUIDE': 'info'}[s.level] || 'default';
                html += `<tr><td>${escapeHtml(s.username)}</td>`;
                html += `<td><span class="label label-${levelClass}">${s.level}</span></td>`;
                html += `<td><button class="btn btn-sm btn-info btn-edit-staff" data-username="${escapeHtml(s.username)}" data-level="${s.level}">✏️ Edit</button></td></tr>`;
            });
            html += '</tbody></table>';
            $('#staff-list').innerHTML = html;

            // Add click handlers for edit buttons
            document.querySelectorAll('.btn-edit-staff').forEach(btn => {
                btn.addEventListener('click', function() {
                    const username = this.getAttribute('data-username');
                    const level = this.getAttribute('data-level');
                    openEditStaffModal(username, level);
                });
            });
        });
    }

    function loadChannels() {
        callAPI('channels', ['20']).then(data => {
            if (data.error) {
                $('#channels-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#channels-list').innerHTML = '<p>No registered channels.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Channel</th><th>Owner</th><th>Registered</th><th>Last Used</th></tr></thead><tbody>';
            data.forEach(c => {
                html += `<tr><td><strong>${escapeHtml(c.name)}</strong></td>`;
                html += `<td>${escapeHtml(c.owner)}</td>`;
                html += `<td>${formatTimestamp(c.registered_at)}</td>`;
                html += `<td>${timeAgo(c.last_used)}</td></tr>`;
            });
            html += '</tbody></table>';
            $('#channels-list').innerHTML = html;
        });
    }

    function loadRecentRegs() {
        callAPI('recent-registrations', ['10']).then(data => {
            if (data.error) {
                $('#recent-registrations').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#recent-registrations').innerHTML = '<p>No registrations.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Nickname</th><th>Registered</th><th>Last Seen</th><th>MFA</th></tr></thead><tbody>';
            data.forEach(r => {
                html += `<tr><td><strong>${escapeHtml(r.nickname)}</strong></td>`;
                html += `<td>${formatTimestamp(r.registered_at)}</td>`;
                html += `<td>${timeAgo(r.last_seen)}</td>`;
                html += `<td>${r.mfa_enabled ? '<span class="label label-success">Yes</span>' : '<span class="label label-default">No</span>'}</td></tr>`;
            });
            html += '</tbody></table>';
            $('#recent-registrations').innerHTML = html;
        });
    }

    function loadConfig() {
        callAPI('config').then(data => {
            if (data.error) {
                $('#server-config').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            let html = '<dl class="dl-horizontal">';
            if (data.server) {
                html += `<dt>Server Name:</dt><dd>${escapeHtml(data.server.name)}</dd>`;
                html += `<dt>Network:</dt><dd>${escapeHtml(data.server.network)}</dd>`;
            }
            html += `<dt>Ports:</dt><dd>${JSON.stringify(data.port)}</dd>`;
            html += `<dt>SSL:</dt><dd>${data.ssl_enabled ? 'Yes' : 'No'}</dd>`;
            html += '</dl>';
            $('#server-config').innerHTML = html;
        });
    }

    // ========================================================================
    // STAFF MANAGEMENT
    // ========================================================================

    function openEditStaffModal(username, currentLevel) {
        $('#edit-staff-username').textContent = username;
        $('#edit-staff-level').value = currentLevel;
        $('#modal-edit-staff').style.display = 'block';

        // Store username for later use
        $('#modal-edit-staff').setAttribute('data-username', username);
    }

    function addStaff() {
        const username = $('#staff-username').value.trim();
        const password = $('#staff-password').value;
        const passwordConfirm = $('#staff-password-confirm').value;
        const level = $('#staff-level').value;

        // Validation
        if (!username || !password) {
            showToast('Error', 'Username and password are required', 'error');
            return;
        }

        if (password !== passwordConfirm) {
            showToast('Error', 'Passwords do not match', 'error');
            return;
        }

        if (password.length < 8) {
            showToast('Error', 'Password must be at least 8 characters', 'error');
            return;
        }

        callAPI('add-staff', [username, password, level]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-add-staff').style.display = 'none';
                $('#staff-username').value = '';
                $('#staff-password').value = '';
                $('#staff-password-confirm').value = '';
                loadStaff();
            }
        });
    }

    function changeStaffLevel() {
        const username = $('#modal-edit-staff').getAttribute('data-username');
        const newLevel = $('#edit-staff-level').value;

        callAPI('change-staff-level', [username, newLevel]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-edit-staff').style.display = 'none';
                loadStaff();
            }
        });
    }

    function changeStaffPassword() {
        const username = $('#modal-edit-staff').getAttribute('data-username');
        const newPassword = $('#edit-staff-password').value;
        const confirmPassword = $('#edit-staff-password-confirm').value;

        if (!newPassword) {
            showToast('Error', 'Password is required', 'error');
            return;
        }

        if (newPassword !== confirmPassword) {
            showToast('Error', 'Passwords do not match', 'error');
            return;
        }

        if (newPassword.length < 8) {
            showToast('Error', 'Password must be at least 8 characters', 'error');
            return;
        }

        callAPI('change-staff-password', [username, newPassword]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#edit-staff-password').value = '';
                $('#edit-staff-password-confirm').value = '';
            }
        });
    }

    function deleteStaff() {
        const username = $('#modal-edit-staff').getAttribute('data-username');

        if (!confirm(`Are you sure you want to delete staff member '${username}'? This cannot be undone!`)) {
            return;
        }

        callAPI('delete-staff', [username]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-edit-staff').style.display = 'none';
                loadStaff();
            }
        });
    }

    function loadLogs() {
        const level = $('#log-level-filter').value || null;
        const search = $('#log-search-input').value || null;
        const args = ['100'];
        if (level) args.push(level);
        if (search) args.push(search);

        callAPI('logs', args).then(data => {
            if (data.error) {
                $('#server-logs').textContent = `Error: ${data.error}`;
                return;
            }
            $('#server-logs').textContent = data.logs || 'No logs.';
        });
    }

    function searchNicks() {
        const query = $('#search-nicks-input').value;
        if (!query) {
            $('#search-nicks-results').innerHTML = '';
            return;
        }
        callAPI('search-nicks', [query]).then(data => {
            if (data.error) {
                $('#search-nicks-results').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#search-nicks-results').innerHTML = '<p>No results.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Nickname</th><th>Email</th><th>Registered</th><th>Last Seen</th><th>MFA</th></tr></thead><tbody>';
            data.forEach(n => {
                html += `<tr><td><strong>${escapeHtml(n.nickname)}</strong></td>`;
                html += `<td>${escapeHtml(n.email)}</td>`;
                html += `<td>${formatTimestamp(n.registered_at)}</td>`;
                html += `<td>${timeAgo(n.last_seen)}</td>`;
                html += `<td>${n.mfa_enabled ? '<span class="label label-success">Yes</span>' : '<span class="label label-default">No</span>'}</td></tr>`;
            });
            html += '</tbody></table>';
            $('#search-nicks-results').innerHTML = html;
        });
    }

    function searchChannels() {
        const query = $('#search-channels-input').value;
        if (!query) {
            $('#search-channels-results').innerHTML = '';
            return;
        }
        callAPI('search-channels', [query]).then(data => {
            if (data.error) {
                $('#search-channels-results').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (data.length === 0) {
                $('#search-channels-results').innerHTML = '<p>No results.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Channel</th><th>Owner</th><th>Registered</th><th>Last Used</th></tr></thead><tbody>';
            data.forEach(c => {
                html += `<tr><td><strong>${escapeHtml(c.name)}</strong></td>`;
                html += `<td>${escapeHtml(c.owner)}</td>`;
                html += `<td>${formatTimestamp(c.registered_at)}</td>`;
                html += `<td>${timeAgo(c.last_used)}</td></tr>`;
            });
            html += '</tbody></table>';
            $('#search-channels-results').innerHTML = html;
        });
    }

    function loadAll() {
        loadServiceStatus();
        loadRealtimeStatus();
        loadStats();
        loadAccessList();
        loadNewsflash();
        loadNewsflashSettings();
        loadMailbox();
        loadStaff();
        loadChannels();
        loadRecentRegs();
        loadConfig();
        loadLogs();
    }

    // Initialize
    console.log('pyIRCX module loading...');

    document.addEventListener('DOMContentLoaded', function() {
        console.log('DOM ready, initializing...');
        loadAll();

        // Service buttons
        if ($('#btn-start')) $('#btn-start').addEventListener('click', () => controlService('start'));
        if ($('#btn-restart')) $('#btn-restart').addEventListener('click', () => controlService('restart'));
        if ($('#btn-stop')) $('#btn-stop').addEventListener('click', () => controlService('stop'));

        // Access management
        if ($('#btn-add-access')) {
            $('#btn-add-access').addEventListener('click', () => {
                $('#modal-add-access').style.display = 'block';
            });
        }
        if ($('#btn-cancel-access')) {
            $('#btn-cancel-access').addEventListener('click', () => {
                $('#modal-add-access').style.display = 'none';
            });
        }
        if ($('#btn-save-access')) {
            $('#btn-save-access').addEventListener('click', () => {
                const type = $('#access-type').value;
                const pattern = $('#access-pattern').value;
                const reason = $('#access-reason').value;
                const timeout = $('#access-timeout').value || '0';
                if (!pattern || !reason) {
                    showToast('Validation Error', 'Please fill in all required fields', 'warning');
                    return;
                }
                callAPI('add-server-access', [type, pattern, currentUser.name, reason, timeout]).then(res => {
                    if (res.error) showToast('Error', res.error, 'error');
                    else {
                        $('#modal-add-access').style.display = 'none';
                        $('#access-pattern').value = '';
                        $('#access-reason').value = '';
                        $('#access-timeout').value = '0';
                        showToast('Success', 'Access rule added', 'success');
                        loadAccessList();
                    }
                });
            });
        }

        // Newsflash management
        if ($('#btn-add-newsflash')) {
            $('#btn-add-newsflash').addEventListener('click', () => {
                $('#modal-add-newsflash').style.display = 'block';
            });
        }
        if ($('#btn-cancel-newsflash')) {
            $('#btn-cancel-newsflash').addEventListener('click', () => {
                $('#modal-add-newsflash').style.display = 'none';
            });
        }
        if ($('#btn-save-newsflash')) {
            $('#btn-save-newsflash').addEventListener('click', () => {
                const msg = $('#newsflash-message').value;
                const priority = $('#newsflash-priority').value;
                if (!msg) {
                    showToast('Validation Error', 'Please enter a message', 'warning');
                    return;
                }
                callAPI('add-newsflash', [msg, currentUser.name, priority]).then(res => {
                    if (res.error) showToast('Error', res.error, 'error');
                    else {
                        $('#modal-add-newsflash').style.display = 'none';
                        $('#newsflash-message').value = '';
                        $('#newsflash-priority').value = '0';
                        showToast('Success', 'NewsFlash added', 'success');
                        loadNewsflash();
                    }
                });
            });
        }
        
        // NewsFlash Settings
        if ($('#btn-save-newsflash-settings')) {
            $('#btn-save-newsflash-settings').addEventListener('click', saveNewsflashSettings);
        }

        // Staff Management
        if ($('#btn-add-staff')) {
            $('#btn-add-staff').addEventListener('click', () => {
                $('#modal-add-staff').style.display = 'block';
            });
        }
        if ($('#btn-cancel-staff')) {
            $('#btn-cancel-staff').addEventListener('click', () => {
                $('#modal-add-staff').style.display = 'none';
            });
        }
        if ($('#btn-save-staff')) {
            $('#btn-save-staff').addEventListener('click', addStaff);
        }
        if ($('#btn-cancel-edit-staff')) {
            $('#btn-cancel-edit-staff').addEventListener('click', () => {
                $('#modal-edit-staff').style.display = 'none';
            });
        }
        if ($('#btn-change-level')) {
            $('#btn-change-level').addEventListener('click', changeStaffLevel);
        }
        if ($('#btn-change-password')) {
            $('#btn-change-password').addEventListener('click', changeStaffPassword);
        }
        if ($('#btn-delete-staff')) {
            $('#btn-delete-staff').addEventListener('click', deleteStaff);
        }

        // Search
        if ($('#btn-search-nicks')) $('#btn-search-nicks').addEventListener('click', searchNicks);
        if ($('#search-nicks-input')) {
            $('#search-nicks-input').addEventListener('keypress', e => {
                if (e.which === 13) searchNicks();
            });
        }
        if ($('#btn-search-channels')) $('#btn-search-channels').addEventListener('click', searchChannels);
        if ($('#search-channels-input')) {
            $('#search-channels-input').addEventListener('keypress', e => {
                if (e.which === 13) searchChannels();
            });
        }

        // Config editor
        if ($('#btn-edit-config')) {
            $('#btn-edit-config').addEventListener('click', () => {
                callAPI('full-config').then(data => {
                    $('#config-editor').value = JSON.stringify(data, null, 2);
                    $('#modal-edit-config').style.display = 'block';
                });
            });
        }
        if ($('#btn-cancel-config')) {
            $('#btn-cancel-config').addEventListener('click', () => {
                $('#modal-edit-config').style.display = 'none';
            });
        }
        if ($('#btn-save-config')) {
            $('#btn-save-config').addEventListener('click', () => {
                const configText = $('#config-editor').value;
                try {
                    JSON.parse(configText);
                } catch (e) {
                    showToast('Invalid JSON', e.message, 'error');
                    return;
                }
                if (confirm('Save config and restart?')) {
                    callAPI('set-config', [configText]).then(res => {
                        if (res.error) showToast('Error', res.error, 'error');
                        else {
                            $('#modal-edit-config').style.display = 'none';
                            showToast('Success', 'Configuration saved, restarting service...', 'success');
                            controlService('restart');
                        }
                    });
                }
            });
        }

        // Logs
        if ($('#btn-refresh-logs')) $('#btn-refresh-logs').addEventListener('click', loadLogs);
        if ($('#log-level-filter')) $('#log-level-filter').addEventListener('change', loadLogs);

        // Auto-refresh
        setInterval(loadServiceStatus, 10000);
        setInterval(loadRealtimeStatus, 10000);
        setInterval(() => {
            loadStats();
            loadChannels();
            loadRecentRegs();
        }, 30000);

        console.log('pyIRCX initialized successfully');
    });
})();
