console.log("=== admin.js LOADING ===");
(function() {
    "use strict";
    const currentUser = {name: 'admin'};
    let nicksCurrentPage = 1;
    let channelsCurrentPage = 1;
    const itemsPerPage = 20;
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

    function openModal(modalId) {
        const modal = $('#' + modalId);
        if (modal) {
            modal.style.display = 'block';
        }
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
        const fd = new FormData();
        fd.append('cmd', cmd);
        args.forEach((a,i) => fd.append(`args[${i}]`, a));
        return fetch('api.php', {method: 'POST', body: fd})
            .then(r => {
                if (r.status === 401) {
                    // Unauthorized - redirect to login
                    window.location.href = 'login.php';
                    throw new Error('Unauthorized');
                }
                return r.json();
            })
            .catch(err => {
                if (err.message !== 'Unauthorized') {
                    return { error: err.message };
                }
                throw err;
            });
    }

    // Service control
    function controlService(action) {
        const actionLabels = {
            start: '▶️ Starting',
            stop: '⏹️ Stopping',
            restart: '🔄 Restarting'
        };

        showToast('Service Control', `${actionLabels[action]} pyIRCX service...`, 'info');

        fetch('api.php', {method: 'POST', body: (() => { const fd = new FormData(); fd.append('cmd', 'service-control'); fd.append('action', action); return fd; })() }).then(r => r.json()).then(d => { if(d.error) throw new Error(d.error); })
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
        fetch('api.php?cmd=service-status')
            .then(r => r.json())
            .then(data => {
                const status = data.status.trim();
                
                let statusHtml = '<div class="service-status-card ';
                
                if (status === 'active') {
                    statusHtml += 'service-running">';
                    statusHtml += '<div class="service-status-icon">✅</div>';
                    statusHtml += '<div class="service-status-info">';
                    statusHtml += '<div class="service-status-text">Running</div>';
                    statusHtml += '<div class="service-status-desc">pyIRCX server is online and accepting connections</div>';
                    statusHtml += '</div>';
                } else if (status === 'inactive' || status === 'failed') {
                    statusHtml += 'service-stopped">';
                    statusHtml += '<div class="service-status-icon">⭕</div>';
                    statusHtml += '<div class="service-status-info">';
                    statusHtml += '<div class="service-status-text">Stopped</div>';
                    statusHtml += '<div class="service-status-desc">pyIRCX server is not running</div>';
                    statusHtml += '</div>';
                } else {
                    statusHtml += 'service-unknown">';
                    statusHtml += '<div class="service-status-icon">❓</div>';
                    statusHtml += '<div class="service-status-info">';
                    statusHtml += '<div class="service-status-text">Unknown</div>';
                    statusHtml += '<div class="service-status-desc">Status: ' + status + '</div>';
                    statusHtml += '</div>';
                }
                
                statusHtml += '</div>';
                $('#service-status').innerHTML = statusHtml;
            })
            .catch(err => {
                $('#service-status').innerHTML = '<div class="alert alert-danger">Error loading service status</div>';
            });
    }

    function loadRealtimeStatus() {
        callAPI('realtime-status').then(data => {
            if (data.error) {
                $('#connected-users').innerHTML = '<div class="empty-state"><div class="empty-state-icon">💤</div><div class="empty-state-text">Server Not Running</div><div class="empty-state-subtext">Start the service to see connected users</div></div>';
                $('#active-channels').innerHTML = '<div class="empty-state"><div class="empty-state-icon">💤</div><div class="empty-state-text">Server Not Running</div><div class="empty-state-subtext">Start the service to see active channels</div></div>';
                $('#connected-count').textContent = '0';
                $('#channel-count').textContent = '0';
                return;
            }

            const age = data.status_age || 0;
            const color = age < 30 ? 'success' : (age < 60 ? 'warning' : 'danger');

            const users = data.connected_users || [];
            $('#connected-count').textContent = users.length;

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
                
                // Make table sortable
                const connectedTable = $('#connected-users table');
                if (connectedTable) makeSortable(connectedTable);
            }

            const chans = data.active_channels || [];
            $('#channel-count').textContent = chans.length;

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
                
                // Make table sortable
                const activeChansTable = $('#active-channels table');
                if (activeChansTable) makeSortable(activeChansTable);
            }

            // Get linked servers
            const servers = data.linked_servers || [];
            const linkedCountEl = $('#linked-count'); if (linkedCountEl) linkedCountEl.textContent = servers.length;

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
                $('#server-stats').innerHTML = '<div class="alert alert-danger">' + escapeHtml(data.error) + '</div>';
                return;
            }


            let html = '<div class="stats-grid">';

            html += '<div class="stat-section">';
            html += '<h4 class="stat-section-title">Real-time Statistics</h4>';
            html += '<div class="stat-cards">';
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">👥</div>';
            html += '<div class="stat-value">' + (data.connected_users || 0) + '</div>';
            html += '<div class="stat-label">Connected Users</div>';
            html += '</div>';
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">#️⃣</div>';
            html += '<div class="stat-value">' + (data.active_channels || 0) + '</div>';
            html += '<div class="stat-label">Active Channels</div>';
            html += '</div>';
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">🔗</div>';
            html += '<div class="stat-value">' + (data.linked_servers || 0) + '</div>';
            html += '<div class="stat-label">Linked Servers</div>';
            html += '</div>';
            
            if (data.peak_users) {
                html += '<div class="stat-card">';
                html += '<div class="stat-icon">📊</div>';
                html += '<div class="stat-value">' + data.peak_users + '</div>';
                html += '<div class="stat-label">Peak Users</div>';
                html += '</div>';
            }
            
            html += '</div></div>';

            html += '<div class="stat-section">';
            html += '<h4 class="stat-section-title">Server Information</h4>';
            html += '<div class="stat-cards">';
            
            if (data.uptime_seconds) {
                const uptime = formatUptime(data.uptime_seconds);
                html += '<div class="stat-card">';
                html += '<div class="stat-icon">⏱️</div>';
                html += '<div class="stat-value-small">' + uptime + '</div>';
                html += '<div class="stat-label">Server Uptime</div>';
                html += '</div>';
            }
            
            const statusClass = data.server_running ? 'stat-card-success' : 'stat-card-danger';
            const statusIcon = data.server_running ? '✅' : '⛔';
            const statusText = data.server_running ? 'Running' : 'Stopped';
            html += '<div class="stat-card ' + statusClass + '">';
            html += '<div class="stat-icon">' + statusIcon + '</div>';
            html += '<div class="stat-value-small">' + statusText + '</div>';
            html += '<div class="stat-label">Server Status</div>';
            html += '</div>';
            
            html += '</div></div>';

            html += '<div class="stat-section">';
            html += '<h4 class="stat-section-title">Database Statistics</h4>';
            html += '<div class="stat-cards">';
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">📝</div>';
            html += '<div class="stat-value">' + (data.registered_nicks || 0) + '</div>';
            html += '<div class="stat-label">Registered Nicks</div>';
            html += '</div>';
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">🏷️</div>';
            html += '<div class="stat-value">' + (data.registered_channels || 0) + '</div>';
            html += '<div class="stat-label">Registered Channels</div>';
            html += '</div>';
            
            let staffDetails = '';
            if (data.staff.by_level) {
                const levels = [];
                if (data.staff.by_level.ADMIN) levels.push(data.staff.by_level.ADMIN + ' Admin');
                if (data.staff.by_level.SYSOP) levels.push(data.staff.by_level.SYSOP + ' SysOp');
                if (data.staff.by_level.GUIDE) levels.push(data.staff.by_level.GUIDE + ' Guide');
                if (levels.length) staffDetails = '<div class="stat-detail">' + levels.join(' • ') + '</div>';
            }
            
            html += '<div class="stat-card">';
            html += '<div class="stat-icon">👔</div>';
            html += '<div class="stat-value">' + (data.staff.total || 0) + '</div>';
            html += '<div class="stat-label">Staff Members</div>';
            html += staffDetails;
            html += '</div>';

            html += '<div class="stat-card">';
            html += '<div class="stat-icon">📬</div>';
            html += '<div class="stat-value">' + (data.unread_mailbox || 0) + '</div>';
            html += '<div class="stat-label">Unread Mailbox</div>';
            html += '</div>';

            html += '<div class="stat-card">';
            html += '<div class="stat-icon">📰</div>';
            html += '<div class="stat-value">' + (data.newsflash_count || 0) + '</div>';
            html += '<div class="stat-label">NewsFlash Items</div>';
            html += '</div>';

            if (data.server_access) {
                const denies = data.server_access.DENY || 0;
                const grants = data.server_access.GRANT || 0;
                const total = denies + grants;
                let accessDetail = '';
                if (denies || grants) {
                    accessDetail = '<div class="stat-detail">' + denies + ' ban' + (denies !== 1 ? 's' : '') + ' • ' + grants + ' grant' + (grants !== 1 ? 's' : '') + '</div>';
                }
                html += '<div class="stat-card">';
                html += '<div class="stat-icon">🚫</div>';
                html += '<div class="stat-value">' + total + '</div>';
                html += '<div class="stat-label">Access Rules</div>';
                html += accessDetail;
                html += '</div>';
            }
            
            html += '</div></div>';
            html += '</div>';

            $('#server-stats').innerHTML = html;
        });
    }

    function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    function loadAccessList() {
        callAPI('server-access-list').then(data => {
            if (data.error) {
                $('#access-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            
            // Filter out expired rules
            const activeRules = data.filter(r => !r.expired);
            
            if (activeRules.length === 0) {
                $('#access-list').innerHTML = '<div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">No Access Rules</div><div class="empty-state-subtext">Add rules to control server access</div></div>';
                return;
            }
            
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Type</th><th>Pattern</th><th>Reason</th><th>Set By</th><th>Set At</th><th>Actions</th></tr></thead><tbody>';
            activeRules.forEach(r => {
                html += '<tr>';
                html += `<td><span class="label label-${r.type === 'DENY' ? 'danger' : 'success'}">${r.type}</span></td>`;
                html += `<td>${escapeHtml(r.pattern)}</td>`;
                html += `<td>${escapeHtml(r.reason)}</td>`;
                html += `<td>${escapeHtml(r.set_by)}</td>`;
                html += `<td>${formatTimestamp(r.set_at)}</td>`;
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

    function sendMailboxMessage() {
        const sender = $('#mailbox-from').value.trim();
        const recipient = $('#mailbox-to').value.trim();
        const message = $('#mailbox-message').value.trim();

        if (!sender || !recipient || !message) {
            showToast('Error', 'All fields are required', 'error');
            return;
        }

        callAPI('send-mailbox-message', [sender, recipient, message]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-send-mailbox').style.display = 'none';
                $('#mailbox-from').value = '';
                $('#mailbox-to').value = '';
                $('#mailbox-message').value = '';
                loadMailbox();
            }
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
            html += '<thead><tr><th>Username</th><th>Real Name</th><th>Email</th><th>Level</th><th>Actions</th></tr></thead><tbody>';
            data.forEach(s => {
                const levelClass = {'SYSOP': 'danger', 'ADMIN': 'warning', 'GUIDE': 'info'}[s.level] || 'default';
                html += `<tr><td>${escapeHtml(s.username)}</td>`;
                const realnameDisplay = s.realname ? escapeHtml(s.realname) : '<em class="text-muted">Not set</em>';
                const forceIndicator = s.force_realname ? ' <span class="label label-warning" style="font-size: 10px;" title="Real name is enforced for this staff member">🔒 Enforced</span>' : '';
                html += `<td>${realnameDisplay}${forceIndicator}</td>`;
                html += `<td>${s.email ? escapeHtml(s.email) : '<em class="text-muted">Not set</em>'}</td>`;
                html += `<td><span class="label label-${levelClass}">${s.level}</span></td>`;
                html += `<td><button class="btn btn-sm btn-info btn-edit-staff" data-username="${escapeHtml(s.username)}" data-level="${s.level}" data-realname="${s.realname || ''}" data-email="${s.email || ''}" data-force-realname="${s.force_realname}">✏️ Edit</button></td></tr>`;
            });
            html += '</tbody></table>';
            $('#staff-list').innerHTML = html;

            // Add click handlers for edit buttons
            document.querySelectorAll('.btn-edit-staff').forEach(btn => {
                btn.addEventListener('click', function() {
                    const username = this.getAttribute('data-username');
                    const level = this.getAttribute('data-level');
                    const realname = this.getAttribute('data-realname');
                    const email = this.getAttribute('data-email');
                    const forceRealname = this.getAttribute('data-force-realname') === 'true';
                    openEditStaffModal(username, level, realname, email, forceRealname);
                });
            });
        });
    }


    function loadChannels(page = 1) {
        channelsCurrentPage = page;
        const offset = (page - 1) * itemsPerPage;

        callAPI('list-channels-paginated', [itemsPerPage.toString(), offset.toString()]).then(response => {
            if (response.error) {
                $('#channels-list').innerHTML = `<div class="alert alert-danger">${escapeHtml(response.error)}</div>`;
                return;
            }

            const data = response.data || [];
            const total = response.total || 0;

            if (data.length === 0) {
                $('#channels-list').innerHTML = '<p>No registered channels.</p>';
                $('#channels-pagination').style.display = 'none';
                return;
            }

            let html = '<table class="table table-striped table-bordered table-condensed">';
            html += '<thead><tr><th>Channel</th><th>Owner</th><th>Registered</th><th>Last Used</th><th>Actions</th></tr></thead><tbody>';
            data.forEach(c => {
                html += `<tr><td><strong>${escapeHtml(c.name)}</strong></td>`;
                html += `<td>${escapeHtml(c.owner)}</td>`;
                html += `<td>${formatTimestamp(c.registered_at)}</td>`;
                html += `<td>${timeAgo(c.last_used)}</td>`;
                html += `<td>`;
                html += `<button class="btn btn-info btn-xs" onclick="openEditChannelModal('${escapeHtml(c.name)}', '${escapeHtml(c.owner)}')">Edit</button> `;
                html += `<button class="btn btn-danger btn-xs" onclick="unregisterChannel('${escapeHtml(c.name)}')">Delete</button>`;
                html += `</td></tr>`;
            });
            html += '</tbody></table>';
            $('#channels-list').innerHTML = html;

            // Render pagination
            renderChannelsPagination(total, page);
        });
    }

    function loadRecentRegs(page = 1) {
        nicksCurrentPage = page;
        const offset = (page - 1) * itemsPerPage;

        callAPI('list-nicks-paginated', [itemsPerPage.toString(), offset.toString()]).then(response => {
            if (response.error) {
                $('#recent-registrations').innerHTML = `<div class="alert alert-danger">${escapeHtml(response.error)}</div>`;
                return;
            }

            const data = response.data || [];
            const total = response.total || 0;

            if (data.length === 0) {
                $('#recent-registrations').innerHTML = '<p>No registrations.</p>';
                $('#nicks-pagination').style.display = 'none';
                return;
            }

            let html = '<table class="table table-striped table-bordered table-condensed">';
            html += '<thead><tr><th>Nickname</th><th>Registered</th><th>Last Seen</th><th>MFA</th><th>Email</th><th>Actions</th></tr></thead><tbody>';
            data.forEach(r => {
                html += `<tr><td><strong>${escapeHtml(r.nickname)}</strong></td>`;
                html += `<td>${formatTimestamp(r.registered_at)}</td>`;
                html += `<td>${timeAgo(r.last_seen)}</td>`;
                html += `<td>${r.mfa_enabled ? '<span class="label label-success">Yes</span>' : '<span class="label label-default">No</span>'}</td>`;
                html += `<td>${escapeHtml(r.email)}</td>`;
                html += `<td>`;
                html += `<button class="btn btn-info btn-xs" onclick="openEditNickModal('${escapeHtml(r.nickname)}', '${escapeHtml(r.email)}')">Edit</button> `;
                html += `<button class="btn btn-danger btn-xs" onclick="unregisterNick('${escapeHtml(r.nickname)}')">Delete</button>`;
                html += `</td></tr>`;
            });
            html += '</tbody></table>';
            $('#recent-registrations').innerHTML = html;
            
            // Make table sortable
            const nickTable = $('#recent-registrations table');
            if (nickTable) makeSortable(nickTable);

            // Render pagination
            renderNicksPagination(total, page);
        });
    }

    function renderNicksPagination(total, currentPage) {
        const totalPages = Math.ceil(total / itemsPerPage);

        if (totalPages <= 1) {
            $('#nicks-pagination').style.display = 'none';
            return;
        }

        $('#nicks-pagination').style.display = 'flex';

        const start = (currentPage - 1) * itemsPerPage + 1;
        const end = Math.min(currentPage * itemsPerPage, total);

        let html = '';
        html += `<button class="btn btn-default" onclick="loadRecentRegs(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>`;
        html += `<span class="pagination-info">Page ${currentPage} of ${totalPages} (${start}-${end} of ${total})</span>`;
        html += `<button class="btn btn-default" onclick="loadRecentRegs(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Next</button>`;

        $('#nicks-pagination').innerHTML = html;
    }

    function renderChannelsPagination(total, currentPage) {
        const totalPages = Math.ceil(total / itemsPerPage);

        if (totalPages <= 1) {
            $('#channels-pagination').style.display = 'none';
            return;
        }

        $('#channels-pagination').style.display = 'flex';

        const start = (currentPage - 1) * itemsPerPage + 1;
        const end = Math.min(currentPage * itemsPerPage, total);

        let html = '';
        html += `<button class="btn btn-default" onclick="loadChannels(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>`;
        html += `<span class="pagination-info">Page ${currentPage} of ${totalPages} (${start}-${end} of ${total})</span>`;
        html += `<button class="btn btn-default" onclick="loadChannels(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Next</button>`;

        $('#channels-pagination').innerHTML = html;
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
    // TABLE SORTING UTILITY
    // ========================================================================
    
    function makeSortable(table) {
        const headers = table.querySelectorAll('thead th');
        headers.forEach((header, index) => {
            // Skip action columns
            if (header.textContent.trim() === 'Actions') {
                return;
            }
            
            header.style.cursor = 'pointer';
            header.style.userSelect = 'none';
            header.title = 'Click to sort';
            
            // Add sort indicator
            const indicator = document.createElement('span');
            indicator.className = 'sort-indicator';
            indicator.innerHTML = ' ↕';
            indicator.style.opacity = '0.3';
            header.appendChild(indicator);
            
            header.addEventListener('click', () => {
                sortTable(table, index, header);
            });
        });
    }
    
    function sortTable(table, columnIndex, header) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        // Determine current sort direction
        const currentDir = header.getAttribute('data-sort-dir') || 'asc';
        const newDir = currentDir === 'asc' ? 'desc' : 'asc';
        
        // Clear all sort indicators
        table.querySelectorAll('thead th').forEach(th => {
            th.removeAttribute('data-sort-dir');
            const indicator = th.querySelector('.sort-indicator');
            if (indicator) {
                indicator.innerHTML = ' ↕';
                indicator.style.opacity = '0.3';
            }
        });
        
        // Set new sort direction
        header.setAttribute('data-sort-dir', newDir);
        const indicator = header.querySelector('.sort-indicator');
        if (indicator) {
            indicator.innerHTML = newDir === 'asc' ? ' ↑' : ' ↓';
            indicator.style.opacity = '1';
        }
        
        // Sort rows
        rows.sort((a, b) => {
            const aCell = a.cells[columnIndex];
            const bCell = b.cells[columnIndex];
            
            // Get text content, handling nested elements
            let aText = aCell.textContent.trim();
            let bText = bCell.textContent.trim();
            
            // Try to parse as number
            const aNum = parseFloat(aText.replace(/[^0-9.-]/g, ''));
            const bNum = parseFloat(bText.replace(/[^0-9.-]/g, ''));
            
            let comparison = 0;
            if (!isNaN(aNum) && !isNaN(bNum)) {
                comparison = aNum - bNum;
            } else {
                comparison = aText.localeCompare(bText, undefined, {numeric: true, sensitivity: 'base'});
            }
            
            return newDir === 'asc' ? comparison : -comparison;
        });
        
        // Reorder rows in DOM
        rows.forEach(row => tbody.appendChild(row));
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
        const realname = $('#staff-realname').value.trim() || '';
        const email = $('#staff-email').value.trim() || '';
        const forceRealname = $('#staff-force-realname').checked ? '1' : '0';

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

        callAPI('add-staff', [username, password, level, realname, email, forceRealname]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-add-staff').style.display = 'none';
                $('#staff-username').value = '';
                $('#staff-password').value = '';
                $('#staff-password-confirm').value = '';
                $('#staff-realname').value = '';
                $('#staff-email').value = '';
                $('#staff-force-realname').checked = false;
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

    function updateStaffProfile() {
        const username = $('#modal-edit-staff').getAttribute('data-username');
        const realname = $('#edit-staff-realname').value.trim() || '';
        const email = $('#edit-staff-email').value.trim() || '';
        const forceRealname = $('#edit-staff-force-realname').checked ? '1' : '0';

        callAPI('update-staff-profile', [username, realname, email, forceRealname]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                loadStaff();
            }
        });
    }

    // ========================================================================
    // NICKNAME AND CHANNEL REGISTRATION
    // ========================================================================

    function registerNickname() {
        const nickname = $('#register-nick-nickname').value.trim();
        const password = $('#register-nick-password').value;
        const passwordConfirm = $('#register-nick-password-confirm').value;
        const email = $('#register-nick-email').value.trim();

        // Validation
        if (!nickname || !password) {
            showToast('Error', 'Nickname and password are required', 'error');
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

        const args = [nickname, password];
        if (email) {
            args.push(email);
        }

        callAPI('register-nick', args).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-register-nick').style.display = 'none';
                $('#register-nick-nickname').value = '';
                $('#register-nick-password').value = '';
                $('#register-nick-password-confirm').value = '';
                $('#register-nick-email').value = '';
                loadRecentRegs(nicksCurrentPage);
            }
        });
    }

    function registerChannel() {
        const channelName = $('#register-channel-name').value.trim();
        const ownerNick = $('#register-channel-owner').value.trim();

        // Validation
        if (!channelName || !ownerNick) {
            showToast('Error', 'Channel name and owner nickname are required', 'error');
            return;
        }

        if (!channelName.startsWith('#')) {
            showToast('Error', 'Channel name must start with #', 'error');
            return;
        }

        callAPI('register-channel', [channelName, ownerNick]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-register-channel').style.display = 'none';
                $('#register-channel-name').value = '';
                $('#register-channel-owner').value = '';
                loadChannels(channelsCurrentPage);
            }
        });
    }

    function unregisterNick(nickname) {
        if (!confirm(`Are you sure you want to unregister nickname '${nickname}'? This cannot be undone!`)) {
            return;
        }

        callAPI('unregister-nick', [nickname]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                loadRecentRegs(nicksCurrentPage);
            }
        });
    }

    function unregisterChannel(channelName) {
        if (!confirm(`Are you sure you want to unregister channel '${channelName}'? This cannot be undone!`)) {
            return;
        }

        callAPI('unregister-channel', [channelName]).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                loadChannels(channelsCurrentPage);
            }
        });
    }

    function openEditNickModal(nickname, email) {
        $('#edit-nick-name').textContent = nickname;
        $('#edit-nick-password').value = '';
        $('#edit-nick-password-confirm').value = '';
        $('#edit-nick-email').value = email && email !== 'Not set' ? email : '';
        $('#modal-edit-nick').style.display = 'block';
        $('#modal-edit-nick').setAttribute('data-nickname', nickname);
    }

    function editNickname() {
        const nickname = $('#modal-edit-nick').getAttribute('data-nickname');
        const password = $('#edit-nick-password').value;
        const passwordConfirm = $('#edit-nick-password-confirm').value;
        const email = $('#edit-nick-email').value.trim();

        // Validation
        if (password && password !== passwordConfirm) {
            showToast('Error', 'Passwords do not match', 'error');
            return;
        }

        if (password && password.length < 8) {
            showToast('Error', 'Password must be at least 8 characters', 'error');
            return;
        }

        if (!password && !email) {
            showToast('Error', 'No changes specified', 'error');
            return;
        }

        const args = [nickname, password || '', email || ''];

        callAPI('edit-nick', args).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                showToast('Success', res.message, 'success');
                $('#modal-edit-nick').style.display = 'none';
                loadRecentRegs(nicksCurrentPage);
            }
        });
    }

    function openEditChannelModal(channelName, owner) {
        $('#edit-channel-name').textContent = channelName;
        $('#edit-channel-owner').value = '';
        $('#edit-channel-description').value = '';
        $('#edit-channel-topic').value = '';
        $('#edit-channel-onjoin').value = '';
        $('#edit-channel-onpart').value = '';
        $('#edit-channel-memberkey').value = '';
        $('#edit-channel-hostkey').value = '';
        $('#edit-channel-ownerkey').value = '';
        $('#edit-channel-userlimit').value = '';

        // Clear all mode checkboxes
        ['n', 't', 'i', 'm', 'p', 's', 'a', 'd', 'f', 'h', 'j', 'u', 'w', 'x', 'y'].forEach(mode => {
            const checkbox = $(`#mode-${mode}`);
            if (checkbox) checkbox.checked = false;
        });
        $('#mode-clear').checked = false;

        // Load ACCESS lists for this channel
        loadAccessLists(channelName);

        // Show first ACCESS tab by default
        showAccessTab('owner');

        $('#modal-edit-channel').style.display = 'block';
        $('#modal-edit-channel').setAttribute('data-channel', channelName);
    }

    function editChannel() {
        const channelName = $('#modal-edit-channel').getAttribute('data-channel');

        // Collect all field values
        const owner = $('#edit-channel-owner').value.trim();
        const description = $('#edit-channel-description').value.trim();
        const topic = $('#edit-channel-topic').value.trim();
        const onjoin = $('#edit-channel-onjoin').value.trim();
        const onpart = $('#edit-channel-onpart').value.trim();
        const memberkey = $('#edit-channel-memberkey').value.trim();
        const hostkey = $('#edit-channel-hostkey').value.trim();
        const ownerkey = $('#edit-channel-ownerkey').value.trim();

        // Build modes string from checkboxes
        let modes = '';
        if ($('#mode-clear').checked) {
            // Clear all modes
            modes = '*';
        } else {
            // Collect checked modes (Basic: n,t,i,m,p,s | Extended: a,d,f,h,j,u,w,x,y)
            const modesList = [];
            const modeCheckboxes = ['n', 't', 'i', 'm', 'p', 's', 'a', 'd', 'f', 'h', 'j', 'u', 'w', 'x', 'y'];
            for (const mode of modeCheckboxes) {
                if ($('#mode-' + mode).checked) {
                    modesList.push(mode);
                }
            }

            // Add +l mode if user limit is specified
            const userLimit = $('#edit-channel-userlimit').value.trim();
            if (userLimit && parseInt(userLimit) > 0) {
                modesList.push('l');
            }

            // Only set modes if at least one checkbox is checked
            if (modesList.length > 0) {
                modes = modesList.join('');
            }
        }

        // Check if any changes were made
        if (!owner && !description && !topic && !modes && !onjoin && !onpart &&
            !memberkey && !hostkey && !ownerkey) {
            showToast('Error', 'No changes specified', 'error');
            return;
        }

        // Build args array with all parameters
        const args = [
            channelName,
            owner || '',
            description || '',
            topic || '',
            modes || '',
            onjoin || '',
            onpart || '',
            memberkey || '',
            hostkey || '',
            ownerkey || ''
        ];

        callAPI('edit-channel', args).then(res => {
            if (res.error) {
                showToast('Error', res.error, 'error');
            } else {
                // Save ACCESS lists
                return saveAccessLists(channelName).then(accessRes => {
                    if (accessRes && accessRes.error) {
                        showToast('Warning', 'Channel updated but ACCESS save failed: ' + accessRes.error, 'warning');
                    } else {
                        showToast('Success', res.message, 'success');
                    }
                    $('#modal-edit-channel').style.display = 'none';
                    loadChannels(channelsCurrentPage);
                }).catch(err => {
                    showToast('Warning', 'Channel updated but ACCESS save failed', 'warning');
                    $('#modal-edit-channel').style.display = 'none';
                    loadChannels(channelsCurrentPage);
                });
            }
        });
    }

    function loadLogs() {
        const level = $('#log-level-filter').value || null;
        const search = $('#log-search-input').value || null;
        const args = ['200'];  // Increased to 200 lines
        if (level) args.push(level);
        if (search) args.push(search);

        callAPI('logs', args).then(data => {
            if (data.error) {
                $('#server-logs').innerHTML = `<div class="alert alert-danger">Error: ${escapeHtml(data.error)}</div>`;
                return;
            }
            
            if (!data.logs || data.logs.trim() === '') {
                $('#server-logs').innerHTML = '<div class="empty-state"><div class="empty-state-icon">📄</div><div class="empty-state-text">No Logs Found</div></div>';
                return;
            }
            
            // Parse log lines
            const logLines = data.logs.trim().split('\n');
            // Support both journalctl format and file format
            const journalRegex = /^\S+\s+(\S+\s+\S+)\s+\S+\s+pyircx\[\d+\]:\s+\[([A-Z]+)\]\s+\S+:\s+(.+)$/;
            const fileRegex = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+\[([A-Z]+)\]\s+(.+)$/;
            
            let html = '<table class="table table-striped table-bordered log-table">';
            html += '<thead><tr><th width="180">Timestamp</th><th width="80">Level</th><th>Message</th></tr></thead><tbody>';
            
            logLines.reverse().forEach(line => {
                let match = line.match(journalRegex) || line.match(fileRegex);
                if (match) {
                    const [, timestamp, level, message] = match;
                    const levelClass = level === 'ERROR' ? 'danger' : level === 'WARNING' ? 'warning' : 'info';
                    html += '<tr>';
                    html += `<td style="font-family: monospace; font-size: 12px;">${escapeHtml(timestamp)}</td>`;
                    html += `<td><span class="label label-${levelClass}">${level}</span></td>`;
                    html += `<td style="font-size: 13px;">${escapeHtml(message)}</td>`;
                    html += '</tr>';
                } else if (line.trim() && !line.includes('-- Boot ') && !line.includes('-- Journal')) {
                    // Fallback for non-standard log lines (skip journal metadata)
                    html += '<tr>';
                    html += '<td colspan="3" style="font-family: monospace; font-size: 12px;">' + escapeHtml(line) + '</td>';
                    html += '</tr>';
                }
            });
            
            html += '</tbody></table>';
            html += `<div style="margin-top: 10px; color: #666; font-size: 13px;">Showing ${logLines.length} log entries</div>`;
            $('#server-logs').innerHTML = html;
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
    }

    function navigateToPage(pageName) {
        $$('.nav-item').forEach(item => item.classList.remove('active'));
        $(`.nav-item[data-page="${pageName}"]`)?.classList.add('active');
        $$('.page').forEach(page => page.classList.remove('active'));
        if (pageName === 'config') initConfigForm();
        $(`#page-${pageName}`)?.classList.add('active');
        
        switch(pageName) {
            case 'dashboard': loadServiceStatus(); loadRealtimeStatus(); loadStats(); break;
            case 'users': loadRecentRegs(); loadRealtimeStatus(); break;
            case 'channels': loadChannels(); loadRealtimeStatus(); break;
            case 'staff': loadStaff(); break;
            case 'access': loadAccessList(); break;
            case 'newsflash': loadNewsflash(); loadNewsflashSettings(); break;
            case 'mailbox': loadMailbox(); break;
            case 'config': initConfigForm(); break;
            case 'logs': loadLogs(); break;
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
    // Global fetch wrapper to handle 401 unauthorized
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        return originalFetch.apply(this, args).then(response => {
            if (response.status === 401) {
                window.location.href = 'login.php';
                throw new Error('Unauthorized');
            }
            return response;
        });
    };
        console.log('pyIRCX initializing');
        $$('.nav-item').forEach(item => {
            item.addEventListener('click', function(e) {
                // Allow logout link to work normally
                if (this.classList.contains('nav-logout')) {
                    return; // Let the browser handle the navigation
                }
                e.preventDefault();
                navigateToPage(this.getAttribute('data-page'));
            });
        });
        navigateToPage(window.location.hash.substring(1) || 'dashboard');
        loadAll();
        setInterval(() => { if ($('.page.active')?.id === 'page-dashboard') { loadServiceStatus(); loadRealtimeStatus(); } }, 10000);

        // Nickname Editing
        if ($('#btn-cancel-edit-nick')) {
            $('#btn-cancel-edit-nick').addEventListener('click', () => {
                $('#modal-edit-nick').style.display = 'none';
            });
        }
        if ($('#btn-save-edit-nick')) {
            $('#btn-save-edit-nick').addEventListener('click', editNickname);
        }

        // Channel Editing
        if ($('#btn-cancel-edit-channel')) {
            $('#btn-cancel-edit-channel').addEventListener('click', () => {
                $('#modal-edit-channel').style.display = 'none';
            });
        }
        if ($('#btn-save-edit-channel')) {
            $('#btn-save-edit-channel').addEventListener('click', editChannel);
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
        if ($('#btn-update-profile')) {
            $('#btn-update-profile').addEventListener('click', updateStaffProfile);
        }

        // Nickname Registration
        if ($('#btn-cancel-register-nick')) {
            $('#btn-cancel-register-nick').addEventListener('click', () => {
                $('#modal-register-nick').style.display = 'none';
            });
        }
        if ($('#btn-save-register-nick')) {
            $('#btn-save-register-nick').addEventListener('click', registerNickname);
        }

        // Channel Registration
        if ($('#btn-cancel-register-channel')) {
            $('#btn-cancel-register-channel').addEventListener('click', () => {
                $('#modal-register-channel').style.display = 'none';
            });
        }
        if ($('#btn-save-register-channel')) {
            $('#btn-save-register-channel').addEventListener('click', registerChannel);
        }

        // Config editor
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
        
        // Mailbox
        if ($('#btn-send-mailbox')) {
            $('#btn-send-mailbox').addEventListener('click', () => {
                $('#modal-send-mailbox').style.display = 'block';
            });
        }
        if ($('#btn-save-mailbox')) {
            $('#btn-save-mailbox').addEventListener('click', sendMailboxMessage);
        }
        if ($('#btn-cancel-mailbox')) {
            $('#btn-cancel-mailbox').addEventListener('click', () => {
                $('#modal-send-mailbox').style.display = 'none';
            });
        }
        if ($('#log-level-filter')) $('#log-level-filter').addEventListener('change', loadLogs);
    });

    window.openModal = openModal;
    window.loadRecentRegs = loadRecentRegs;
    window.loadChannels = loadChannels;
    window.unregisterNick = unregisterNick;
    window.unregisterChannel = unregisterChannel;
    window.openEditNickModal = openEditNickModal;
    window.openEditChannelModal = openEditChannelModal;

    // ACCESS list management
    let currentAccessLists = {
        OWNER: [],
        HOST: [],
        VOICE: [],
        GRANT: [],
        DENY: []
    };

    function showAccessTab(level) {
        // Hide all panels
        $$('.access-panel').forEach(panel => panel.style.display = 'none');

        // Remove active state from all tabs
        ['owner', 'host', 'voice', 'grant', 'deny'].forEach(l => {
            const tab = $(`#access-tab-${l}`);
            if (tab) tab.style.fontWeight = 'normal';
        });

        // Show selected panel and mark tab as active
        const panel = $(`#access-${level}`);
        if (panel) panel.style.display = 'block';

        const tab = $(`#access-tab-${level}`);
        if (tab) tab.style.fontWeight = '600';
    }

    function loadAccessLists(channelName) {
        // Load ACCESS lists for the channel
        callAPI('get-channel-access', [channelName]).then(res => {
            if (res.error) {
                console.error('Failed to load ACCESS lists:', res.error);
                currentAccessLists = {OWNER: [], HOST: [], VOICE: [], GRANT: [], DENY: []};
            } else {
                currentAccessLists = res.access_list || {OWNER: [], HOST: [], VOICE: [], GRANT: [], DENY: []};
            }

            // Update all list displays
            ['owner', 'host', 'voice', 'grant', 'deny'].forEach(level => {
                refreshAccessList(level);
            });
        });
    }

    function refreshAccessList(level) {
        const levelUpper = level.toUpperCase();
        const listDiv = $(`#access-${level}-list`);
        if (!listDiv) return;

        const entries = currentAccessLists[levelUpper] || [];
        if (entries.length === 0) {
            listDiv.innerHTML = '<em style="color: #999;">No entries</em>';
            return;
        }

        let html = '<div style="max-height: 200px; overflow-y: auto;">';
        entries.forEach((entry, index) => {
            const mask = entry[0] || entry;  // Support both array format and simple string
            html += `<div style="padding: 5px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center;">
                <code>${escapeHtml(mask)}</code>
                <button type="button" class="btn btn-sm btn-danger" onclick="removeAccessEntry('${level}', ${index})" style="padding: 2px 8px;">Remove</button>
            </div>`;
        });
        html += '</div>';
        listDiv.innerHTML = html;
    }

    function addAccessEntry(level) {
        const input = $(`#access-${level}-mask`);
        if (!input) return;

        const mask = input.value.trim();
        if (!mask) {
            showToast('Error', 'Please enter a hostmask', 'error');
            return;
        }

        // Basic validation
        if (!mask.includes('!') || !mask.includes('@')) {
            showToast('Error', 'Hostmask must be in format: nick!user@host', 'error');
            return;
        }

        const levelUpper = level.toUpperCase();
        if (!currentAccessLists[levelUpper]) {
            currentAccessLists[levelUpper] = [];
        }

        // Add entry (format: [mask, set_by, set_at, timeout, reason])
        currentAccessLists[levelUpper].push([mask, 'admin', Math.floor(Date.now() / 1000), 0, '']);
        refreshAccessList(level);
        input.value = '';
        showToast('Success', `Added ${mask} to ${levelUpper} list`, 'success');
    }

    function removeAccessEntry(level, index) {
        const levelUpper = level.toUpperCase();
        if (!currentAccessLists[levelUpper] || index >= currentAccessLists[levelUpper].length) {
            return;
        }

        const removed = currentAccessLists[levelUpper].splice(index, 1);
        refreshAccessList(level);
        showToast('Success', `Removed ${removed[0][0] || removed[0]} from ${levelUpper} list`, 'success');
    }

    function saveAccessLists(channelName) {
        // Save ACCESS lists with channel edits
        return callAPI('set-channel-access', [channelName, JSON.stringify(currentAccessLists)]);
    }

    window.showAccessTab = showAccessTab;
    window.addAccessEntry = addAccessEntry;
    window.removeAccessEntry = removeAccessEntry;
    window.loadAccessLists = loadAccessLists;

    // Configuration form management
    let currentConfig = null;

    function initConfigForm() {
        // Tab switching
        $$('.config-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                const tabName = this.getAttribute('data-tab');
                $$('.config-tab').forEach(t => t.classList.remove('active'));
                $$('.config-tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                $('#config-tab-' + tabName).classList.add('active');
            });
        });

        // Load configuration into form
        loadConfigForm();

        // Save button
        if ($('#btn-save-config-form')) {
            $('#btn-save-config-form').addEventListener('click', saveConfigForm);
        }

        // Edit JSON button (opens old modal)
        if ($('#btn-edit-config-json')) {
            $('#btn-edit-config-json').addEventListener('click', () => {
                if (currentConfig) {
                    $('#config-editor').value = JSON.stringify(currentConfig, null, 2);
                    $('#modal-edit-config').style.display = 'block';
                }
            });
        }
    }

    function loadConfigForm() {
        callAPI('full-config').then(config => {
            if (config.error) {
                showToast('Error', 'Failed to load configuration', 'error');
                return;
            }
            currentConfig = config;

            // Server settings
            $('#cfg-server-name').value = config.server?.name || '';
            $('#cfg-server-network').value = config.server?.network || '';
            $('#cfg-server-staff-message').value = config.server?.staff_login_message || '';

            // Network settings
            $('#cfg-network-addr').value = config.network?.listen_addr || '';
            $('#cfg-network-ports').value = (config.network?.listen_ports || []).join(',');
            $('#cfg-network-ipv6').checked = config.network?.enable_ipv6 || false;
            $('#cfg-network-resolve').checked = config.network?.resolve_hostnames || false;

            // Database settings
            $('#cfg-database-path').value = config.database?.path || '';
            $('#cfg-database-pool').value = config.database?.pool_size || 5;

            // Limits
            $('#cfg-limits-max-users').value = config.limits?.max_users || 1000;
            $('#cfg-limits-msg-length').value = config.limits?.msg_length || 512;
            $('#cfg-limits-nick-cooldown').value = config.limits?.nick_change_cooldown || 60;
            $('#cfg-limits-max-nick').value = config.limits?.max_nick_length || 30;
            $('#cfg-limits-max-user').value = config.limits?.max_user_length || 30;
            $('#cfg-limits-max-channel').value = config.limits?.max_channel_length || 50;
            $('#cfg-limits-max-channels').value = config.limits?.max_channels || 500;
            $('#cfg-limits-max-channels-user').value = config.limits?.max_channels_per_user || 20;

            // Security
            $('#cfg-security-flood-enabled').checked = config.security?.enable_flood_protection || false;
            $('#cfg-security-flood-msgs').value = config.security?.flood_messages || 5;
            $('#cfg-security-flood-window').value = config.security?.flood_window || 2;
            $('#cfg-security-throttle-enabled').checked = config.security?.enable_connection_throttle || false;
            $('#cfg-security-throttle').value = config.security?.connection_throttle || 100;
            $('#cfg-security-throttle-window').value = config.security?.throttle_window || 60;
            $('#cfg-security-cap-timeout').value = config.security?.cap_timeout || 60;
            $('#cfg-security-auth-attempts').value = config.security?.auth_max_attempts || 5;
            $('#cfg-security-auth-lockout').value = config.security?.auth_lockout_duration || 300;
            $('#cfg-security-auth-window').value = config.security?.auth_lockout_window || 600;

            // DNSBL
            $('#cfg-dnsbl-enabled').checked = config.security?.dnsbl?.enabled || false;
            $('#cfg-dnsbl-action').value = config.security?.dnsbl?.action || 'reject';
            $('#cfg-dnsbl-lists').value = (config.security?.dnsbl?.lists || []).join('\n');

            // Proxy detection
            $('#cfg-proxy-enabled').checked = config.security?.proxy_detection?.enabled || false;
            $('#cfg-proxy-ports').value = (config.security?.proxy_detection?.ports || []).join(',');
            $('#cfg-proxy-action').value = config.security?.proxy_detection?.action || 'reject';

            // Services
            $('#cfg-servicebot-enabled').checked = config.servicebot?.enabled || false;
            $('#cfg-services-count').value = config.services?.servicebot_count || 10;
            $('#cfg-services-max-channels').value = config.services?.servicebot_max_channels || 10;
            $('#cfg-profanity-enabled').checked = config.servicebot?.profanity_filter?.enabled || false;
            $('#cfg-profanity-action').value = config.servicebot?.profanity_filter?.action || 'warn';
            $('#cfg-profanity-case').checked = config.servicebot?.profanity_filter?.case_sensitive || false;
            $('#cfg-malicious-enabled').checked = config.servicebot?.malicious_detection?.enabled || false;
            $('#cfg-malicious-flood-threshold').value = config.servicebot?.malicious_detection?.flood_threshold || 5;
            $('#cfg-malicious-caps').value = config.servicebot?.malicious_detection?.caps_threshold || 0.7;
            $('#cfg-malicious-url').value = config.servicebot?.malicious_detection?.url_spam_threshold || 3;

            // SSL
            $('#cfg-ssl-enabled').checked = config.ssl?.enabled || false;
            $('#cfg-ssl-ports').value = (config.ssl?.ports || []).join(',');
            $('#cfg-ssl-cert').value = config.ssl?.cert_file || '';
            $('#cfg-ssl-key').value = config.ssl?.key_file || '';
            $('#cfg-ssl-min-version').value = config.ssl?.min_version || 'TLSv1.2';
            $('#cfg-ssl-auto-reload').checked = config.ssl?.auto_reload || false;

            // Linking
            $('#cfg-linking-enabled').checked = config.linking?.enabled || false;
            $('#cfg-linking-host').value = config.linking?.bind_host || '';
            $('#cfg-linking-port').value = config.linking?.bind_port || 7001;

            // Advanced
            $('#cfg-transcript-enabled').checked = config.transcript?.enabled || false;
            $('#cfg-transcript-dir').value = config.transcript?.directory || '';
            $('#cfg-transcript-max').value = config.transcript?.max_lines || 10000;
            $('#cfg-persist-auto').checked = config.persistence?.auto_save || false;
            $('#cfg-persist-interval').value = config.persistence?.save_interval || 300;
            $('#cfg-newsflash-connect').checked = config.newsflash?.on_connect || false;
            $('#cfg-newsflash-periodic').checked = config.newsflash?.periodic_enabled || false;
            $('#cfg-newsflash-interval').value = config.newsflash?.periodic_interval || 3600;
        });
    }

    function saveConfigForm() {
        if (!currentConfig) {
            showToast('Error', 'Configuration not loaded', 'error');
            return;
        }

        // Build config object from form
        const newConfig = JSON.parse(JSON.stringify(currentConfig)); // Deep clone

        // Server settings
        newConfig.server.name = $('#cfg-server-name').value;
        newConfig.server.network = $('#cfg-server-network').value;
        newConfig.server.staff_login_message = $('#cfg-server-staff-message').value;

        // Network settings
        newConfig.network.listen_addr = $('#cfg-network-addr').value;
        newConfig.network.listen_ports = $('#cfg-network-ports').value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        newConfig.network.enable_ipv6 = $('#cfg-network-ipv6').checked;
        newConfig.network.resolve_hostnames = $('#cfg-network-resolve').checked;

        // Database settings
        newConfig.database.path = $('#cfg-database-path').value;
        newConfig.database.pool_size = parseInt($('#cfg-database-pool').value);

        // Limits
        newConfig.limits.max_users = parseInt($('#cfg-limits-max-users').value);
        newConfig.limits.msg_length = parseInt($('#cfg-limits-msg-length').value);
        newConfig.limits.nick_change_cooldown = parseInt($('#cfg-limits-nick-cooldown').value);
        newConfig.limits.max_nick_length = parseInt($('#cfg-limits-max-nick').value);
        newConfig.limits.max_user_length = parseInt($('#cfg-limits-max-user').value);
        newConfig.limits.max_channel_length = parseInt($('#cfg-limits-max-channel').value);
        newConfig.limits.max_channels = parseInt($('#cfg-limits-max-channels').value);
        newConfig.limits.max_channels_per_user = parseInt($('#cfg-limits-max-channels-user').value);

        // Security
        newConfig.security.enable_flood_protection = $('#cfg-security-flood-enabled').checked;
        newConfig.security.flood_messages = parseInt($('#cfg-security-flood-msgs').value);
        newConfig.security.flood_window = parseInt($('#cfg-security-flood-window').value);
        newConfig.security.enable_connection_throttle = $('#cfg-security-throttle-enabled').checked;
        newConfig.security.connection_throttle = parseInt($('#cfg-security-throttle').value);
        newConfig.security.throttle_window = parseInt($('#cfg-security-throttle-window').value);
        newConfig.security.cap_timeout = parseInt($('#cfg-security-cap-timeout').value);
        newConfig.security.auth_max_attempts = parseInt($('#cfg-security-auth-attempts').value);
        newConfig.security.auth_lockout_duration = parseInt($('#cfg-security-auth-lockout').value);
        newConfig.security.auth_lockout_window = parseInt($('#cfg-security-auth-window').value);

        // DNSBL
        newConfig.security.dnsbl.enabled = $('#cfg-dnsbl-enabled').checked;
        newConfig.security.dnsbl.action = $('#cfg-dnsbl-action').value;
        newConfig.security.dnsbl.lists = $('#cfg-dnsbl-lists').value.split('\n').map(l => l.trim()).filter(l => l);

        // Proxy detection
        newConfig.security.proxy_detection.enabled = $('#cfg-proxy-enabled').checked;
        newConfig.security.proxy_detection.ports = $('#cfg-proxy-ports').value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        newConfig.security.proxy_detection.action = $('#cfg-proxy-action').value;

        // Services
        newConfig.servicebot.enabled = $('#cfg-servicebot-enabled').checked;
        newConfig.services.servicebot_count = parseInt($('#cfg-services-count').value);
        newConfig.services.servicebot_max_channels = parseInt($('#cfg-services-max-channels').value);
        newConfig.servicebot.profanity_filter.enabled = $('#cfg-profanity-enabled').checked;
        newConfig.servicebot.profanity_filter.action = $('#cfg-profanity-action').value;
        newConfig.servicebot.profanity_filter.case_sensitive = $('#cfg-profanity-case').checked;
        newConfig.servicebot.malicious_detection.enabled = $('#cfg-malicious-enabled').checked;
        newConfig.servicebot.malicious_detection.flood_threshold = parseInt($('#cfg-malicious-flood-threshold').value);
        newConfig.servicebot.malicious_detection.caps_threshold = parseFloat($('#cfg-malicious-caps').value);
        newConfig.servicebot.malicious_detection.url_spam_threshold = parseInt($('#cfg-malicious-url').value);

        // SSL
        newConfig.ssl.enabled = $('#cfg-ssl-enabled').checked;
        newConfig.ssl.ports = $('#cfg-ssl-ports').value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        newConfig.ssl.cert_file = $('#cfg-ssl-cert').value;
        newConfig.ssl.key_file = $('#cfg-ssl-key').value;
        newConfig.ssl.min_version = $('#cfg-ssl-min-version').value;
        newConfig.ssl.auto_reload = $('#cfg-ssl-auto-reload').checked;

        // Linking
        newConfig.linking.enabled = $('#cfg-linking-enabled').checked;
        newConfig.linking.bind_host = $('#cfg-linking-host').value;
        newConfig.linking.bind_port = parseInt($('#cfg-linking-port').value);

        // Advanced
        newConfig.persistence.auto_save = $('#cfg-persist-auto').checked;
        newConfig.persistence.save_interval = parseInt($('#cfg-persist-interval').value);
        newConfig.newsflash.on_connect = $('#cfg-newsflash-connect').checked;
        newConfig.newsflash.periodic_enabled = $('#cfg-newsflash-periodic').checked;
        newConfig.newsflash.periodic_interval = parseInt($('#cfg-newsflash-interval').value);

        // Confirm and save
        if (confirm('Save configuration and restart server?')) {
            callAPI('set-config', [JSON.stringify(newConfig)]).then(res => {
                if (res.error) {
                    showToast('Error', res.error, 'error');
                } else {
                    showToast('Success', 'Configuration saved, restarting service...', 'success');
                    controlService('restart');
                    currentConfig = newConfig;
                }
            });
        }
    }

    // MOTD Editor Functions
    window.loadMotd = async function() {
        try {
            const res = await callAPI('get-motd');
            if (res.error) {
                showToast('Error', res.error, 'error');
                return;
            }

            const motdEditor = $('#motd-editor');
            if (res.motd && Array.isArray(res.motd)) {
                motdEditor.value = res.motd.join('\n');
            } else {
                motdEditor.value = '';
            }
            showToast('Success', 'MOTD loaded', 'success');
        } catch (err) {
            showToast('Error', 'Failed to load MOTD: ' + err.message, 'error');
        }
    };

    window.saveMotd = async function() {
        const motdEditor = $('#motd-editor');
        const motdText = motdEditor.value.trim();

        if (!motdText) {
            if (!confirm('Set an empty MOTD? This will use the default MOTD.')) {
                return;
            }
        }

        try {
            const res = await callAPI('set-motd', [motdText]);
            if (res.error) {
                showToast('Error', res.error, 'error');
                return;
            }

            showToast('Success', 'MOTD saved successfully! Reload the service for changes to take effect.', 'success');
        } catch (err) {
            showToast('Error', 'Failed to save MOTD: ' + err.message, 'error');
        }
    };

    // Load MOTD when config page is shown
    const originalShowPage = window.showPage;
    window.showPage = function(page) {
        originalShowPage(page);
        if (page === 'config') {
            // Load MOTD if MOTD tab becomes active
            const motdTab = document.querySelector('[data-tab="motd"]');
            if (motdTab) {
                motdTab.addEventListener('click', () => {
                    setTimeout(() => loadMotd(), 100);
                }, { once: true });
            }
        }
    };
})();
console.log("=== admin.js LOADED ===");
