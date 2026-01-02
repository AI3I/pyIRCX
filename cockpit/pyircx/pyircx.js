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
        return cockpit.spawn(fullArgs, { err: 'message' })
            .then(out => JSON.parse(out))
            .catch(err => ({ error: err.message || 'Unknown error' }));
    }

    // Service control
    function controlService(action) {
        cockpit.spawn(['sudo', 'systemctl', action, 'pyircx.service'], { err: 'message', superuser: 'try' })
            .then(() => setTimeout(loadServiceStatus, 1000))
            .catch(err => alert(`Failed to ${action}: ${err.message}`));
    }

    // Load functions
    function loadServiceStatus() {
        cockpit.spawn(['systemctl', 'is-active', 'pyircx.service'], { err: 'ignore' })
            .then(out => {
                const status = out.trim();
                let html = status === 'active' ? '<span class="label label-success">Running</span>' :
                          status === 'inactive' ? '<span class="label label-default">Stopped</span>' :
                          status === 'failed' ? '<span class="label label-danger">Failed</span>' :
                          '<span class="label label-warning">Unknown</span>';
                $('#service-status').innerHTML = html;
            })
            .catch(() => {
                $('#service-status').innerHTML = '<span class="label label-warning">Not found</span>';
            });
    }

    function loadRealtimeStatus() {
        callAPI('realtime-status').then(data => {
            if (data.error) {
                $('#realtime-status').innerHTML = `<div class="alert alert-warning">${escapeHtml(data.error)}</div>`;
                $('#connected-users').innerHTML = '<p>Server not running.</p>';
                $('#active-channels').innerHTML = '<p>Server not running.</p>';
                $('#connected-count').textContent = '0';
                $('#channel-count').textContent = '0';
                return;
            }

            const age = data.status_age || 0;
            const color = age < 30 ? 'success' : (age < 60 ? 'warning' : 'danger');
            $('#realtime-status').innerHTML = `<p>Last updated: <span class="label label-${color}">${Math.floor(age)}s ago</span></p>`;

            const users = data.connected_users || [];
            $('#connected-count').textContent = users.length;

            if (users.length === 0) {
                $('#connected-users').innerHTML = '<p>No users connected.</p>';
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

            if (chans.length === 0) {
                $('#active-channels').innerHTML = '<p>No active channels.</p>';
            } else {
                let html = '<table class="table table-striped table-bordered table-condensed">';
                html += '<thead><tr><th>Channel</th><th>Topic</th><th>Members</th></tr></thead><tbody>';
                chans.forEach(c => {
                    const topic = c.topic || '(No topic)';
                    html += `<tr><td><strong>${escapeHtml(c.name)}</strong></td>`;
                    html += `<td>${escapeHtml(topic)}</td><td>${c.member_count}</td></tr>`;
                });
                html += '</tbody></table>';
                $('#active-channels').innerHTML = html;
            }
        });
    }

    function loadStats() {
        callAPI('stats').then(data => {
            if (data.error) {
                $('#server-stats').innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error)}</div>`;
                return;
            }
            let html = '<dl class="dl-horizontal">';
            html += `<dt>Staff:</dt><dd>${data.staff.total}</dd>`;
            html += `<dt>Registered Nicks:</dt><dd>${data.registered_nicks}</dd>`;
            html += `<dt>Registered Channels:</dt><dd>${data.registered_channels}</dd>`;
            html += `<dt>Unread Mailbox:</dt><dd>${data.unread_mailbox}</dd>`;
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
                $('#access-list').innerHTML = '<p>No access rules configured.</p>';
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
                            if (res.error) alert(`Error: ${res.error}`);
                            else loadAccessList();
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
                    if (confirm('Delete this newsflash?')) {
                        callAPI('delete-newsflash', [id]).then(res => {
                            if (res.error) alert(`Error: ${res.error}`);
                            else loadNewsflash();
                        });
                    }
                });
            });
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
                $('#staff-list').innerHTML = '<p>No staff.</p>';
                return;
            }
            let html = '<table class="table table-striped table-bordered">';
            html += '<thead><tr><th>Username</th><th>Level</th></tr></thead><tbody>';
            data.forEach(s => {
                const levelClass = {'SYSOP': 'danger', 'ADMIN': 'warning', 'GUIDE': 'info'}[s.level] || 'default';
                html += `<tr><td>${escapeHtml(s.username)}</td>`;
                html += `<td><span class="label label-${levelClass}">${s.level}</span></td></tr>`;
            });
            html += '</tbody></table>';
            $('#staff-list').innerHTML = html;
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
                    alert('Fill in all fields');
                    return;
                }
                callAPI('add-server-access', [type, pattern, currentUser.name, reason, timeout]).then(res => {
                    if (res.error) alert(`Error: ${res.error}`);
                    else {
                        $('#modal-add-access').style.display = 'none';
                        $('#access-pattern').value = '';
                        $('#access-reason').value = '';
                        $('#access-timeout').value = '0';
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
                    alert('Enter a message');
                    return;
                }
                callAPI('add-newsflash', [msg, currentUser.name, priority]).then(res => {
                    if (res.error) alert(`Error: ${res.error}`);
                    else {
                        $('#modal-add-newsflash').style.display = 'none';
                        $('#newsflash-message').value = '';
                        $('#newsflash-priority').value = '0';
                        loadNewsflash();
                    }
                });
            });
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
                    alert(`Invalid JSON: ${e.message}`);
                    return;
                }
                if (confirm('Save config and restart?')) {
                    callAPI('set-config', [configText]).then(res => {
                        if (res.error) alert(`Error: ${res.error}`);
                        else {
                            $('#modal-edit-config').style.display = 'none';
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
