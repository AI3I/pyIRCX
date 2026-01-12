<?php
session_start();

// Authentication check - redirect to login if not authenticated
if (!isset($_SESSION["admin_user"]) || !isset($_SESSION["admin_level"]) || $_SESSION["admin_level"] !== "ADMIN") {
    header("Location: login.php");
    exit();
}

$admin_user = htmlspecialchars($_SESSION["admin_user"]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pyIRCX Server Administration</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Toast Container -->
    <div class="toast-container" id="toast-container"></div>

    <!-- Main Layout -->
    <div class="layout">
        <!-- Sidebar Navigation -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <h1>💬 pyIRCX</h1>
                <div class="sidebar-subtitle">Administration Panel</div>
                <div class="sidebar-user" style="margin-top: 8px; font-size: 13px; opacity: 0.9;">Logged in as: <strong><?php echo $admin_user; ?></strong></div>
            </div>
            <nav class="sidebar-nav">
                <a href="#dashboard" class="nav-item active" data-page="dashboard">
                    <span class="nav-icon">📊</span>
                    <span class="nav-label">Dashboard</span>
                </a>
                <a href="#users" class="nav-item" data-page="users">
                    <span class="nav-icon">👥</span>
                    <span class="nav-label">Users</span>
                </a>
                <a href="#channels" class="nav-item" data-page="channels">
                    <span class="nav-icon">💬</span>
                    <span class="nav-label">Channels</span>
                </a>
                <a href="#staff" class="nav-item" data-page="staff">
                    <span class="nav-icon">👮</span>
                    <span class="nav-label">Staff</span>
                </a>
                <a href="#access" class="nav-item" data-page="access">
                    <span class="nav-icon">🛡️</span>
                    <span class="nav-label">Access Control</span>
                </a>
                <a href="#newsflash" class="nav-item" data-page="newsflash">
                    <span class="nav-icon">📢</span>
                    <span class="nav-label">NewsFlash</span>
                </a>
                <a href="#mailbox" class="nav-item" data-page="mailbox">
                    <span class="nav-icon">📬</span>
                    <span class="nav-label">Mailbox</span>
                </a>
                <a href="#config" class="nav-item" data-page="config">
                    <span class="nav-icon">⚙️</span>
                    <span class="nav-label">Configuration</span>
                </a>
                <a href="#logs" class="nav-item" data-page="logs">
                    <span class="nav-icon">📄</span>
                    <span class="nav-label">Logs</span>
                </a>
                <a href="logout.php" class="nav-item nav-logout" style="margin-top: auto; background: rgba(231, 76, 60, 0.2); border-left: 4px solid #c0392b;">
                    <span class="nav-icon">🚪</span>
                    <span class="nav-label">Logout</span>
                </a>
            </nav>
        </aside>

        <!-- Main Content Area -->
        <main class="content">
            <!-- Dashboard Page -->
            <div class="page active" id="page-dashboard">
                <div class="page-header">
                    <h2>Dashboard</h2>
                    <p>Server overview and statistics</p>
                </div>


                <!-- Service Control -->
                <div class="card">
                    <div class="card-header">
                        <h3>🔌 Service Control</h3>
                    </div>
                    <div class="card-body">
                        <div id="service-status">Loading...</div>
                        <div class="button-group">
                            <button class="btn btn-success" id="btn-start">▶️ Start</button>
                            <button class="btn btn-warning" id="btn-restart">🔄 Restart</button>
                            <button class="btn btn-danger" id="btn-stop">⏹️ Stop</button>
                        </div>
                    </div>
                </div>

                <!-- Server Statistics -->
                <div class="card">
                    <div class="card-header">
                        <h3>📈 Server Statistics</h3>
                    </div>
                    <div class="card-body">
                        <div id="server-stats">Loading...</div>
                    </div>
                </div>

                <!-- Linked Servers -->
                <div class="card">
                    <div class="card-header">
                        <h3>🔗 Linked Servers</h3>
                    </div>
                    <div class="card-body">
                        <div id="linked-servers">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Users Page -->
            <div class="page" id="page-users">
                <div class="page-header">
                    <h2>Users</h2>
                    <p>Connected users and registered nicknames</p>
                </div>

                <!-- Search -->
                <div class="card">
                    <div class="card-header">
                        <h3>🔍 Search Nicknames</h3>
                    </div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" id="search-nicks-input" class="form-control" placeholder="Enter nickname...">
                            <button class="btn btn-primary" id="btn-search-nicks">Search</button>
                        </div>
                        <div id="search-nicks-results"></div>
                    </div>
                </div>

                <!-- Connected Users -->
                <div class="card">
                    <div class="card-header">
                        <h3>👥 Connected Users <span id="connected-count" class="badge">0</span></h3>
                    </div>
                    <div class="card-body">
                        <div id="connected-users">Loading...</div>
                    </div>
                </div>

                <!-- Registered Nicknames -->
                <div class="card">
                    <div class="card-header">
                        <h3>📝 Registered Nicknames</h3>
                        <button class="btn btn-primary btn-sm" onclick="openModal('modal-register-nick')">Register Nickname</button>
                    </div>
                    <div class="card-body">
                        <div id="recent-registrations">Loading...</div>
                        <div id="nicks-pagination" class="pagination-controls"></div>
                    </div>
                </div>
            </div>

            <!-- Channels Page -->
            <div class="page" id="page-channels">
                <div class="page-header">
                    <h2>Channels</h2>
                    <p>Active and registered channels</p>
                </div>

                <!-- Search -->
                <div class="card">
                    <div class="card-header">
                        <h3>🔍 Search Channels</h3>
                    </div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" id="search-channels-input" class="form-control" placeholder="Enter channel name...">
                            <button class="btn btn-primary" id="btn-search-channels">Search</button>
                        </div>
                        <div id="search-channels-results"></div>
                    </div>
                </div>

                <!-- Active Channels -->
                <div class="card">
                    <div class="card-header">
                        <h3>💬 Active Channels <span id="channel-count" class="badge">0</span></h3>
                    </div>
                    <div class="card-body">
                        <div id="active-channels">Loading...</div>
                    </div>
                </div>

                <!-- Registered Channels -->
                <div class="card">
                    <div class="card-header">
                        <h3>📋 Registered Channels</h3>
                        <button class="btn btn-primary btn-sm" onclick="openModal('modal-register-channel')">Register Channel</button>
                    </div>
                    <div class="card-body">
                        <div id="channels-list">Loading...</div>
                        <div id="channels-pagination" class="pagination-controls"></div>
                    </div>
                </div>
            </div>

            <!-- Staff Page -->
            <div class="page" id="page-staff">
                <div class="page-header">
                    <h2>Staff Management</h2>
                    <p>Manage server staff members</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>👮 Staff Members</h3>
                        <button class="btn btn-success" id="btn-add-staff">➕ Add Staff</button>
                    </div>
                    <div class="card-body">
                        <div id="staff-list">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Access Control Page -->
            <div class="page" id="page-access">
                <div class="page-header">
                    <h2>Access Control</h2>
                    <p>Server-level access rules and bans</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>🛡️ Access Rules</h3>
                        <button class="btn btn-success" id="btn-add-access">➕ Add Rule</button>
                    </div>
                    <div class="card-body">
                        <div id="access-list">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- NewsFlash Page -->
            <div class="page" id="page-newsflash">
                <div class="page-header">
                    <h2>NewsFlash Management</h2>
                    <p>Manage server-wide announcements</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>📢 Broadcast Settings</h3>
                    </div>
                    <div class="card-body">
                        <div class="newsflash-settings">
                            <div class="settings-row">
                                <div class="setting-item">
                                    <div class="setting-label">
                                        <strong>Send on Connect</strong>
                                        <p class="setting-description">Automatically send NewsFlash messages when users connect to the server</p>
                                    </div>
                                    <div class="setting-control">
                                        <label class="toggle-switch">
                                            <input type="checkbox" id="newsflash-on-connect">
                                            <span class="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="settings-row">
                                <div class="setting-item">
                                    <div class="setting-label">
                                        <strong>Periodic Broadcast</strong>
                                        <p class="setting-description">Periodically broadcast NewsFlash messages to all connected users</p>
                                    </div>
                                    <div class="setting-control">
                                        <label class="toggle-switch">
                                            <input type="checkbox" id="newsflash-periodic-enabled">
                                            <span class="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="settings-row">
                                <div class="setting-item">
                                    <div class="setting-label">
                                        <strong>Broadcast Interval</strong>
                                        <p class="setting-description">How often to broadcast messages (in minutes)</p>
                                    </div>
                                    <div class="setting-control">
                                        <input type="number" id="newsflash-interval" class="form-control" value="30" min="1" max="1440" style="width: 120px;">
                                        <span style="margin-left: 8px; color: #666;">minutes</span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="settings-row" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                                <button class="btn btn-primary" id="btn-save-newsflash-settings">💾 Save Settings</button>
                                <span id="newsflash-settings-status" style="margin-left: 15px;"></span>
                            </div>
                        </div>
                    </div>

                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>📢 NewsFlash Messages</h3>
                        <button class="btn btn-success" id="btn-add-newsflash">➕ Add NewsFlash</button>
                    </div>
                    <div class="card-body">
                        <div id="newsflash-list">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Mailbox Page -->
            <div class="page" id="page-mailbox">
                <div class="page-header">
                    <h2>Mailbox</h2>
                    <p>View user mailbox messages</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>📬 Recent Messages</h3>
                        <button class="btn btn-success" id="btn-send-mailbox">✉️ Send Message</button>
                    </div>
                    <div class="card-body">
                        <div id="mailbox-list">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Configuration Page -->
            <div class="page" id="page-config">
                <div class="page-header">
                    <h2>Configuration</h2>
                    <p>Server configuration settings</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>⚙️ Server Configuration</h3>
                        <div style="float: right;">
                            <button class="btn btn-primary" id="btn-save-config-form">💾 Save Configuration</button>
                            <button class="btn btn-info" id="btn-edit-config-json">📝 Edit JSON</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="config-tabs">
                            <button class="config-tab active" data-tab="server">Server</button>
                            <button class="config-tab" data-tab="limits">Limits</button>
                            <button class="config-tab" data-tab="security">Security</button>
                            <button class="config-tab" data-tab="services">Services</button>
                            <button class="config-tab" data-tab="ssl">SSL/TLS</button>
                            <button class="config-tab" data-tab="linking">Linking</button>
                            <button class="config-tab" data-tab="advanced">Advanced</button>
                        </div>

                        <!-- Server Tab -->
                        <div class="config-tab-content active" id="config-tab-server">
                            <h4>Server Settings</h4>
                            <div class="form-group">
                                <label>Server Name</label>
                                <input type="text" class="form-control" id="cfg-server-name">
                            </div>
                            <div class="form-group">
                                <label>Network Name</label>
                                <input type="text" class="form-control" id="cfg-server-network">
                            </div>
                            <div class="form-group">
                                <label>Staff Login Message</label>
                                <input type="text" class="form-control" id="cfg-server-staff-message">
                            </div>

                            <h4 style="margin-top: 20px;">Network Settings</h4>
                            <div class="form-group">
                                <label>Listen Address</label>
                                <input type="text" class="form-control" id="cfg-network-addr">
                                <small>Use 0.0.0.0 for all interfaces</small>
                            </div>
                            <div class="form-group">
                                <label>Listen Ports (comma-separated)</label>
                                <input type="text" class="form-control" id="cfg-network-ports">
                                <small>Example: 6667,7000</small>
                            </div>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-network-ipv6"> Enable IPv6</label>
                            </div>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-network-resolve"> Resolve Hostnames</label>
                            </div>

                            <h4 style="margin-top: 20px;">Database Settings</h4>
                            <div class="form-group">
                                <label>Database Path</label>
                                <input type="text" class="form-control" id="cfg-database-path">
                            </div>
                            <div class="form-group">
                                <label>Connection Pool Size</label>
                                <input type="number" class="form-control" id="cfg-database-pool">
                            </div>
                        </div>

                        <!-- Limits Tab -->
                        <div class="config-tab-content" id="config-tab-limits">
                            <h4>Connection & User Limits</h4>
                            <div class="form-group">
                                <label>Maximum Users</label>
                                <input type="number" class="form-control" id="cfg-limits-max-users">
                            </div>
                            <div class="form-group">
                                <label>Message Length</label>
                                <input type="number" class="form-control" id="cfg-limits-msg-length">
                            </div>
                            <div class="form-group">
                                <label>Nickname Change Cooldown (seconds)</label>
                                <input type="number" class="form-control" id="cfg-limits-nick-cooldown">
                            </div>
                            <div class="form-group">
                                <label>Maximum Nickname Length</label>
                                <input type="number" class="form-control" id="cfg-limits-max-nick">
                            </div>
                            <div class="form-group">
                                <label>Maximum Username Length</label>
                                <input type="number" class="form-control" id="cfg-limits-max-user">
                            </div>
                            <div class="form-group">
                                <label>Maximum Channel Name Length</label>
                                <input type="number" class="form-control" id="cfg-limits-max-channel">
                            </div>
                            <div class="form-group">
                                <label>Maximum Total Channels</label>
                                <input type="number" class="form-control" id="cfg-limits-max-channels">
                            </div>
                            <div class="form-group">
                                <label>Maximum Channels Per User</label>
                                <input type="number" class="form-control" id="cfg-limits-max-channels-user">
                            </div>
                        </div>

                        <!-- Security Tab -->
                        <div class="config-tab-content" id="config-tab-security">
                            <h4>Flood Protection</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-security-flood-enabled"> Enable Flood Protection</label>
                            </div>
                            <div class="form-group">
                                <label>Flood Messages Threshold</label>
                                <input type="number" class="form-control" id="cfg-security-flood-msgs">
                            </div>
                            <div class="form-group">
                                <label>Flood Window (seconds)</label>
                                <input type="number" class="form-control" id="cfg-security-flood-window">
                            </div>

                            <h4 style="margin-top: 20px;">Connection Throttling</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-security-throttle-enabled"> Enable Connection Throttle</label>
                            </div>
                            <div class="form-group">
                                <label>Connection Throttle Limit</label>
                                <input type="number" class="form-control" id="cfg-security-throttle">
                            </div>
                            <div class="form-group">
                                <label>Throttle Window (seconds)</label>
                                <input type="number" class="form-control" id="cfg-security-throttle-window">
                            </div>

                            <h4 style="margin-top: 20px;">Authentication</h4>
                            <div class="form-group">
                                <label>CAP Timeout (seconds)</label>
                                <input type="number" class="form-control" id="cfg-security-cap-timeout">
                            </div>
                            <div class="form-group">
                                <label>Maximum Auth Attempts</label>
                                <input type="number" class="form-control" id="cfg-security-auth-attempts">
                            </div>
                            <div class="form-group">
                                <label>Auth Lockout Duration (seconds)</label>
                                <input type="number" class="form-control" id="cfg-security-auth-lockout">
                            </div>
                            <div class="form-group">
                                <label>Auth Lockout Window (seconds)</label>
                                <input type="number" class="form-control" id="cfg-security-auth-window">
                            </div>

                            <h4 style="margin-top: 20px;">DNSBL</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-dnsbl-enabled"> Enable DNSBL</label>
                            </div>
                            <div class="form-group">
                                <label>DNSBL Action</label>
                                <select class="form-control" id="cfg-dnsbl-action">
                                    <option value="reject">Reject</option>
                                    <option value="warn">Warn</option>
                                    <option value="tag">Tag</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>DNSBL Lists (one per line)</label>
                                <textarea class="form-control" id="cfg-dnsbl-lists" rows="3"></textarea>
                            </div>

                            <h4 style="margin-top: 20px;">Proxy Detection</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-proxy-enabled"> Enable Proxy Detection</label>
                            </div>
                            <div class="form-group">
                                <label>Proxy Ports (comma-separated)</label>
                                <input type="text" class="form-control" id="cfg-proxy-ports">
                            </div>
                            <div class="form-group">
                                <label>Proxy Action</label>
                                <select class="form-control" id="cfg-proxy-action">
                                    <option value="reject">Reject</option>
                                    <option value="warn">Warn</option>
                                    <option value="tag">Tag</option>
                                </select>
                            </div>
                        </div>

                        <!-- Services Tab -->
                        <div class="config-tab-content" id="config-tab-services">
                            <h4>Service Bots</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-servicebot-enabled"> Enable Service Bots</label>
                            </div>
                            <div class="form-group">
                                <label>Service Bot Count</label>
                                <input type="number" class="form-control" id="cfg-services-count">
                            </div>
                            <div class="form-group">
                                <label>Maximum Channels Per Bot</label>
                                <input type="number" class="form-control" id="cfg-services-max-channels">
                            </div>

                            <h4 style="margin-top: 20px;">Profanity Filter</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-profanity-enabled"> Enable Profanity Filter</label>
                            </div>
                            <div class="form-group">
                                <label>Filter Action</label>
                                <select class="form-control" id="cfg-profanity-action">
                                    <option value="warn">Warn</option>
                                    <option value="kick">Kick</option>
                                    <option value="ban">Ban</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-profanity-case"> Case Sensitive</label>
                            </div>

                            <h4 style="margin-top: 20px;">Malicious Detection</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-malicious-enabled"> Enable Malicious Detection</label>
                            </div>
                            <div class="form-group">
                                <label>Flood Threshold</label>
                                <input type="number" class="form-control" id="cfg-malicious-flood-threshold">
                            </div>
                            <div class="form-group">
                                <label>CAPS Threshold (%)</label>
                                <input type="number" step="0.01" class="form-control" id="cfg-malicious-caps">
                            </div>
                            <div class="form-group">
                                <label>URL Spam Threshold</label>
                                <input type="number" class="form-control" id="cfg-malicious-url">
                            </div>
                        </div>

                        <!-- SSL Tab -->
                        <div class="config-tab-content" id="config-tab-ssl">
                            <h4>SSL/TLS Settings</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-ssl-enabled"> Enable SSL/TLS</label>
                            </div>
                            <div class="form-group">
                                <label>SSL Ports (comma-separated)</label>
                                <input type="text" class="form-control" id="cfg-ssl-ports">
                            </div>
                            <div class="form-group">
                                <label>Certificate File Path</label>
                                <input type="text" class="form-control" id="cfg-ssl-cert">
                            </div>
                            <div class="form-group">
                                <label>Key File Path</label>
                                <input type="text" class="form-control" id="cfg-ssl-key">
                            </div>
                            <div class="form-group">
                                <label>Minimum TLS Version</label>
                                <select class="form-control" id="cfg-ssl-min-version">
                                    <option value="TLSv1.2">TLS 1.2</option>
                                    <option value="TLSv1.3">TLS 1.3</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-ssl-auto-reload"> Auto-reload Certificates</label>
                            </div>
                        </div>

                        <!-- Linking Tab -->
                        <div class="config-tab-content" id="config-tab-linking">
                            <h4>Server Linking</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-linking-enabled"> Enable Server Linking</label>
                            </div>
                            <div class="form-group">
                                <label>Bind Host</label>
                                <input type="text" class="form-control" id="cfg-linking-host">
                            </div>
                            <div class="form-group">
                                <label>Bind Port</label>
                                <input type="number" class="form-control" id="cfg-linking-port">
                            </div>
                        </div>

                        <!-- Advanced Tab -->
                        <div class="config-tab-content" id="config-tab-advanced">
                            <h4>Transcripts</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-transcript-enabled"> Enable Transcripts</label>
                            </div>
                            <div class="form-group">
                                <label>Transcript Directory</label>
                                <input type="text" class="form-control" id="cfg-transcript-dir">
                            </div>
                            <div class="form-group">
                                <label>Maximum Lines Per File</label>
                                <input type="number" class="form-control" id="cfg-transcript-max">
                            </div>

                            <h4 style="margin-top: 20px;">Persistence</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-persist-auto"> Auto-save State</label>
                            </div>
                            <div class="form-group">
                                <label>Save Interval (seconds)</label>
                                <input type="number" class="form-control" id="cfg-persist-interval">
                            </div>

                            <h4 style="margin-top: 20px;">NewsFlash</h4>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-newsflash-connect"> Show on Connect</label>
                            </div>
                            <div class="form-group">
                                <label><input type="checkbox" id="cfg-newsflash-periodic"> Enable Periodic Announcements</label>
                            </div>
                            <div class="form-group">
                                <label>Periodic Interval (seconds)</label>
                                <input type="number" class="form-control" id="cfg-newsflash-interval">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Logs Page -->
            <div class="page" id="page-logs">
                <div class="page-header">
                    <h2>Server Logs</h2>
                    <p>View and filter server logs</p>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>📄 Log Viewer</h3>
                    </div>
                    <div class="card-body">
                        <div class="log-controls">
                            <label>
                                Level:
                                <select id="log-level-filter" class="form-control">
                                    <option value="">All</option>
                                    <option value="INFO">INFO</option>
                                    <option value="WARNING">WARNING</option>
                                    <option value="ERROR">ERROR</option>
                                </select>
                            </label>
                            <label>
                                Search:
                                <input type="text" id="log-search-input" class="form-control" placeholder="Search logs...">
                            </label>
                            <button class="btn btn-secondary" id="btn-refresh-logs">🔄 Refresh</button>
                        </div>
                        <pre id="server-logs">Loading...</pre>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Modals (same as before, will be included) -->
    <!-- Modal: Add Access Rule -->
    <div id="modal-add-access" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>Add Access Rule</h4></div>
                <div class="modal-body">
                    <label>Type:</label>
                    <select id="access-type" class="form-control">
                        <option value="DENY">DENY (Ban)</option>
                        <option value="GRANT">GRANT (Allow)</option>
                    </select>
                    <label style="margin-top: 10px;">Pattern:</label>
                    <input type="text" id="access-pattern" class="form-control" placeholder="*!*@*.example.com">
                    <label style="margin-top: 10px;">Reason:</label>
                    <input type="text" id="access-reason" class="form-control">
                    <label style="margin-top: 10px;">Duration (minutes, 0=permanent):</label>
                    <input type="number" id="access-timeout" class="form-control" value="0">
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-access">Add</button>
                    <button class="btn btn-default" id="btn-cancel-access">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Add NewsFlash -->
    <div id="modal-add-newsflash" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>Add NewsFlash</h4></div>
                <div class="modal-body">
                    <label>Message:</label>
                    <textarea id="newsflash-message" class="form-control" rows="3"></textarea>
                    <label style="margin-top: 10px;">Priority:</label>
                    <select id="newsflash-priority" class="form-control">
                        <option value="0">Normal</option>
                        <option value="1">High</option>
                        <option value="2">Critical</option>
                    </select>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-newsflash">Add</button>
                    <button class="btn btn-default" id="btn-cancel-newsflash">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Additional modals (staff, config, etc.) would go here - keeping this concise -->
    <!-- The full version would include all modals from the original code -->

    <script src="admin.js?v=1768179291"></script>
    <!-- Modal: Edit Configuration -->
    <div id="modal-edit-config" class="modal" style="display: none;">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header"><h4>✏️ Edit Configuration</h4></div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <strong>⚠️ Warning:</strong> Invalid JSON will be rejected. Service will restart after saving.
                    </div>
                    <textarea id="config-editor" class="form-control" rows="35" style="font-family: monospace; font-size: 13px; width: 100%;"></textarea>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-config">💾 Save & Restart</button>
                    <button class="btn btn-default" id="btn-cancel-config">Cancel</button>
                </div>
            </div>
        </div>
    </div>


    <!-- Modal: Send Mailbox Message -->
    <div id="modal-send-mailbox" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>✉️ Send Message</h4></div>
                <div class="modal-body">
                    <label>From (Sender):</label>
                    <input type="text" id="mailbox-from" class="form-control" placeholder="Sender nickname">
                    <label style="margin-top: 10px;">To (Recipient):</label>
                    <input type="text" id="mailbox-to" class="form-control" placeholder="Recipient nickname">
                    <label style="margin-top: 10px;">Message:</label>
                    <textarea id="mailbox-message" class="form-control" rows="4" placeholder="Enter message..."></textarea>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-mailbox">Send</button>
                    <button class="btn btn-default" id="btn-cancel-mailbox">Cancel</button>
                </div>
            </div>
        </div>
    </div>

</body>
</html>

    <!-- Modal: Add Staff -->
    <div id="modal-add-staff" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>Add Staff Member</h4></div>
                <div class="modal-body">
                    <label>Username:</label>
                    <input type="text" id="staff-username" class="form-control" placeholder="3-20 characters (letters, numbers, _, -)">
                    <label style="margin-top: 10px;">Password:</label>
                    <input type="password" id="staff-password" class="form-control" placeholder="Minimum 8 characters">
                    <label style="margin-top: 10px;">Confirm Password:</label>
                    <input type="password" id="staff-password-confirm" class="form-control">
                    <label style="margin-top: 10px;">Real Name (Optional):</label>
                    <input type="text" id="staff-realname" class="form-control" placeholder="Staff member's real name">
                    <label style="margin-top: 10px;">Email (Optional):</label>
                    <input type="email" id="staff-email" class="form-control" placeholder="email@example.com">
                    <div style="margin-top: 15px;">
                        <label style="display: block; margin-bottom: 5px;">
                            <input type="checkbox" id="staff-force-realname">
                            <strong>Force Real Name</strong> - Require this staff member to use their real name
                        </label>
                    </div>
                    <label style="margin-top: 10px;">Level:</label>
                    <select id="staff-level" class="form-control">
                        <option value="GUIDE">GUIDE (IRC guide)</option>
                        <option value="SYSOP">SYSOP (IRC operator)</option>
                        <option value="ADMIN">ADMIN (IRC administrator)</option>
                    </select>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-staff">Add Staff</button>
                    <button class="btn btn-default" id="btn-cancel-staff">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Edit Staff -->
    <div id="modal-edit-staff" class="modal" style="display: none;">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header"><h4>Edit Staff Member: <span id="edit-staff-username"></span></h4></div>
                <div class="modal-body">
                    <h5 style="margin-top: 0;">Change Level</h5>
                    <label>New Level:</label>
                    <select id="edit-staff-level" class="form-control">
                        <option value="GUIDE">GUIDE (IRC guide)</option>
                        <option value="SYSOP">SYSOP (IRC operator)</option>
                        <option value="ADMIN">ADMIN (IRC administrator)</option>
                    </select>
                    <button class="btn btn-info" id="btn-change-level" style="margin-top: 10px;">Change Level</button>

                    <hr style="margin: 20px 0;">

                    <h5>Profile Information</h5>
                    <label>Real Name:</label>
                    <input type="text" id="edit-staff-realname" class="form-control" placeholder="Optional">
                    <label style="margin-top: 10px;">Email:</label>
                    <input type="email" id="edit-staff-email" class="form-control" placeholder="Optional">
                    <div style="margin-top: 15px;">
                        <label style="display: block;">
                            <input type="checkbox" id="edit-staff-force-realname">
                            <strong>Force Real Name</strong> - Require this staff member to use their real name when connected
                        </label>
                    </div>
                    <button class="btn btn-info" id="btn-update-profile" style="margin-top: 10px;">Update Profile</button>

                    <hr style="margin: 20px 0;">

                    <h5>Change Password</h5>
                    <label>New Password:</label>
                    <input type="password" id="edit-staff-password" class="form-control" placeholder="Minimum 8 characters">
                    <label style="margin-top: 10px;">Confirm Password:</label>
                    <input type="password" id="edit-staff-password-confirm" class="form-control">
                    <button class="btn btn-warning" id="btn-change-password" style="margin-top: 10px;">Change Password</button>

                    <hr style="margin: 20px 0;">

                    <h5>Delete Staff Member</h5>
                    <p style="color: #d9534f;">Warning: This action cannot be undone!</p>
                    <button class="btn btn-danger" id="btn-delete-staff">Delete Staff Member</button>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-default" id="btn-cancel-edit-staff">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Register Nickname -->
    <div id="modal-register-nick" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>Register Nickname</h4></div>
                <div class="modal-body">
                    <label>Nickname:</label>
                    <input type="text" id="register-nick-nickname" class="form-control" placeholder="Must start with a letter, 1-30 characters">
                    <label style="margin-top: 10px;">Password:</label>
                    <input type="password" id="register-nick-password" class="form-control" placeholder="Minimum 8 characters">
                    <label style="margin-top: 10px;">Confirm Password:</label>
                    <input type="password" id="register-nick-password-confirm" class="form-control">
                    <label style="margin-top: 10px;">Email (optional):</label>
                    <input type="email" id="register-nick-email" class="form-control" placeholder="user@example.com or leave empty">
                    <div class="alert alert-info" style="margin-top: 10px;">
                        <strong>ℹ️ Note:</strong> This will create a registered nickname that users can identify to with the IDENTIFY command.
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-register-nick">Register Nickname</button>
                    <button class="btn btn-default" id="btn-cancel-register-nick">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Register Channel -->
    <div id="modal-register-channel" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>Register Channel</h4></div>
                <div class="modal-body">
                    <label>Channel Name:</label>
                    <input type="text" id="register-channel-name" class="form-control" placeholder="#channelname">
                    <label style="margin-top: 10px;">Owner (Nickname, Staff, or Service):</label>
                    <input type="text" id="register-channel-owner" class="form-control" placeholder="Registered nickname, staff username, or service name">
                    <div class="alert alert-info" style="margin-top: 10px;">
                        <strong>ℹ️ Note:</strong> Owner can be:
                        <ul style="margin: 5px 0 0 0; padding-left: 20px;">
                            <li>A registered nickname</li>
                            <li>A staff username (ADMIN/SYSOP/GUIDE)</li>
                            <li>A service name: <strong>System, Registrar, Messenger, NewsFlash, NickServ, ChanServ, OperServ, HelpServ, MemoServ, BotServ, HostServ, StatServ, InfoServ, Global, ALIS, Services</strong></li>
                        </ul>
                        Staff and service accounts will automatically get registered_nicks entries. Channel name must start with # and contain only letters, numbers, _, -.
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-register-channel">Register Channel</button>
                    <button class="btn btn-default" id="btn-cancel-register-channel">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Edit Nickname -->
    <div id="modal-edit-nick" class="modal" style="display: none;">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header"><h4>Edit Nickname: <span id="edit-nick-name"></span></h4></div>
                <div class="modal-body">
                    <label>New Password (leave empty to keep current):</label>
                    <input type="password" id="edit-nick-password" class="form-control" placeholder="Minimum 8 characters">
                    <label style="margin-top: 10px;">Confirm New Password:</label>
                    <input type="password" id="edit-nick-password-confirm" class="form-control">
                    <label style="margin-top: 10px;">Email (leave empty to keep current, enter * to clear):</label>
                    <input type="email" id="edit-nick-email" class="form-control" placeholder="user@example.com or * to clear">
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-edit-nick">Save Changes</button>
                    <button class="btn btn-default" id="btn-cancel-edit-nick">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Edit Channel -->
    <div id="modal-edit-channel" class="modal" style="display: none;">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header"><h4>Edit Channel: <span id="edit-channel-name"></span></h4></div>
                <div class="modal-body" >
                    <!-- Basic Properties -->
                    <h5 style="margin-top: 0; border-bottom: 2px solid #ddd; padding-bottom: 5px;">Basic Properties</h5>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-owner" style="font-weight: 600;">Channel Owner</label>
                        <input type="text" id="edit-channel-owner" class="form-control" style="width: 100%; max-width: 100%; box-sizing: border-box;" placeholder="Leave empty to keep current">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Registered nickname, staff username (ADMIN/SYSOP/GUIDE), or service name
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-description" style="font-weight: 600;">Description</label>
                        <textarea id="edit-channel-description" class="form-control" style="width: 100%;" rows="2" placeholder="Leave empty to keep current, * to clear"></textarea>
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Brief description of channel purpose
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-topic" style="font-weight: 600;">Channel Topic</label>
                        <input type="text" id="edit-channel-topic" class="form-control" style="width: 100%;" placeholder="Leave empty to keep current, * to clear">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Default topic that will be set when channel is created
                        </small>
                    </div>

                    <!-- Channel Modes -->
                    <h5 style="margin-top: 25px; border-bottom: 2px solid #ddd; padding-bottom: 5px;">Channel Modes</h5>
                    <small class="form-text text-muted" style="display: block; margin-bottom: 15px;">
                        Select modes to enable for this channel. Leave all unchecked to keep current settings.
                    </small>

                    <div style="margin-bottom: 15px;">
                        <strong style="display: block; margin-bottom: 10px;">Basic Modes:</strong>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-n" style="margin-right: 8px;">
                                    <strong>+n</strong>&nbsp;(No External)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Block messages from users not in channel</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-t" style="margin-right: 8px;">
                                    <strong>+t</strong>&nbsp;(Topic Lock)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Only hosts/owners can change topic</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-i" style="margin-right: 8px;">
                                    <strong>+i</strong>&nbsp;(Invite Only)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Requires invite or key to join</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-m" style="margin-right: 8px;">
                                    <strong>+m</strong>&nbsp;(Moderated)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Only voiced/hosts can speak</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-p" style="margin-right: 8px;">
                                    <strong>+p</strong>&nbsp;(Private)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Channel marked as private</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-s" style="margin-right: 8px;">
                                    <strong>+s</strong>&nbsp;(Secret)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Hidden from WHO/WHOIS/LIST</small>
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 15px;">
                        <strong style="display: block; margin-bottom: 10px;">Extended Modes:</strong>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-a" style="margin-right: 8px;">
                                    <strong>+a</strong>&nbsp;(Authenticated)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Only authenticated/staff users can join</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-d" style="margin-right: 8px;">
                                    <strong>+d</strong>&nbsp;(Clone)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Create overflow channels when limit reached</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-f" style="margin-right: 8px;">
                                    <strong>+f</strong>&nbsp;(Filtered)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Strip mIRC formatting codes</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-h" style="margin-right: 8px;">
                                    <strong>+h</strong>&nbsp;(Hidden)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Hidden from LIST (but not WHO)</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-j" style="margin-right: 8px;">
                                    <strong>+j</strong>&nbsp;(No Invitations)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Block INVITE command in channel</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-u" style="margin-right: 8px;">
                                    <strong>+u</strong>&nbsp;(Knock)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Enable KNOCK command (request invite)</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-w" style="margin-right: 8px;">
                                    <strong>+w</strong>&nbsp;(No Whispers)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Block WHISPER command</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-x" style="margin-right: 8px;">
                                    <strong>+x</strong>&nbsp;(Auditorium)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Hide member list from non-hosts</small>
                            </div>

                            <div>
                                <label style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <input type="checkbox" id="mode-y" style="margin-right: 8px;">
                                    <strong>+y</strong>&nbsp;(Transcript)
                                </label>
                                <small class="text-muted" style="display: block; margin-left: 24px;">Enable message logging/history</small>
                            </div>
                        </div>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-userlimit" style="font-weight: 600;">User Limit (+l)</label>
                        <input type="number" id="edit-channel-userlimit" class="form-control" style="width: 150px;" min="0" max="999" placeholder="0-999">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Maximum number of users allowed in channel (0 or empty = unlimited)
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: flex; align-items: center;">
                            <input type="checkbox" id="mode-clear" style="margin-right: 8px;">
                            <strong>Clear all modes</strong>
                        </label>
                        <small class="form-text text-muted" style="display: block; margin-left: 24px;">
                            Check this to remove all modes (equivalent to entering * in old text field)
                        </small>
                    </div>

                    <div class="alert alert-warning" style="margin-top: 10px; margin-bottom: 15px;">
                        <strong>ℹ️ Note:</strong> Mode <strong>+k</strong> (channel key) is automatically set when you specify a <strong>Member Key</strong> below. No separate checkbox needed.
                    </div>

                    <!-- Channel Keys -->
                    <h5 style="margin-top: 25px; border-bottom: 2px solid #ddd; padding-bottom: 5px;">Channel Keys</h5>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-memberkey" style="font-weight: 600;">Member Key</label>
                        <input type="text" id="edit-channel-memberkey" class="form-control" style="width: 100%;" placeholder="Leave empty to keep current, * to clear">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Password required for regular members to join the channel
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-hostkey" style="font-weight: 600;">Host Key</label>
                        <input type="text" id="edit-channel-hostkey" class="form-control" style="width: 100%;" placeholder="Leave empty to keep current, * to clear">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Password to join with host/operator (+o) privileges automatically
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-ownerkey" style="font-weight: 600;">Owner Key</label>
                        <input type="text" id="edit-channel-ownerkey" class="form-control" style="width: 100%;" placeholder="Leave empty to keep current, * to clear">
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Password to join with owner (+q) privileges automatically
                        </small>
                    </div>

                    <!-- Join/Part Messages -->
                    <h5 style="margin-top: 25px; border-bottom: 2px solid #ddd; padding-bottom: 5px;">Join/Part Messages</h5>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-onjoin" style="font-weight: 600;">On-Join Message</label>
                        <textarea id="edit-channel-onjoin" class="form-control" style="width: 100%;" rows="3" placeholder="Leave empty to keep current, * to clear"></textarea>
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Custom message sent to users when they join the channel (sent as PRIVMSG from channel)
                        </small>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label for="edit-channel-onpart" style="font-weight: 600;">On-Part Message</label>
                        <textarea id="edit-channel-onpart" class="form-control" style="width: 100%;" rows="3" placeholder="Leave empty to keep current, * to clear"></textarea>
                        <small class="form-text text-muted" style="display: block; margin-top: 5px;">
                            Custom message sent to users when they leave the channel (sent as NOTICE)
                        </small>
                    </div>

                    <!-- ACCESS List Management -->
                    <h5 style="margin-top: 25px; border-bottom: 2px solid #ddd; padding-bottom: 5px;">ACCESS List Management</h5>
                    <small class="form-text text-muted" style="display: block; margin-bottom: 15px;">
                        Control who can join and what privileges they receive. ACCESS entries use hostmasks (e.g., *!*@*.example.com or nickname!*@*).
                    </small>

                    <div style="margin-bottom: 20px;">
                        <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 10px;">
                            <button type="button" class="btn btn-sm btn-default" id="access-tab-owner" onclick="showAccessTab('owner')" style="font-weight: 600;">OWNER (+q)</button>
                            <button type="button" class="btn btn-sm btn-default" id="access-tab-host" onclick="showAccessTab('host')">HOST (+o)</button>
                            <button type="button" class="btn btn-sm btn-default" id="access-tab-voice" onclick="showAccessTab('voice')">VOICE (+v)</button>
                            <button type="button" class="btn btn-sm btn-default" id="access-tab-grant" onclick="showAccessTab('grant')">GRANT</button>
                            <button type="button" class="btn btn-sm btn-default" id="access-tab-deny" onclick="showAccessTab('deny')">DENY (Ban)</button>
                        </div>

                        <div id="access-list-container" style="border: 1px solid #ddd; padding: 15px; background: #f9f9f9; min-height: 150px;">
                            <div id="access-owner" class="access-panel" style="display: block;">
                                <strong>OWNER (+q) - Grants owner privileges on join</strong>
                                <div id="access-owner-list" style="margin-top: 10px;"></div>
                                <div style="margin-top: 10px;">
                                    <input type="text" id="access-owner-mask" class="form-control" style="width: 60%; display: inline-block;" placeholder="Hostmask (e.g., bob!*@*, *!*@*.example.com)">
                                    <button type="button" class="btn btn-sm btn-primary" onclick="addAccessEntry('owner')" style="margin-left: 10px;">Add</button>
                                </div>
                            </div>

                            <div id="access-host" class="access-panel" style="display: none;">
                                <strong>HOST (+o) - Grants host/operator privileges on join</strong>
                                <div id="access-host-list" style="margin-top: 10px;"></div>
                                <div style="margin-top: 10px;">
                                    <input type="text" id="access-host-mask" class="form-control" style="width: 60%; display: inline-block;" placeholder="Hostmask (e.g., bob!*@*, *!*@*.example.com)">
                                    <button type="button" class="btn btn-sm btn-primary" onclick="addAccessEntry('host')" style="margin-left: 10px;">Add</button>
                                </div>
                            </div>

                            <div id="access-voice" class="access-panel" style="display: none;">
                                <strong>VOICE (+v) - Grants voice privileges on join</strong>
                                <div id="access-voice-list" style="margin-top: 10px;"></div>
                                <div style="margin-top: 10px;">
                                    <input type="text" id="access-voice-mask" class="form-control" style="width: 60%; display: inline-block;" placeholder="Hostmask (e.g., bob!*@*, *!*@*.example.com)">
                                    <button type="button" class="btn btn-sm btn-primary" onclick="addAccessEntry('voice')" style="margin-left: 10px;">Add</button>
                                </div>
                            </div>

                            <div id="access-grant" class="access-panel" style="display: none;">
                                <strong>GRANT - Allowed to join (bypasses +i invite-only mode)</strong>
                                <div id="access-grant-list" style="margin-top: 10px;"></div>
                                <div style="margin-top: 10px;">
                                    <input type="text" id="access-grant-mask" class="form-control" style="width: 60%; display: inline-block;" placeholder="Hostmask (e.g., bob!*@*, *!*@*.example.com)">
                                    <button type="button" class="btn btn-sm btn-primary" onclick="addAccessEntry('grant')" style="margin-left: 10px;">Add</button>
                                </div>
                            </div>

                            <div id="access-deny" class="access-panel" style="display: none;">
                                <strong>DENY - Denied access (works like ban)</strong>
                                <div id="access-deny-list" style="margin-top: 10px;"></div>
                                <div style="margin-top: 10px;">
                                    <input type="text" id="access-deny-mask" class="form-control" style="width: 60%; display: inline-block;" placeholder="Hostmask (e.g., *!*@*.spam.host)">
                                    <button type="button" class="btn btn-sm btn-danger" onclick="addAccessEntry('deny')" style="margin-left: 10px;">Add</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="alert alert-info" style="margin-top: 20px; margin-bottom: 0;">
                        <strong>💡 Tips:</strong>
                        <ul style="margin: 5px 0 0 0; padding-left: 20px;">
                            <li>Leave any field empty to keep its current value</li>
                            <li>Enter <code>*</code> in text fields to clear/remove that property</li>
                            <li>Uncheck all mode boxes to keep current modes unchanged</li>
                            <li>ACCESS entries are permanent and stored with the channel</li>
                            <li>Changes take effect immediately for new channel instances</li>
                        </ul>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-edit-channel">Save Changes</button>
                    <button class="btn btn-default" id="btn-cancel-edit-channel">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal: Send Mailbox Message -->
    <div id="modal-send-mailbox" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>✉️ Send Message</h4></div>
                <div class="modal-body">
                    <label>From (Sender):</label>
                    <input type="text" id="mailbox-from" class="form-control" placeholder="Sender nickname">
                    <label style="margin-top: 10px;">To (Recipient):</label>
                    <input type="text" id="mailbox-to" class="form-control" placeholder="Recipient nickname">
                    <label style="margin-top: 10px;">Message:</label>
                    <textarea id="mailbox-message" class="form-control" rows="4" placeholder="Enter message..."></textarea>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-mailbox">Send</button>
                    <button class="btn btn-default" id="btn-cancel-mailbox">Cancel</button>
                </div>
            </div>
        </div>
    </div>

</body>

    <!-- Modal: Send Mailbox Message -->
    <div id="modal-send-mailbox" class="modal" style="display: none;">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h4>✉️ Send Message</h4></div>
                <div class="modal-body">
                    <label>From (Sender):</label>
                    <input type="text" id="mailbox-from" class="form-control" placeholder="Sender nickname">
                    <label style="margin-top: 10px;">To (Recipient):</label>
                    <input type="text" id="mailbox-to" class="form-control" placeholder="Recipient nickname">
                    <label style="margin-top: 10px;">Message:</label>
                    <textarea id="mailbox-message" class="form-control" rows="4" placeholder="Enter message..."></textarea>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" id="btn-save-mailbox">Send</button>
                    <button class="btn btn-default" id="btn-cancel-mailbox">Cancel</button>
                </div>
            </div>
        </div>
    </div>

</body></html>
