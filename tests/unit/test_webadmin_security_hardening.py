#!/usr/bin/env python3
"""
Static security hardening checks for WebAdmin assets.
"""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEBADMIN_DIR = PROJECT_ROOT / "webadmin"
WEBCHAT_FILE = PROJECT_ROOT / "webchat" / "index.html"
WEBCHAT_GATEWAY_FILE = PROJECT_ROOT / "webchat" / "gateway.py"
WEBCHAT_CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "webchat" / "webchat.conf.example"
MAIN_CONFIG_FILE = PROJECT_ROOT / "pyircx_config.json"
INSTALL_SCRIPT = PROJECT_ROOT / "install.sh"
MAIN_SERVER_FILE = PROJECT_ROOT / "pyircx.py"
WEBADMIN_INDEX_FILE = WEBADMIN_DIR / "index.php"
WEBADMIN_LOGIN_FILE = WEBADMIN_DIR / "login.php"
WEBADMIN_API_FILE = WEBADMIN_DIR / "api.php"
WEBADMIN_SESSION_AUTH_FILE = WEBADMIN_DIR / "session_auth.php"
API_HELPERS_FILE = PROJECT_ROOT / "api_helpers.py"
LINKING_FILE = PROJECT_ROOT / "linking.py"
DEFAULT_CONFIG_GEN_FILE = PROJECT_ROOT / "utils" / "generate_default_config.py"
README_FILE = PROJECT_ROOT / "README.md"
DOC_CONFIG_FILE = PROJECT_ROOT / "docs" / "user" / "CONFIG.md"
DOC_TESTHARNESS_FILE = PROJECT_ROOT / "docs" / "testing" / "TESTHARNESS.md"
TOPOLOGY_TEST_FILE = PROJECT_ROOT / "tests" / "integration" / "network" / "topology.py"
STRESS_TEST_FILE = PROJECT_ROOT / "tests" / "integration" / "load" / "stress_test.py"
RUN_TESTS_FILE = PROJECT_ROOT / "run_tests.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_admin_js_has_no_inline_onclick_handlers():
    admin_js = _read(WEBADMIN_DIR / "admin.js")
    assert "onclick=" not in admin_js


def test_webadmin_index_has_no_inline_onclick_handlers():
    index_php = _read(WEBADMIN_INDEX_FILE)
    assert "onclick=" not in index_php


def test_webchat_has_no_inline_event_handlers():
    webchat_html = _read(WEBCHAT_FILE)
    assert "onclick=" not in webchat_html
    assert "onmouseover=" not in webchat_html
    assert "onmouseout=" not in webchat_html


def test_linking_tls_fields_exist_in_index_php():
    index_php = _read(WEBADMIN_DIR / "index.php")
    required_ids = [
        "cfg-linking-tls-enabled",
        "cfg-linking-tls-verify",
        "cfg-linking-tls-cert",
        "cfg-linking-tls-key",
        "cfg-linking-tls-ca",
    ]
    for field_id in required_ids:
        assert field_id in index_php


def test_linking_tls_round_trip_in_admin_js():
    admin_js = _read(WEBADMIN_DIR / "admin.js")
    required_tokens = [
        "setCheck('#cfg-linking-tls-enabled'",
        "setCheck('#cfg-linking-tls-verify'",
        "setVal('#cfg-linking-tls-cert'",
        "setVal('#cfg-linking-tls-key'",
        "setVal('#cfg-linking-tls-ca'",
        "newConfig.linking.tls.enabled = getCheck('#cfg-linking-tls-enabled')",
        "newConfig.linking.tls.verify = getCheck('#cfg-linking-tls-verify')",
        "newConfig.linking.tls.cert_file = getVal('#cfg-linking-tls-cert') || null",
        "newConfig.linking.tls.key_file = getVal('#cfg-linking-tls-key') || null",
        "newConfig.linking.tls.ca_file = getVal('#cfg-linking-tls-ca') || null",
    ]
    for token in required_tokens:
        assert token in admin_js


def test_login_php_rate_limit_paths_present():
    login_php = _read(WEBADMIN_LOGIN_FILE)
    required_tokens = [
        "function rate_check(",
        "function rate_record_failure(",
        "function rate_clear(",
        "$rate = rate_check(",
        "rate_record_failure(",
        "rate_clear(",
    ]
    for token in required_tokens:
        assert token in login_php


def test_admin_js_uses_crypto_for_password_generation():
    admin_js = _read(WEBADMIN_DIR / "admin.js")
    assert "crypto.getRandomValues" in admin_js


def test_main_config_secure_defaults():
    cfg = _read(MAIN_CONFIG_FILE)
    assert '"auth_require_ssl": true' in cfg
    assert '"pass_require_ssl": true' in cfg
    assert '"default_password": "__CHANGE_ME__"' in cfg
    assert '"password": "__CHANGE_ME__"' in cfg


def test_webchat_context_menu_uses_bound_actions():
    webchat_html = _read(WEBCHAT_FILE)
    assert "class=\"context-menu-item cm-action\"" in webchat_html
    assert "function bindContextMenuActions()" in webchat_html
    assert "data-action=\"whois\"" in webchat_html
    assert "data-action=\"start-pm\"" in webchat_html


def test_install_script_generates_secrets_and_wires_them():
    install_sh = _read(INSTALL_SCRIPT)
    assert "generate_install_secrets() {" in install_sh
    assert "secrets.token_urlsafe(18)" in install_sh
    assert "secrets.token_urlsafe(24)" in install_sh
    assert "--admin-password \"$GENERATED_ADMIN_PASS\"" in install_sh
    assert "webchat/webchat.conf.example" in install_sh
    assert "cfg.set('webirc', 'password', webirc_password)" in install_sh


def test_server_runtime_ssl_default_for_pass_auth():
    server_py = _read(MAIN_SERVER_FILE)
    assert "pass_require_ssl = CONFIG.get('security', 'pass_require_ssl', default=True)" in server_py


def test_api_helpers_uses_cross_process_rate_limit_state():
    api_helpers = _read(API_HELPERS_FILE)
    assert "_RATE_LIMIT_FILE" in api_helpers
    assert "_check_rate_limit_shared" in api_helpers
    assert "fcntl.flock" in api_helpers


def test_linking_defaults_require_tls():
    linking_py = _read(LINKING_FILE)
    assert "self.tls_enabled = CONFIG.get('linking', 'tls', 'enabled', default=True)" in linking_py
    assert "self.tls_required = CONFIG.get('linking', 'tls', 'required', default=True)" in linking_py
    assert "if self.tls_required and not self.tls_enabled:" in linking_py


def test_generate_default_config_no_eval():
    generator = _read(DEFAULT_CONFIG_GEN_FILE)
    assert "ast.literal_eval" in generator
    assert "config = eval(" not in generator


def test_docs_no_longer_reference_changeme_defaults():
    readme = _read(README_FILE)
    config_doc = _read(DOC_CONFIG_FILE)
    testharness_doc = _read(DOC_TESTHARNESS_FILE)
    combined = "\n".join([readme, config_doc, testharness_doc])
    assert "changeme" not in combined


def test_integration_harness_uses_test_admin_password_env():
    topology = _read(TOPOLOGY_TEST_FILE)
    stress = _read(STRESS_TEST_FILE)
    run_tests = _read(RUN_TESTS_FILE)
    assert "PASS changeme" not in topology
    assert "PASS changeme" not in stress
    assert "PYIRCX_TEST_ADMIN_PASS" in topology
    assert "PYIRCX_TEST_ADMIN_PASS" in stress
    assert "export PYIRCX_TEST_ADMIN_PASS" in run_tests


def test_webadmin_php_fallback_targets_repo_root_api():
    api_php = _read(WEBADMIN_API_FILE)
    login_php = _read(WEBADMIN_LOGIN_FILE)
    assert "dirname(__DIR__) . '/api.py'" in api_php
    assert "dirname(__DIR__) . '/api.py'" in login_php


def test_webadmin_secret_commands_use_stdin_payload():
    api_php = _read(WEBADMIN_API_FILE)
    admin_js = _read(WEBADMIN_DIR / "admin.js")
    assert "stdin_payload" in admin_js
    assert "proc_open($cmd_parts" in api_php
    assert "'add-staff' => 'add-staff-stdin'" in api_php
    assert "'change-staff-password' => 'change-staff-password-stdin'" in api_php
    assert "'register-nick' => 'register-nick-stdin'" in api_php
    assert "'edit-nick' => 'edit-nick-stdin'" in api_php


def test_webadmin_session_expiry_is_enforced():
    session_auth = _read(WEBADMIN_SESSION_AUTH_FILE)
    login_php = _read(WEBADMIN_LOGIN_FILE)
    index_php = _read(WEBADMIN_INDEX_FILE)
    api_php = _read(WEBADMIN_API_FILE)
    assert "PYIRCX_WEBADMIN_ABSOLUTE_TIMEOUT" in session_auth
    assert "PYIRCX_WEBADMIN_IDLE_TIMEOUT" in session_auth
    assert "$_SESSION['last_activity'] = $now;" in session_auth
    assert "pyircx_require_admin_session(false);" in index_php
    assert "pyircx_require_admin_session(true);" in api_php
    assert "$_SESSION['last_activity'] = $_SESSION['login_time'];" in login_php
    assert "?expired=1" in session_auth


def test_webchat_only_trusts_forwarded_headers_from_trusted_proxies():
    gateway_py = _read(WEBCHAT_GATEWAY_FILE)
    config_example = _read(WEBCHAT_CONFIG_EXAMPLE_FILE)
    assert "trusted_proxies" in gateway_py
    assert "self._is_trusted_proxy(remote_ip)" in gateway_py
    assert "return remote_ip" in gateway_py
    assert "trusted_proxies = 127.0.0.1/32, ::1/128" in config_example


def test_webchat_install_and_docs_use_ini_config_format():
    install_sh = _read(INSTALL_SCRIPT)
    upgrade_sh = _read(PROJECT_ROOT / "upgrade.sh")
    service = _read(PROJECT_ROOT / "pyircx-webchat.service")
    change_password = _read(PROJECT_ROOT / "change_password.sh")
    readme = _read(PROJECT_ROOT / "README.md")
    webchat_readme = _read(PROJECT_ROOT / "webchat" / "README.md")
    remote_deploy = _read(PROJECT_ROOT / "webchat" / "REMOTE_DEPLOYMENT.md")
    repair_sh = _read(PROJECT_ROOT / "repair.sh")
    assert "EnvironmentFile" not in service
    assert "gateway.py --config /etc/pyircx/webchat.conf" in service
    assert "cfg.set('webirc', 'password', password)" in change_password
    assert "change-staff-password-stdin" in change_password
    assert "webadmin_config.json" not in change_password
    assert "json.dumps({\"password\": sys.argv[1]})" in change_password
    assert "[webirc]" in readme
    assert "[webirc]" in webchat_readme
    assert "[webirc]" in remote_deploy
    assert 'cp "$SCRIPT_DIR/version.json" "$WEBCHAT_WEB_DIR/"' in install_sh
    assert 'cp "$SCRIPT_DIR/version.json" /var/www/html/webchat/' in upgrade_sh
    assert "[webirc]" in repair_sh


def test_web_ui_reads_shared_version_metadata():
    webadmin = _read(WEBADMIN_DIR / "index.php")
    webchat = _read(WEBCHAT_FILE)
    landing = _read(PROJECT_ROOT / "index.html")
    assert "version.json" in webadmin
    assert "fetch('./version.json')" in webchat
    assert "fetch('./version.json')" in landing


def test_webadmin_logs_page_has_connection_sessions_tab():
    index = _read(WEBADMIN_DIR / "index.php")
    api_php = _read(WEBADMIN_DIR / "api.php")
    admin_js = _read(WEBADMIN_DIR / "admin.js")

    assert "Connection Sessions" in index
    assert "connection-sessions" in api_php
    assert "loadConnectionLogs" in admin_js


def test_webchat_client_ctcp_support_matches_clientinfo():
    webchat = _read(WEBCHAT_FILE)
    assert 'CLIENTINFO ACTION CLIENTINFO ERRMSG FINGER PING SOURCE TIME USERINFO VERSION' in webchat
    assert "case 'FINGER':" in webchat
    assert "case 'USERINFO':" in webchat
    assert "case 'SOURCE':" in webchat
    assert 'ERRMSG ${command} :Unsupported CTCP query' in webchat
