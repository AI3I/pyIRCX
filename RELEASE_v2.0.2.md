# pyIRCX v2.0.2 Release Notes

**Release Date:** April 20, 2026
**Focus:** Staff connection history, WebAdmin visibility, and cleaner shutdowns

---

## Highlights

- Added staff-only `/LASTLOGONS` connection-history numerics with persistent completed-session storage.
- Added `/LASTLOGONS VERBOSE` for logout time and disconnect reason while keeping the default table compact.
- Added a WebAdmin Logs subtab for persisted connection sessions.
- Added configurable retention for completed connection sessions.
- Fixed systemd restart behavior so graceful shutdown exits without requiring SIGKILL.

---

## New Features

### Staff LASTLOGONS

`/LASTLOGONS` and aliases `/LOGONS` and `/LASTLOGON` now provide a staff-only flat table using numerics:

- `976` - LASTLOGONS start
- `977` - table header, separator, and rows
- `978` - LASTLOGONS end

Default columns:

- `Nickname`
- `Username`
- `Real Name`
- `IP Address`
- `Logon Time`
- `Duration`
- `Status`

`/LASTLOGONS VERBOSE` adds:

- `Logout Time`
- `Reason`

### Persisted Connection Sessions

Completed sessions are persisted in SQLite and survive server restarts. Active sessions continue to be generated from runtime memory and display as `online`.

New configuration:

- `limits.max_connection_sessions` - maximum completed sessions retained by count.
- `limits.connection_session_retention_days` - optional age-based pruning; `0` disables age pruning.

### WebAdmin Connection Session Logs

The WebAdmin Logs page now has two tabs:

- `Server Logs`
- `Connection Sessions`

The Connection Sessions tab reads persisted `connection_sessions` data through the WebAdmin API and supports search plus result limiting.

---

## Bug Fixes

- LASTLOGONS output now uses pyIRCX numerics instead of NOTICE delivery.
- LASTLOGONS is restricted to staff; unprivileged users receive `481`.
- IP addresses are displayed directly instead of misleading hostname/PTR-style output.
- Nickname and username columns respect configured `NICKLEN` and `USERLEN`.
- Standalone DB initialization now creates `connection_sessions`; this is no longer trunk-only.
- Systemd restarts now complete cleanly after graceful shutdown.
- Async DB pool shutdown now closes tracked `aiosqlite` workers to avoid lingering non-daemon threads.

---

## Testing

Validated locally:

```bash
python -m py_compile pyircx.py api.py database.py init_database.py help_text.py responses.py
pytest -q --assert=plain tests/unit/test_ircv3_features.py tests/unit/test_init_database.py tests/unit/test_api.py tests/unit/test_help_text.py tests/unit/test_webadmin_security_hardening.py tests/unit/test_versioning.py tests/unit/test_responses.py
python validate_responses.py --quiet
```

Validated on `atlas.jdlewis.net`:

- `/LASTLOGONS VERBOSE` returns `976/977/978`.
- Non-staff `/LASTLOGONS` returns `481`.
- WebAdmin API returns persisted connection sessions.
- `systemctl restart pyircx` exits cleanly without systemd SIGKILL.

---

## Upgrade Notes

Deploy the updated application files and restart pyIRCX:

```bash
sudo systemctl restart pyircx
sudo systemctl status pyircx
```

If maintaining a custom config, add these keys under `limits` if they are not present:

```json
{
  "max_connection_sessions": 1000,
  "connection_session_retention_days": 0
}
```

No breaking protocol changes are introduced in this release.
