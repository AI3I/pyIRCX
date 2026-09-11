# pyIRCX v2.0.6 Release Notes

Release date: September 10, 2026

pyIRCX v2.0.6 is a maintenance and hardening release: it fixes bcrypt-hashed server links, graceful shutdown on Python 3.9/3.10, and two permission gaps, and it gets CI running again.

## Highlights

- Server links configured with bcrypt-hashed passwords (from `utils/hash_link_password.py`) now authenticate; previously every handshake failed with a `NameError`.
- Graceful shutdown works on Python 3.9 and 3.10 again. It used `asyncio.timeout()` (3.11+), so older interpreters skipped link shutdown, client disconnects, session persistence, and the database pool close.
- `CREATE` can no longer set `+r` or `+z` on a new channel; it follows the same rules as `MODE`.
- WebAdmin admin-queue commands reject CR/LF/NUL in reasons, topics, and owner names, closing a queue-command and raw-IRC-line injection path.
- WEBIRC and plaintext link passwords are compared in constant time.
- systemd units re-enable `ProtectSystem=full` and `PrivateTmp=true`.
- New `requirements.txt` / `requirements-dev.txt`; install and repair use them, and install `websockets` correctly on PEP 668 distributions.
- STATS, CONFIG, STAFF, and PROFANITY handlers moved from `pyircx.py` to the new `staff_commands.py` module.
- CI updated to Node 24 actions, ruff linting, and Python 3.9 through 3.14.

## Validation

- Full local unit suite passes with 420 tests (new coverage for link authentication, admin-queue validation, and CREATE modes).
- Server started and exercised under a transient systemd unit with the new `ProtectSystem=full` sandbox (CREATE, STATS, STAFF, CONFIG, graceful shutdown).
- Two-server link test: plaintext and bcrypt link passwords both authenticate (on 2.0.5 the bcrypt link failed with `name 'bcrypt' is not defined`).
- Integration suite (`run_tests.sh`) run on 2.0.5 and 2.0.6 side by side: no new failures beyond one timing-sensitive topology test. Both versions show the same ~118 pre-existing integration failures on the test host.
- Shell syntax checks passed for install, repair, upgrade, and release scripts.

## Upgrade Notes

Existing installations can use `upgrade.sh`, which copies the new `staff_commands.py` module and the updated systemd units.

- **Linked networks:** linking requires an exact version match, so upgrade every linked server to 2.0.6 together.
- **Custom paths:** with `ProtectSystem=full`, `/usr`, `/boot`, and `/etc` (except `/etc/pyircx`) are read-only to the service. If you point the database, transcripts, or logs somewhere under those trees, add a matching `ReadWritePaths=` line to `/etc/systemd/system/pyircx.service`.
- **Python:** 3.9 is now the documented minimum (3.8 was never tested).
