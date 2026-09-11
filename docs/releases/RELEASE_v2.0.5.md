# pyIRCX v2.0.5 Release Notes

Release date: July 12, 2026

pyIRCX v2.0.5 is a maintenance release focused on reliable shutdown session history and cleaner certificate-renewal operations.

## Highlights

- Active local sessions are now flushed to persistent connection history during graceful shutdown before sockets and the database pool are torn down.
- Session history recording is guarded so the same user session is not written twice when shutdown and disconnect handling overlap.
- Expected client disconnect socket errors such as connection resets, broken pipes, and timeouts are handled quietly in debug mode.
- Certbot renewal setup now prefers the distro-provided `certbot.timer` and disables the duplicate pyIRCX renewal timer when both exist.
- Setup, repair, and upgrade scripts now install a certbot deploy hook to reload Apache/httpd, reload pyIRCX, and restart WebChat after renewed certificates are deployed.
- Repair validation now detects missing deploy hooks, disabled distro renewal timers, duplicate pyIRCX renewal timers, and missing `ssl-cert` group membership with the active issue counter.

## Validation

- Added unit coverage for shutdown persistence of active connection sessions.
- Full local unit suite passes with 412 tests.
- Shell syntax checks passed for repair, setup_ssl, and upgrade scripts.

## Upgrade Notes

Existing installations can use `upgrade.sh`. Systems using Let's Encrypt certificates should end up on the distribution certbot timer when available, with the pyIRCX-specific renewal timer disabled to avoid duplicate renewal jobs. The certbot deploy hook handles service reloads after certificate renewal.
