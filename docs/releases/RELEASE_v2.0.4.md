# pyIRCX v2.0.4 Release Notes

Release date: May 25, 2026

pyIRCX v2.0.4 is an operations hardening release for DNSBL enforcement, WebAdmin command dispatch, installer consistency, and SELinux-aware Fedora/RHEL deployment.

## Highlights

- Default DNSBL providers now favor maintained lists: `xbl.spamhaus.org`, `dnsbl.dronebl.org`, `torexit.dan.me.uk`, and `all.s5h.net`.
- Removed stale or questionable defaults: `rbl.efnetrbl.org`, `proxy.bl.gweep.ca`, `dnsbl.tornevall.org`, and `bl.spamcop.net`.
- WebAdmin admin commands now use a lock file and atomic processing handoff so commands are not lost when the API and server touch the queue at the same time.
- DNSBL policy responses such as `127.255.255.x` are logged clearly, making resolver misconfiguration visible without treating those responses as blacklist hits.
- Install, repair, and upgrade scripts now consistently install version metadata, preserve queue permissions, create the queue lock file, and configure Unbound/systemd-resolved correctly.
- Fedora/RHEL WebAdmin setup now installs SELinux management tooling before applying contexts and local policy modules.

## Validation

- Local test suite: 410 tests passing.
- Shell syntax checks passed for installer, repair, upgrade, Apache, SSL, and uninstall scripts.
- Fedora 44 validation covered fresh install, service startup, WebAdmin, Unbound, repair, upgrade, and SELinux enforcing mode.
- Debian 13 production-path validation covered DNSBL resolver behavior.

## Upgrade Notes

Existing installations can use `upgrade.sh`. For systems using WebAdmin, the upgrade path refreshes the admin command queue permissions and creates the sidecar lock file. For systems using local Unbound, the repair path can also re-check resolver wiring.
