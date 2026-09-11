# pyIRCX v2.0.3 Release Notes

**Release Date:** May 5, 2026
**Focus:** DNSBL false-positive fix and installer resolver configuration

---

## Highlights

- Fixed DNSBL checks incorrectly blocking clean IPs due to Spamhaus policy responses being misread as real hits.
- Fixed installer resolver configuration that left public nameservers ahead of the local unbound instance, bypassing it entirely for DNSBL lookups.
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()` inside async context.

---

## Bug Fixes

### DNSBL False Positives (security.py)

Spamhaus and other DNSBL operators return sentinel values in the `127.255.255.x` range to indicate a query policy problem (e.g. `127.255.255.254` = "you are using a public resolver and are not subscribed"). These are not actual blacklist hits, but the previous code treated any `127.x.x.x` response as a listing, causing every connection from any IP to be rejected when the server was queried via a public nameserver.

Two fixes applied:

1. **Response validation** — only treat DNS responses in `127.0.x.x` through `127.254.x.x` as real hits; explicitly exclude `127.255.255.x`.
2. **`asyncio.get_running_loop()`** — replaced the deprecated `asyncio.get_event_loop()` call inside the async `check_ip()` method. In Python 3.12+, the old call inside a running coroutine can raise `RuntimeError`, which was silently swallowed by the generic `except Exception` handler, causing all DNSBL checks to return "not listed" regardless of actual status.

### Installer Resolver Configuration (install.sh)

The systemd-resolved integration block had two bugs that left the local unbound instance unused:

1. **Wrong DNS address** — `DNS=127.0.0.53` was written instead of `DNS=127.0.0.1`. `127.0.0.53` is the systemd-resolved stub, not unbound.
2. **Symlink to uplink resolv.conf** — the install left `/etc/resolv.conf` pointing at `/run/systemd/resolve/resolv.conf` (uplink mode), which lists all DHCP-provided nameservers from network interfaces first. These public nameservers were tried before unbound, triggering Spamhaus's public-resolver policy block on every DNSBL query.

Fix: write a static, immutable `/etc/resolv.conf` containing only `nameserver 127.0.0.1` so all DNS resolution goes through the local recursive resolver.

---

## Testing

Validated on `atlas.jdlewis.net`:

- Connections from previously blocked clean IPs now succeed.
- `xbl.spamhaus.org` returns `NXDOMAIN` (not listed) via local unbound for a clean WAN IP that was previously producing `127.255.255.254`.
- `pyircx.service` starts cleanly after deployment.

---

## Upgrade Notes

Deploy the updated files and restart pyIRCX:

```bash
sudo systemctl restart pyircx
sudo systemctl status pyircx
```

If your server was installed with a prior version and you are running unbound as the local resolver, verify that `/etc/resolv.conf` contains only `nameserver 127.0.0.1` and is not a symlink to `/run/systemd/resolve/resolv.conf`. If it is still a symlink, run:

```bash
rm -f /etc/resolv.conf
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
chattr +i /etc/resolv.conf
```

No configuration file changes are required. No breaking protocol changes are introduced in this release.
