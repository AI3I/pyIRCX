# pyIRCX Polkit Authorization Rules

Polkit (PolicyKit) rules required for the Web Administration Panel to control the pyIRCX service without requiring sudo or passwordless sudo.

## Overview

Polkit provides fine-grained authorization for system services. These rules allow the web server user to manage the pyIRCX systemd service through D-Bus.

**Security Benefits:**
- No sudo configuration needed
- No password storage required
- Audit logging via polkit
- More secure than NOPASSWD sudo

## Required File

### 10-pyircx-admin.rules

**Purpose:** Grant the web server user permission to manage `pyircx.service`

**Location:** `/etc/polkit-1/rules.d/10-pyircx-admin.rules`

**Permissions:**
- File mode: `644` (rw-r--r--)
- Owner: `root:root`

## Installation

### Automated (via install.sh)
The installation script handles polkit rule setup automatically.

### Manual Installation

1. **Copy the rules file:**
```bash
sudo cp polkit/10-pyircx-admin.rules /etc/polkit-1/rules.d/
```

2. **Set correct permissions:**
```bash
sudo chown root:root /etc/polkit-1/rules.d/10-pyircx-admin.rules
sudo chmod 644 /etc/polkit-1/rules.d/10-pyircx-admin.rules
```

3. **Reload polkit (optional, usually automatic):**
```bash
sudo systemctl reload polkit
```

## Verification

### Test Authorization

Try to manage the service via web admin:
```bash
curl -X POST -d "cmd=service-control&action=status" \
  http://localhost/webadmin/api.php
```

Should return service status without errors.

### Check Polkit Logs

```bash
# View polkit decisions
sudo journalctl -u polkit -n 50

# Look for pyircx-related authorization
sudo journalctl | grep polkit | grep pyircx
```

## Rule Details

### 10-pyircx-admin.rules

```javascript
polkit.addRule(function(action, subject) {
    // Allow the web server user to manage pyircx.service
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "pyircx.service" &&
        ["apache", "www-data"].indexOf(subject.user) !== -1) {
        return polkit.Result.YES;
    }
});
```

**Breakdown:**
- `action.id` - The specific D-Bus action being requested
- `action.lookup("unit")` - Which systemd unit is being controlled
- `subject.user` - Which user is making the request
- `polkit.Result.YES` - Grant authorization

**Actions Permitted:**
- Start service: `systemctl start pyircx.service`
- Stop service: `systemctl stop pyircx.service`
- Restart service: `systemctl restart pyircx.service`
- Check status: `systemctl status pyircx.service`

**Limitations:**
- Only works for `pyircx.service` (not other services)
- Only grants access to the configured web server user (`apache` or `www-data` by default)
- Only allows manage-units action

## Troubleshooting

### Service Control Fails

**Check rule is installed:**
```bash
ls -la /etc/polkit-1/rules.d/10-pyircx-admin.rules
```

**Verify syntax:**
```bash
sudo polkit -V
sudo journalctl -u polkit | tail -20
```

**Test D-Bus directly:**
```bash
sudo -u www-data busctl call \
  org.freedesktop.systemd1 \
  /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager \
  GetUnit s "pyircx.service"
```

### Common Issues

**"Permission denied" errors:**
- Check file permissions (should be 644, root:root)
- Verify polkit service is running: `systemctl status polkit`
- Check for SELinux denials: `sudo ausearch -m avc | grep polkit`

**Rule not taking effect:**
- Reload polkit: `sudo systemctl reload polkit`
- Check for JavaScript syntax errors in the rule file
- Ensure file is in `/etc/polkit-1/rules.d/` (not `/usr/share/polkit-1/rules.d/`)

**Works via command line but not web:**
- Verify the web server/PHP worker is running as the expected user: `ps aux | egrep 'httpd|apache2|php-fpm'`
- Check SELinux is allowing D-Bus communication (see selinux/README.md)
- Verify PHP-FPM user matches: `grep '^user' /etc/php-fpm.d/www.conf`

## Uninstallation

```bash
sudo rm /etc/polkit-1/rules.d/10-pyircx-admin.rules
sudo systemctl reload polkit
```

## Alternative: Using Sudo (Not Recommended)

If polkit is not available, you can use sudo with NOPASSWD:

```bash
# Add to /etc/sudoers.d/pyircx-admin
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl start pyircx.service
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop pyircx.service
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart pyircx.service
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl status pyircx.service
```

**Note:** Polkit is preferred as it provides better security and auditing.

## Security Considerations

### What This Grants
- The web server user can start/stop/restart pyircx service only
- The web server user cannot manage other services
- The web server user cannot modify unit files
- The web server user cannot reload systemd daemon

### What This Doesn't Grant
- No shell access
- No ability to modify files outside web root
- No access to other systemd units
- No password disclosure required

### Audit Trail
All polkit decisions are logged:
```bash
sudo journalctl -u polkit | grep pyircx
```

## Testing

### Test Service Control

```bash
# As the web server user, test systemctl via D-Bus
sudo -u www-data systemctl status pyircx.service

# Via web interface
curl -X POST -d "cmd=service-control&action=restart" \
  http://localhost/webadmin/api.php
```

Both should work without password prompts.

## References

- [Polkit Manual](https://www.freedesktop.org/software/polkit/docs/latest/)
- [Systemd D-Bus API](https://www.freedesktop.org/wiki/Software/systemd/dbus/)
- [Polkit Actions](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html)

## Support

For polkit-related issues:
- Check `/var/log/messages` or `journalctl -u polkit`
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
