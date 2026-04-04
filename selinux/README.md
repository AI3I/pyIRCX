# pyIRCX SELinux Policies

SELinux policy modules required for the Web Administration Panel to function correctly on SELinux-enabled systems (Fedora, RHEL, CentOS, etc.).

## Required Policies

### 1. pyircx-httpd-systemd.te
**Purpose:** Allows Apache (httpd_t) to communicate with systemd via D-Bus

**Enables:**
- Service control (Start/Stop/Restart) from web admin panel
- Uses polkit for authorization (more secure than sudo)

**Permissions granted:**
- `dbus_chat_system_bus` - Communicate with system D-Bus
- `systemd_status_all_unit_files` - Check unit file status
- `systemd_start_systemd_services` - Start/restart services

### 2. pyircx-httpd-journal-v3.te
**Purpose:** Allows Apache (httpd_t) to read systemd journal files

**Enables:**
- Log viewing from journalctl in web admin panel
- Real-time server log display

**Permissions granted:**
- `read` - Read journal files
- `open` - Open journal file descriptors
- `map` - Memory-map journal files

## Installation

### Automated (via install.sh)
The installation script handles SELinux policy setup automatically.

### Manual Installation

1. **Compile the policies:**
```bash
cd selinux/

# Compile httpd-systemd policy
checkmodule -M -m -o pyircx-httpd-systemd.mod pyircx-httpd-systemd.te
semodule_package -o pyircx-httpd-systemd.pp -m pyircx-httpd-systemd.mod

# Compile httpd-journal policy
checkmodule -M -m -o pyircx-httpd-journal-v3.mod pyircx-httpd-journal-v3.te
semodule_package -o pyircx-httpd-journal-v3.pp -m pyircx-httpd-journal-v3.mod
```

2. **Install the policies:**
```bash
sudo semodule -i pyircx-httpd-systemd.pp
sudo semodule -i pyircx-httpd-journal-v3.pp
```

3. **Verify installation:**
```bash
sudo semodule -l | grep pyircx
```

Expected output:
```
pyircx-httpd-journal-v3
pyircx-httpd-systemd
```

## Verification

### Test Service Control
```bash
# Should return service status without errors
curl http://localhost/pyircx-admin/api.php?cmd=service-status
```

### Test Log Access
```bash
# Should return logs from journalctl
curl http://localhost/pyircx-admin/api.php?cmd=logs&args[]=10
```

Check the response includes `"source": "journalctl"`.

## Troubleshooting

### Check for SELinux Denials
```bash
# View recent denials
sudo ausearch -m avc -ts recent | grep httpd

# Generate policy from denials
sudo ausearch -m avc -ts recent | audit2allow -M myfix
```

### Common Issues

**Service control fails:**
- Check polkit rules are installed: `ls /etc/polkit-1/rules.d/10-pyircx-admin.rules`
- Verify SELinux policy: `sudo semodule -l | grep pyircx-httpd-systemd`
- Check for D-Bus denials: `sudo ausearch -m avc | grep dbus`

**Log viewer shows "source: file" instead of "journalctl":**
- Verify SELinux policy: `sudo semodule -l | grep pyircx-httpd-journal`
- Check apache is in systemd-journal group: `groups apache`
- Check for journal access denials: `sudo ausearch -m avc | grep journal`

## Uninstallation

```bash
sudo semodule -r pyircx-httpd-systemd
sudo semodule -r pyircx-httpd-journal-v3
```

## Policy Details

### pyircx-httpd-systemd.te
```
module pyircx-httpd-systemd 1.0;

require {
    type httpd_t;
}

#============= httpd_t ==============
gen_require(`
    type systemd_unit_file_t;
')

allow httpd_t self:dbus send_msg;
dbus_chat_system_bus(httpd_t)
systemd_status_all_unit_files(httpd_t)
systemd_start_systemd_services(httpd_t)
```

### pyircx-httpd-journal-v3.te
```
module pyircx-httpd-journal-v3 1.0;

require {
    type var_log_t;
    type httpd_t;
    class file { map open read };
}

#============= httpd_t ==============
allow httpd_t var_log_t:file { open read };
allow httpd_t var_log_t:file map;
```

## Security Notes

- These policies grant minimal required permissions
- Service control uses polkit for authorization (not sudo)
- Only affects httpd_t context (Apache web server)
- Does not grant access to other services or files
- Recommended for production use

## Support

For SELinux-related issues, check:
- `/var/log/audit/audit.log` - SELinux denial logs
- `sudo sealert -a /var/log/audit/audit.log` - Human-readable analysis
- GitHub Issues: https://github.com/AI3I/pyIRCX/issues
