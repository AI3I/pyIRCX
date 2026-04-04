# pyIRCX Web Admin - Installation Guide

## Overview

This is the supported browser-based admin panel for pyIRCX. It runs on any standard web server (Apache/nginx) with PHP support.

## Features

- ✅ Multi-page interface with sidebar navigation
- ✅ Dashboard overview with real-time stats
- ✅ User management (connected + registered)
- ✅ Channel management (active + registered)
- ✅ Staff management
- ✅ Access control (bans/glines)
- ✅ NewsFlash management
- ✅ Mailbox viewer
- ✅ Configuration editor
- ✅ Log viewer
- ✅ Service control (start/stop/restart)

## Requirements

- Apache or nginx webserver
- PHP 7.4 or higher
- pyIRCX installed (api.py accessible)
- polkit rules for `pyircx.service` control

## Installation

### 1. Copy files to web root

```bash
sudo cp -r ./webadmin/* /var/www/html/webadmin/
sudo chown -R www-data:www-data /var/www/html/webadmin/
sudo chmod 755 /var/www/html/webadmin/
```

### 2. Configure api.php path

Edit `/var/www/html/webadmin/api.php` and verify the path to your `api.py`:

```php
// Line ~55
$API_PATH = '/opt/pyircx/api.py';
```

Change to your actual api.py location if different:
- System install: `/opt/pyircx/api.py`
- Custom: `/path/to/your/api.py`

### 3. Configure polkit for service control

The web interface should use the shipped polkit rule instead of sudo:

```bash
sudo cp polkit/10-pyircx-admin.rules /etc/polkit-1/rules.d/
sudo chown root:root /etc/polkit-1/rules.d/10-pyircx-admin.rules
sudo chmod 644 /etc/polkit-1/rules.d/10-pyircx-admin.rules
sudo systemctl reload polkit
```

### 4. Configure SELinux (if enabled)

If your system uses SELinux (RHEL, Fedora, CentOS), configure security contexts:

```bash
# Set SELinux contexts for web admin files
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/webadmin(/.*)?" 2>/dev/null || true
sudo restorecon -Rv /var/www/html/webadmin 2>/dev/null || true

# Set SELinux contexts for config directory
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/etc/pyircx(/.*)?" 2>/dev/null || true
sudo restorecon -Rv /etc/pyircx 2>/dev/null || true
```

These contexts allow the web server to read and write configuration files while maintaining security isolation.

### 5. Configure permissions

Add the web server user to the pyircx group:

```bash
# For Apache (Fedora/RHEL)
sudo usermod -a -G pyircx apache
sudo systemctl restart php-fpm

# For Apache/nginx (Debian/Ubuntu)
sudo usermod -a -G pyircx www-data
sudo systemctl restart php-fpm
```

Set proper directory and file permissions:

```bash
# Set directory permissions (group write enabled)
sudo chmod 775 /opt/pyircx
sudo chmod 775 /etc/pyircx

# Keep /etc as the config source of truth and /opt as a symlink
sudo chown root:pyircx /etc/pyircx/pyircx_config.json
sudo chmod 660 /etc/pyircx/pyircx_config.json
sudo ln -sfn /etc/pyircx/pyircx_config.json /opt/pyircx/pyircx_config.json
sudo chmod 664 /opt/pyircx/pyircx.db
```

### 6. Test permissions

```bash
# Test systemctl access
sudo -u www-data systemctl is-active pyircx.service

# Test file write access
sudo -u www-data test -w /etc/pyircx/pyircx_config.json && echo "Config writable" || echo "Config not writable"
```

Should return `active`, `inactive`, or `failed` without asking for a password, and config should be writable.

### 7. Access the interface

Open your browser to:

```
http://your-server/webadmin/
```

## Apache Configuration (Optional)

For cleaner URLs and better security:

```apache
<Directory /var/www/html/webadmin>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

# Optional: Add basic auth
<Directory /var/www/html/webadmin>
    AuthType Basic
    AuthName "pyIRCX Admin"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

Create password file:
```bash
sudo htpasswd -c /etc/apache2/.htpasswd admin
sudo systemctl restart apache2
```

## nginx Configuration (Optional)

```nginx
location /webadmin/ {
    alias /var/www/html/webadmin/;
    index index.html;

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $request_filename;
        include fastcgi_params;
    }

    # Optional: Add basic auth
    auth_basic "pyIRCX Admin";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

## Security Recommendations

1. **Session Authentication**: Web admin uses IRC staff account authentication with CSRF protection
2. **Use HTTPS**: Configure SSL/TLS certificate for encrypted connections
3. **Restrict access**: Use firewall rules or web server IP restrictions to limit admin panel access
4. **SELinux Enforcement**: Keep SELinux enabled for mandatory access control (recommended on RHEL/Fedora/CentOS)
5. **Group Permissions**: Web admin uses group-based permissions (775/664) instead of world-writable files
6. **Limit service control**: Use the shipped polkit authorization rule restricted to `pyircx.service`
7. **Keep updated**: Ensure PHP, web server, and pyIRCX are kept up to date with security patches

## Troubleshooting

### "Permission denied" errors

Check file permissions and group membership:
```bash
# Check ownership
sudo chown -R www-data:www-data /var/www/html/webadmin/
sudo chown root:pyircx /etc/pyircx/pyircx_config.json

# Check permissions
sudo chmod 775 /etc/pyircx
sudo chmod 660 /etc/pyircx/pyircx_config.json

# Runtime config path should be a symlink back to /etc
sudo ln -sfn /etc/pyircx/pyircx_config.json /opt/pyircx/pyircx_config.json

# Verify web server user is in pyircx group
groups www-data

# If not in group, add and restart PHP-FPM
sudo usermod -a -G pyircx www-data
sudo systemctl restart php-fpm
```

### SELinux denials

If you see "Permission denied" on SELinux systems, check audit logs:
```bash
# Check for SELinux denials
sudo ausearch -m avc -ts recent

# Verify SELinux contexts
ls -Z /etc/pyircx/
ls -Z /var/www/html/webadmin/

# Expected contexts:
# httpd_sys_rw_content_t for both directories

# Restore contexts if incorrect
sudo restorecon -Rv /etc/pyircx
sudo restorecon -Rv /var/www/html/webadmin
```

### Service control doesn't work

Test service access as the web user:
```bash
sudo -u www-data systemctl is-active pyircx.service
```

If it asks for authentication, check your polkit rule and web server user.

### API returns errors

Check api.py path in api.php:
```bash
ls -l /opt/pyircx/api.py
```

Test api.py manually:
```bash
python3 /opt/pyircx/api.py stats
```

### PHP errors

Enable error logging:
```bash
sudo tail -f /var/log/apache2/error.log
# or for nginx
sudo tail -f /var/log/nginx/error.log
```

## Support

- GitHub: https://github.com/AI3I/pyIRCX
- Issues: Report bugs via GitHub Issues
