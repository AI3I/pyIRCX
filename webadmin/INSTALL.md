# pyIRCX Web Admin - Installation Guide

## Overview

This is a standalone web admin panel for pyIRCX that runs on any standard webserver (Apache/nginx) with PHP support. No Cockpit dependency required!

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
- sudo privileges for systemctl commands

## Installation

### 1. Copy files to web root

```bash
sudo cp -r ./webadmin/* /var/www/html/webadmin/
sudo chown -R www-data:www-data /var/www/html/webadmin/
sudo chmod 755 /var/www/html/webadmin/
```

### 2. Configure api.php path

Edit `/var/www/html/webadmin/api.php` and verify the path to your api.py:

```php
// Line ~55
$API_PATH = '/usr/share/cockpit/pyircx/api.py';
```

Change to your actual api.py location if different:
- System install: `/usr/share/cockpit/pyircx/api.py`
- Opt install: `/opt/pyircx/cockpit/pyircx/api.py`
- Custom: `/path/to/your/api.py`

### 3. Configure sudo for service control

The web interface needs sudo privileges to control the pyIRCX service. Create a sudoers entry:

```bash
sudo visudo -f /etc/sudoers.d/pyircx-web
```

Add this line (replace `www-data` with your web server user if different):

```
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl start pyircx.service, /usr/bin/systemctl stop pyircx.service, /usr/bin/systemctl restart pyircx.service, /usr/bin/systemctl is-active pyircx.service
```

Save and exit.

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

# For Apache (Debian/Ubuntu)
sudo usermod -a -G pyircx www-data
sudo systemctl restart php-fpm
```

Set proper directory and file permissions:

```bash
# Set directory permissions (group write enabled)
sudo chmod 775 /opt/pyircx
sudo chmod 775 /etc/pyircx

# Set config file permissions (group write enabled)
sudo chmod 664 /etc/pyircx/pyircx_config.json
sudo chmod 664 /opt/pyircx/pyircx.db
```

### 6. Test permissions

```bash
# Test systemctl access
sudo -u apache systemctl is-active pyircx.service

# Test file write access
sudo -u apache test -w /etc/pyircx/pyircx_config.json && echo "Config writable" || echo "Config not writable"
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

1. **Session Authentication**: Web admin uses IRC staff account authentication with CSRF protection (v2.0.0)
2. **Use HTTPS**: Configure SSL/TLS certificate for encrypted connections
3. **Restrict access**: Use firewall rules or web server IP restrictions to limit admin panel access
4. **SELinux Enforcement**: Keep SELinux enabled for mandatory access control (recommended on RHEL/Fedora/CentOS)
5. **Group Permissions**: Web admin uses group-based permissions (775/664) instead of world-writable files
6. **Limit sudo/polkit**: Service control uses polkit authorization (passwordless but restricted to pyircx.service)
7. **Keep updated**: Ensure PHP, web server, and pyIRCX are kept up to date with security patches

## Troubleshooting

### "Permission denied" errors

Check file permissions and group membership:
```bash
# Check ownership
sudo chown -R apache:apache /var/www/html/webadmin/
sudo chown pyircx:pyircx /etc/pyircx/pyircx_config.json

# Check permissions
sudo chmod 775 /etc/pyircx
sudo chmod 664 /etc/pyircx/pyircx_config.json

# Verify web server user is in pyircx group
groups apache

# If not in group, add and restart PHP-FPM
sudo usermod -a -G pyircx apache
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

Test sudo config:
```bash
sudo -u www-data systemctl is-active pyircx.service
```

If it asks for password, check your sudoers file.

### API returns errors

Check api.py path in api.php:
```bash
ls -l /usr/share/cockpit/pyircx/api.py
```

Test api.py manually:
```bash
python3 /usr/share/cockpit/pyircx/api.py stats
```

### PHP errors

Enable error logging:
```bash
sudo tail -f /var/log/apache2/error.log
# or for nginx
sudo tail -f /var/log/nginx/error.log
```

## Uninstalling Cockpit Module

Since you're using the standalone web admin now, you can remove the Cockpit module:

```bash
sudo rm -rf /usr/share/cockpit/pyircx/
```

The api.py file should stay accessible at its location for the PHP backend to use.

## Migrating from Cockpit

The standalone version has these improvements:
- ✅ No Cockpit dependency
- ✅ Multi-page layout with sidebar (cleaner, less busy)
- ✅ Runs on standard webserver
- ✅ Easier to customize
- ✅ Better mobile responsiveness
- ✅ Same functionality as Cockpit version

## Support

- GitHub: https://github.com/0x8007000E/pyIRCX
- Issues: Report bugs via GitHub Issues
