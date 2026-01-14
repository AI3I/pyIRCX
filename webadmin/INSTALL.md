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
sudo cp -r /home/jdlewis/GitHub/pyIRCX/webadmin/* /var/www/html/webadmin/
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

### 4. Test permissions

```bash
sudo -u www-data systemctl is-active pyircx.service
```

Should return `active`, `inactive`, or `failed` without asking for a password.

### 5. Access the interface

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

1. **Add authentication**: Use HTTP Basic Auth (shown above) or implement PHP session-based auth
2. **Use HTTPS**: Configure SSL/TLS certificate
3. **Restrict access**: Use firewall rules or web server IP restrictions
4. **Limit sudo**: The sudoers entry is already restrictive, but audit it regularly
5. **Keep PHP updated**: Ensure PHP and web server are patched

## Troubleshooting

### "Permission denied" errors

Check file permissions:
```bash
sudo chown -R www-data:www-data /var/www/html/webadmin/
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

- GitHub: https://github.com/jdlewis/pyIRCX
- Issues: Report bugs via GitHub Issues

## License

GNU General Public License v3.0

Copyright (C) 2026 pyIRCX Project
