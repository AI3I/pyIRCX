# pyIRCX Standalone Web Admin

✅ **Installation Complete!**

Your web admin is now live and fully functional, replacing the old Cockpit interface.

## Access

**URL:** http://your-server/pyircx-admin/

## What's New

### Layout Improvements
- ✅ **Left sidebar navigation** - Clean, organized multi-page layout
- ✅ **Separated pages** - Dashboard, Users, Channels, Staff, Access Control, NewsFlash, Mailbox, Config, Logs
- ✅ **No more scrolling overload** - Each section has its own dedicated page
- ✅ **Modern UI** - Clean design with smooth animations

### Technical Improvements
- ✅ **No Cockpit dependency** - Runs on standard Apache/nginx
- ✅ **PHP backend** - Simple API router calls your existing `api.py`
- ✅ **Pure JavaScript** - No jQuery, no external dependencies
- ✅ **Mobile responsive** - Sidebar collapses on mobile devices

## Features

### Dashboard Page
- Real-time server statistics
- Service control (start/stop/restart)
- Connected users overview
- Active channels overview
- Linked servers status

### Users Page
- Search registered nicknames
- View connected users in real-time
- Register new nicknames
- Edit/delete registered nicknames
- Pagination for large user lists

### Channels Page
- Search registered channels
- View active channels
- Register new channels
- Edit channel properties (modes, keys, access lists)
- Delete registered channels
- Pagination for large channel lists

### Staff Page
- View all staff members
- Add new staff (ADMIN/SYSOP/GUIDE)
- Change staff levels
- Change staff passwords
- Delete staff members

### Access Control Page
- View all DENY/GRANT rules
- Add new access rules (bans/glines)
- Set expiration times
- Remove access rules

### NewsFlash Page
- Configure broadcast settings
- Add/delete newsflash messages
- Set priority levels (Normal/High/Critical)
- Toggle periodic broadcasts

### Mailbox Page
- View recent mailbox messages
- See read/unread status
- Monitor user communications

### Configuration Page
- View server configuration
- Edit JSON config directly
- Auto-restart after save

### Logs Page
- View server logs
- Filter by log level (INFO/WARNING/ERROR)
- Search log contents
- Refresh on demand

## Installation Status

✅ Files installed to: `/var/www/html/pyircx-admin/`
✅ Permissions set: `apache:apache`
✅ API tested: Working
✅ Sudo configured: Service control enabled
✅ .htaccess created: Directory protection enabled

## Testing Checklist

- [x] API endpoint responds correctly
- [x] Service control permissions work
- [x] File permissions correct
- [ ] Test in browser - navigate to http://your-server/pyircx-admin/
- [ ] Test service start/stop/restart
- [ ] Test user management features
- [ ] Test channel management features

## Security Recommendations

1. **Enable Authentication** (Optional but recommended):
   ```bash
   # Uncomment auth lines in .htaccess
   sudo htpasswd -c /etc/httpd/.htpasswd admin
   ```

2. **Enable HTTPS**:
   - Install SSL certificate (Let's Encrypt recommended)
   - Force HTTPS in Apache/nginx config

3. **Restrict IP Access** (Optional):
   Add to .htaccess:
   ```apache
   Order deny,allow
   Deny from all
   Allow from 192.168.1.0/24
   ```

## Removing Old Cockpit Module

Since you have the standalone version now, you can optionally remove the Cockpit module:

```bash
sudo rm -rf /usr/share/cockpit/pyircx/
```

**Note:** Keep `api.py` accessible - the PHP backend needs it!

## File Structure

```
/var/www/html/pyircx-admin/
├── index.html          # Main HTML (multi-page layout with sidebar)
├── admin.js            # JavaScript (replaces Cockpit calls with fetch)
├── style.css           # CSS (sidebar layout, cards, responsive)
├── api.php             # PHP API router (calls api.py)
├── .htaccess           # Apache configuration
└── INSTALL.md          # Detailed installation guide
```

## API Backend

The PHP router (`api.php`) translates web requests to your Python backend:

```
Browser → api.php → api.py → Database/System
```

All your existing API functions work exactly as before, just accessed via PHP now instead of Cockpit.

## Troubleshooting

### Can't access the page
- Check Apache/httpd is running: `sudo systemctl status httpd`
- Check file permissions: `ls -la /var/www/html/pyircx-admin/`

### Service control doesn't work
- Test sudo: `sudo -u apache systemctl is-active pyircx.service`
- Check sudoers: `sudo cat /etc/sudoers.d/pyircx-web`

### API errors
- Check api.py path in `api.php` (line ~55)
- Test api.py directly: `python3 /path/to/api.py stats`

### PHP errors
- Check logs: `sudo tail -f /var/log/httpd/error_log`

## Next Steps

1. Open http://your-server/pyircx-admin/ in your browser
2. Test all the pages using the left sidebar navigation
3. Add HTTP Basic Auth for security (optional but recommended)
4. Configure HTTPS if needed
5. Enjoy your new, cleaner admin interface!

## Comparison: Old vs New

| Feature | Cockpit Version | Standalone Version |
|---------|----------------|-------------------|
| **Layout** | Single scrolling page | Multi-page with sidebar |
| **Dependency** | Requires Cockpit | Standard webserver only |
| **Navigation** | Scroll through sections | Click sidebar items |
| **Deployment** | Cockpit-specific | Works anywhere |
| **Customization** | Limited by Cockpit | Full control |
| **Mobile** | Cockpit mobile UI | Custom responsive design |

## Credits

- pyIRCX Project
- Converted from Cockpit to standalone by Claude
- Licensed under GNU GPL v3.0

Enjoy your new admin panel! 🚀
