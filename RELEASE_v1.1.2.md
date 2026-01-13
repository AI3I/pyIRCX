# pyIRCX v1.1.2 Release - Channel Operations & Database Architecture

**Release Date:** January 12, 2026  
**Type:** Bug fixes, database improvements, feature enhancements

---

## 🎯 Highlights

### Channel Unlock Button Fixed
- Services (+s) can now set/unset MODE +z (locked mode)
- Web admin unlock button now works correctly
- System user maintains proper service privileges (no longer incorrectly has +a)

### Database Architecture Overhaul
- **Migrated from `reg_chans` to `registered_channels`** with JSON properties column
- **Dynamic channels** by default - created on-demand, lost when empty
- **Registered channels** persist full state including:
  - Owners, hosts, voices
  - ACCESS lists (OWNER/HOST/VOICE/GRANT/DENY)
  - Topic, keys (member/host/owner)
  - User limits, modes
  - ONJOIN/ONPART messages
- All channel properties stored as flexible JSON

### Configuration Improvements
- Removed static `modes` section from config template
- Mode strings now hardcoded in server (prevents configuration errors)
- Removed hardcoded DEFAULT configuration block
- Server now requires config file to start

---

## 🔧 Bug Fixes

| Component | Issue | Fix |
|-----------|-------|-----|
| **MODE +z/-z** | Services couldn't set locked mode | Allow `is_service()` in permission check |
| **User Modes** | Inconsistent mode string (missing 's') | Now consistently `agiorsxz` |
| **Channel Modes** | Incorrect documentation | Fixed: x=auditorium, u=knock-mode, z=locked |
| **STATS s** | Didn't show virtual services | Removed `not u.is_virtual` check |
| **Channel +r** | Desync between flag and mode | Synchronized `channel.registered` with `modes['r']` |
| **UNREGISTER** | Didn't remove +r mode | Now removes mode and broadcasts change |
| **ADMIN Unregister** | Permission check order wrong | Check ADMIN privileges before database |

---

## 🗄️ Database Changes

### Schema Updates
```sql
-- Added to registered_channels table
ALTER TABLE registered_channels ADD COLUMN properties TEXT;
```

### Migration Notes
- Migration is **automatic** on server startup
- Legacy `reg_chans` table removed entirely
- No manual migration script needed
- Old `reg_chans` data NOT migrated automatically

### API Updates
Updated 8 functions to use new schema:
- `search_channels` - Query registered_channels with owner lookup
- `get_registered_channels` - Updated schema queries
- `edit_channel` - Update properties JSON column
- `get_channel_details` - Read from properties
- `get_channel_access` - ACCESS lists from JSON
- `set_channel_access` - Update JSON (requires registered channel)
- `get_registered_channels_paginated` - Proper owner joins
- `unregister_channel` - Fixed column name

---

## ✨ Enhancements

- **MODE -r Support** - High staff can use `MODE #channel -r` to unregister channels
- **Database Permissions** - Apache user added to pyircx group for web admin write access
- **Comprehensive Documentation** - Added mode documentation at 3 locations in code
- **Channel Persistence** - Removed `load_channels()`, `save_channels()`, `periodic_save()`

---

## 🗑️ Removed

- **DEFAULT Configuration Block** (lines 112-229 in pyircx.py)
- **Legacy Channel Persistence** (load/save functions)
- **Migration Script** (migrate_1.0_to_1.1.sh - automatic now)
- **reg_chans Table** (replaced with registered_channels)

---

## 📦 Installation & Upgrade

### Fresh Install
```bash
git clone https://github.com/AI3I/pyIRCX.git
cd pyIRCX
sudo ./install.sh
```

### Upgrade from v1.1.0/v1.1.1
```bash
cd pyIRCX
git pull
sudo ./upgrade.sh
```

Database schema will update automatically on first startup.

### Upgrade from v1.0.x
1. Backup your database: `cp /opt/pyircx/pyircx.db /opt/pyircx/pyircx.db.backup`
2. Run upgrade script: `sudo ./upgrade.sh`
3. Database migrations run automatically on startup

---

## 🔗 Version Compatibility

- **Database:** Automatic migration from v1.0.x and v1.1.x
- **Config:** Compatible with v1.1.0/v1.1.1 configs (modes section ignored if present)
- **API:** Web admin requires updated api.py (included)
- **Clients:** Fully compatible with all IRC/IRCX clients

---

## 📝 Files Changed

| File | Changes |
|------|---------|
| `pyircx.py` | Version 1.1.2, channel unlock fix, mode fixes, schema updates |
| `api.py` | Migrated to registered_channels schema (8 functions) |
| `upgrade.sh` | Version 1.1.2, removed migration script reference |
| `pyircx_config.json` | Removed modes section from template |
| `CHANGELOG.md` | Added comprehensive 1.1.2 release notes |
| `README.md` | Updated for 1.1.1 and 1.1.2 |

---

## 🐛 Known Issues

- Old channels in legacy `reg_chans` table will not load (manual migration needed if important)
- First-time users should use install.sh, not upgrade.sh

---

## 👥 Credits

Development and testing by the pyIRCX Project team with assistance from Claude Sonnet 4.5.

---

## 📄 License

GNU General Public License v3.0

---

**Full Changelog:** https://github.com/AI3I/pyIRCX/blob/main/CHANGELOG.md  
**Documentation:** https://github.com/AI3I/pyIRCX/blob/main/README.md
