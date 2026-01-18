# Repository References Audit

This document lists all repository-specific references that need updating when moving to a new GitHub user/repository.

**Date:** 2026-01-18
**Current References:** AI3I/pyIRCX, jdlewis, yourusername

---

## Summary

**Total Files to Update:** 13 files
**Reference Types:** GitHub URLs, clone commands, local paths, author names, copyright

---

## 1. GitHub Repository URLs

### Current References Found:
- `github.com/0x8007000E/pyIRCX` (7 occurrences)
- `github.com/0x8007000E/pyIRCX` (1 occurrence)
- `github.com/0x8007000E/pyIRCX` (4 occurrences - placeholder)
- `github.com/0x8007000E/pyIRCX` (1 occurrence - likely error)

### Files Requiring Updates:

#### **README.md** (4 occurrences)
```
Line 353: git clone https://github.com/0x8007000E/pyIRCX.git
Line 750: git clone https://github.com/0x8007000E/pyIRCX.git
Line 779: - **Issues**: [GitHub Issues](https://github.com/0x8007000E/pyIRCX/issues)
Line 780: - **Discussions**: [GitHub Discussions](https://github.com/0x8007000E/pyIRCX/discussions)
```
**Action:** Replace `AI3I/pyIRCX` with new GitHub user/repo

---

#### **uninstall.sh** (1 occurrence)
```
echo "Feedback and bug reports: https://github.com/0x8007000E/pyIRCX/issues"
```
**Action:** Replace `AI3I/pyIRCX` with new GitHub user/repo

---

#### **utils/bump_version.sh** (1 occurrence)
```
https://github.com/0x8007000E/pyIRCX
```
**Action:** Replace `AI3I/pyIRCX` with new GitHub user/repo

---

#### **docs/user/SELINUX.md** (1 occurrence)
```
For questions or issues, see: https://github.com/0x8007000E/pyIRCX
```
**Action:** Replace `AI3I/pyIRCX` with new GitHub user/repo

---

#### **webadmin/INSTALL.md** (1 occurrence)
```
- GitHub: https://github.com/0x8007000E/pyIRCX
```
**Action:** Replace `jdlewis/pyIRCX` with new GitHub user/repo

---

#### **polkit/README.md** (1 occurrence - PLACEHOLDER)
```
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
```
**Action:** Replace `yourusername/pyIRCX` with new GitHub user/repo

---

#### **selinux/README.md** (1 occurrence - PLACEHOLDER)
```
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
```
**Action:** Replace `yourusername/pyIRCX` with new GitHub user/repo

---

#### **docs/admin/CONFIG_REFERENCE.md** (1 occurrence - PLACEHOLDER)
```
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
```
**Action:** Replace `yourusername/pyIRCX` with new GitHub user/repo

---

#### **docs/admin/WEBADMIN_API.md** (1 occurrence - PLACEHOLDER)
```
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
```
**Action:** Replace `yourusername/pyIRCX` with new GitHub user/repo

---

#### **docs/api/API_REFERENCE.md** (1 occurrence - ERROR)
```
- GitHub Issues: https://github.com/0x8007000E/pyIRCX/issues
```
**Action:** Replace `anthropics/pyIRCX` with new GitHub user/repo
**Note:** This appears to be an error - should never have been anthropics

---

## 2. Local File Paths

### Current References Found:
- `/home/jdlewis/GitHub/pyIRCX/` (4 occurrences)
- User: `jdlewis` (2 occurrences)

### Files Requiring Updates:

#### **webadmin/INSTALL.md** (1 occurrence)
```
sudo cp -r /home/jdlewis/GitHub/pyIRCX/webadmin/* /var/www/html/webadmin/
```
**Action:** Replace with generic path or relative path
**Suggested:** `sudo cp -r ./webadmin/* /var/www/html/webadmin/`

---

#### **docs/development/VERSION_MANAGEMENT.md** (1 occurrence)
```
Read /home/jdlewis/GitHub/pyIRCX/RELEASE_CHECKLIST.md
```
**Action:** Replace with relative path
**Suggested:** `Read docs/development/RELEASE_CHECKLIST.md`

---

#### **docs/api/API_REFERENCE.md** (1 occurrence)
```
- Documentation: /home/jdlewis/GitHub/pyIRCX/docs/
```
**Action:** Replace with relative path
**Suggested:** `- Documentation: docs/`

---

#### **tests/integration/logs/README.md** (1 occurrence)
```
**User**: jdlewis
```
**Action:** This is example output - can be left as-is or changed to generic username

---

#### **tests/integration/logs/EXAMPLE.md** (1 occurrence)
```
**User**: jdlewis
```
**Action:** This is example output - can be left as-is or changed to generic username

---

## 3. Copyright & Author References

### Current References Found:
- `Copyright © 2026 John D. Lewis. All rights reserved.` (1 occurrence)
- `© 2024-2026 pyIRCX Development Team` (1 occurrence)

### Files Requiring Updates:

#### **README.md** (1 occurrence)
```
Line ~15: Copyright © 2026 John D. Lewis. All rights reserved.
```
**Action:** Update copyright holder name if changing ownership

---

#### **docs/INDEX.md** (1 occurrence)
```
Line ~197: **Copyright:** © 2024-2026 pyIRCX Development Team
```
**Action:** Update copyright year/holder if needed

---

## 4. Search & Replace Commands

Once you have the new GitHub username and repository name, use these commands:

### Replace GitHub Repository References

```bash
# Replace AI3I/pyIRCX
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" -o -name "*.json" \) \
  -not -path "./.git/*" -not -path "./.claude/*" \
  -exec sed -i 's|github\.com/AI3I/pyIRCX|github.com/NEWUSER/NEWREPO|g' {} +

# Replace jdlewis/pyIRCX
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" -o -name "*.json" \) \
  -not -path "./.git/*" -not -path "./.claude/*" \
  -exec sed -i 's|github\.com/jdlewis/pyIRCX|github.com/NEWUSER/NEWREPO|g' {} +

# Replace yourusername/pyIRCX (placeholder)
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" -o -name "*.json" \) \
  -not -path "./.git/*" -not -path "./.claude/*" \
  -exec sed -i 's|github\.com/yourusername/pyIRCX|github.com/NEWUSER/NEWREPO|g' {} +

# Replace anthropics/pyIRCX (error)
find . -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" -o -name "*.json" \) \
  -not -path "./.git/*" -not -path "./.claude/*" \
  -exec sed -i 's|github\.com/anthropics/pyIRCX|github.com/NEWUSER/NEWREPO|g' {} +
```

### Replace Local Paths

```bash
# Replace /home/jdlewis/GitHub/pyIRCX/ with relative paths (manual)
# Edit these files individually:
# - webadmin/INSTALL.md
# - docs/development/VERSION_MANAGEMENT.md
# - docs/api/API_REFERENCE.md
```

### Replace Copyright

```bash
# Update copyright holder (if needed)
sed -i 's/Copyright © 2026 John D\. Lewis/Copyright © 2026 YOUR_NAME/g' README.md
```

---

## 5. Verification After Updates

```bash
# Verify no old references remain
grep -r "AI3I/pyIRCX" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git
grep -r "jdlewis/pyIRCX" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git
grep -r "yourusername/pyIRCX" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git
grep -r "anthropics/pyIRCX" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git
grep -r "/home/jdlewis/GitHub/pyIRCX" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git

# Verify new references are correct
grep -r "NEWUSER/NEWREPO" . --include="*.md" --include="*.sh" --include="*.py" --exclude-dir=.git | wc -l
# Should show ~13 occurrences
```

---

## 6. Files Summary

**Files with GitHub URL references (12):**
1. `README.md` (4 refs - AI3I)
2. `uninstall.sh` (1 ref - AI3I)
3. `utils/bump_version.sh` (1 ref - AI3I)
4. `docs/user/SELINUX.md` (1 ref - AI3I)
5. `webadmin/INSTALL.md` (1 ref - jdlewis)
6. `polkit/README.md` (1 ref - yourusername placeholder)
7. `selinux/README.md` (1 ref - yourusername placeholder)
8. `docs/admin/CONFIG_REFERENCE.md` (1 ref - yourusername placeholder)
9. `docs/admin/WEBADMIN_API.md` (1 ref - yourusername placeholder)
10. `docs/api/API_REFERENCE.md` (1 ref - anthropics ERROR)

**Files with local paths (3):**
11. `webadmin/INSTALL.md`
12. `docs/development/VERSION_MANAGEMENT.md`
13. `docs/api/API_REFERENCE.md`

**Files with copyright (2):**
- `README.md`
- `docs/INDEX.md`

**Files with example usernames (2 - optional):**
- `tests/integration/logs/README.md`
- `tests/integration/logs/EXAMPLE.md`

---

## 7. Recommended Actions

### Step 1: Decide on New Repository Details
- New GitHub Username: `_______________`
- New Repository Name: `_______________`
- New Copyright Holder: `_______________`

### Step 2: Run Automated Replacements
Use the search & replace commands above with your new values.

### Step 3: Manual Edits
Manually update these files:
- `webadmin/INSTALL.md` - Change absolute path to relative
- `docs/development/VERSION_MANAGEMENT.md` - Change absolute path to relative
- `docs/api/API_REFERENCE.md` - Change absolute path to relative
- `README.md` - Update copyright holder if needed

### Step 4: Verify
Run verification commands to ensure all references updated correctly.

### Step 5: Test
- Clone from new repository
- Verify all documentation links work
- Check install scripts reference correct paths

---

## 8. Notes

### GitHub Username Variations Found:
- `AI3I` - Most common (7 occurrences) - REAL
- `jdlewis` - Webadmin doc (1 occurrence) - REAL
- `yourusername` - Placeholders (4 occurrences) - PLACEHOLDER
- `anthropics` - API doc (1 occurrence) - ERROR

### Path Variations Found:
- `/home/jdlewis/GitHub/pyIRCX/` - Absolute paths (3 occurrences)
- Should be replaced with relative paths for portability

### Copyright Considerations:
- Current: `Copyright © 2026 John D. Lewis`
- Update if transferring ownership
- Keep proprietary license notice intact

---

**Ready for Migration:** Yes
**Requires Manual Review:** 3 files (path updates)
**Estimated Time:** 10-15 minutes for full migration

