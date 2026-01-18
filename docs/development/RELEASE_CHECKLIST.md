# Release Checklist for pyIRCX

This document ensures nothing is missed during version releases.

---

## 📋 Pre-Release Checklist

### 1. Version Number Updates

Update version in ALL of these locations:

- [ ] `pyircx.py` - Lines 10-12 (`__version__`, `__version_label__`, `__created__`)
- [ ] `README.md` - Version badges and latest version mentions
- [ ] `CHANGELOG.md` - Add new version section (if exists)
- [ ] `install.sh` - Line 64 (`INSTALL_VERSION`)
- [ ] `webadmin/index.php` - Line 97 (version display in sidebar)
- [ ] `webchat/index.html` - Line 216 (version display in header)
- [ ] Create new `RELEASE_v{VERSION}.md` file

**Search commands to find version references:**
```bash
grep -r "1\.1\.\d" --include="*.md" --include="*.py" .
grep -r "__version__" --include="*.py" .
grep -r "version.*=" --include="*.json" .
```

---

### 2. Date/Timestamp Updates

- [ ] Update `__created__` timestamp in `pyircx.py` (line 27)
- [ ] Update release date in `RELEASE_v{VERSION}.md`
- [ ] Check copyright years in file headers (if new year)

**Get current date:**
```bash
date "+%a %b %d %I:%M:%S %p %Z %Y"
```

---

### 3. Documentation Updates

#### README.md
- [ ] Update version number in title/header
- [ ] Update "Latest Release" section
- [ ] Update any version-specific installation instructions
- [ ] Update feature list if new features added

#### Installation Scripts
- [ ] Check `install.sh` for any hardcoded versions
- [ ] Check `upgrade.sh` for version references
- [ ] Check `repair.sh` for version-specific paths

#### Release Notes
- [ ] Create `RELEASE_v{VERSION}.md` with:
  - [ ] Release date
  - [ ] Summary of changes
  - [ ] Breaking changes section
  - [ ] Upgrade instructions
  - [ ] Files modified
  - [ ] Known issues (if any)
  - [ ] Contributors/acknowledgments

---

### 4. Code Quality Checks

- [ ] Run server and verify it starts: `sudo systemctl restart pyircx && systemctl status pyircx`
- [ ] Check logs for errors: `sudo journalctl -u pyircx -n 50`
- [ ] Run test suite: `python3 pyIRCX_test_users.py` (if applicable)
- [ ] Verify web admin panel loads (if modified)
- [ ] Check for any TODOs or FIXME comments added
- [ ] Verify no debug code left in production

**Quick checks:**
```bash
# Check for debug statements
grep -r "print(" --include="*.py" . | grep -v "def print\|# print"

# Check for bare except clauses
grep -r "except:" --include="*.py" .

# Check for TODO/FIXME
grep -r "TODO\|FIXME" --include="*.py" .
```

---

### 5. Git Operations

- [ ] Stage all changes: `git add -A`
- [ ] Review staged changes: `git status`
- [ ] Create descriptive commit message with:
  - [ ] Version number in title
  - [ ] Summary of changes
  - [ ] Breaking changes noted
  - [ ] Co-Authored-By line
- [ ] Commit: `git commit -m "..."`
- [ ] Create annotated tag: `git tag -a v{VERSION} -m "Description"`
- [ ] Verify tag: `git tag -l "v*" | tail -5`

---

### 6. Remote Operations

- [ ] Push commits: `git push origin main`
- [ ] Push tags: `git push origin --tags`
- [ ] Verify remote: `git log origin/main -5`
- [ ] Create GitHub release: `gh release create v{VERSION} --title "Title" --notes-file RELEASE_v{VERSION}.md`
- [ ] Verify release: `gh release view v{VERSION}`

---

## 🔍 Files That Commonly Need Updates

### Always Check These Files:

1. **pyircx.py**
   - `__version__` (line ~25)
   - `__created__` (line ~27)

2. **README.md**
   - Version mentions in header
   - Latest release section
   - Installation instructions

3. **install.sh / upgrade.sh / repair.sh**
   - Version-specific paths
   - Compatibility notes

4. **webadmin/** (if modified)
   - Version display in UI
   - API version compatibility

5. **api.py** (if modified)
   - Version endpoints
   - API version constants

---

## 📊 Version Numbering Convention

pyIRCX follows Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`

- **MAJOR** (1.x.x): Breaking changes, major architecture changes
- **MINOR** (x.1.x): New features, significant improvements, non-breaking changes
- **PATCH** (x.x.1): Bug fixes, security patches, minor improvements

### Examples:
- `1.1.2 → 1.1.3`: Security fixes, code quality (PATCH)
- `1.1.3 → 1.2.0`: Modular refactoring, new features (MINOR)
- `1.2.0 → 2.0.0`: Breaking API changes, major rewrite (MAJOR)

---

## 🤖 Automated Version Check Script

Run this before each release:

```bash
#!/bin/bash
# version_check.sh - Verify all version references

echo "Checking version consistency..."

# Get version from pyircx.py
VERSION=$(grep "__version__" pyircx.py | cut -d'"' -f2)
echo "Current version in pyircx.py: $VERSION"

# Check for inconsistent version numbers
echo -e "\n=== Searching for old version numbers ==="
grep -r "1\.[0-9]\.[0-9]" --include="*.md" --include="*.py" . | grep -v ".git" | grep -v "RELEASE_" | grep -v "CHANGELOG"

# Check for missing release notes
if [ ! -f "RELEASE_v${VERSION}.md" ]; then
    echo -e "\n⚠️  WARNING: RELEASE_v${VERSION}.md not found!"
fi

# Check for outdated copyright years
CURRENT_YEAR=$(date +%Y)
echo -e "\n=== Checking copyright years ==="
grep -r "Copyright.*202[0-9]" --include="*.py" . | grep -v "$CURRENT_YEAR" | head -5

echo -e "\n=== Version check complete ==="
```

---

## 🔄 Quick Reference Command Sequence

```bash
# 1. Update version in pyircx.py (manual edit)
# 2. Create release notes
# 3. Update README.md
# 4. Run checks
sudo systemctl restart pyircx && systemctl status pyircx
./version_check.sh

# 5. Git operations
git add -A
git status
git commit -m "Release v{VERSION} - Description"
git tag -a v{VERSION} -m "Description"

# 6. Push everything
git push origin main
git push origin --tags

# 7. Create GitHub release
gh release create v{VERSION} --title "Title" --notes-file RELEASE_v{VERSION}.md
gh release view v{VERSION}
```

---

## ✅ Post-Release Verification

After release is published:

- [ ] Check GitHub release page renders correctly
- [ ] Verify download links work
- [ ] Test fresh installation from released version
- [ ] Update any external documentation/wikis
- [ ] Announce release (if applicable)
- [ ] Monitor for issues in first 24-48 hours

---

## 📝 Notes

- Keep this checklist updated as the project evolves
- Add new items when you discover missing steps
- Review this checklist before EVERY release
- Automate what you can, but manual review is still important

**Last Updated:** January 14, 2026 (v1.1.3)
