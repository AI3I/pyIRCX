# Version Management Guide for pyIRCX

This document explains how version management works in pyIRCX and the tools available to ensure consistency.

---

## 📁 Version Management Files

### Core Files
1. **`RELEASE_CHECKLIST.md`** - Complete checklist for releases (Claude & humans)
2. **`utils/bump_version.sh`** - Automated version bumping script
3. **`utils/version_check.sh`** - Pre-release verification script
4. **`RELEASE_v{VERSION}.md`** - Release notes for each version

### Version Location in Code
- `pyircx.py` lines 25-27:
  - `__version__` - Version string (e.g., "1.1.3")
  - `__version_label__` - Project label ("pyIRCX")
  - `__created__` - Timestamp of version creation

---

## 🔄 Release Workflow

### For Claude (AI Assistant)

**When creating a new version, follow these steps:**

1. **Read the checklist FIRST:**
   ```bash
   Read docs/development/RELEASE_CHECKLIST.md
   ```

2. **Use the bump script:**
   ```bash
   ./utils/bump_version.sh <new_version>
   ```
   This automatically:
   - Updates `__version__` in pyircx.py
   - Updates `__created__` timestamp
   - Creates release notes template
   - Shows next steps

3. **Fill in release notes:**
   - Edit `RELEASE_v{VERSION}.md` with actual changes
   - Include all sections from template
   - Review upgrade instructions

4. **Run version check:**
   ```bash
   ./utils/version_check.sh <new_version>
   ```
   This verifies:
   - Version consistency
   - Release notes exist
   - No bare except clauses
   - Git status clean
   - Tag exists

5. **Test the server:**
   ```bash
   sudo systemctl restart pyircx
   sudo systemctl status pyircx
   ```

6. **Follow RELEASE_CHECKLIST.md** for remaining steps:
   - Git commit with detailed message
   - Create annotated tag
   - Push to remote
   - Create GitHub release

### For Human Developers

Same workflow as above, but can manually edit files if preferred.

---

## 🛠️ Available Scripts

### 1. bump_version.sh

**Purpose:** Automatically update version across the project

**Usage:**
```bash
./utils/bump_version.sh 1.2.0
```

**What it does:**
- Updates `__version__` in pyircx.py
- Updates `__created__` timestamp
- Updates README.md (if version mentioned)
- Creates release notes template if missing
- Shows next steps

**Example:**
```bash
$ ./utils/bump_version.sh 1.2.0
Current version: 1.1.3
New version:     1.2.0

Proceed with version bump? (y/n) y

Updating files...
  - pyircx.py ... ✓
  - README.md ... ✓
  - Creating RELEASE_v1.2.0.md ... ✓

Version bump complete!
```

---

### 2. version_check.sh

**Purpose:** Verify version consistency before release

**Usage:**
```bash
./utils/version_check.sh [expected_version]
```

**What it checks:**
- ✓ Version in pyircx.py
- ✓ Release notes file exists
- ✓ Release date is current
- ✓ Version mentioned in README.md
- ⚠️ Old version numbers in files
- ✓ No bare except clauses
- ⚠️ Debug print() statements
- ✓ Copyright years current
- ✓ Git working directory clean
- ✓ Git tag exists

**Example:**
```bash
$ ./utils/version_check.sh 1.1.3
=== pyIRCX Version Consistency Check ===

Current version in pyircx.py: 1.1.3
✓ Version matches expected: 1.1.3

=== Checking Release Notes ===
✓ RELEASE_v1.1.3.md exists
✓ Release date is current

...

✓ All checks passed!
```

---

## 📋 What Gets Updated During Release

### Automatic (via scripts)
- ✅ `pyircx.py` - `__version__` and `__created__`
- ✅ Release notes template created
- ✅ README.md - version mentions replaced

### Manual (must review)
- 📝 Release notes - fill in actual changes
- 📝 README.md - update features/installation if needed
- 📝 Git commit message - detailed description
- 📝 Git tag annotation - release description
- 📝 GitHub release - verify rendering

### Optional (situational)
- 📝 Installation scripts (install.sh, upgrade.sh) - if paths/versions hardcoded
- 📝 API documentation - if API changed
- 📝 Web admin UI - if version displayed
- 📝 Database migrations - if schema changed

---

## 🔍 Common Issues and Solutions

### Issue: "Version not found in README.md"

**Solution:** Manually add version to README.md or update references:
```bash
sed -i "s/1.1.2/1.1.3/g" README.md
```

### Issue: "Old version numbers found"

**Context:** Script finds old versions in:
- Old release notes (RELEASE_v1.1.2.md) - **Normal, don't change**
- Old changelog entries - **Normal, don't change**
- Comments/documentation - **May need updating**

**Solution:** Review each occurrence:
```bash
grep -r "1.1.2" --include="*.md" --include="*.py" .
```

### Issue: "Bare except clauses found"

**Solution:** Fix before release:
```bash
# Find them
grep -rn "except:" --include="*.py" .

# Replace with specific exceptions
# See SECURITY_AND_PERFORMANCE_AUDIT.md for examples
```

### Issue: "Git working directory not clean"

**Solution:** Either commit changes or stash them:
```bash
git status
git add -A
git commit -m "Prepare for release"
```

---

## 📊 Version Numbering Strategy

pyIRCX follows **Semantic Versioning (SemVer)**: `MAJOR.MINOR.PATCH`

### When to bump MAJOR (1.x.x → 2.x.x)
- Breaking API changes
- Major architecture rewrite
- Incompatible config changes
- Database schema breaking changes

**Example:** Modular refactor that changes import paths

### When to bump MINOR (x.1.x → x.2.x)
- New features added
- Significant improvements
- Non-breaking enhancements
- New commands/capabilities

**Example:** Adding OAuth2 authentication support

### When to bump PATCH (x.x.1 → x.x.2)
- Bug fixes
- Security patches
- Code quality improvements
- Documentation updates
- Minor tweaks

**Example:** Fixing rate limiting bug, improving error handling

---

## 🤖 AI Assistant Guidelines

**Before every release, Claude should:**

1. ✅ Read `RELEASE_CHECKLIST.md`
2. ✅ Run `./utils/bump_version.sh`
3. ✅ Fill in `RELEASE_v{VERSION}.md` with actual changes
4. ✅ Run `./utils/version_check.sh`
5. ✅ Test server restart
6. ✅ Follow checklist for git operations
7. ✅ Create GitHub release
8. ✅ Verify release published

**Never skip these steps!**

---

## 🔄 Quick Reference

### Starting a Release
```bash
# 1. Decide version number (1.2.0)
# 2. Run bump script
./utils/bump_version.sh 1.2.0

# 3. Edit release notes
nano RELEASE_v1.2.0.md

# 4. Test server
sudo systemctl restart pyircx && systemctl status pyircx

# 5. Run checks
./utils/version_check.sh 1.2.0
```

### Finishing a Release
```bash
# 6. Git operations
git add -A
git commit -m "Release v1.2.0 - Description"
git tag -a v1.2.0 -m "Description"

# 7. Push
git push origin main
git push origin --tags

# 8. Create release
gh release create v1.2.0 --title "pyIRCX v1.2.0 - Title" --notes-file RELEASE_v1.2.0.md
```

---

## 📝 Maintenance

**Keep these files updated:**
- This document when workflow changes
- RELEASE_CHECKLIST.md when new steps discovered
- Scripts when new checks needed

**Review quarterly:**
- Are scripts still catching all issues?
- Are there new files that need version updates?
- Is the workflow efficient?

---

**Last Updated:** January 14, 2026 (v1.1.3)
**Introduced:** v1.1.3
**Purpose:** Prevent version inconsistencies and missed updates
