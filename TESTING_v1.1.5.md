# Test Coverage Needed for v1.1.5

## Current Test Status

**Existing Tests:**
- `testing/staff.py` - test_stats_ssl()
- `testing/users.py` - test_stats_command(), test_stats_uptime(), test_stats_staff(), test_stats_help()

**Missing Tests for v1.1.5:**

### 1. STATS System Tests

#### New STATS Flags (Need Tests)
- [ ] **STATS p** - Peak usage statistics
  - Test peak_users is tracked
  - Test peak_time is recorded
  - Test output format

- [ ] **STATS f** - Flood protection statistics
  - Test flood_events counter
  - Test flood protection triggers increment counter

- [ ] **STATS m** - Message statistics
  - Test total messages count
  - Test per-channel message tracking
  - Test all channels shown (no limit)

- [ ] **STATS b** - ServiceBot statistics
  - Test violations tracking
  - Test actions tracking
  - Test configuration display

- [ ] **STATS n** - Network statistics
  - Test server name, network name
  - Test user/channel counts
  - Test uptime display

- [ ] **STATS v** - Command usage (staff only)
  - Test command_usage tracking
  - Test all commands shown (no limit)
  - Test staff-only access
  - Test non-staff rejection

#### Enhanced STATS Flags (Need Tests)
- [ ] **STATS k** - Ban statistics (no limits)
  - Test all ACCESS DENY entries shown
  - Test all server bans shown
  - Test no "... and X more" messages

- [ ] **STATS *** - Comprehensive report
  - Test hierarchical indentation
  - Test all commands shown (not top 10)
  - Test all channels shown (not top 5)
  - Test all violations shown (not top 3)

### 2. Help System Tests

#### Main HELP Command (Need Tests)
- [ ] **HELP (no topic)**
  - Test topics list includes REGISTER
  - Test all 8 topics shown

- [ ] **HELP REGISTER (NEW)**
  - Test nickname registration section
  - Test channel registration section
  - Test MFA commands documented
  - Test syntax examples present

- [ ] **HELP COMMANDS**
  - Test Registration category present
  - Test all command categories shown

### 3. Service Tests

#### Registrar Service (Need Tests)
- [ ] **MSG Registrar HELP**
  - Test comprehensive help output
  - Test all command sections present
  - Test nickname/channel/settings/MFA documented

#### ServiceBot Service (Need Tests)
- [ ] **MSG ServiceBot01 HELP (case variations)**
  - Test `/msg ServiceBot01 HELP` works
  - Test `/msg servicebot01 help` works (lowercase)
  - Test `/msg SERVICEBOT01 HELP` works (uppercase)
  - Test comprehensive help output
  - Test monitoring features documented
  - Test actions explained

- [ ] **MSG ServiceBot01 STATUS**
  - Test channel list shown
  - Test capacity display (X/10 channels)
  - Test detection status shown

### 4. Statistics Tracking Tests

#### Real-Time Tracking (Need Tests)
- [ ] **command_usage tracking**
  - Test each command increments counter
  - Test counters persist during session
  - Test counters reset on restart

- [ ] **peak_users tracking**
  - Test peak updates on new high
  - Test peak_time recorded correctly
  - Test peak persists during session

- [ ] **flood_events tracking**
  - Test flood protection increments counter
  - Test staff exempt from counting
  - Test counter accuracy

- [ ] **messages_by_channel tracking**
  - Test per-channel message counts
  - Test PRIVMSG counted
  - Test NOTICE counted

- [ ] **servicebot_violations tracking**
  - Test profanity violations counted
  - Test flood violations counted
  - Test CAPS violations counted
  - Test URL spam violations counted
  - Test repeat violations counted

- [ ] **servicebot_actions tracking**
  - Test warn actions counted
  - Test gag actions counted
  - Test kick actions counted

### 5. Bug Fix Tests

#### ServiceBot Case-Insensitive Routing (Need Tests)
- [ ] Test `/msg servicebot01 help` works
- [ ] Test `/msg ServiceBot01 help` works
- [ ] Test `/msg SERVICEBOT01 help` works
- [ ] Test all ServiceBots respond case-insensitively

### 6. Regression Tests

#### Existing Functionality (Should Pass)
- [ ] Existing STATS commands still work
- [ ] Existing HELP topics unchanged
- [ ] Service commands work as before
- [ ] Web chat basic functions work
- [ ] No breaking changes introduced

## Test Implementation Priority

**High Priority:**
1. STATS new flags (p, f, m, b, n, v) - Core feature
2. HELP REGISTER - User-facing documentation
3. ServiceBot case-insensitive routing - Bug fix verification
4. Statistics tracking - Data integrity

**Medium Priority:**
5. Service HELP commands - User experience
6. STATS limit removal verification - Data completeness
7. Enhanced STATS flags - Improvement verification

**Low Priority:**
8. Regression tests - Confidence checks

## Test Files

**v1.1.5 Test Files (CREATED):**
- `testing/stats.py` - All new STATS flags and enhancements (16 tests)
- `testing/help.py` - HELP command comprehensive tests (18 tests)
- `testing/services.py` - Service improvements tests (13 tests)

**Existing Test Files (UPDATED):**
- `testing/access.py` - Modernized to async/await pattern (10 tests)
- `testing/users.py` - Core IRC/IRCX protocol tests (115 tests)
- `testing/staff.py` - Staff authentication tests (39 tests)
- `testing/links.py` - Server linking tests (4 tests)

**Test Runner (UPDATED):**
- `run_tests.sh` - Updated for v1.1.5 test structure (~215 total tests)

## Test Execution

**Run all tests:**
```bash
./run_tests.sh
```

**Run specific test file:**
```bash
python3 testing/stats_v1.1.5.py
```

**Manual testing commands:**
```
/STATS p
/STATS f
/STATS m
/STATS b
/STATS n
/STATS v
/STATS k
/STATS *
/HELP REGISTER
/MSG Registrar HELP
/MSG ServiceBot01 HELP
/MSG servicebot01 help
```

## Test Coverage Goals

**Target:** 80%+ coverage of new features
**Current:** ~20% (only existing STATS ? test)
**Gap:** Need 15-20 new test functions

## Notes

- All new features are user-facing and should have automated tests
- Statistics tracking is critical for admin monitoring - needs thorough testing
- ServiceBot case-insensitive routing is a bug fix - must have regression test
- HELP system is documentation - should verify completeness
- STATS limit removal is behavioral change - needs verification tests

## Action Items

1. Create `testing/stats_v1.1.5.py` with 8 new STATS flag tests
2. Create `testing/help_system.py` with HELP REGISTER tests
3. Update `testing/services.py` with ServiceBot case tests
4. Add statistics tracking tests to `testing/users.py`
5. Run full test suite before final release
6. Document test results in release notes

---

**Test Status for v1.1.5 Release:**
✅ Manual testing completed
✅ Automated test coverage complete (47 tests)
✅ All v1.1.5 features covered
✅ Test files ready for execution

**Test Files Created:**
- `testing/stats.py` - 16 tests for STATS system (p, f, m, b, n, v, k, *)
- `testing/help.py` - 18 tests for HELP system (all topics including REGISTER)
- `testing/services.py` - 13 tests for service improvements (Registrar, ServiceBot)

**Test Staff Accounts:**
- admin/changeme (ADMIN)
- sysop/changeme (SYSOP)
- guide/changeme (GUIDE)
