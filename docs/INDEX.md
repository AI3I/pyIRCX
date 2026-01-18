# pyIRCX Documentation Index

**Version:** 2.0.0+
**Last Updated:** 2026-01-18

---

## Quick Start

- **[README.md](../README.md)** - Project overview, features, installation
- **[CHANGELOG.md](../CHANGELOG.md)** - Version history and changes
- **[SECURITY.md](../SECURITY.md)** - Security policies and vulnerability reporting

---

## User Documentation

### Getting Started
- **[Installation & Setup](../README.md#installation)** - Installation instructions
- **[User Manual](user/MANUAL.md)** - Complete user guide and command reference
- **[Configuration Guide](user/CONFIG.md)** - Configuration file reference
- **[Staff Account Reference](user/STAFF_ACCOUNT_REFERENCE.md)** - Staff commands and authentication

### Advanced Features
- **[Server Linking](LINKING.md)** - Distributed network setup and topology
- **[SELinux Setup](user/SELINUX.md)** - SELinux configuration for production

---

## Administrator Documentation

### Configuration & Management
- **[Configuration Reference](admin/CONFIG_REFERENCE.md)** - Complete config parameter reference
- **[WebAdmin API](admin/WEBADMIN_API.md)** - WebAdmin HTTP API documentation

### API Documentation
- **[REST API Reference](api/API_REFERENCE.md)** - HTTP REST API endpoints and usage

---

## Testing Documentation

### Test Suites
- **[Testing Guide](testing/TESTING.md)** - Test harness documentation and usage
- **[Test Coverage Analysis](testing/TEST_COVERAGE_ANALYSIS.md)** - Test coverage metrics
- **[Test Audit](testing/TEST_AUDIT_v2.0.0.md)** - v2.0.0 test audit report
- **[Test Harness Details](testing/TESTHARNESS.md)** - Test harness implementation

### Running Tests
- **[Integration Tests](../tests/integration/README.md)** - Integration test suite documentation
- **[Stress Testing](../tests/integration/STRESS_TEST.md)** - Load testing guide
- **[Specialized Tests](../tests/integration/SPECIALIZED_TESTS.md)** - Advanced testing scenarios

---

## Development Documentation

### Development Resources
- **[Release Checklist](development/RELEASE_CHECKLIST.md)** - Pre-release validation checklist
- **[Version Management](development/VERSION_MANAGEMENT.md)** - Version numbering and tagging
- **[API Code Analysis](development/API_CODE_ANALYSIS.md)** - API codebase analysis
- **[API Refactoring Notes](development/API_REFACTORING_TODO.md)** - Completed refactoring work

---

## Performance & Security

- **[Performance Guide](performance/PERFORMANCE.md)** - Performance tuning and optimization
- **[Security & Performance Audit](performance/SECURITY_AND_PERFORMANCE_AUDIT.md)** - Security and performance analysis

---

## Network Architecture

- **[Server Linking Guide](LINKING.md)** - Comprehensive linking setup and troubleshooting
  - Trunk-branch topology
  - Clock synchronization requirements
  - Version compatibility
  - Protocol details
  - Troubleshooting guide

---

## File Organization

```
docs/
├── INDEX.md                    # This file
├── LINKING.md                  # Server linking guide
├── admin/                      # Administrator documentation
│   ├── CONFIG_REFERENCE.md
│   └── WEBADMIN_API.md
├── api/                        # API documentation
│   └── API_REFERENCE.md
├── development/                # Development resources
│   ├── API_CODE_ANALYSIS.md
│   ├── API_REFACTORING_TODO.md
│   ├── RELEASE_CHECKLIST.md
│   └── VERSION_MANAGEMENT.md
├── performance/                # Performance & security
│   ├── PERFORMANCE.md
│   └── SECURITY_AND_PERFORMANCE_AUDIT.md
├── releases/                   # Release notes
│   └── README.md
├── testing/                    # Testing documentation
│   ├── TEST_AUDIT_v2.0.0.md
│   ├── TEST_COVERAGE_ANALYSIS.md
│   ├── TESTHARNESS.md
│   └── TESTING.md
└── user/                       # End-user documentation
    ├── CONFIG.md
    ├── MANUAL.md
    ├── SELINUX.md
    └── STAFF_ACCOUNT_REFERENCE.md
```

---

## Version-Specific Documentation

### Current Version (v2.0.0+)
- Server linking and distributed networks
- IRCX CREATE command
- Enhanced authentication (PASS, AUTH, SASL)
- Comprehensive services (Registrar, Messenger, NewsFlash, ServiceBots)
- WebAdmin interface
- REST API

### Legacy Documentation
For older versions, see [CHANGELOG.md](../CHANGELOG.md) for historical feature information.

---

## External Resources

- **Protocol Specifications**
  - RFC 1459 - Internet Relay Chat Protocol
  - RFC 2810-2813 - IRC Client/Server/Channel/Operator Protocols
  - IRCX Extensions (Microsoft proprietary)

---

## Getting Help

1. **Check documentation** - Start with this index
2. **Read troubleshooting** - See [LINKING.md](LINKING.md#troubleshooting) for common issues
3. **Review CHANGELOG** - See if your issue is addressed in recent releases
4. **Check security policy** - See [SECURITY.md](../SECURITY.md) for security issues

---

**License:** Proprietary - All Rights Reserved
**Copyright:** © 2024-2026 pyIRCX Development Team
