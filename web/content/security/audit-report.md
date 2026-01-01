---
title: 'Security Audit Report'
description: 'Latest security audit findings and remediations for Bolt21 Lightning wallet. Grade: A-'
layout: 'docs'
css: ['docs.css']
priority: 0.6
---

# Security Audit Report

**Date**: December 2024
**Grade**: A
**Status**: All critical issues resolved

## Executive Summary

Bolt21 underwent a comprehensive security audit covering mobile application security, network security, and cryptographic implementations. All critical (P0) and high-priority (P1) vulnerabilities have been remediated.

## Audit Scope

| Area | Coverage |
|------|----------|
| Mobile App (Flutter) | ✅ Full review |
| iOS Native (Swift) | ✅ Full review |
| Android Native (Kotlin) | ✅ Full review |
| Network Security | ✅ Full review |
| Cryptography | ✅ Full review |
| Authentication | ✅ Full review |

## Findings Summary

### Resolved Issues

| Priority | Finding | Status |
|----------|---------|--------|
| P0 | Certificate pinning for Community Node | ✅ Fixed |
| P0 | Certificate pinning for GitHub (updates) | ✅ Fixed |
| P1 | Biometric bypass via split payments | ✅ Fixed |
| P1 | TrustKit version pinning | ✅ Fixed |
| P2 | Time window reset bypass | ✅ Fixed |
| P3 | Defense-in-depth validation | ✅ Fixed |

### Intentional Exceptions

| Finding | Decision | Rationale |
|---------|----------|-----------|
| CoinGecko certificate pinning | Not pinned | CoinGecko rotates certificates frequently, making pinning impractical. Price data is display-only and cannot affect fund security. |
| LND node connection | User-controlled | Users connect to their own LND nodes. They control both endpoints of the connection. |

### Security Strengths

The audit identified several strong security practices:

1. **Cryptography**: AES-256-GCM encryption with secure random nonces
2. **Secret Management**: No hardcoded API keys, proper use of build-time flags
3. **Input Validation**: Comprehensive address validation including unicode attack prevention
4. **Secure Logging**: Custom SecureLogger redacts sensitive data (mnemonics, keys, addresses)
5. **SSRF Protection**: Community node URL validator blocks private IPs/localhost
6. **Backup Prevention**: Android backup disabled to protect wallet data

## Detailed Findings

### P0-01: Missing Certificate Pinning (Community Node)

**Risk**: Man-in-the-middle attacks could intercept Community Node communications

**Remediation**: Added Let's Encrypt certificate pins for `community.bolt21.io` on both Android and iOS

**Files Changed**:
- `android/app/src/main/res/xml/network_security_config.xml`
- `ios/Runner/AppDelegate.swift`

### P0-02: Missing Certificate Pinning (GitHub)

**Risk**: Update check could be manipulated to serve malicious versions

**Remediation**: Added DigiCert certificate pins for `github.com`, `api.github.com`, and `raw.githubusercontent.com`

**Files Changed**:
- `android/app/src/main/res/xml/network_security_config.xml`
- `ios/Runner/AppDelegate.swift`

### P1-01: Biometric Bypass via Split Payments

**Risk**: Attacker could drain wallet by sending multiple payments under 100k sat threshold

**Remediation**: Implemented `PaymentTrackerService` with:
- 5-minute rolling window for payment tracking (100k sats)
- 24-hour daily cumulative limit (500k sats)
- Dual-layer protection prevents time-based bypass attacks
- Biometric required when cumulative amount exceeds thresholds

**Files Changed**:
- `lib/services/payment_tracker_service.dart` (new)
- `lib/screens/send_screen.dart`

## Test Coverage

| Metric | Value |
|--------|-------|
| Total Tests | 752 |
| Pass Rate | 100% |
| Test Categories | Unit, Widget, Integration, Security |

## Recommendations

### Implemented
- ✅ Certificate pinning for all critical domains
- ✅ Cumulative payment tracking
- ✅ Exact version pinning for security dependencies

### Future Considerations
- Consider adding certificate pin expiration monitoring
- Evaluate migration to explicit pinning library (e.g., dio_certificate_pinner)
- Add automated security regression tests

## Verification

All security implementations are open source and can be verified:

- [GitHub Repository](https://github.com/BoltTwentyOne/Bolt21)
- [Security Documentation](https://github.com/BoltTwentyOne/Bolt21/tree/main/docs/security)

## Full Audit Reports

View our complete audit history on GitHub:

| Report | Description |
|--------|-------------|
| [Executive Summary](https://github.com/BoltTwentyOne/Bolt21/blob/main/docs/security/summary-executive.md) | High-level security overview |
| [Cryptographic Audit](https://github.com/BoltTwentyOne/Bolt21/blob/main/docs/security/audit-cryptographic-mr-blackkeys.md) | Full cryptographic review |
| [Red Team Audit](https://github.com/BoltTwentyOne/Bolt21/blob/main/docs/security/audit-red-team.md) | Adversarial security testing |
| [Network Assessment](https://github.com/BoltTwentyOne/Bolt21/blob/main/docs/security/assessment-network.md) | Network security analysis |
| [Payment Audit](https://github.com/BoltTwentyOne/Bolt21/blob/main/docs/security/audit-payment.md) | Payment flow security |

---

**Report vulnerabilities**: support@bolt21.io

**Full audit history**: [GitHub Security Docs](https://github.com/BoltTwentyOne/Bolt21/tree/main/docs/security)
