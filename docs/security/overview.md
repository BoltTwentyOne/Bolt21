# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: support@bolt21.io

Please include the following information:
- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

We will respond within 48 hours and work with you to understand and resolve the issue promptly.

## Security Measures

Bolt21 implements the following security measures:

### Authentication & Authorization
- **Biometric-only authentication** - No PIN/pattern fallback (prevents shoulder surfing)
- **Payment re-authentication** - Large payments (>100k sats) require biometric confirmation
- **Secure storage** - Keys stored in iOS Keychain / Android Keystore

### Data Protection
- **AES-256-GCM encryption** - All sensitive data encrypted at rest
- **Secure clipboard** - Auto-clears after 30 seconds with race condition protection
- **Log sanitization** - Mnemonics, keys, and addresses are redacted from logs
- **Screen recording protection** - Content hidden during screen capture

### Network Security
- **Certificate pinning** - TrustKit (iOS) and network_security_config (Android)
- **TLS 1.2+ required** - No insecure connections allowed
- **Forward secrecy** - All connections use forward-secret cipher suites

### Supply Chain Security
- **Pinned dependencies** - Git dependencies pinned to specific commits
- **No bundled secrets** - API keys provided via dart-define at build time

### Crash Recovery
- **Operation state persistence** - Payment state survives app crashes
- **Atomic transactions** - Mutex locks prevent double-spend
- **Idempotent payments** - Duplicate payment prevention

## Security Audit

This application has undergone comprehensive penetration testing. The security audit verified:

- Zero critical vulnerabilities
- Zero high-severity vulnerabilities
- All OWASP Mobile Top 10 addressed
- Industry security standards met

## Responsible Disclosure

We believe in responsible disclosure and will:
1. Confirm receipt of your report within 48 hours
2. Provide an estimated timeline for a fix
3. Notify you when the vulnerability is fixed
4. Credit you in our security acknowledgments (if desired)

Thank you for helping keep Bolt21 users safe.
