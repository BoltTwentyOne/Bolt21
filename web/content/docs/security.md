---
title: 'Security'
priority: 0.8
description: 'Learn about Bolt21 security features - AES-256-GCM encryption, biometric protection, certificate pinning, and how we protect your Bitcoin.'
layout: 'docs'
weight: 2
css: ['docs.css']
---

# Security

Bolt21 is built with security as a core principle. Your keys never leave your device, and multiple layers of protection keep your Bitcoin safe.

## Security Grade: A

Bolt21 has passed comprehensive security audits including:

- **30/30 attack vectors blocked** in red team testing
- **AES-256-GCM encryption** for all sensitive data
- **Certificate pinning** on iOS and Android
- **Memory-safe key handling** with secure wiping

## Self-Custodial Architecture

**Your keys. Your Bitcoin. Always.**

- Seed phrase generated and stored only on your device
- No server ever sees your private keys
- Full BIP39 compliance for wallet recovery
- Works offline after initial setup

## Encryption & Key Storage

### Seed Phrase Protection
- Encrypted with AES-256-GCM (authenticated encryption)
- Stored in platform secure storage (iOS Keychain / Android Keystore)
- Triple-overwrite memory wiping after use
- Never logged or transmitted

### Data at Rest
- All sensitive data encrypted before storage
- Unique encryption key per wallet
- Secure random number generation (cryptographically secure)

## Biometric Authentication

Protect your wallet with Face ID, Touch ID, or fingerprint:

- **Required for large payments** (100k+ sats)
- **Cumulative tracking** prevents split-payment attacks
- **Daily limits** (200k sats, max 3 payments without biometric)
- **Device-level security** using platform biometric APIs

[Learn more about biometrics →](/docs/biometrics)

## Network Security

### Certificate Pinning
All API connections use certificate pinning to prevent man-in-the-middle attacks:

- 12 certificate pins for Breez SDK endpoints
- iOS and Android native implementations
- Automatic rejection of untrusted certificates

### No Tracking
- No analytics or tracking SDKs
- No crash reporting with user data
- Minimal network requests

## Payment Security

### Invoice Validation
- BOLT11 signatures verified before payment
- Amount tampering detected and rejected
- Replay attack protection via operation tracking

### Balance Protection
- Real-time balance validation before payments
- Prevents overspending through race conditions
- Atomic state updates

## What We Don't Do

- ❌ Store your seed phrase on any server
- ❌ Have access to your private keys
- ❌ Track your payments or balances
- ❌ Use third-party analytics
- ❌ Include hidden backdoors

## Security Best Practices

### Protect Your Seed Phrase
1. Write it down on paper (not digital)
2. Store in a secure location
3. Never share with anyone
4. Never enter on websites

### Device Security
1. Enable device passcode/biometrics
2. Keep your OS updated
3. Don't jailbreak/root your device
4. Download only from official app stores

### Payment Hygiene
1. Verify addresses before sending
2. Start with small test payments
3. Enable biometric authentication
4. Review payment history regularly

## Reporting Security Issues

Found a vulnerability? We take security seriously.

**Email:** security@bolt21.io

We appreciate responsible disclosure and will acknowledge researchers who help improve Bolt21 security.

---

**Next:** [Biometric Authentication](/docs/biometrics)
