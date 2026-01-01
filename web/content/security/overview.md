---
title: 'Security Overview'
description: 'Comprehensive overview of Bolt21 security architecture and protections for your self-custodial Bitcoin wallet.'
layout: 'docs'
css: ['docs.css']
priority: 0.7
---

# Security Overview

Bolt21 is designed with security as the foundation. As a self-custodial wallet, you maintain complete control of your Bitcoin - we never have access to your funds or recovery phrase.

## Core Security Principles

### Self-Custody First
Your 12-word recovery phrase is generated locally on your device and never leaves it. We cannot access, recover, or freeze your funds. This is by design.

### Defense in Depth
We implement multiple overlapping security layers:
- **Network Security**: Certificate pinning prevents man-in-the-middle attacks
- **Local Security**: Biometric authentication protects against unauthorized access
- **Code Security**: Open source allows community verification
- **Payment Security**: Cumulative tracking prevents split-payment attacks

### Transparency
Every line of code is [open source on GitHub](https://github.com/BoltTwentyOne/Bolt21). Security comes from transparency, not obscurity.

## Security Features

| Feature | Protection |
|---------|------------|
| Certificate Pinning | Prevents MITM attacks on network connections |
| Biometric Auth | Requires Face ID/fingerprint for large payments |
| Cumulative Tracking | Prevents bypassing biometrics via split payments |
| Screenshot Protection | Blocks screen recording and screenshots |
| Secure Storage | Encrypts sensitive data with AES-256-GCM |
| No Analytics | Zero tracking or telemetry |

## What We Don't Do

- We never store your recovery phrase
- We never have access to your private keys
- We never collect personal information
- We never track your transactions
- We never require account registration

---

**Questions?** Contact support@bolt21.io
