---
title: 'Certificate Pinning'
description: 'How Bolt21 uses certificate pinning to protect your wallet from man-in-the-middle attacks and network-level threats.'
layout: 'docs'
css: ['docs.css']
priority: 0.6
---

# Certificate Pinning

Certificate pinning is a security technique that ensures your app only communicates with legitimate servers, even if an attacker has compromised your network.

## The Threat

Man-in-the-middle (MITM) attacks occur when an attacker intercepts communication between your wallet and Lightning servers. Without protection, attackers could:

- Intercept payment data
- Redirect funds to different addresses
- Steal authentication tokens
- Inject malicious responses

## Our Protection

Bolt21 implements certificate pinning on both iOS and Android:

### Pinned Domains

| Domain | Purpose | Certificate Authority |
|--------|---------|----------------------|
| api.breez.technology | Lightning SDK | Let's Encrypt |
| community.bolt21.io | Community Node | Let's Encrypt |
| github.com | App Updates | DigiCert |
| greenlight.blockstream.com | Node Backend | Let's Encrypt |

### How It Works

1. **Pin Storage**: We embed the cryptographic fingerprints of trusted certificate authorities directly in the app
2. **Connection Validation**: Every HTTPS connection validates the server certificate against our stored pins
3. **Rejection**: If the certificate doesn't match, the connection is immediately terminated
4. **No Fallback**: There is no way to bypass pinning - invalid certificates always fail

### Technical Implementation

- **iOS**: TrustKit 3.0.4 with certificate chain validation
- **Android**: Network Security Config with SHA-256 pins
- **Pin Rotation**: Multiple pins from CA chain ensure continuity during certificate renewals
- **Expiration**: Pins are set to expire 2026-12-31 with monitoring for updates

## What This Means For You

Even if you're on a compromised network (public WiFi, corporate proxy, malicious hotspot), attackers cannot:

- Read your Lightning payment data
- Modify API responses
- Impersonate Bolt21 servers
- Downgrade your connection security

## Verification

Our certificate pinning implementation is open source:
- [Android Config](https://github.com/BoltTwentyOne/Bolt21/blob/main/android/app/src/main/res/xml/network_security_config.xml)
- [iOS Implementation](https://github.com/BoltTwentyOne/Bolt21/blob/main/ios/Runner/AppDelegate.swift)

---

**Security researchers**: If you find a way to bypass our pinning, please report to support@bolt21.io
