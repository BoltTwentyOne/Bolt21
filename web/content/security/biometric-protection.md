---
title: 'Biometric Protection'
description: 'How Bolt21 uses biometric authentication and cumulative payment tracking to protect your Bitcoin from unauthorized transactions.'
layout: 'docs'
css: ['docs.css']
priority: 0.6
---

# Biometric Protection

Bolt21 uses advanced biometric security to protect your funds from unauthorized access, even if someone gains physical access to your device.

## Payment Authorization

### Large Payment Protection

Payments of 100,000 sats (~$100 USD) or more require biometric authentication:

- **Face ID** on supported iPhones
- **Touch ID** on supported devices
- **Fingerprint** on Android devices

This ensures that even if your phone is unlocked, significant payments require your explicit biometric approval.

### Cumulative Tracking

We implemented a sophisticated protection against "split payment attacks" where an attacker might try to drain your wallet through multiple small payments:

```
Example Attack (BLOCKED):
- Payment 1: 99,000 sats ✓ (under threshold)
- Payment 2: 99,000 sats ✓ (under threshold)
- Payment 3: 99,000 sats → BIOMETRIC REQUIRED
  (cumulative: 297,000 sats in 5 minutes)
```

**How it works:**
1. We track all payments within a 5-minute rolling window
2. If cumulative payments approach 100,000 sats, biometric is required
3. The window resets after 5 minutes of no payments
4. This prevents attackers from draining funds via many small transactions

## No PIN Fallback

Unlike many apps, Bolt21 uses `biometricOnly` mode:

- **No PIN fallback** for payment authorization
- Biometric failure = payment blocked
- This prevents shoulder-surfing attacks where someone watches you enter a PIN

## What's Protected

| Action | Biometric Required |
|--------|-------------------|
| Send ≥100k sats | Always |
| Cumulative sends ≥100k in 5 min | Always |
| View recovery phrase | Always |
| Delete wallet | Always |
| Export data | Always |

## Screen Security

Additional protections when your app is in the background:

- **Screenshot blocking** on Android (FLAG_SECURE)
- **Screen recording overlay** on iOS
- **App switcher blur** hides sensitive data
- **No screen capture** of recovery phrases

## Technical Details

- Biometric data never leaves your device
- We use platform-native APIs (LocalAuthentication on iOS, BiometricPrompt on Android)
- No biometric templates are stored by Bolt21
- Authentication is handled entirely by your device's secure enclave

---

**Source code**: [Payment Tracker Service](https://github.com/BoltTwentyOne/Bolt21/blob/main/lib/services/payment_tracker_service.dart)
