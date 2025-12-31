---
title: 'Biometric Authentication'
description: 'Secure your Bolt21 wallet with Face ID, Touch ID, or fingerprint authentication. Learn how to set up and manage biometric security.'
layout: 'docs'
weight: 4
css: ['docs.css']
---

# Biometric Authentication

Bolt21 uses your device's biometric security (Face ID, Touch ID, or fingerprint) to protect your wallet from unauthorized access.

## Why Biometrics?

- **Faster access** - Unlock your wallet instantly with a glance or touch
- **More secure than PINs** - Biometrics can't be shoulder-surfed
- **Required for large payments** - Extra protection for transactions over 100,000 sats

## Setting Up Biometrics

### During Wallet Creation

1. Create a new wallet or restore an existing one
2. After saving your recovery phrase, you'll be prompted to enable biometrics
3. Authenticate with Face ID, Touch ID, or fingerprint
4. Done! Your wallet is now protected

### After Setup

If you skipped biometric setup initially:

1. Open **Settings** (gear icon)
2. Tap **Security**
3. Toggle **Biometric Authentication** on
4. Authenticate to confirm

## How It Works

### Wallet Access
Every time you open Bolt21, you'll need to authenticate with biometrics. This prevents anyone who picks up your phone from accessing your funds.

### Large Payment Protection
Payments over 100,000 sats require re-authentication, even if you're already in the app. This protects you if someone grabs your phone while it's unlocked.

### What's Protected
- Viewing wallet balance
- Viewing recovery phrase
- Sending payments
- Changing security settings

## Troubleshooting

### "Biometrics not available"
- Ensure Face ID/Touch ID is set up in your device settings
- Restart the app and try again
- Some older devices may not support biometrics

### "Authentication failed"
- Make sure your face/finger is properly positioned
- Clean your device's sensor
- After multiple failures, you may need to wait before trying again

### Changing Biometric Data
If you update your Face ID or fingerprint in device settings, Bolt21 will automatically use your new biometric data.

## Security Notes

- **Biometrics are device-local** - Your biometric data never leaves your device
- **No cloud storage** - We don't store any biometric information
- **Recovery phrase is backup** - If biometrics fail, you can always restore from your 12-word phrase

---

**Next:** [Managing Your Wallets](/docs/wallet-management)
