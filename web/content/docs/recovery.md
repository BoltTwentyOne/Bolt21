---
title: 'Recovery & Restore'
description: 'How to recover your Bolt21 wallet using your 12-word recovery phrase. Restore access to your Bitcoin on any device.'
layout: 'docs'
weight: 6
css: ['docs.css']
---

# Recovery & Restore

Lost your phone? Got a new device? You can restore your Bolt21 wallet anywhere using your 12-word recovery phrase.

## What You Need

- Your **12-word recovery phrase** (written down during wallet creation)
- A device with Bolt21 installed (Android, iOS coming soon)

That's it. No account, no password, no email verification.

## Restoring Your Wallet

1. Download and open Bolt21
2. Tap **Restore Existing Wallet**
3. Enter your 12 words in the correct order
4. Tap **Restore**
5. Set up biometric authentication
6. Your wallet is restored!

### What Gets Restored

- Full wallet access
- Your BOLT12 offer (same as before)
- On-chain Bitcoin balance
- Lightning balance (via Breez SDK)
- Channel state

### What Doesn't Transfer

- Wallet nickname (you can set a new one)
- App settings (biometrics, preferences)
- Transaction labels (if you added any)

## Recovery Scenarios

### Lost Phone

1. Get a new device
2. Download Bolt21
3. Restore with your 12 words
4. Your funds are safe

### Broken Phone

Same as above. Your funds exist on the Bitcoin/Lightning network, not on your phone.

### Stolen Phone

1. Restore immediately on a new device
2. Consider sending funds to a new wallet (new 12 words)
3. If you had biometrics enabled, the thief can't access your funds without your face/fingerprint

### Upgrading Devices

You can have Bolt21 on multiple devices with the same wallet. Just restore on the new device. However, avoid using both simultaneously to prevent sync issues.

### Forgot Recovery Phrase

**If you never wrote it down:** Unfortunately, there's no way to recover your funds. This is the tradeoff of self-custody.

**If you wrote it down but can't find it:**
- Check all secure locations
- Look for any paper notes from when you created the wallet
- The phrase is the only way to recover

## Partial Recovery Phrase

If you only have some words:

- **11 of 12 words:** Technically possible to brute-force, but difficult. Contact support@bolt21.io
- **10 or fewer:** Recovery is extremely unlikely

## Common Issues

### "Invalid recovery phrase"
- Check spelling of each word
- Ensure words are in the correct order
- All words should be from the BIP39 word list
- Check for extra spaces

### "Wallet shows zero balance"
- Lightning balance syncs after connecting to the network
- Wait a few minutes for the wallet to sync
- On-chain balance appears after blockchain sync

### "Different address than before"
- Addresses change for privacy (this is normal)
- Your BOLT12 offer remains the same
- Previous addresses still work

## Protecting Your Recovery Phrase

Your 12 words are the keys to your Bitcoin. Treat them like cash.

### Storage Options

| Method | Durability | Security | Cost |
|--------|-----------|----------|------|
| Paper | Low (fire/water) | Medium | Free |
| Metal plate | High | Medium | $20-50 |
| Split storage | High | High | Free |
| Safety deposit | High | High | ~$50/year |

### What NOT to Do

- Don't store digitally (photos, cloud, notes apps)
- Don't share with anyone
- Don't enter on any website
- Don't trust anyone who asks for it (Bolt21 will never ask)

---

**Next:** [Community Node](/docs/community-node)
