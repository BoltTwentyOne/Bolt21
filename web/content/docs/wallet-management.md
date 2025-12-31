---
title: 'Wallet Management'
description: 'Learn how to create, backup, switch between, and delete wallets in Bolt21. Manage multiple Bitcoin Lightning wallets securely.'
layout: 'docs'
weight: 5
css: ['docs.css']
---

# Wallet Management

Bolt21 supports multiple wallets, letting you organize your Bitcoin for different purposes. Each wallet has its own recovery phrase and balance.

## Creating a Wallet

### Your First Wallet

1. Download and open Bolt21
2. Tap **Create New Wallet**
3. **Write down your 12-word recovery phrase** on paper
4. Verify your phrase by selecting words in order
5. Set up biometric authentication
6. Your wallet is ready!

### Additional Wallets

1. Open **Settings** → **Manage Wallets**
2. Tap **Add Wallet**
3. Choose **Create New** or **Restore Existing**
4. Follow the setup process
5. Switch between wallets from the Manage Wallets screen

## Backing Up Your Wallet

Your 12-word recovery phrase IS your backup. Without it, you cannot recover your funds.

### Viewing Your Recovery Phrase

1. Open **Settings**
2. Tap **Backup Wallet** or **View Recovery Phrase**
3. Authenticate with biometrics
4. Your 12 words will be displayed

### Backup Best Practices

**DO:**
- Write it on paper (or metal for fire/water resistance)
- Store in a secure location (safe, safety deposit box)
- Consider splitting between two locations
- Test your backup by restoring to a second device

**DON'T:**
- Take a screenshot
- Store in cloud storage (iCloud, Google Drive)
- Email or text it to yourself
- Store on your computer
- Share with anyone

## Switching Wallets

1. Open **Settings** → **Manage Wallets**
2. Tap the wallet you want to use
3. Authenticate if required
4. You're now using the selected wallet

Each wallet is completely separate with its own:
- Balance
- BOLT12 offer
- Transaction history
- Lightning channels

## Editing Wallet Details

1. Open **Settings** → **Manage Wallets**
2. Tap the edit icon next to a wallet
3. Change the wallet name
4. Tap **Save**

Wallet names are for your organization only and aren't shared with anyone.

## Deleting a Wallet

**Warning:** This removes the wallet from this device. Your funds are NOT deleted from the Bitcoin network.

### Before Deleting

1. **Backup your recovery phrase** if you haven't already
2. **Send all funds** to another wallet if you don't want to keep the phrase
3. Understand that you can restore anytime with the 12 words

### To Delete

1. Open **Settings** → **Manage Wallets**
2. Swipe left on the wallet (or tap delete icon)
3. Confirm deletion
4. Authenticate with biometrics

### After Deleting

- The wallet is removed from your device
- Your recovery phrase still works to restore it
- Any funds remain on the Lightning network
- Channels may close if not accessed for extended periods

## Multi-Wallet Use Cases

### Personal + Business
Keep business income separate from personal spending.

### Savings + Spending
Hot wallet for daily use, separate wallet for larger savings.

### Mining Payouts
Dedicated wallet for receiving Ocean or other mining payouts.

### Testing
Create a test wallet with small amounts to learn the app.

---

**Next:** [Recovery & Restore](/docs/recovery)
