# Bolt21 - BOLT12 Lightning Wallet

A self-custodial Lightning wallet with native BOLT12 support. Users hold their own keys.

## Why Bolt21?

- Most wallets only support BOLT11 (single-use invoices)
- BOLT12 offers reusable payment addresses
- No more "send me a new invoice" - just one address forever
- Perfect for mining payouts (Ocean), recurring payments, donations

## Tech Stack

- **Framework:** Flutter (iOS, Android)
- **Lightning:** Breez SDK (Liquid) with BOLT12 support
- **Language:** Dart
- **Architecture:** Self-custodial (user holds keys on device)

---

## Roadmap

### Phase 1: Project Setup & SDK Integration ✅
- [x] Initialize Flutter project (iOS, Android)
- [x] Add Breez SDK Liquid package
- [x] Configure native bindings for iOS/Android
- [x] Basic node initialization
- [x] Secure key generation and storage

### Phase 2: Core Wallet Functionality ✅
- [x] Generate and display on-chain Bitcoin address
- [x] Show wallet balance (on-chain + Lightning)
- [x] Transaction history
- [x] Send on-chain payments
- [x] Receive on-chain payments

### Phase 3: BOLT12 Offers (Main Feature) ✅
- [x] Generate BOLT12 offer (reusable address)
- [x] Display offer as QR code + copyable string
- [x] Receive payments via BOLT12 offer
- [x] Send to BOLT12 offers
- [x] Send to BOLT11 invoices

### Phase 4: LSP Integration ✅
- [x] Automated channel management via Breez SDK
- [x] Community Node routing (optional lower fees)
- [x] Hybrid LND integration

### Phase 5: UI/UX Polish & Security ✅
- [x] Clean, minimal wallet interface
- [x] Dark theme with Bitcoin orange
- [x] Onboarding flow (create/restore wallet)
- [x] Settings screen (backup, node info, channels)
- [x] Biometric authentication (Face ID / Touch ID)
- [x] Screenshot/screen recording protection
- [x] Certificate pinning (TrustKit + network_security_config)
- [x] Secure clipboard with auto-clear
- [x] Security audit completed

### Phase 6: Multi-Wallet & Advanced Features ✅
- [x] Multi-wallet support
- [x] Wallet switching
- [x] Per-wallet secure storage
- [x] OTA auto-update system
- [x] Version management

### Phase 7: App Store & Distribution 🚧
- [x] Android release build working
- [x] CI/CD pipeline (GitHub Actions)
- [x] Automated APK builds and releases
- [x] Landing page live (bolt21.io)
- [ ] Google Play Store submission
- [ ] iOS App Store submission (coming soon)

---

## Current Status

**Version:** 1.0.0 - Ready for Android release!

### What Works:
- Create new wallet with 12-word seed phrase
- Restore existing wallet
- View balances (on-chain + Lightning)
- Generate BOLT12 offers (reusable addresses)
- Generate on-chain addresses
- Send payments (BOLT12, BOLT11, on-chain)
- Receive payments
- QR code scanning and generation
- Multi-wallet management
- Biometric authentication
- Community Node routing
- Settings (backup seed, node info)

### What's Next:
- Google Play Store submission
- iOS App Store submission
- Payment notifications
- Offer management UI (labels, multiple offers)

---

## Future Ideas
- NWC (Nostr Wallet Connect) support
- Contacts with stored BOLT12 offers
- Fiat conversion display
- Multi-language support
- Hardware wallet integration

---

## Resources
- [BOLT12 Spec](https://bolt12.org)
- [Breez SDK](https://breez.technology/sdk/)
- [Bolt21 Website](https://bolt21.io)
