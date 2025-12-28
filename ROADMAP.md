# Bolt21 - BOLT12 Lightning Wallet

A self-custodial Lightning wallet with native BOLT12 support. Users hold their own keys.

## Why Bolt21?

- Most wallets only support BOLT11 (single-use invoices)
- BOLT12 offers reusable payment addresses
- No more "send me a new invoice" - just one address forever
- Perfect for mining payouts (Ocean), recurring payments, donations

## Tech Stack

- **Framework:** Flutter (iOS, Android, Web)
- **Lightning:** LDK (Lightning Dev Kit) with BOLT12 support
- **Language:** Dart
- **Architecture:** Self-custodial (user holds keys on device)

---

## Roadmap

### Phase 1: Project Setup & LDK Integration
- [x] Initialize Flutter project (iOS, Android, Web)
- [ ] Add ldk-node-flutter package
- [ ] Configure native bindings for iOS/Android
- [ ] Basic LDK node initialization
- [ ] Secure key generation and storage

### Phase 2: Core Wallet Functionality
- [ ] Generate and display on-chain Bitcoin address
- [ ] Show wallet balance (on-chain + Lightning)
- [ ] Transaction history
- [ ] Send on-chain payments
- [ ] Receive on-chain payments

### Phase 3: BOLT12 Offers (Main Feature)
- [ ] Generate BOLT12 offer (reusable address)
- [ ] Display offer as QR code + copyable string
- [ ] Receive payments via BOLT12 offer
- [ ] Payment notifications
- [ ] Offer management (multiple offers, labels)

### Phase 4: LSP Integration
- [ ] Connect to Lightning Service Provider
- [ ] Automated channel opening
- [ ] Inbound liquidity for new users
- [ ] Zero-conf channels for instant receiving

### Phase 5: UI/UX Polish & Security
- [ ] Clean, minimal wallet interface
- [ ] Biometric authentication
- [ ] Encrypted local storage
- [ ] Backup/restore with seed phrase
- [ ] Security audit

### Phase 6: App Store & Web Deployment
- [ ] iOS App Store submission
- [ ] Google Play Store submission
- [ ] Web app deployment
- [ ] Landing page

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
- [LDK Documentation](https://lightningdevkit.org)
- [ldk-node-flutter](https://github.com/LtbLightning/ldk-node-flutter)
