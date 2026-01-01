---
title: 'Open Source Transparency'
description: 'Bolt21 is 100% open source. Every line of code is publicly auditable on GitHub for maximum transparency and security.'
layout: 'docs'
css: ['docs.css']
priority: 0.6
---

# Open Source Transparency

Bolt21 is completely open source. We believe security comes from transparency, not obscurity.

## Why Open Source?

### Verifiable Security
Anyone can audit our code to verify:
- We don't have backdoors
- We don't collect your data
- We don't have access to your keys
- Our security claims are accurate

### Community Review
Open source enables:
- Security researchers to find vulnerabilities
- Developers to contribute improvements
- Users to verify our claims
- Independent security audits

### Trust Through Transparency
You don't have to trust us - you can verify everything yourself.

## What's Open Source

**Everything.**

| Component | Repository |
|-----------|------------|
| Flutter App | [BoltTwentyOne/Bolt21](https://github.com/BoltTwentyOne/Bolt21) |
| iOS Native Code | [ios/Runner](https://github.com/BoltTwentyOne/Bolt21/tree/main/ios/Runner) |
| Android Native Code | [android/app](https://github.com/BoltTwentyOne/Bolt21/tree/main/android/app) |
| Website | [web/](https://github.com/BoltTwentyOne/Bolt21/tree/main/web) |
| Security Configs | [docs/security](https://github.com/BoltTwentyOne/Bolt21/tree/main/docs/security) |

## Key Security Files

Review our security implementation directly:

- **Certificate Pinning (Android)**: [`network_security_config.xml`](https://github.com/BoltTwentyOne/Bolt21/blob/main/android/app/src/main/res/xml/network_security_config.xml)
- **Certificate Pinning (iOS)**: [`AppDelegate.swift`](https://github.com/BoltTwentyOne/Bolt21/blob/main/ios/Runner/AppDelegate.swift)
- **Payment Tracking**: [`payment_tracker_service.dart`](https://github.com/BoltTwentyOne/Bolt21/blob/main/lib/services/payment_tracker_service.dart)
- **Biometric Auth**: [`auth_service.dart`](https://github.com/BoltTwentyOne/Bolt21/blob/main/lib/services/auth_service.dart)
- **Encryption**: [`encryption_helper.dart`](https://github.com/BoltTwentyOne/Bolt21/blob/main/lib/utils/encryption_helper.dart)
- **Address Validation**: [`address_validator.dart`](https://github.com/BoltTwentyOne/Bolt21/blob/main/lib/utils/address_validator.dart)

## Build Verification

You can build Bolt21 from source:

```bash
# Clone the repository
git clone https://github.com/BoltTwentyOne/Bolt21.git
cd Bolt21

# Install dependencies
flutter pub get

# Build for your platform
flutter build apk --release  # Android
flutter build ios --release  # iOS
```

## Contributing

We welcome security contributions:

1. **Report Vulnerabilities**: support@bolt21.io
2. **Submit Fixes**: Pull requests welcome
3. **Audit Code**: Review and document findings
4. **Improve Docs**: Help others understand our security

## License

Bolt21 is released under the MIT License, allowing you to:
- Use the code commercially
- Modify and distribute
- Use privately
- Patent use

---

**GitHub**: [github.com/BoltTwentyOne/Bolt21](https://github.com/BoltTwentyOne/Bolt21)
