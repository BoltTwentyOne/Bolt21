# Bolt21

A privacy-focused Lightning wallet for Android with BOLT12 support, built on the Breez SDK.

## Features

- Lightning payments (send & receive)
- BOLT12 offers (static payment codes)
- Multi-wallet support
- Community Node routing (optional)
- Biometric authentication
- Privacy-first design

## Getting Started

### Prerequisites

- Flutter 3.32.0+
- Android SDK
- A Breez API key ([get one here](https://breez.technology/sdk/))

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/CaliforniaHodl/Bolt21.git
   cd Bolt21
   ```

2. Create your environment file:
   ```bash
   cp .env.example .env.local
   ```

3. Add your Breez API key to `.env.local`:
   ```
   BREEZ_API_KEY=your_key_here
   ```

4. Install dependencies:
   ```bash
   flutter pub get
   ```

5. Run the app:
   ```bash
   flutter run
   ```

### Building

Use the build script to create a release APK:
```bash
./scripts/build.sh
```

Or build manually:
```bash
flutter build apk --release --dart-define=BREEZ_API_KEY="your_key"
```

## Contributing

We welcome contributions! Please follow these guidelines:

### Branch Structure

- `main` - Production-ready code, triggers releases
- `staging` - Pre-release testing
- `develop` - Active development, submit PRs here

### How to Contribute

1. Fork the repository
2. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Run tests and linting:
   ```bash
   flutter test
   flutter analyze
   ```
5. Commit with clear messages:
   ```bash
   git commit -m "Add feature: brief description"
   ```
6. Push and open a PR against `develop`

### Code Style

- Follow [Effective Dart](https://dart.dev/effective-dart) guidelines
- Run `flutter analyze` before submitting
- Keep PRs focused and atomic

### Security

If you discover a security vulnerability, please email security@bolt21.io instead of opening a public issue.

Security audit reports are published in `/docs/security/`.

## Documentation

- [Roadmap](ROADMAP.md)
- [Security Audits](docs/security/)

## Support

- Email: support@bolt21.io
- Issues: [GitHub Issues](https://github.com/CaliforniaHodl/Bolt21/issues)

## License

MIT License - see [LICENSE](LICENSE) for details.
