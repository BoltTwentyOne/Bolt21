import 'package:flutter/material.dart';
import '../utils/theme.dart';
import 'create_wallet_screen.dart';
import 'restore_wallet_screen.dart';

class WelcomeScreen extends StatelessWidget {
  const WelcomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            children: [
              const Spacer(),

              // Logo/Icon
              Container(
                width: 120,
                height: 120,
                decoration: BoxDecoration(
                  color: Bolt21Theme.orange.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.bolt,
                  size: 64,
                  color: Bolt21Theme.orange,
                ),
              ),
              const SizedBox(height: 32),

              // Title
              Text(
                'Bolt21',
                style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                  fontWeight: FontWeight.bold,
                  color: Bolt21Theme.orange,
                ),
              ),
              const SizedBox(height: 12),

              // Subtitle
              const Text(
                'Self-custodial Lightning wallet\nwith BOLT12 support',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Bolt21Theme.textSecondary,
                  fontSize: 16,
                ),
              ),

              const Spacer(),

              // Features list
              const _FeatureItem(
                icon: Icons.repeat,
                text: 'Reusable payment addresses',
              ),
              const SizedBox(height: 12),
              const _FeatureItem(
                icon: Icons.key,
                text: 'You control your keys',
              ),
              const SizedBox(height: 12),
              const _FeatureItem(
                icon: Icons.bolt,
                text: 'Instant Lightning payments',
              ),

              const Spacer(),

              // Buttons
              SizedBox(
                width: double.infinity,
                height: 56,
                child: ElevatedButton(
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => const CreateWalletScreen(),
                      ),
                    );
                  },
                  child: const Text(
                    'Create New Wallet',
                    style: TextStyle(fontSize: 18),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                height: 56,
                child: OutlinedButton(
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => const RestoreWalletScreen(),
                      ),
                    );
                  },
                  child: const Text(
                    'Restore Existing Wallet',
                    style: TextStyle(fontSize: 18),
                  ),
                ),
              ),
              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }
}

class _FeatureItem extends StatelessWidget {
  final IconData icon;
  final String text;

  const _FeatureItem({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Bolt21Theme.darkCard,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, color: Bolt21Theme.orange, size: 20),
        ),
        const SizedBox(width: 16),
        Text(
          text,
          style: const TextStyle(fontSize: 16),
        ),
      ],
    );
  }
}
