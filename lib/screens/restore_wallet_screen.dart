import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:bip39/bip39.dart' as bip39;
import '../providers/wallet_provider.dart';
import '../services/secure_storage_service.dart';
import '../utils/theme.dart';
import 'home_screen.dart';

class RestoreWalletScreen extends StatefulWidget {
  const RestoreWalletScreen({super.key});

  @override
  State<RestoreWalletScreen> createState() => _RestoreWalletScreenState();
}

class _RestoreWalletScreenState extends State<RestoreWalletScreen> {
  final List<TextEditingController> _controllers =
      List.generate(12, (_) => TextEditingController());
  final List<FocusNode> _focusNodes = List.generate(12, (_) => FocusNode());
  bool _isLoading = false;
  String? _error;
  String _syncStatus = '';
  int _syncStep = 0;
  static const int _totalSyncSteps = 4;

  @override
  void dispose() {
    // SECURITY: Clear mnemonic words from text controllers before disposal
    for (final controller in _controllers) {
      controller.clear();
      controller.dispose();
    }
    for (final node in _focusNodes) {
      node.dispose();
    }
    super.dispose();
  }

  /// SECURITY: Clear all mnemonic input fields
  void _clearMnemonicFields() {
    for (final controller in _controllers) {
      controller.clear();
    }
  }

  String get _mnemonic {
    return _controllers.map((c) => c.text.trim().toLowerCase()).join(' ');
  }

  bool get _isComplete {
    return _controllers.every((c) => c.text.trim().isNotEmpty);
  }

  void _updateSyncStatus(String status, int step) {
    if (mounted) {
      setState(() {
        _syncStatus = status;
        _syncStep = step;
      });
    }
  }

  Future<void> _restoreWallet() async {
    if (!_isComplete) return;

    setState(() {
      _isLoading = true;
      _error = null;
      _syncStatus = 'Validating recovery phrase...';
      _syncStep = 1;
    });

    try {
      final mnemonic = _mnemonic;

      // Validate mnemonic format (word count)
      final words = mnemonic.split(' ');
      if (words.length != 12) {
        throw Exception('Recovery phrase must be exactly 12 words');
      }

      // Validate BIP39 mnemonic checksum and word list
      if (!bip39.validateMnemonic(mnemonic)) {
        throw Exception(
          'Invalid recovery phrase. Please check that all words are spelled correctly '
          'and are valid BIP39 words.'
        );
      }

      _updateSyncStatus('Saving recovery phrase...', 2);
      await SecureStorageService.saveMnemonic(mnemonic);

      // SECURITY: Clear mnemonic from UI after secure storage
      _clearMnemonicFields();

      _updateSyncStatus('Connecting to Lightning network...', 3);
      final wallet = context.read<WalletProvider>();
      await wallet.initializeWallet(mnemonic: mnemonic);

      if (wallet.error != null) {
        // Clear saved mnemonic if initialization failed
        await SecureStorageService.clearWallet();
        setState(() {
          _error = wallet.error;
          _isLoading = false;
          _syncStatus = '';
          _syncStep = 0;
        });
        return;
      }

      _updateSyncStatus('Syncing wallet data...', 4);
      // Give a moment for the UI to update
      await Future.delayed(const Duration(milliseconds: 500));

      if (mounted) {
        // Show success message with balance
        final balance = wallet.totalBalanceSats;
        final paymentCount = wallet.payments.length;

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Wallet restored! Balance: $balance sats, $paymentCount transactions found.',
            ),
            backgroundColor: Bolt21Theme.success,
            duration: const Duration(seconds: 3),
          ),
        );

        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (_) => const HomeScreen()),
          (route) => false,
        );
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
        _syncStatus = '';
        _syncStep = 0;
      });
    }
  }

  void _onWordChanged(int index, String value) {
    // Auto-advance to next field when word is complete (has space or 3+ chars)
    if (value.contains(' ')) {
      final words = value.trim().split(RegExp(r'\s+'));
      _controllers[index].text = words.first;

      // Paste multiple words
      for (var i = 1; i < words.length && index + i < 12; i++) {
        _controllers[index + i].text = words[i];
      }

      final nextIndex = (index + words.length).clamp(0, 11);
      if (nextIndex < 12) {
        _focusNodes[nextIndex].requestFocus();
      }
    }
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Restore Wallet'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          // Instructions
          const Text(
            'Enter your 12-word recovery phrase',
            style: TextStyle(
              fontSize: 16,
              color: Bolt21Theme.textSecondary,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'You can paste all 12 words at once into the first field',
            style: TextStyle(
              fontSize: 14,
              color: Bolt21Theme.textSecondary,
            ),
          ),
          const SizedBox(height: 24),

          // Word input grid
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              childAspectRatio: 2.2,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
            ),
            itemCount: 12,
            itemBuilder: (context, index) {
              return Container(
                decoration: BoxDecoration(
                  color: Bolt21Theme.darkCard,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: _focusNodes[index].hasFocus
                        ? Bolt21Theme.orange
                        : Bolt21Theme.darkBorder,
                  ),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 28,
                      alignment: Alignment.center,
                      child: Text(
                        '${index + 1}',
                        style: const TextStyle(
                          color: Bolt21Theme.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ),
                    Expanded(
                      child: TextField(
                        controller: _controllers[index],
                        focusNode: _focusNodes[index],
                        decoration: const InputDecoration(
                          border: InputBorder.none,
                          contentPadding: EdgeInsets.symmetric(horizontal: 4),
                          isDense: true,
                        ),
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 14,
                        ),
                        autocorrect: false,
                        enableSuggestions: false,
                        textInputAction: index < 11
                            ? TextInputAction.next
                            : TextInputAction.done,
                        onChanged: (value) => _onWordChanged(index, value),
                        onSubmitted: (_) {
                          if (index < 11) {
                            _focusNodes[index + 1].requestFocus();
                          } else {
                            _restoreWallet();
                          }
                        },
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
          const SizedBox(height: 24),

          // Error message
          if (_error != null)
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Bolt21Theme.error.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: Bolt21Theme.error.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.error_outline, color: Bolt21Theme.error),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _error!,
                      style: const TextStyle(color: Bolt21Theme.error),
                    ),
                  ),
                ],
              ),
            ),
          if (_error != null) const SizedBox(height: 24),

          // Restore button or sync progress
          if (_isLoading) ...[
            // Sync progress indicator
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Bolt21Theme.darkCard,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Column(
                children: [
                  const CircularProgressIndicator(color: Bolt21Theme.orange),
                  const SizedBox(height: 16),
                  Text(
                    _syncStatus,
                    style: const TextStyle(
                      fontSize: 16,
                      color: Bolt21Theme.textPrimary,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  // Progress bar
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: _syncStep / _totalSyncSteps,
                      backgroundColor: Bolt21Theme.darkBg,
                      valueColor: const AlwaysStoppedAnimation<Color>(
                        Bolt21Theme.orange,
                      ),
                      minHeight: 8,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Step $_syncStep of $_totalSyncSteps',
                    style: const TextStyle(
                      fontSize: 12,
                      color: Bolt21Theme.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
          ] else ...[
            SizedBox(
              height: 56,
              child: ElevatedButton(
                onPressed: _isComplete ? _restoreWallet : null,
                child: const Text(
                  'Restore Wallet',
                  style: TextStyle(fontSize: 18),
                ),
              ),
            ),
          ],
          const SizedBox(height: 50),
        ],
      ),
    );
  }
}
