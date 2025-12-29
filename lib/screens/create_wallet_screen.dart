import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../providers/wallet_provider.dart';
import '../services/secure_storage_service.dart';
import '../utils/theme.dart';
import '../utils/secure_clipboard.dart';
import 'home_screen.dart';

class CreateWalletScreen extends StatefulWidget {
  const CreateWalletScreen({super.key});

  @override
  State<CreateWalletScreen> createState() => _CreateWalletScreenState();
}

class _CreateWalletScreenState extends State<CreateWalletScreen> {
  String? _mnemonic;
  bool _isLoading = true;
  bool _backedUp = false;
  bool _showWords = false;

  @override
  void initState() {
    super.initState();
    _generateMnemonic();
  }

  @override
  void dispose() {
    // SECURITY: Clear mnemonic from memory when leaving screen
    // Note: Dart strings are immutable and can't be truly wiped,
    // but clearing the reference helps minimize exposure window
    _mnemonic = null;
    super.dispose();
  }

  void _generateMnemonic() {
    final wallet = context.read<WalletProvider>();
    final mnemonic = wallet.generateMnemonic();
    setState(() {
      _mnemonic = mnemonic;
      _isLoading = false;
    });
  }

  Future<void> _createWallet() async {
    if (_mnemonic == null) return;

    setState(() => _isLoading = true);

    // SECURITY: Copy mnemonic to local variable and clear class field ASAP
    final mnemonicCopy = _mnemonic!;

    try {
      // Save mnemonic securely
      await SecureStorageService.saveMnemonic(mnemonicCopy);

      // Initialize wallet
      final wallet = context.read<WalletProvider>();
      await wallet.initializeWallet(mnemonic: mnemonicCopy);

      // SECURITY: Clear mnemonic from UI state after successful storage
      if (mounted) {
        setState(() => _mnemonic = null);
      }

      // Check if initialization succeeded
      if (wallet.error != null) {
        throw Exception(wallet.error);
      }

      if (mounted) {
        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (_) => const HomeScreen()),
          (route) => false,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isLoading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to create wallet: $e'),
            backgroundColor: Bolt21Theme.error,
            duration: const Duration(seconds: 5),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final words = _mnemonic?.split(' ') ?? [];

    return Scaffold(
      appBar: AppBar(
        title: const Text('Create Wallet'),
      ),
      body: _isLoading && _mnemonic == null
          ? const Center(
              child: CircularProgressIndicator(color: Bolt21Theme.orange),
            )
          : ListView(
              padding: const EdgeInsets.all(24),
              children: [
                // Warning card
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Bolt21Theme.error.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: Bolt21Theme.error.withValues(alpha: 0.3),
                    ),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.warning_amber, color: Bolt21Theme.error),
                      SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'Write down these 12 words and store them safely. They are the only way to recover your wallet.',
                          style: TextStyle(color: Bolt21Theme.error),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 24),

                // Seed phrase display
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'Recovery Phrase',
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 16,
                              ),
                            ),
                            TextButton.icon(
                              onPressed: () {
                                setState(() => _showWords = !_showWords);
                              },
                              icon: Icon(
                                _showWords
                                    ? Icons.visibility_off
                                    : Icons.visibility,
                                size: 18,
                              ),
                              label: Text(_showWords ? 'Hide' : 'Show'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 16),
                        GridView.builder(
                          shrinkWrap: true,
                          physics: const NeverScrollableScrollPhysics(),
                          gridDelegate:
                              const SliverGridDelegateWithFixedCrossAxisCount(
                            crossAxisCount: 3,
                            childAspectRatio: 2.5,
                            crossAxisSpacing: 8,
                            mainAxisSpacing: 8,
                          ),
                          itemCount: words.length,
                          itemBuilder: (context, index) {
                            return Container(
                              decoration: BoxDecoration(
                                color: Bolt21Theme.darkBg,
                                borderRadius: BorderRadius.circular(8),
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
                                    child: Text(
                                      _showWords ? words[index] : '••••',
                                      style: const TextStyle(
                                        fontFamily: 'monospace',
                                        fontWeight: FontWeight.w500,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            );
                          },
                        ),
                        const SizedBox(height: 16),
                        OutlinedButton.icon(
                          onPressed: () async {
                            await SecureClipboard.copyWithTimeout(
                              context,
                              _mnemonic ?? '',
                              timeout: const Duration(seconds: 30),
                            );
                          },
                          icon: const Icon(Icons.copy, size: 18),
                          label: const Text('Copy to Clipboard (30s auto-clear)'),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Backup confirmation
                CheckboxListTile(
                  value: _backedUp,
                  onChanged: (value) {
                    setState(() => _backedUp = value ?? false);
                  },
                  title: const Text(
                    'I have written down my recovery phrase',
                  ),
                  subtitle: const Text(
                    'I understand that losing it means losing access to my funds',
                    style: TextStyle(
                      color: Bolt21Theme.textSecondary,
                      fontSize: 12,
                    ),
                  ),
                  controlAffinity: ListTileControlAffinity.leading,
                  activeColor: Bolt21Theme.orange,
                  contentPadding: EdgeInsets.zero,
                ),
                const SizedBox(height: 24),

                // Create button
                SizedBox(
                  height: 56,
                  child: ElevatedButton(
                    onPressed: _backedUp && !_isLoading ? _createWallet : null,
                    child: _isLoading
                        ? const SizedBox(
                            width: 24,
                            height: 24,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Colors.black,
                            ),
                          )
                        : const Text(
                            'Create Wallet',
                            style: TextStyle(fontSize: 18),
                          ),
                  ),
                ),
                const SizedBox(height: 32),
              ],
            ),
    );
  }
}
