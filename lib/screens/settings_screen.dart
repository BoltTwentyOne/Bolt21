import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../providers/wallet_provider.dart';
import '../services/auth_service.dart';
import '../services/secure_storage_service.dart';
import '../utils/theme.dart';
import '../utils/secure_clipboard.dart';
import 'welcome_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _biometricEnabled = false;
  bool _biometricAvailable = false;
  String _biometricType = 'Biometrics';

  @override
  void initState() {
    super.initState();
    _loadBiometricSettings();
  }

  Future<void> _loadBiometricSettings() async {
    final available = await AuthService.canUseBiometrics();
    final enabled = await AuthService.isBiometricEnabled();
    final type = await AuthService.getBiometricTypeName();
    setState(() {
      _biometricAvailable = available;
      _biometricEnabled = enabled;
      _biometricType = type;
    });
  }

  Future<void> _toggleBiometric(bool value) async {
    if (value) {
      // Use device credentials (PIN/pattern allowed) for initial enable
      // This is a one-time setup flow - actual unlock will require biometrics only
      final success = await AuthService.authenticateWithDeviceCredentials(
        reason: 'Authenticate to enable $_biometricType lock',
      );
      if (!success) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Authentication failed or cancelled'),
              backgroundColor: Bolt21Theme.error,
            ),
          );
        }
        return;
      }
    }
    await AuthService.setBiometricEnabled(value);
    setState(() => _biometricEnabled = value);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(value
            ? '$_biometricType lock enabled'
            : '$_biometricType lock disabled'),
          backgroundColor: Bolt21Theme.success,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          const _SectionHeader(title: 'Security'),
          if (_biometricAvailable)
            SwitchListTile(
              secondary: Icon(
                _biometricType == 'Face ID' ? Icons.face : Icons.fingerprint,
                color: Bolt21Theme.orange,
              ),
              title: Text('Unlock with $_biometricType'),
              subtitle: const Text('Require authentication to open app'),
              value: _biometricEnabled,
              onChanged: _toggleBiometric,
              activeTrackColor: Bolt21Theme.orange.withValues(alpha: 0.5),
              thumbColor: WidgetStateProperty.resolveWith((states) {
                if (states.contains(WidgetState.selected)) {
                  return Bolt21Theme.orange;
                }
                return null;
              }),
            )
          else
            const ListTile(
              leading: Icon(Icons.fingerprint, color: Bolt21Theme.textSecondary),
              title: Text('Biometric Auth'),
              subtitle: Text('Not available on this device'),
            ),
          const Divider(),

          const _SectionHeader(title: 'Wallet'),
          _SettingsTile(
            icon: Icons.key,
            title: 'Backup Recovery Phrase',
            subtitle: 'View your 12-word seed phrase',
            onTap: () => _showBackupSheet(context),
          ),
          _SettingsTile(
            icon: Icons.account_balance_wallet,
            title: 'Node Info',
            subtitle: 'View your node ID and status',
            onTap: () => _showNodeInfo(context),
          ),
          const Divider(),

          const _SectionHeader(title: 'Lightning'),
          _SettingsTile(
            icon: Icons.electrical_services,
            title: 'Channels',
            subtitle: 'View and manage Lightning channels',
            onTap: () => _showChannels(context),
          ),
          _SettingsTile(
            icon: Icons.water_drop,
            title: 'Liquidity (LSP)',
            subtitle: 'Configure Lightning Service Provider',
            onTap: () => _showLspConfig(context),
          ),
          const Divider(),

          const _SectionHeader(title: 'About'),
          _SettingsTile(
            icon: Icons.info_outline,
            title: 'About Bolt21',
            subtitle: 'Version, licenses, and more',
            onTap: () => _showAbout(context),
          ),
          const Divider(),

          const _SectionHeader(title: 'Danger Zone'),
          _SettingsTile(
            icon: Icons.delete_forever,
            title: 'Reset Wallet',
            subtitle: 'Delete all data and start fresh',
            textColor: Bolt21Theme.error,
            onTap: () => _confirmReset(context),
          ),
        ],
      ),
    );
  }

  void _showBackupSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const _BackupSheet(),
    );
  }

  void _showNodeInfo(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const _NodeInfoSheet(),
    );
  }

  void _showChannels(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const ChannelsScreen()),
    );
  }

  void _showLspConfig(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const _LspConfigSheet(),
    );
  }

  void _showAbout(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: 'Bolt21',
      applicationVersion: '0.1.0',
      applicationIcon: Container(
        width: 48,
        height: 48,
        decoration: BoxDecoration(
          color: Bolt21Theme.orange.withValues(alpha: 0.1),
          shape: BoxShape.circle,
        ),
        child: const Icon(Icons.bolt, color: Bolt21Theme.orange),
      ),
      children: [
        const Text(
          'Self-custodial Lightning wallet with native BOLT12 support.',
        ),
        const SizedBox(height: 16),
        const Text(
          'Built with Flutter and LDK.',
          style: TextStyle(color: Bolt21Theme.textSecondary),
        ),
      ],
    );
  }

  void _confirmReset(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: Bolt21Theme.darkCard,
        title: const Text('Reset Wallet?'),
        content: const Text(
          'This will delete all wallet data including your seed phrase. '
          'Make sure you have backed up your recovery phrase before continuing.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await _resetWallet(context);
            },
            child: const Text(
              'Reset',
              style: TextStyle(color: Bolt21Theme.error),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _resetWallet(BuildContext context) async {
    final wallet = context.read<WalletProvider>();
    await wallet.lightningService.disconnect();
    await SecureStorageService.clearWallet();

    if (context.mounted) {
      Navigator.pushAndRemoveUntil(
        context,
        MaterialPageRoute(builder: (_) => const WelcomeScreen()),
        (route) => false,
      );
    }
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;

  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          color: Bolt21Theme.textSecondary,
          letterSpacing: 1.2,
        ),
      ),
    );
  }
}

class _SettingsTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final Color? textColor;

  const _SettingsTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.textColor,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon, color: textColor ?? Bolt21Theme.orange),
      title: Text(title, style: TextStyle(color: textColor)),
      subtitle: Text(
        subtitle,
        style: const TextStyle(color: Bolt21Theme.textSecondary, fontSize: 12),
      ),
      trailing: const Icon(
        Icons.chevron_right,
        color: Bolt21Theme.textSecondary,
      ),
      onTap: onTap,
    );
  }
}

/// Sheet to display and backup seed phrase
class _BackupSheet extends StatefulWidget {
  const _BackupSheet();

  @override
  State<_BackupSheet> createState() => _BackupSheetState();
}

class _BackupSheetState extends State<_BackupSheet> {
  String? _mnemonic;
  bool _isLoading = true;
  bool _showWords = false;

  @override
  void initState() {
    super.initState();
    _loadMnemonic();
  }

  Future<void> _loadMnemonic() async {
    final mnemonic = await SecureStorageService.getMnemonic();
    setState(() {
      _mnemonic = mnemonic;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final words = _mnemonic?.split(' ') ?? [];

    return DraggableScrollableSheet(
      initialChildSize: 0.7,
      minChildSize: 0.5,
      maxChildSize: 0.9,
      expand: false,
      builder: (context, scrollController) {
        return ListView(
          controller: scrollController,
          padding: const EdgeInsets.all(24),
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Bolt21Theme.textSecondary,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Recovery Phrase',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            const Text(
              'Write these words down and store them safely',
              style: TextStyle(color: Bolt21Theme.textSecondary),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),

            if (_isLoading)
              const Center(child: CircularProgressIndicator())
            else ...[
              // Show/hide toggle
              Center(
                child: TextButton.icon(
                  onPressed: () => setState(() => _showWords = !_showWords),
                  icon: Icon(_showWords ? Icons.visibility_off : Icons.visibility),
                  label: Text(_showWords ? 'Hide Words' : 'Show Words'),
                ),
              ),
              const SizedBox(height: 16),

              // Word grid
              GridView.builder(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
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
              const SizedBox(height: 24),

              // Copy button with security warning
              OutlinedButton.icon(
                onPressed: () async {
                  await SecureClipboard.copyWithTimeout(
                    context,
                    _mnemonic ?? '',
                    timeout: const Duration(seconds: 30),
                  );
                },
                icon: const Icon(Icons.copy),
                label: const Text('Copy to Clipboard (30s auto-clear)'),
              ),
            ],
          ],
        );
      },
    );
  }
}

/// Sheet to display node information
class _NodeInfoSheet extends StatelessWidget {
  const _NodeInfoSheet();

  @override
  Widget build(BuildContext context) {
    return Consumer<WalletProvider>(
      builder: (context, wallet, child) {
        return Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Bolt21Theme.textSecondary,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Node Information',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 24),

              _InfoRow(
                label: 'Node ID',
                value: wallet.nodeId ?? 'Loading...',
                copyable: true,
              ),
              const SizedBox(height: 16),
              _InfoRow(
                label: 'Network',
                value: 'Bitcoin Mainnet',
              ),
              const SizedBox(height: 16),
              _InfoRow(
                label: 'Status',
                value: wallet.isInitialized ? 'Running' : 'Stopped',
                valueColor: wallet.isInitialized
                    ? Bolt21Theme.success
                    : Bolt21Theme.error,
              ),
              const SizedBox(height: 24),
            ],
          ),
        );
      },
    );
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  final bool copyable;
  final Color? valueColor;

  const _InfoRow({
    required this.label,
    required this.value,
    this.copyable = false,
    this.valueColor,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            color: Bolt21Theme.textSecondary,
            fontSize: 12,
          ),
        ),
        const SizedBox(height: 4),
        Row(
          children: [
            Expanded(
              child: Text(
                value.length > 20
                    ? '${value.substring(0, 10)}...${value.substring(value.length - 10)}'
                    : value,
                style: TextStyle(
                  fontFamily: 'monospace',
                  color: valueColor,
                ),
              ),
            ),
            if (copyable)
              IconButton(
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: value));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Copied'),
                      backgroundColor: Bolt21Theme.success,
                    ),
                  );
                },
              ),
          ],
        ),
      ],
    );
  }
}

/// Sheet for LSP configuration
class _LspConfigSheet extends StatelessWidget {
  const _LspConfigSheet();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Center(
            child: Container(
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Bolt21Theme.textSecondary,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Lightning Service Provider',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'LSPs provide automatic channel liquidity so you can receive payments without manually opening channels.',
            style: TextStyle(color: Bolt21Theme.textSecondary),
          ),
          const SizedBox(height: 24),

          // Info card
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Bolt21Theme.orange.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: Bolt21Theme.orange.withValues(alpha: 0.3),
              ),
            ),
            child: const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.info_outline, color: Bolt21Theme.orange, size: 20),
                    SizedBox(width: 8),
                    Text(
                      'Coming Soon',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: Bolt21Theme.orange,
                      ),
                    ),
                  ],
                ),
                SizedBox(height: 8),
                Text(
                  'LSP configuration UI is in development. For now, LSP can be configured in code via LspConfig.',
                  style: TextStyle(fontSize: 13),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Recommended LSPs
          const Text(
            'Recommended LSPs:',
            style: TextStyle(fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 8),
          const Text('• Voltage Flow (voltage.cloud)'),
          const Text('• Megalith (megalithic.me)'),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

/// Screen explaining Liquid-based swaps
class ChannelsScreen extends StatelessWidget {
  const ChannelsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Liquidity'),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.swap_horiz,
                size: 64,
                color: Bolt21Theme.orange.withValues(alpha: 0.7),
              ),
              const SizedBox(height: 16),
              const Text(
                'Liquid-Based Swaps',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'Bolt21 uses Breez SDK with Liquid Network for instant swaps. '
                'No traditional Lightning channels are needed.\n\n'
                'Payments are automatically converted between Lightning and Liquid, '
                'giving you the best of both worlds.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Bolt21Theme.textSecondary),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
