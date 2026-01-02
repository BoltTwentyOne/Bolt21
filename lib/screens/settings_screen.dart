import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';
import '../providers/wallet_provider.dart';
import '../services/auth_service.dart';
import '../services/secure_storage_service.dart';
import '../utils/theme.dart';
import '../utils/secure_clipboard.dart';
import '../utils/secure_string.dart';
import 'manage_wallets_screen.dart';
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
      // Authenticate before enabling
      final success = await AuthService.authenticateWithDeviceCredentials(
        reason: 'Authenticate to enable $_biometricType lock',
      );
      if (!success) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Authentication cancelled'),
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
            icon: Icons.account_balance_wallet,
            title: 'Manage Wallets',
            subtitle: 'Add, rename, or delete wallets',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ManageWalletsScreen()),
            ),
          ),
          _SettingsTile(
            icon: Icons.key,
            title: 'Backup Recovery Phrase',
            subtitle: 'View your 12-word seed phrase',
            onTap: () => _showBackupSheet(context),
          ),
          _SettingsTile(
            icon: Icons.info_outline,
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
            icon: Icons.bolt,
            title: 'Spark Network',
            subtitle: 'Bitcoin-native Layer 2 info',
            onTap: () => _showSparkInfo(context),
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
          'Built with Flutter and Breez SDK.',
          style: TextStyle(color: Bolt21Theme.textSecondary),
        ),
        const SizedBox(height: 16),
        GestureDetector(
          onTap: () => _launchEmail('support@bolt21.io'),
          child: const Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.email, size: 16, color: Bolt21Theme.orange),
              SizedBox(width: 8),
              Text(
                'support@bolt21.io',
                style: TextStyle(
                  color: Bolt21Theme.orange,
                  decoration: TextDecoration.underline,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Future<void> _launchEmail(String email) async {
    final uri = Uri(scheme: 'mailto', path: email);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri);
    }
  }

  void _showSparkInfo(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => const _SparkInfoSheet(),
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
    await SecureStorageService.clearAllWallets();

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
  // SECURITY: Use SecureString to enable memory wiping on disposal
  SecureString? _mnemonic;
  String? _walletName;
  bool _isLoading = true;
  bool _showWords = false;

  @override
  void initState() {
    super.initState();
    _loadMnemonic();
  }

  @override
  void dispose() {
    // SECURITY: Securely wipe mnemonic from memory (triple-overwrite pattern)
    _mnemonic?.dispose();
    _mnemonic = null;
    super.dispose();
  }

  Future<void> _loadMnemonic() async {
    final wallet = context.read<WalletProvider>();
    final mnemonic = await wallet.getMnemonic();
    setState(() {
      // SECURITY: Store mnemonic as SecureString for memory wiping
      _mnemonic = mnemonic != null ? SecureString.fromString(mnemonic) : null;
      _walletName = wallet.activeWallet?.name;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final words = _mnemonic?.value.split(' ') ?? [];

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
            Text(
              _walletName != null ? '$_walletName Recovery Phrase' : 'Recovery Phrase',
              style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
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
                    _mnemonic?.value ?? '',
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
              const SizedBox(height: 40),
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
                tooltip: 'Copy to clipboard',
                onPressed: () async {
                  // SECURITY: Use SecureClipboard with auto-clear for node config data
                  await SecureClipboard.copyWithTimeout(
                    context,
                    value,
                    timeout: const Duration(seconds: 45),
                    showWarning: false, // Node config less sensitive than mnemonic
                  );
                },
              ),
          ],
        ),
      ],
    );
  }
}

/// Sheet to explain Spark network benefits
class _SparkInfoSheet extends StatelessWidget {
  const _SparkInfoSheet();

  @override
  Widget build(BuildContext context) {
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
            const Row(
              children: [
                Icon(Icons.bolt, color: Bolt21Theme.orange, size: 28),
                SizedBox(width: 12),
                Text(
                  'Spark Network',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Bitcoin-native Layer 2 for Lightning payments',
              style: TextStyle(color: Bolt21Theme.textSecondary),
            ),
            const SizedBox(height: 24),

            // Benefits
            const Text(
              'Why Spark?',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            _SparkBenefitItem(
              icon: Icons.account_balance,
              title: 'Real Bitcoin',
              description: 'Your funds are actual BTC on the Bitcoin blockchain, not synthetic assets or wrapped tokens.',
            ),
            _SparkBenefitItem(
              icon: Icons.savings,
              title: 'Lower Fees',
              description: 'No swap fees or conversion costs. Pay only Lightning routing fees.',
            ),
            _SparkBenefitItem(
              icon: Icons.flash_on,
              title: 'No Swaps Required',
              description: 'Direct Lightning routing without intermediary token conversions.',
            ),
            _SparkBenefitItem(
              icon: Icons.security,
              title: 'Self-Custodial',
              description: 'You control your keys and funds. No third-party custody.',
            ),
            const SizedBox(height: 24),

            // Technical info
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
                        'Built on Breez SDK',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Bolt21Theme.orange,
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 8),
                  Text(
                    'Bolt21 uses the Breez SDK Spark implementation for seamless Bitcoin-native Lightning payments with full self-custody.',
                    style: TextStyle(fontSize: 13),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],
        );
      },
    );
  }
}

class _SparkBenefitItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final String description;

  const _SparkBenefitItem({
    required this.icon,
    required this.title,
    required this.description,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Bolt21Theme.orange.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: Bolt21Theme.orange, size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  description,
                  style: const TextStyle(
                    color: Bolt21Theme.textSecondary,
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
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


