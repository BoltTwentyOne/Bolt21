import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_breez_liquid/flutter_breez_liquid.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';
import '../providers/wallet_provider.dart';
import '../services/auth_service.dart';
import '../services/lnd_service.dart';
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
            icon: Icons.router,
            title: 'Connect Your Node',
            subtitle: 'Use your own LND node for sends',
            onTap: () => _showConnectNode(context),
          ),
          Consumer<WalletProvider>(
            builder: (context, wallet, _) => _SettingsTile(
              icon: Icons.people,
              title: 'Community Node',
              subtitle: wallet.isCommunityNodeEnabled
                  ? 'Enabled - lower fees via shared node'
                  : 'Route payments via community node',
              onTap: () => _showCommunityNode(context),
            ),
          ),
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
          _SettingsTile(
            icon: Icons.refresh,
            title: 'Recover Stuck Funds',
            subtitle: 'Reclaim funds from failed swaps',
            onTap: () => _showRefundables(context),
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

  void _showConnectNode(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const ConnectNodeScreen()),
    );
  }

  void _showCommunityNode(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const _CommunityNodeSheet(),
    );
  }

  void _showRefundables(BuildContext context) async {
    final wallet = context.read<WalletProvider>();

    // Show loading
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => const Center(child: CircularProgressIndicator()),
    );

    try {
      final refundables = await wallet.lightningService.listRefundables();
      if (!context.mounted) return;
      Navigator.pop(context); // Close loading

      if (refundables.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No stuck funds to recover'),
            backgroundColor: Bolt21Theme.success,
          ),
        );
        return;
      }

      // Show refundables
      showModalBottomSheet(
        context: context,
        backgroundColor: Bolt21Theme.darkCard,
        isScrollControlled: true,
        shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        builder: (ctx) => _RefundablesSheet(
          refundables: refundables,
          wallet: wallet,
        ),
      );
    } catch (e) {
      if (!context.mounted) return;
      Navigator.pop(context); // Close loading
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error checking refundables: $e'),
          backgroundColor: Bolt21Theme.error,
        ),
      );
    }
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

/// Sheet for Community Node configuration with privacy disclosure
class _CommunityNodeSheet extends StatefulWidget {
  const _CommunityNodeSheet();

  @override
  State<_CommunityNodeSheet> createState() => _CommunityNodeSheetState();
}

class _CommunityNodeSheetState extends State<_CommunityNodeSheet> {
  bool _isLoading = false;

  Future<void> _toggleCommunityNode(bool enable) async {
    setState(() => _isLoading = true);

    try {
      final wallet = context.read<WalletProvider>();
      await wallet.setCommunityNodeEnabled(enable);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(enable
                ? 'Community Node enabled'
                : 'Community Node disabled'),
            backgroundColor: Bolt21Theme.success,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: $e'),
            backgroundColor: Bolt21Theme.error,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<WalletProvider>(
      builder: (context, wallet, _) {
        final isEnabled = wallet.isCommunityNodeEnabled;
        final status = wallet.communityNodeStatus;

        return DraggableScrollableSheet(
          initialChildSize: 0.65,
          minChildSize: 0.4,
          maxChildSize: 0.85,
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
                    Icon(Icons.people, color: Colors.blue, size: 28),
                    SizedBox(width: 12),
                    Text(
                      'Community Node',
                      style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                const Text(
                  'Route BOLT11 payments through a community-operated Lightning node for potentially lower fees.',
                  style: TextStyle(color: Bolt21Theme.textSecondary),
                ),
                const SizedBox(height: 24),

                // Status card
                if (isEnabled && status != null)
                  Container(
                    padding: const EdgeInsets.all(16),
                    margin: const EdgeInsets.only(bottom: 16),
                    decoration: BoxDecoration(
                      color: status.online
                          ? Bolt21Theme.success.withValues(alpha: 0.1)
                          : Bolt21Theme.error.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: status.online
                            ? Bolt21Theme.success.withValues(alpha: 0.3)
                            : Bolt21Theme.error.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          status.online ? Icons.check_circle : Icons.warning,
                          color: status.online ? Bolt21Theme.success : Bolt21Theme.error,
                          size: 20,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                status.online ? 'Online' : 'Offline (will use Breez)',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  color: status.online ? Bolt21Theme.success : Bolt21Theme.error,
                                ),
                              ),
                              if (status.online) ...[
                                const SizedBox(height: 4),
                                Text(
                                  '${status.channels} channels • ${_formatSats(status.spendable)} spendable',
                                  style: const TextStyle(
                                    color: Bolt21Theme.textSecondary,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),

                // Privacy disclosure
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
                          Icon(Icons.privacy_tip, color: Bolt21Theme.orange, size: 20),
                          SizedBox(width: 8),
                          Text(
                            'Privacy Notice',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: Bolt21Theme.orange,
                            ),
                          ),
                        ],
                      ),
                      SizedBox(height: 12),
                      Text(
                        'When using the Community Node, the node operator can see:',
                        style: TextStyle(fontSize: 13),
                      ),
                      SizedBox(height: 8),
                      _PrivacyItem(text: 'Payment amounts'),
                      _PrivacyItem(text: 'Payment destinations (invoices)'),
                      _PrivacyItem(text: 'Your IP address (if not using VPN/Tor)'),
                      SizedBox(height: 12),
                      Text(
                        'The node operator cannot access your wallet, seed phrase, or on-chain funds.',
                        style: TextStyle(
                          fontSize: 12,
                          color: Bolt21Theme.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 24),

                // Benefits
                const Text(
                  'Benefits',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                const _BenefitItem(
                  icon: Icons.savings,
                  text: 'Lower fees than Breez/Liquid swaps',
                ),
                const _BenefitItem(
                  icon: Icons.bolt,
                  text: 'Direct Lightning routing (no swaps)',
                ),
                const _BenefitItem(
                  icon: Icons.autorenew,
                  text: 'Automatic fallback to Breez if offline',
                ),
                const SizedBox(height: 24),

                // Toggle switch
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Bolt21Theme.darkBg,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Enable Community Node',
                            style: TextStyle(fontWeight: FontWeight.w500),
                          ),
                          Text(
                            isEnabled ? 'Currently enabled' : 'Currently disabled',
                            style: const TextStyle(
                              color: Bolt21Theme.textSecondary,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                      _isLoading
                          ? const SizedBox(
                              width: 24,
                              height: 24,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : Switch(
                              value: isEnabled,
                              onChanged: _toggleCommunityNode,
                              activeThumbColor: Colors.blue,
                              activeTrackColor: Colors.blue.withValues(alpha: 0.5),
                            ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Note about own node
                if (wallet.isLndConnected)
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Bolt21Theme.success.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.info_outline, color: Bolt21Theme.success, size: 18),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Your own node (${wallet.lndNodeInfo?.alias}) takes priority over Community Node.',
                            style: const TextStyle(
                              color: Bolt21Theme.success,
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            );
          },
        );
      },
    );
  }

  String _formatSats(int sats) {
    if (sats >= 1000000) {
      return '${(sats / 1000000).toStringAsFixed(2)}M sats';
    } else if (sats >= 1000) {
      return '${(sats / 1000).toStringAsFixed(1)}k sats';
    }
    return '$sats sats';
  }
}

class _PrivacyItem extends StatelessWidget {
  final String text;

  const _PrivacyItem({required this.text});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          const Text('  •  ', style: TextStyle(color: Bolt21Theme.orange)),
          Expanded(child: Text(text, style: const TextStyle(fontSize: 13))),
        ],
      ),
    );
  }
}

class _BenefitItem extends StatelessWidget {
  final IconData icon;
  final String text;

  const _BenefitItem({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, color: Colors.blue, size: 18),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: const TextStyle(fontSize: 13))),
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

/// Sheet to display and recover stuck funds
class _RefundablesSheet extends StatefulWidget {
  final List<RefundableSwap> refundables;
  final WalletProvider wallet;

  const _RefundablesSheet({
    required this.refundables,
    required this.wallet,
  });

  @override
  State<_RefundablesSheet> createState() => _RefundablesSheetState();
}

class _RefundablesSheetState extends State<_RefundablesSheet> {
  bool _isProcessing = false;

  Future<void> _refundSwap(RefundableSwap swap) async {
    setState(() => _isProcessing = true);

    try {
      // Get an on-chain address to refund to
      final refundAddress = await widget.wallet.lightningService.getOnChainAddress();

      // Get recommended fees
      final fees = await widget.wallet.lightningService.getRecommendedFees();

      // Process refund
      await widget.wallet.lightningService.refundSwap(
        swapAddress: swap.swapAddress,
        refundAddress: refundAddress,
        feeRateSatPerVbyte: fees.fastestFee.toInt(),
      );

      if (!mounted) return;

      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Refund initiated for ${swap.amountSat} sats'),
          backgroundColor: Bolt21Theme.success,
        ),
      );

      // Refresh wallet
      await widget.wallet.refreshAll();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Refund failed: $e'),
          backgroundColor: Bolt21Theme.error,
        ),
      );
    } finally {
      if (mounted) {
        setState(() => _isProcessing = false);
      }
    }
  }

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
                color: Bolt21Theme.textSecondary.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: 20),
          const Text(
            'Stuck Funds',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          Text(
            '${widget.refundables.length} swap(s) can be recovered',
            style: const TextStyle(color: Bolt21Theme.textSecondary),
          ),
          const SizedBox(height: 24),

          // List refundables
          ...widget.refundables.map((swap) => Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Bolt21Theme.darkBg,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: Bolt21Theme.orange.withValues(alpha: 0.3),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      '${swap.amountSat} sats',
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: Bolt21Theme.orange,
                      ),
                    ),
                    if (_isProcessing)
                      const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    else
                      ElevatedButton(
                        onPressed: () => _refundSwap(swap),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Bolt21Theme.orange,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 16,
                            vertical: 8,
                          ),
                        ),
                        child: const Text('Recover'),
                      ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  'Address: ${swap.swapAddress.substring(0, 16)}...',
                  style: const TextStyle(
                    fontSize: 12,
                    color: Bolt21Theme.textSecondary,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          )),

          const SizedBox(height: 16),
          const Text(
            'Tap "Recover" to return these funds to your wallet. '
            'This may take a few minutes to confirm on-chain.',
            style: TextStyle(
              fontSize: 12,
              color: Bolt21Theme.textSecondary,
            ),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }
}

/// Screen to connect to user's LND node
class ConnectNodeScreen extends StatefulWidget {
  const ConnectNodeScreen({super.key});

  @override
  State<ConnectNodeScreen> createState() => _ConnectNodeScreenState();
}

class _ConnectNodeScreenState extends State<ConnectNodeScreen> {
  final _restUrlController = TextEditingController();
  final _macaroonController = TextEditingController();
  final _lndService = LndService();

  bool _isLoading = false;
  bool _isConnected = false;
  LndNodeInfo? _nodeInfo;
  LndBalance? _balance;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadExistingCredentials();
  }

  @override
  void dispose() {
    _restUrlController.dispose();
    _macaroonController.dispose();
    super.dispose();
  }

  Future<void> _loadExistingCredentials() async {
    final restUrl = await SecureStorageService.getLndRestUrl();
    final macaroon = await SecureStorageService.getLndMacaroon();

    if (restUrl != null && macaroon != null) {
      _restUrlController.text = restUrl;
      _macaroonController.text = macaroon;
      // Auto-connect if credentials exist
      await _testConnection();
    }
  }

  Future<void> _testConnection() async {
    if (_restUrlController.text.isEmpty || _macaroonController.text.isEmpty) {
      setState(() => _error = 'Please enter REST URL and macaroon');
      return;
    }

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      _lndService.configure(
        restUrl: _restUrlController.text.trim(),
        macaroon: _macaroonController.text.trim(),
      );

      final info = await _lndService.connect();
      final balance = await _lndService.getBalance();

      // Save credentials on successful connection
      await SecureStorageService.saveLndCredentials(
        restUrl: _restUrlController.text.trim(),
        macaroon: _macaroonController.text.trim(),
      );

      setState(() {
        _isConnected = true;
        _nodeInfo = info;
        _balance = balance;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Connected to ${info.alias}!'),
            backgroundColor: Bolt21Theme.success,
          ),
        );
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isConnected = false;
      });
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _disconnect() async {
    await SecureStorageService.clearLndCredentials();
    _lndService.disconnect();
    setState(() {
      _isConnected = false;
      _nodeInfo = null;
      _balance = null;
      _restUrlController.clear();
      _macaroonController.clear();
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Node disconnected'),
          backgroundColor: Bolt21Theme.orange,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Connect Your Node'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Status card
            if (_isConnected && _nodeInfo != null) ...[
              _ConnectedNodeCard(
                nodeInfo: _nodeInfo!,
                balance: _balance,
                onDisconnect: _disconnect,
              ),
              const SizedBox(height: 24),
            ] else ...[
              // Instructions
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
                          'Connect to Your LND Node',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            color: Bolt21Theme.orange,
                          ),
                        ),
                      ],
                    ),
                    SizedBox(height: 8),
                    Text(
                      'Use your own Lightning node for sending payments with near-zero fees.\n\n'
                      'You\'ll need:\n'
                      '• REST API URL (e.g., https://your-node:8080)\n'
                      '• Admin macaroon (hex encoded)',
                      style: TextStyle(color: Bolt21Theme.textSecondary, fontSize: 13),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // REST URL input
              TextField(
                controller: _restUrlController,
                decoration: const InputDecoration(
                  labelText: 'REST API URL',
                  hintText: 'https://your-node.local:8080',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.link),
                ),
                keyboardType: TextInputType.url,
              ),
              const SizedBox(height: 16),

              // Macaroon input
              TextField(
                controller: _macaroonController,
                decoration: const InputDecoration(
                  labelText: 'Admin Macaroon (hex)',
                  hintText: '0201036c6e6402...',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.vpn_key),
                ),
                maxLines: 3,
              ),
              const SizedBox(height: 8),
              Text(
                'Get this from: lncli bakemacaroon --save_to admin.macaroon',
                style: TextStyle(
                  fontSize: 11,
                  color: Bolt21Theme.textSecondary.withValues(alpha: 0.7),
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 24),

              // Error display
              if (_error != null) ...[
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Bolt21Theme.error.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.error_outline, color: Bolt21Theme.error, size: 20),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error!,
                          style: const TextStyle(color: Bolt21Theme.error, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
              ],

              // Connect button
              SizedBox(
                width: double.infinity,
                height: 48,
                child: ElevatedButton(
                  onPressed: _isLoading ? null : _testConnection,
                  child: _isLoading
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Connect'),
                ),
              ),
            ],

            const SizedBox(height: 32),

            // How it works
            const Text(
              'How it works',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            _HowItWorksItem(
              icon: Icons.bolt,
              title: 'BOLT12 Receives',
              description: 'Still uses Breez SDK for Ocean mining payouts',
            ),
            _HowItWorksItem(
              icon: Icons.send,
              title: 'Sends via Your Node',
              description: 'Use your channels for near-zero fee payments',
            ),
            _HowItWorksItem(
              icon: Icons.account_balance_wallet,
              title: 'Your Liquidity',
              description: 'Payments route through your 10M+ sat channels',
            ),
          ],
        ),
      ),
    );
  }
}

class _ConnectedNodeCard extends StatelessWidget {
  final LndNodeInfo nodeInfo;
  final LndBalance? balance;
  final VoidCallback onDisconnect;

  const _ConnectedNodeCard({
    required this.nodeInfo,
    required this.balance,
    required this.onDisconnect,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Bolt21Theme.success.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Bolt21Theme.success.withValues(alpha: 0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Bolt21Theme.success.withValues(alpha: 0.2),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.check, color: Bolt21Theme.success, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      nodeInfo.alias,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      '${nodeInfo.numActiveChannels} channels • ${nodeInfo.syncedToChain ? "Synced" : "Syncing..."}',
                      style: const TextStyle(
                        color: Bolt21Theme.textSecondary,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          if (balance != null) ...[
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _BalanceStat(
                  label: 'Spendable',
                  value: '${_formatSats(balance!.spendableBalance)} sats',
                ),
                _BalanceStat(
                  label: 'On-chain',
                  value: '${_formatSats(balance!.onChainConfirmed)} sats',
                ),
              ],
            ),
          ],
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton(
              onPressed: onDisconnect,
              style: OutlinedButton.styleFrom(
                foregroundColor: Bolt21Theme.error,
                side: const BorderSide(color: Bolt21Theme.error),
              ),
              child: const Text('Disconnect'),
            ),
          ),
        ],
      ),
    );
  }

  String _formatSats(int sats) {
    if (sats >= 1000000) {
      return '${(sats / 1000000).toStringAsFixed(2)}M';
    } else if (sats >= 1000) {
      return '${(sats / 1000).toStringAsFixed(1)}k';
    }
    return sats.toString();
  }
}

class _BalanceStat extends StatelessWidget {
  final String label;
  final String value;

  const _BalanceStat({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          label,
          style: const TextStyle(
            color: Bolt21Theme.textSecondary,
            fontSize: 12,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          value,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
            fontSize: 14,
          ),
        ),
      ],
    );
  }
}

class _HowItWorksItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final String description;

  const _HowItWorksItem({
    required this.icon,
    required this.title,
    required this.description,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: Bolt21Theme.orange, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(fontWeight: FontWeight.w500),
                ),
                Text(
                  description,
                  style: const TextStyle(
                    color: Bolt21Theme.textSecondary,
                    fontSize: 12,
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
