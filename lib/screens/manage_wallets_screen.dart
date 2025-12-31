import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../models/wallet_metadata.dart';
import '../providers/wallet_provider.dart';
import '../utils/theme.dart';
import '../utils/formatters.dart';

/// Screen for managing multiple wallets
class ManageWalletsScreen extends StatelessWidget {
  const ManageWalletsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Manage Wallets'),
      ),
      body: Consumer<WalletProvider>(
        builder: (context, wallet, child) {
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // Wallet list
              ...wallet.wallets.map((w) => _WalletCard(
                wallet: w,
                isActive: w.id == wallet.activeWallet?.id,
                balance: w.id == wallet.activeWallet?.id
                    ? wallet.totalBalanceSats
                    : null,
              )),
              const SizedBox(height: 16),
              // Add wallet button
              OutlinedButton.icon(
                onPressed: () => _showAddWalletOptions(context),
                icon: const Icon(Icons.add),
                label: const Text('Add Wallet'),
                style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.all(16),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  void _showAddWalletOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              margin: const EdgeInsets.only(top: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Bolt21Theme.darkBorder,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(height: 24),
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Bolt21Theme.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(Icons.add, color: Bolt21Theme.orange),
              ),
              title: const Text('Create New Wallet'),
              subtitle: const Text('Generate a new seed phrase'),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(context, '/create-wallet', arguments: {'addWallet': true});
              },
            ),
            const Divider(color: Bolt21Theme.darkBorder),
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Bolt21Theme.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(Icons.file_download_outlined, color: Bolt21Theme.orange),
              ),
              title: const Text('Import Existing Wallet'),
              subtitle: const Text('Restore from seed phrase'),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(context, '/restore-wallet', arguments: {'addWallet': true});
              },
            ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}

class _WalletCard extends StatelessWidget {
  final WalletMetadata wallet;
  final bool isActive;
  final int? balance;

  const _WalletCard({
    required this.wallet,
    required this.isActive,
    this.balance,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: isActive ? Bolt21Theme.orange : Bolt21Theme.darkBorder,
          width: isActive ? 2 : 1,
        ),
      ),
      child: InkWell(
        onTap: () => _showWalletActions(context),
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: isActive
                          ? Bolt21Theme.orange
                          : Bolt21Theme.darkBg,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      Icons.bolt,
                      color: isActive ? Colors.black : Bolt21Theme.textSecondary,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Flexible(
                              child: Text(
                                wallet.name,
                                style: const TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (isActive) ...[
                              const SizedBox(width: 8),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: Bolt21Theme.orange,
                                  borderRadius: BorderRadius.circular(10),
                                ),
                                child: const Text(
                                  'Active',
                                  style: TextStyle(
                                    fontSize: 10,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.black,
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text(
                          balance != null
                              ? formatSats(balance!)
                              : 'Tap to switch',
                          style: TextStyle(
                            color: Bolt21Theme.textSecondary,
                            fontSize: isActive ? 14 : 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.more_vert),
                    tooltip: 'Wallet options',
                    onPressed: () => _showWalletActions(context),
                    color: Bolt21Theme.textSecondary,
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showWalletActions(BuildContext context) {
    final walletProvider = context.read<WalletProvider>();
    final canDelete = walletProvider.wallets.length > 1;

    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              margin: const EdgeInsets.only(top: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Bolt21Theme.darkBorder,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  Text(
                    wallet.name,
                    style: const TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            if (!isActive)
              ListTile(
                leading: const Icon(Icons.swap_horiz, color: Bolt21Theme.orange),
                title: const Text('Switch to this wallet'),
                onTap: () async {
                  Navigator.pop(context);
                  HapticFeedback.mediumImpact();
                  await walletProvider.switchWallet(wallet.id);
                },
              ),
            ListTile(
              leading: const Icon(Icons.edit, color: Bolt21Theme.textSecondary),
              title: const Text('Rename'),
              onTap: () {
                Navigator.pop(context);
                _showRenameDialog(context, walletProvider);
              },
            ),
            ListTile(
              leading: const Icon(Icons.key, color: Bolt21Theme.textSecondary),
              title: const Text('View Recovery Phrase'),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(
                  context,
                  '/recovery-phrase',
                  arguments: {'walletId': wallet.id, 'walletName': wallet.name},
                );
              },
            ),
            if (canDelete)
              ListTile(
                leading: const Icon(Icons.delete_outline, color: Bolt21Theme.error),
                title: Text(
                  'Delete Wallet',
                  style: TextStyle(color: Bolt21Theme.error),
                ),
                onTap: () {
                  Navigator.pop(context);
                  _showDeleteConfirmation(context, walletProvider);
                },
              ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  void _showRenameDialog(BuildContext context, WalletProvider walletProvider) {
    final controller = TextEditingController(text: wallet.name);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Bolt21Theme.darkCard,
        title: const Text('Rename Wallet'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(
            labelText: 'Wallet Name',
            hintText: 'Enter wallet name',
          ),
          maxLength: 30,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              final newName = controller.text.trim();
              if (newName.isNotEmpty && newName != wallet.name) {
                await walletProvider.renameWallet(wallet.id, newName);
                if (context.mounted) {
                  Navigator.pop(context);
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Wallet renamed'),
                      backgroundColor: Bolt21Theme.success,
                    ),
                  );
                }
              } else {
                Navigator.pop(context);
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  void _showDeleteConfirmation(BuildContext context, WalletProvider walletProvider) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Bolt21Theme.darkCard,
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Bolt21Theme.error),
            const SizedBox(width: 8),
            const Text('Delete Wallet'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This action cannot be undone. Make sure you have backed up your recovery phrase.',
              style: TextStyle(color: Bolt21Theme.textSecondary),
            ),
            const SizedBox(height: 16),
            Text(
              'Type "${wallet.name}" to confirm:',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: controller,
              decoration: InputDecoration(
                hintText: wallet.name,
                hintStyle: TextStyle(
                  color: Bolt21Theme.textSecondary.withValues(alpha: 0.3),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: Bolt21Theme.error,
            ),
            onPressed: () async {
              if (controller.text.trim() == wallet.name) {
                Navigator.pop(context);
                try {
                  await walletProvider.deleteWallet(wallet.id);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Wallet deleted'),
                        backgroundColor: Bolt21Theme.success,
                      ),
                    );
                  }
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Error: $e'),
                        backgroundColor: Bolt21Theme.error,
                      ),
                    );
                  }
                }
              }
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
}
