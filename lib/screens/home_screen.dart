import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_breez_liquid/flutter_breez_liquid.dart';
import 'package:provider/provider.dart';
import '../providers/wallet_provider.dart';
import '../services/app_update_service.dart';
import '../services/operation_state_service.dart';
import '../services/price_service.dart';
import '../utils/formatters.dart';
import '../utils/theme.dart';
import '../widgets/wallet_switcher.dart';
import 'receive_screen.dart';
import 'send_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: const Padding(
          padding: EdgeInsets.only(left: 8),
          child: Center(child: WalletSwitcher()),
        ),
        leadingWidth: 160,
        title: Image.asset(
          'assets/images/logo.png',
          height: 32,
        ),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const SettingsScreen()),
              );
            },
          ),
        ],
      ),
      body: Consumer<WalletProvider>(
        builder: (context, wallet, child) {
          if (wallet.isLoading && !wallet.isInitialized) {
            return const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Bolt21Theme.orange),
                  SizedBox(height: 16),
                  Text('Starting Lightning node...'),
                ],
              ),
            );
          }

          if (wallet.error != null && !wallet.isInitialized) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.error_outline, size: 48, color: Bolt21Theme.error),
                    const SizedBox(height: 16),
                    Text(
                      'Failed to start node',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      wallet.error!,
                      textAlign: TextAlign.center,
                      style: const TextStyle(color: Bolt21Theme.textSecondary),
                    ),
                    const SizedBox(height: 24),
                    ElevatedButton(
                      onPressed: () => wallet.refreshAll(),
                      child: const Text('Retry'),
                    ),
                  ],
                ),
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () => wallet.refreshAll(),
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // Incomplete operations warning
                if (wallet.hasIncompleteOperations)
                  _IncompleteOperationsAlert(
                    operations: wallet.incompleteOperations,
                    onDismiss: () => wallet.clearIncompleteOperations(),
                  ),

                // Balance card
                _BalanceCard(wallet: wallet),
                const SizedBox(height: 24),

                // Action buttons
                Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (_) => const ReceiveScreen(),
                            ),
                          );
                        },
                        icon: const Icon(Icons.arrow_downward),
                        label: const Text('Receive'),
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (_) => const SendScreen(),
                            ),
                          );
                        },
                        icon: const Icon(Icons.arrow_upward),
                        label: const Text('Send'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 32),

                // Transactions
                Text(
                  'Recent Activity',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 12),
                _TransactionList(payments: wallet.payments),
              ],
            ),
          );
        },
      ),
    );
  }
}

enum BalanceDisplayMode { sats, usd, btc, hidden }

class _BalanceCard extends StatefulWidget {
  final WalletProvider wallet;

  const _BalanceCard({required this.wallet});

  @override
  State<_BalanceCard> createState() => _BalanceCardState();
}

class _BalanceCardState extends State<_BalanceCard> {
  BalanceDisplayMode _displayMode = BalanceDisplayMode.sats;
  bool _priceLoaded = false;

  @override
  void initState() {
    super.initState();
    _loadPrice();
    _checkForUpdates();
  }

  Future<void> _loadPrice() async {
    await PriceService.instance.fetchBtcPrice();
    if (mounted) {
      setState(() => _priceLoaded = true);
    }
  }

  Future<void> _checkForUpdates() async {
    // Delay slightly to ensure context is ready
    await Future.delayed(const Duration(milliseconds: 500));
    if (mounted) {
      // Check for forced updates first (blocking)
      await AppUpdateService.checkForUpdate(context);
      // Then check for optional updates (non-blocking snackbar)
      if (mounted) {
        await AppUpdateService.checkForOptionalUpdate(context);
      }
    }
  }

  void _cycleDisplayMode() {
    HapticFeedback.selectionClick();
    setState(() {
      switch (_displayMode) {
        case BalanceDisplayMode.sats:
          _displayMode = BalanceDisplayMode.usd;
          break;
        case BalanceDisplayMode.usd:
          _displayMode = BalanceDisplayMode.btc;
          break;
        case BalanceDisplayMode.btc:
          _displayMode = BalanceDisplayMode.hidden;
          break;
        case BalanceDisplayMode.hidden:
          _displayMode = BalanceDisplayMode.sats;
          break;
      }
    });
  }

  String _formatBalance(int sats) {
    final priceService = PriceService.instance;
    switch (_displayMode) {
      case BalanceDisplayMode.sats:
        return formatSats(sats);
      case BalanceDisplayMode.usd:
        final usd = priceService.satsToUsd(sats);
        if (usd == null) return formatSats(sats);
        return priceService.formatUsd(usd);
      case BalanceDisplayMode.btc:
        return priceService.formatBtc(priceService.satsToBtc(sats));
      case BalanceDisplayMode.hidden:
        return '••••••';
    }
  }

  String get _displayModeLabel {
    switch (_displayMode) {
      case BalanceDisplayMode.sats:
        return 'Tap to show USD';
      case BalanceDisplayMode.usd:
        return 'Tap to show BTC';
      case BalanceDisplayMode.btc:
        return 'Tap to hide balance';
      case BalanceDisplayMode.hidden:
        return 'Tap to show balance';
    }
  }

  /// Get total unified balance (Breez + LND spendable)
  int get _unifiedBalance {
    final breezBalance = widget.wallet.totalBalanceSats;
    final lndBalance = widget.wallet.isLndConnected
        ? (widget.wallet.lndBalance?.spendableBalance ?? 0)
        : 0;
    return breezBalance + lndBalance;
  }

  String _getAccessibilityLabel() {
    final balance = _unifiedBalance;
    final hasLnd = widget.wallet.isLndConnected;
    final balanceType = hasLnd ? 'Unified balance' : 'Total balance';

    if (_displayMode == BalanceDisplayMode.hidden) {
      return '$balanceType is hidden. Tap to show balance.';
    }

    return '$balanceType: ${formatSats(balance)}. $_displayModeLabel';
  }

  @override
  Widget build(BuildContext context) {
    final hasLnd = widget.wallet.isLndConnected;

    return Semantics(
      label: _getAccessibilityLabel(),
      button: true,
      child: Card(
        child: InkWell(
          onTap: _cycleDisplayMode,
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              children: [
                Text(
                  hasLnd ? 'Unified Balance' : 'Total Balance',
                  style: const TextStyle(color: Bolt21Theme.textSecondary),
                ),
                const SizedBox(height: 8),
                Text(
                  _formatBalance(_unifiedBalance),
                  style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: Bolt21Theme.orange,
                  ),
                ),
              const SizedBox(height: 4),
              Text(
                _displayModeLabel,
                style: TextStyle(
                  fontSize: 11,
                  color: Bolt21Theme.textSecondary.withValues(alpha: 0.6),
                ),
              ),

              // LND balance breakdown when connected
              if (hasLnd && _displayMode != BalanceDisplayMode.hidden) ...[
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Bolt21Theme.darkBg,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _BalanceBreakdown(
                        icon: Icons.water_drop,
                        label: 'Breez (Liquid)',
                        value: formatSatsCompact(widget.wallet.totalBalanceSats),
                        color: Bolt21Theme.orange,
                      ),
                      Container(
                        width: 1,
                        height: 32,
                        color: Bolt21Theme.textSecondary.withValues(alpha: 0.2),
                      ),
                      _BalanceBreakdown(
                        icon: Icons.router,
                        label: widget.wallet.lndNodeInfo?.alias ?? 'LND',
                        value: formatSatsCompact(
                          widget.wallet.lndBalance?.spendableBalance ?? 0,
                        ),
                        color: Bolt21Theme.success,
                      ),
                    ],
                  ),
                ),
              ],

              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  _BalanceChip(
                    icon: Icons.access_time,
                    label: 'Pending In',
                    value: formatSatsCompact(widget.wallet.pendingReceiveSats),
                  ),
                  const SizedBox(width: 24),
                  _BalanceChip(
                    icon: Icons.schedule_send,
                    label: 'Pending Out',
                    value: formatSatsCompact(widget.wallet.pendingSendSats),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    ),
    );
  }
}

class _BalanceBreakdown extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color color;

  const _BalanceBreakdown({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Icon(icon, size: 18, color: color),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(
            fontSize: 11,
            color: Bolt21Theme.textSecondary,
          ),
          overflow: TextOverflow.ellipsis,
        ),
        const SizedBox(height: 2),
        Text(
          value,
          style: TextStyle(
            fontWeight: FontWeight.w600,
            color: color,
          ),
        ),
      ],
    );
  }
}

class _BalanceChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _BalanceChip({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: Bolt21Theme.textSecondary),
            const SizedBox(width: 4),
            Text(
              label,
              style: const TextStyle(
                fontSize: 12,
                color: Bolt21Theme.textSecondary,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        Text(value, style: const TextStyle(fontWeight: FontWeight.w500)),
      ],
    );
  }
}

class _TransactionList extends StatelessWidget {
  final List<Payment> payments;

  const _TransactionList({required this.payments});

  @override
  Widget build(BuildContext context) {
    if (payments.isEmpty) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            children: [
              Icon(
                Icons.receipt_long_outlined,
                size: 48,
                color: Bolt21Theme.textSecondary.withValues(alpha: 0.5),
              ),
              const SizedBox(height: 12),
              const Text(
                'No transactions yet',
                style: TextStyle(color: Bolt21Theme.textSecondary),
              ),
            ],
          ),
        ),
      );
    }

    return Card(
      child: ListView.separated(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        itemCount: payments.length,
        separatorBuilder: (context, index) => const Divider(height: 1),
        itemBuilder: (context, index) {
          final payment = payments[index];
          final isReceive = payment.paymentType == PaymentType.receive;
          final amount = payment.amountSat.toInt();
          final timestamp = DateTime.fromMillisecondsSinceEpoch(
            payment.timestamp * 1000,
          );
          final timeAgo = _formatTimeAgo(timestamp);

          // Determine icon and color based on payment type and status
          final isPending = payment.status == PaymentState.pending;
          final isFailed = payment.status == PaymentState.failed;

          IconData icon;
          Color iconColor;
          if (isFailed) {
            icon = Icons.error_outline;
            iconColor = Bolt21Theme.error;
          } else if (isPending) {
            icon = Icons.hourglass_empty;
            iconColor = Bolt21Theme.orange;
          } else if (isReceive) {
            icon = Icons.arrow_downward;
            iconColor = Bolt21Theme.success;
          } else {
            icon = Icons.arrow_upward;
            iconColor = Bolt21Theme.orange;
          }

          // Build accessibility label for screen readers
          String semanticLabel;
          if (isFailed) {
            semanticLabel = 'Failed ${isReceive ? "incoming" : "outgoing"} payment of ${_formatAmount(amount)}, $timeAgo';
          } else if (isPending) {
            semanticLabel = 'Pending ${isReceive ? "incoming" : "outgoing"} payment of ${_formatAmount(amount)}, $timeAgo';
          } else {
            semanticLabel = '${isReceive ? "Received" : "Sent"} ${_formatAmount(amount)}, $timeAgo';
          }

          return Semantics(
            label: semanticLabel,
            button: true,
            child: ListTile(
              onTap: () => _showPaymentDetails(context, payment),
              leading: CircleAvatar(
                backgroundColor: iconColor.withValues(alpha: 0.1),
                child: Icon(icon, color: iconColor, size: 20),
              ),
              title: Text(
                '${isReceive ? '+' : '-'}${_formatAmount(amount)}',
                style: TextStyle(
                  fontWeight: FontWeight.w600,
                  color: isReceive ? Bolt21Theme.success : Bolt21Theme.textPrimary,
                ),
              ),
              subtitle: Text(
                isPending ? 'Pending • $timeAgo' : timeAgo,
                style: const TextStyle(
                  color: Bolt21Theme.textSecondary,
                  fontSize: 12,
                ),
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (isFailed)
                    const Text(
                      'Failed',
                      style: TextStyle(color: Bolt21Theme.error, fontSize: 12),
                    ),
                  const SizedBox(width: 4),
                  Icon(
                    Icons.chevron_right,
                    color: Bolt21Theme.textSecondary.withValues(alpha: 0.5),
                    size: 20,
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  void _showPaymentDetails(BuildContext context, Payment payment) {
    final isReceive = payment.paymentType == PaymentType.receive;
    final amount = payment.amountSat.toInt();
    final feesSat = payment.feesSat.toInt();
    final timestamp = DateTime.fromMillisecondsSinceEpoch(payment.timestamp * 1000);

    // Format date
    final dateStr = '${timestamp.day}/${timestamp.month}/${timestamp.year}';
    final timeStr = '${timestamp.hour.toString().padLeft(2, '0')}:${timestamp.minute.toString().padLeft(2, '0')}';

    // Status
    String statusStr;
    Color statusColor;
    switch (payment.status) {
      case PaymentState.pending:
        statusStr = 'Pending';
        statusColor = Bolt21Theme.orange;
        break;
      case PaymentState.complete:
        statusStr = 'Complete';
        statusColor = Bolt21Theme.success;
        break;
      case PaymentState.failed:
        statusStr = 'Failed';
        statusColor = Bolt21Theme.error;
        break;
      default:
        statusStr = 'Unknown';
        statusColor = Bolt21Theme.textSecondary;
    }

    // Payment method
    String methodStr;
    switch (payment.details) {
      case PaymentDetails_Lightning():
        methodStr = 'Lightning';
        break;
      case PaymentDetails_Liquid():
        methodStr = 'Liquid';
        break;
      case PaymentDetails_Bitcoin():
        methodStr = 'On-chain';
        break;
      default:
        methodStr = 'Unknown';
    }

    showModalBottomSheet(
      context: context,
      backgroundColor: Bolt21Theme.darkCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
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

            // Amount
            Center(
              child: Text(
                '${isReceive ? '+' : '-'}${_formatAmount(amount)}',
                style: TextStyle(
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                  color: isReceive ? Bolt21Theme.success : Bolt21Theme.textPrimary,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  statusStr,
                  style: TextStyle(color: statusColor, fontWeight: FontWeight.w500),
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Details
            _DetailRow(label: 'Type', value: isReceive ? 'Received' : 'Sent'),
            _DetailRow(label: 'Method', value: methodStr),
            _DetailRow(label: 'Date', value: '$dateStr at $timeStr'),
            if (feesSat > 0)
              _DetailRow(label: 'Fees', value: '$feesSat sats'),

            const SizedBox(height: 24),

            // Close button
            SizedBox(
              width: double.infinity,
              child: OutlinedButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Close'),
              ),
            ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
  }

  String _formatAmount(int sats) {
    if (sats >= 1000000) {
      return '${(sats / 1000000).toStringAsFixed(2)}M sats';
    } else if (sats >= 1000) {
      final formatted = sats.toString().replaceAllMapped(
        RegExp(r'(\d{1,3})(?=(\d{3})+(?!\d))'),
        (m) => '${m[1]},',
      );
      return '$formatted sats';
    }
    return '$sats sats';
  }

  String _formatTimeAgo(DateTime timestamp) {
    final now = DateTime.now();
    final difference = now.difference(timestamp);

    if (difference.inSeconds < 60) {
      return 'Just now';
    } else if (difference.inMinutes < 60) {
      final mins = difference.inMinutes;
      return '$mins ${mins == 1 ? 'min' : 'mins'} ago';
    } else if (difference.inHours < 24) {
      final hours = difference.inHours;
      return '$hours ${hours == 1 ? 'hour' : 'hours'} ago';
    } else if (difference.inDays < 7) {
      final days = difference.inDays;
      return '$days ${days == 1 ? 'day' : 'days'} ago';
    } else {
      return '${timestamp.day}/${timestamp.month}/${timestamp.year}';
    }
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;

  const _DetailRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(color: Bolt21Theme.textSecondary),
          ),
          Text(
            value,
            style: const TextStyle(fontWeight: FontWeight.w500),
          ),
        ],
      ),
    );
  }
}

/// Alert banner for incomplete operations from previous session
class _IncompleteOperationsAlert extends StatelessWidget {
  final List<OperationState> operations;
  final VoidCallback onDismiss;

  const _IncompleteOperationsAlert({
    required this.operations,
    required this.onDismiss,
  });

  @override
  Widget build(BuildContext context) {
    final sendOps = operations.where((op) => op.isSend).toList();
    final hasPendingSends = sendOps.isNotEmpty;

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: hasPendingSends
            ? Bolt21Theme.error.withValues(alpha: 0.1)
            : Bolt21Theme.orange.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: hasPendingSends
              ? Bolt21Theme.error.withValues(alpha: 0.3)
              : Bolt21Theme.orange.withValues(alpha: 0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                hasPendingSends ? Icons.warning_amber : Icons.info_outline,
                color: hasPendingSends ? Bolt21Theme.error : Bolt21Theme.orange,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  hasPendingSends
                      ? 'Payment May Be Pending'
                      : 'Interrupted Operations',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    color: hasPendingSends
                        ? Bolt21Theme.error
                        : Bolt21Theme.orange,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            hasPendingSends
                ? 'A payment was interrupted. Check your transaction history before sending again to avoid double-paying.'
                : '${operations.length} operation(s) were interrupted. Your balance should still be correct.',
            style: const TextStyle(
              fontSize: 13,
              color: Bolt21Theme.textSecondary,
            ),
          ),
          const SizedBox(height: 12),
          // Show each incomplete operation
          ...operations.map((op) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  children: [
                    Icon(
                      op.isSend ? Icons.arrow_upward : Icons.arrow_downward,
                      size: 14,
                      color: Bolt21Theme.textSecondary,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '${_operationTypeName(op.type)} - ${op.status.name}',
                      style: const TextStyle(
                        fontSize: 12,
                        fontFamily: 'monospace',
                        color: Bolt21Theme.textSecondary,
                      ),
                    ),
                    if (op.amountSat != null) ...[
                      const SizedBox(width: 8),
                      Text(
                        '${op.amountSat} sats',
                        style: const TextStyle(
                          fontSize: 12,
                          color: Bolt21Theme.textSecondary,
                        ),
                      ),
                    ],
                  ],
                ),
              )),
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: onDismiss,
                child: const Text('Dismiss'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _operationTypeName(OperationType type) {
    switch (type) {
      case OperationType.send:
        return 'Send';
      case OperationType.receiveBolt12:
        return 'Receive (BOLT12)';
      case OperationType.receiveOnchain:
        return 'Receive (On-chain)';
      case OperationType.receiveBolt11:
        return 'Receive (Invoice)';
    }
  }
}
