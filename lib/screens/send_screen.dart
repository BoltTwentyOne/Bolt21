import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import '../providers/wallet_provider.dart';
import '../services/auth_service.dart';
import '../services/payment_tracker_service.dart';
import '../utils/address_validator.dart';
import '../utils/theme.dart';

class SendScreen extends StatefulWidget {
  const SendScreen({super.key});

  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  final _controller = TextEditingController();
  final _amountController = TextEditingController();
  bool _isScanning = false;
  String? _paymentType;

  @override
  void dispose() {
    _controller.dispose();
    _amountController.dispose();
    super.dispose();
  }

  void _detectPaymentType(String input) {
    final lower = input.toLowerCase().trim();
    setState(() {
      if (lower.startsWith('lno')) {
        _paymentType = 'BOLT12 Offer';
      } else if (lower.startsWith('lnbc') || lower.startsWith('lntb')) {
        _paymentType = 'BOLT11 Invoice';
      } else if (lower.startsWith('bitcoin:') || lower.startsWith('bc1') || lower.startsWith('1') || lower.startsWith('3')) {
        _paymentType = 'On-chain';
      } else {
        _paymentType = null;
      }
    });
  }

  Future<void> _handlePay() async {
    final wallet = context.read<WalletProvider>();
    final input = _controller.text.trim();

    if (input.isEmpty) return;

    // SECURITY: Validate address to prevent unicode lookalike attacks
    final validationError = AddressValidator.validateDestination(input);
    if (validationError != null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(validationError),
          backgroundColor: Bolt21Theme.error,
        ),
      );
      return;
    }

    // Parse amount if provided (for BOLT12 offers)
    BigInt? amountSat;
    if (_amountController.text.isNotEmpty) {
      final parsed = int.tryParse(_amountController.text.trim());
      if (parsed == null || parsed <= 0 || parsed > 2100000000000000) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Invalid amount. Must be between 1 and 21M BTC in sats.'),
            backgroundColor: Bolt21Theme.error,
          ),
        );
        return;
      }
      amountSat = BigInt.from(parsed);
    }

    // SECURITY: Require biometric re-authentication for large payments
    // Uses cumulative tracking to prevent bypass via split payments
    // (e.g., 10 x 99k sats in 5 min window would still require biometric)
    final paymentAmount = amountSat?.toInt() ?? 0;
    final paymentTracker = PaymentTrackerService();
    if (paymentTracker.shouldRequireBiometric(paymentAmount)) {
      final canUseBiometrics = await AuthService.canUseBiometrics();
      if (canUseBiometrics) {
        final cumulativeAmount = paymentTracker.getCumulativeAmount();
        final totalAmount = cumulativeAmount + paymentAmount;
        final authenticated = await AuthService.authenticate(
          reason: 'Authenticate to send $paymentAmount sats (${totalAmount >= PaymentTrackerService.biometricThresholdSats ? "cumulative: ${totalAmount}" : "large payment"})',
        );
        if (!authenticated) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Authentication required for large or cumulative payments'),
                backgroundColor: Bolt21Theme.error,
              ),
            );
          }
          return;
        }
      }
    }

    // Determine routing: LND > Community Node > Breez
    final useLnd = wallet.shouldUseLndForDestination(input);
    final isBolt11 = _paymentType == 'BOLT11 Invoice';

    String? operationId;
    String successMessage = 'Payment sent!';

    if (useLnd) {
      // Route via user's own LND node (highest priority)
      operationId = await wallet.sendPaymentViaLnd(
        input,
        amountSat: amountSat?.toInt(),
      );
      successMessage = 'Payment sent via ${wallet.lndNodeInfo?.alias ?? "your node"}!';
      HapticFeedback.mediumImpact();
    } else if (isBolt11 && wallet.isCommunityNodeEnabled) {
      // Try Community Node for BOLT11 (if enabled)
      operationId = await wallet.sendPaymentViaCommunityNode(
        input,
        amountSat: amountSat?.toInt(),
      );
      if (operationId != null) {
        successMessage = 'Payment sent via Community Node!';
        HapticFeedback.mediumImpact();
      } else if (wallet.error == null) {
        // Community node unavailable - fallback to Breez
        operationId = await wallet.sendPaymentIdempotent(input, amountSat: amountSat);
        successMessage = 'Payment sent via Breez (Community Node offline)';
      }
    } else {
      // Use Breez SDK (for BOLT12, on-chain, Lightning Address, etc.)
      operationId = await wallet.sendPaymentIdempotent(input, amountSat: amountSat);
    }

    if (operationId != null && mounted) {
      // SECURITY: Record successful payment for cumulative tracking
      paymentTracker.recordPayment(paymentAmount);

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(successMessage),
          backgroundColor: Bolt21Theme.success,
        ),
      );
      Navigator.pop(context);
    } else if (wallet.error != null && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Payment failed: ${wallet.error}'),
          backgroundColor: Bolt21Theme.error,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Send'),
        actions: [
          IconButton(
            icon: Icon(_isScanning ? Icons.edit : Icons.qr_code_scanner),
            tooltip: _isScanning ? 'Enter manually' : 'Scan QR code',
            onPressed: () {
              setState(() {
                _isScanning = !_isScanning;
              });
            },
          ),
        ],
      ),
      body: _isScanning ? _buildScanner() : _buildManualInput(),
    );
  }

  /// Validate and sanitize QR code content to prevent injection attacks
  /// SECURITY: Uses AddressValidator to prevent unicode lookalike attacks
  String? _validateQrCode(String? rawValue) {
    if (rawValue == null || rawValue.isEmpty) return null;

    // Limit QR code size to prevent DoS (max 4KB is generous for any valid payment)
    const maxLength = 4096;
    if (rawValue.length > maxLength) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('QR code too large. Maximum 4KB allowed.'),
          backgroundColor: Bolt21Theme.error,
        ),
      );
      return null;
    }

    // SECURITY: Check for unicode lookalikes before any processing
    if (AddressValidator.containsUnicodeLookalikes(rawValue)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('QR code contains invalid unicode characters. Possible spoofing attempt.'),
          backgroundColor: Bolt21Theme.error,
        ),
      );
      return null;
    }

    // Basic sanitization - remove control characters except newlines
    final sanitized = rawValue.replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'), '');

    // SECURITY: Full validation using AddressValidator
    final validationError = AddressValidator.validateDestination(sanitized.trim());
    if (validationError != null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(validationError),
          backgroundColor: Bolt21Theme.error,
        ),
      );
      return null;
    }

    return sanitized.trim();
  }

  Widget _buildScanner() {
    return Stack(
      children: [
        MobileScanner(
          onDetect: (capture) {
            final barcodes = capture.barcodes;
            for (final barcode in barcodes) {
              final validated = _validateQrCode(barcode.rawValue);
              if (validated != null) {
                setState(() {
                  _controller.text = validated;
                  _isScanning = false;
                });
                _detectPaymentType(validated);
                break;
              }
            }
          },
        ),
        Positioned(
          bottom: 32,
          left: 0,
          right: 0,
          child: Center(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              decoration: BoxDecoration(
                color: Colors.black54,
                borderRadius: BorderRadius.circular(24),
              ),
              child: const Text(
                'Scan a QR code',
                style: TextStyle(color: Colors.white),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildManualInput() {
    return Consumer<WalletProvider>(
      builder: (context, wallet, child) {
        return ListView(
          padding: const EdgeInsets.all(24),
          children: [
            // Input field
            TextField(
              controller: _controller,
              maxLines: 4,
              decoration: const InputDecoration(
                labelText: 'Invoice or Offer',
                hintText: 'Paste BOLT12 offer, BOLT11 invoice, or Bitcoin address',
                alignLabelWithHint: true,
              ),
              onChanged: _detectPaymentType,
            ),
            const SizedBox(height: 12),

            // Payment type indicator with LND badge
            if (_paymentType != null)
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    decoration: BoxDecoration(
                      color: Bolt21Theme.orange.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Bolt21Theme.orange.withValues(alpha: 0.3)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          _paymentType == 'On-chain' ? Icons.link : Icons.bolt,
                          size: 16,
                          color: Bolt21Theme.orange,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          _paymentType!,
                          style: const TextStyle(color: Bolt21Theme.orange),
                        ),
                      ],
                    ),
                  ),
                  // Show routing badge when LND or Community Node will be used
                  if (_paymentType == 'BOLT11 Invoice' && wallet.isLndConnected)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      decoration: BoxDecoration(
                        color: Bolt21Theme.success.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Bolt21Theme.success.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(
                            Icons.router,
                            size: 16,
                            color: Bolt21Theme.success,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            'via ${wallet.lndNodeInfo?.alias ?? "Your Node"}',
                            style: const TextStyle(color: Bolt21Theme.success),
                          ),
                        ],
                      ),
                    )
                  else if (_paymentType == 'BOLT11 Invoice' && wallet.isCommunityNodeEnabled)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      decoration: BoxDecoration(
                        color: Colors.blue.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.blue.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(
                            Icons.people,
                            size: 16,
                            color: Colors.blue,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            'via Community Node${wallet.communityNodeStatus?.online == true ? "" : " (offline)"}',
                            style: const TextStyle(color: Colors.blue),
                          ),
                        ],
                      ),
                    ),
                ],
              ),
            const SizedBox(height: 24),

            // Amount field (for BOLT12 offers that accept any amount)
            if (_paymentType == 'BOLT12 Offer') ...[
              TextField(
                controller: _amountController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Amount (sats)',
                  hintText: 'Enter amount to send',
                ),
              ),
              const SizedBox(height: 24),
            ],

            // Pay button
            SizedBox(
              height: 56,
              child: ElevatedButton(
                onPressed: wallet.isLoading || _controller.text.isEmpty
                    ? null
                    : _handlePay,
                child: wallet.isLoading
                    ? const SizedBox(
                        width: 24,
                        height: 24,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.black,
                        ),
                      )
                    : const Text('Pay', style: TextStyle(fontSize: 18)),
              ),
            ),
            const SizedBox(height: 16),

            // Balance info - show LND balance for BOLT11 when connected
            Center(
              child: Column(
                children: [
                  if (_paymentType == 'BOLT11 Invoice' && wallet.isLndConnected) ...[
                    Text(
                      'LND Spendable: ${wallet.lndBalance?.spendableBalance ?? 0} sats',
                      style: const TextStyle(color: Bolt21Theme.success),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Breez: ${wallet.totalBalanceSats} sats',
                      style: const TextStyle(
                        color: Bolt21Theme.textSecondary,
                        fontSize: 12,
                      ),
                    ),
                  ] else
                    Text(
                      'Available: ${wallet.totalBalanceSats} sats',
                      style: const TextStyle(color: Bolt21Theme.textSecondary),
                    ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }
}
