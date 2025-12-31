/// Tracks recent payment amounts to prevent biometric bypass via split payments
/// SECURITY: Prevents attackers from draining funds by sending multiple small payments
/// below the biometric threshold (e.g., 10 x 99k sats = 990k sats without biometric)
class PaymentTrackerService {
  static final PaymentTrackerService _instance = PaymentTrackerService._internal();
  factory PaymentTrackerService() => _instance;
  PaymentTrackerService._internal();

  /// Time window for cumulative tracking (5 minutes)
  static const Duration _trackingWindow = Duration(minutes: 5);

  /// Threshold above which biometric is required (100k sats)
  static const int biometricThresholdSats = 100000;

  /// List of recent payment timestamps and amounts
  final List<_PaymentRecord> _recentPayments = [];

  /// Check if biometric should be required for a payment
  /// Returns true if cumulative payments in window + current payment exceeds threshold
  bool shouldRequireBiometric(int amountSats) {
    _pruneOldPayments();

    // Calculate cumulative amount in tracking window
    final cumulativeAmount = _recentPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );

    // Require biometric if cumulative + current exceeds threshold
    return (cumulativeAmount + amountSats) >= biometricThresholdSats;
  }

  /// Record a successful payment (call after payment succeeds)
  void recordPayment(int amountSats) {
    _pruneOldPayments();
    _recentPayments.add(_PaymentRecord(
      timestamp: DateTime.now(),
      amountSats: amountSats,
    ));
  }

  /// Get cumulative amount in tracking window (for display purposes)
  int getCumulativeAmount() {
    _pruneOldPayments();
    return _recentPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );
  }

  /// Remove payments older than tracking window
  void _pruneOldPayments() {
    final cutoff = DateTime.now().subtract(_trackingWindow);
    _recentPayments.removeWhere((record) => record.timestamp.isBefore(cutoff));
  }

  /// Clear all tracked payments (for testing or logout)
  void clear() {
    _recentPayments.clear();
  }
}

class _PaymentRecord {
  final DateTime timestamp;
  final int amountSats;

  _PaymentRecord({
    required this.timestamp,
    required this.amountSats,
  });
}
