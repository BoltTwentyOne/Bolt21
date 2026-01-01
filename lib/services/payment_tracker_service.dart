/// Tracks recent payment amounts to prevent biometric bypass via split payments
/// SECURITY: Prevents attackers from draining funds by sending multiple small payments
/// below the biometric threshold (e.g., 10 x 99k sats = 990k sats without biometric)
class PaymentTrackerService {
  static final PaymentTrackerService _instance = PaymentTrackerService._internal();
  factory PaymentTrackerService() => _instance;
  PaymentTrackerService._internal();

  /// Time window for cumulative tracking (5 minutes)
  static const Duration _trackingWindow = Duration(minutes: 5);

  /// Daily cumulative limit (24 hours)
  static const Duration _dailyWindow = Duration(hours: 24);

  /// Threshold above which biometric is required (100k sats)
  static const int biometricThresholdSats = 100000;

  /// Daily cumulative limit for biometric bypass prevention (500k sats/day)
  /// SECURITY: Prevents attacker from gaming 5-minute window by sending 99k every 5min1sec
  static const int dailyCumulativeLimit = 500000;

  /// List of recent payment timestamps and amounts
  final List<_PaymentRecord> _recentPayments = [];

  /// Check if biometric should be required for a payment
  /// Returns true if cumulative payments in window + current payment exceeds threshold
  /// SECURITY: Checks both 5-minute window AND 24-hour cumulative limit
  bool shouldRequireBiometric(int amountSats) {
    _pruneOldPayments();

    // Calculate cumulative amount in 5-minute tracking window
    final cumulativeAmount = _recentPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );

    // Calculate cumulative amount in 24-hour daily window
    final dailyCumulativeAmount = _getDailyCumulativeAmount();

    // SECURITY: Require biometric if EITHER condition is met:
    // 1. Cumulative + current exceeds 100k in 5-minute window (original protection)
    // 2. Cumulative + current exceeds 500k in 24-hour window (prevents gaming)
    return (cumulativeAmount + amountSats) >= biometricThresholdSats ||
        (dailyCumulativeAmount + amountSats) >= dailyCumulativeLimit;
  }

  /// Record a successful payment (call after payment succeeds)
  void recordPayment(int amountSats) {
    _pruneOldPayments();
    _recentPayments.add(_PaymentRecord(
      timestamp: DateTime.now(),
      amountSats: amountSats,
    ));
  }

  /// Get cumulative amount in 5-minute tracking window (for display purposes)
  int getCumulativeAmount() {
    _pruneOldPayments();
    return _recentPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );
  }

  /// Get cumulative amount in 24-hour daily window (for display purposes)
  /// SECURITY: Shows user how much they've sent in past 24 hours
  int getDailyCumulativeAmount() {
    _pruneDailyPayments();
    return _recentPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );
  }

  /// Calculate daily cumulative amount (internal helper)
  int _getDailyCumulativeAmount() {
    final dailyCutoff = DateTime.now().subtract(_dailyWindow);
    return _recentPayments
        .where((record) => record.timestamp.isAfter(dailyCutoff))
        .fold<int>(0, (sum, record) => sum + record.amountSats);
  }

  /// Remove payments older than tracking window (5 minutes)
  void _pruneOldPayments() {
    final cutoff = DateTime.now().subtract(_trackingWindow);
    _recentPayments.removeWhere((record) => record.timestamp.isBefore(cutoff));
  }

  /// Remove payments older than daily window (24 hours)
  void _pruneDailyPayments() {
    final cutoff = DateTime.now().subtract(_dailyWindow);
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
