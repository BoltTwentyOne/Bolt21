import 'package:flutter/foundation.dart';
import 'package:flutter_breez_liquid/flutter_breez_liquid.dart';
import 'package:synchronized/synchronized.dart';
import '../services/lightning_service.dart';
import '../services/operation_state_service.dart';
import '../utils/retry_helper.dart';

/// Wallet state management
class WalletProvider extends ChangeNotifier {
  final LightningService _lightningService = LightningService();
  final OperationStateService _operationStateService = OperationStateService();

  // Atomic mutex lock to prevent concurrent payment operations (TOCTOU-safe)
  final Lock _sendLock = Lock();

  // State
  bool _isLoading = false;
  bool _isInitialized = false;
  String? _error;
  String? _onChainAddress;
  String? _bolt12Offer;
  GetInfoResponse? _info;
  List<Payment> _payments = [];
  List<OperationState> _incompleteOperations = [];

  // Getters
  bool get isLoading => _isLoading;
  bool get isInitialized => _isInitialized;
  String? get error => _error;
  String? get onChainAddress => _onChainAddress;
  String? get bolt12Offer => _bolt12Offer;
  GetInfoResponse? get info => _info;
  List<Payment> get payments => _payments;
  LightningService get lightningService => _lightningService;
  List<OperationState> get incompleteOperations => _incompleteOperations;
  bool get hasIncompleteOperations => _incompleteOperations.isNotEmpty;
  OperationStateService get operationStateService => _operationStateService;

  // Derived getters
  int get totalBalanceSats {
    return _info?.walletInfo.balanceSat.toInt() ?? 0;
  }

  int get pendingReceiveSats {
    return _info?.walletInfo.pendingReceiveSat.toInt() ?? 0;
  }

  int get pendingSendSats {
    return _info?.walletInfo.pendingSendSat.toInt() ?? 0;
  }

  String? get nodeId {
    return _info?.walletInfo.pubkey;
  }

  /// Initialize wallet with existing or new mnemonic
  Future<void> initializeWallet({String? mnemonic}) async {
    _setLoading(true);
    _error = null;

    try {
      // Initialize operation state tracking first
      await _operationStateService.initialize();

      await _lightningService.initialize(mnemonic: mnemonic);
      _isInitialized = true;
      await _refreshAll();

      // Check for any incomplete operations from previous session
      await _checkIncompleteOperations();
    } catch (e) {
      _error = e.toString();
      debugPrint('Wallet initialization error: $e');
    } finally {
      _setLoading(false);
    }
  }

  /// Check for incomplete operations from previous session
  Future<void> _checkIncompleteOperations() async {
    _incompleteOperations = _operationStateService.getIncompleteOperations();

    if (_incompleteOperations.isNotEmpty) {
      debugPrint('Found ${_incompleteOperations.length} incomplete operations');

      // For operations that were in "executing" state, mark as unknown
      // since we don't know if they completed
      for (final op in _incompleteOperations) {
        if (op.status == OperationStatus.executing) {
          await _operationStateService.markUnknown(op.id);
        }
      }

      // Refresh the list after updates
      _incompleteOperations = _operationStateService.getIncompleteOperations();
      notifyListeners();
    }
  }

  /// Acknowledge and dismiss an incomplete operation after user review
  Future<void> acknowledgeIncompleteOperation(String operationId) async {
    await _operationStateService.removeOperation(operationId);
    _incompleteOperations = _operationStateService.getIncompleteOperations();
    notifyListeners();
  }

  /// Clear all incomplete operations (user confirmed they're resolved)
  Future<void> clearIncompleteOperations() async {
    for (final op in _incompleteOperations) {
      await _operationStateService.removeOperation(op.id);
    }
    _incompleteOperations = [];
    notifyListeners();
  }

  /// Generate a new mnemonic
  String generateMnemonic() {
    return _lightningService.generateMnemonic();
  }

  /// Refresh all wallet data
  Future<void> refreshAll() async {
    if (!_isInitialized) return;
    _setLoading(true);
    await _refreshAll();
    _setLoading(false);
  }

  Future<void> _refreshAll() async {
    try {
      // Use retry for network resilience
      _info = await withRefreshRetry(
        operation: () => _lightningService.getInfo(),
        operationName: 'getInfo',
      );
      _payments = await withRefreshRetry(
        operation: () => _lightningService.listPayments(),
        operationName: 'listPayments',
      );
      _error = null;
    } catch (e) {
      // Don't overwrite critical errors with refresh failures
      if (_error == null) {
        _error = 'Failed to refresh: ${e.toString()}';
      }
      debugPrint('Refresh failed: $e');
    }
    notifyListeners();
  }

  /// Get new on-chain address
  Future<String?> generateOnChainAddress() async {
    if (!_isInitialized) return null;

    final operation = await _operationStateService.createOperation(
      type: OperationType.receiveOnchain,
    );

    try {
      await _operationStateService.markExecuting(operation.id);
      _onChainAddress = await _lightningService.getOnChainAddress();
      await _operationStateService.markCompleted(operation.id);
      notifyListeners();
      return _onChainAddress;
    } catch (e) {
      await _operationStateService.markFailed(operation.id, e.toString());
      _error = e.toString();
      notifyListeners();
      return null;
    }
  }

  /// Generate BOLT12 offer
  Future<String?> generateBolt12Offer() async {
    if (!_isInitialized) return null;

    final operation = await _operationStateService.createOperation(
      type: OperationType.receiveBolt12,
    );

    try {
      await _operationStateService.markExecuting(operation.id);
      _bolt12Offer = await _lightningService.generateBolt12Offer();
      await _operationStateService.markCompleted(operation.id);
      notifyListeners();
      return _bolt12Offer;
    } catch (e) {
      await _operationStateService.markFailed(operation.id, e.toString());
      _error = e.toString();
      notifyListeners();
      return null;
    }
  }

  /// Send a payment (BOLT11, BOLT12, Lightning Address, etc.)
  /// Returns operation ID on success for tracking, null on failure
  Future<String?> sendPayment(String destination, {BigInt? amountSat}) async {
    if (!_isInitialized) return null;
    _setLoading(true);

    // Create operation record BEFORE starting - this is critical for crash recovery
    final operation = await _operationStateService.createOperation(
      type: OperationType.send,
      destination: destination,
      amountSat: amountSat?.toInt(),
    );

    try {
      // Mark as preparing (SDK prepare call)
      await _operationStateService.markPreparing(operation.id);

      // Mark as executing (SDK send call)
      await _operationStateService.markExecuting(operation.id);

      final response = await _lightningService.sendPayment(
        destination: destination,
        amountSat: amountSat,
      );

      // Mark as completed with transaction ID
      await _operationStateService.markCompleted(
        operation.id,
        txId: response.payment.txId,
      );

      await _refreshAll();
      return operation.id;
    } catch (e) {
      // Mark as failed with error
      await _operationStateService.markFailed(operation.id, e.toString());
      _error = e.toString();
      notifyListeners();
      return null;
    } finally {
      _setLoading(false);
    }
  }

  /// Send payment with idempotency and atomic mutex lock - prevents double-spend
  /// Uses synchronized Lock for TOCTOU-safe concurrency control
  Future<String?> sendPaymentIdempotent(
    String destination, {
    BigInt? amountSat,
    String? idempotencyKey,
  }) async {
    // Check if lock is already held (non-blocking check for UX)
    if (_sendLock.locked) {
      debugPrint('Payment blocked - another payment is in progress');
      _error = 'Another payment is in progress. Please wait.';
      notifyListeners();
      return null;
    }

    // Atomic lock acquisition - prevents race condition
    return await _sendLock.synchronized(() async {
      // Double-check inside lock (belt and suspenders)
      final existing = _operationStateService.getAllOperations().where((op) =>
          op.destination == destination &&
          op.amountSat == amountSat?.toInt() &&
          op.isIncomplete);

      if (existing.isNotEmpty) {
        debugPrint('Duplicate payment blocked - operation ${existing.first.id} already in progress');
        _error = 'A payment to this destination is already in progress';
        notifyListeners();
        return null;
      }

      return await sendPayment(destination, amountSat: amountSat);
    });
  }

  void _setLoading(bool loading) {
    _isLoading = loading;
    notifyListeners();
  }

  @override
  void dispose() {
    _lightningService.disconnect();
    super.dispose();
  }
}
