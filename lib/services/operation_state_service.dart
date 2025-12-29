import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'secure_storage_service.dart';
import '../utils/secure_logger.dart';

/// Types of wallet operations that can be tracked
enum OperationType {
  send,
  receiveBolt12,
  receiveOnchain,
  receiveBolt11,
}

/// Status of an operation through its lifecycle
enum OperationStatus {
  pending,    // Created but not started
  preparing,  // Calling prepare*() on SDK
  executing,  // Calling send/receive on SDK
  completed,  // Successfully finished
  failed,     // Failed with error
  unknown,    // Interrupted - need to check SDK
}

/// Represents the state of an in-flight operation
class OperationState {
  final String id;
  final OperationType type;
  final String? destination;
  final int? amountSat;
  final OperationStatus status;
  final DateTime startedAt;
  final DateTime? completedAt;
  final String? error;
  final String? txId;
  final Map<String, dynamic>? metadata;

  OperationState({
    required this.id,
    required this.type,
    this.destination,
    this.amountSat,
    required this.status,
    required this.startedAt,
    this.completedAt,
    this.error,
    this.txId,
    this.metadata,
  });

  OperationState copyWith({
    OperationStatus? status,
    DateTime? completedAt,
    String? error,
    String? txId,
    Map<String, dynamic>? metadata,
  }) {
    return OperationState(
      id: id,
      type: type,
      destination: destination,
      amountSat: amountSat,
      status: status ?? this.status,
      startedAt: startedAt,
      completedAt: completedAt ?? this.completedAt,
      error: error ?? this.error,
      txId: txId ?? this.txId,
      metadata: metadata ?? this.metadata,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type.name,
    'destination': destination,
    'amountSat': amountSat,
    'status': status.name,
    'startedAt': startedAt.toIso8601String(),
    'completedAt': completedAt?.toIso8601String(),
    'error': error,
    'txId': txId,
    'metadata': metadata,
  };

  factory OperationState.fromJson(Map<String, dynamic> json) {
    return OperationState(
      id: json['id'] as String,
      type: OperationType.values.firstWhere(
        (e) => e.name == json['type'],
        orElse: () => OperationType.send,
      ),
      destination: json['destination'] as String?,
      amountSat: json['amountSat'] as int?,
      status: OperationStatus.values.firstWhere(
        (e) => e.name == json['status'],
        orElse: () => OperationStatus.unknown,
      ),
      startedAt: DateTime.parse(json['startedAt'] as String),
      completedAt: json['completedAt'] != null
          ? DateTime.parse(json['completedAt'] as String)
          : null,
      error: json['error'] as String?,
      txId: json['txId'] as String?,
      metadata: json['metadata'] as Map<String, dynamic>?,
    );
  }

  bool get isIncomplete =>
      status == OperationStatus.pending ||
      status == OperationStatus.preparing ||
      status == OperationStatus.executing ||
      status == OperationStatus.unknown;

  bool get isComplete => status == OperationStatus.completed;
  bool get isFailed => status == OperationStatus.failed;

  bool get isSend => type == OperationType.send;
  bool get isReceive =>
      type == OperationType.receiveBolt12 ||
      type == OperationType.receiveOnchain ||
      type == OperationType.receiveBolt11;

  @override
  String toString() =>
      'OperationState(id: $id, type: ${type.name}, status: ${status.name})';
}

/// Service for persisting operation state to survive app crashes
/// Uses AES-256-GCM encryption with secure random key stored in keychain
class OperationStateService {
  static const String _fileName = 'operation_state.enc';
  static const String _encryptionKeyStorageKey = 'op_state_encryption_key';
  File? _stateFile;
  List<OperationState> _operations = [];
  SecretKey? _secretKey;

  // AES-256-GCM cipher for authenticated encryption
  final AesGcm _cipher = AesGcm.with256bits();

  // Secure random generator for operation IDs
  final Random _secureRandom = Random.secure();

  /// Initialize the service and load existing state
  Future<void> initialize() async {
    final directory = await getApplicationDocumentsDirectory();
    _stateFile = File('${directory.path}/$_fileName');

    // Get or create encryption key from secure storage
    await _initializeEncryptionKey();

    if (await _stateFile!.exists()) {
      await _loadState();
    }
  }

  /// Initialize encryption key from secure storage or generate new one
  Future<void> _initializeEncryptionKey() async {
    final existingKey = await SecureStorageService.read(_encryptionKeyStorageKey);
    if (existingKey != null && existingKey.isNotEmpty) {
      final keyBytes = base64Decode(existingKey);
      _secretKey = SecretKey(keyBytes);
    } else {
      // Generate new 256-bit key using cryptographically secure random
      _secretKey = await _cipher.newSecretKey();
      final keyBytes = await _secretKey!.extractBytes();
      await SecureStorageService.write(
        _encryptionKeyStorageKey,
        base64Encode(keyBytes),
      );
      SecureLogger.info('Generated new AES-256-GCM encryption key', tag: 'OpState');
    }
  }

  /// Generate a cryptographically secure unique operation ID
  String generateOperationId() {
    // Generate 16 bytes of secure random data
    final bytes = Uint8List.fromList(
      List.generate(16, (_) => _secureRandom.nextInt(256)),
    );
    // Convert to URL-safe base64 and add timestamp prefix for sortability
    final randomPart = base64Url.encode(bytes).replaceAll('=', '');
    final timestamp = DateTime.now().millisecondsSinceEpoch.toRadixString(36);
    return '${timestamp}_$randomPart';
  }

  /// Create a new operation and persist it
  Future<OperationState> createOperation({
    required OperationType type,
    String? destination,
    int? amountSat,
    Map<String, dynamic>? metadata,
  }) async {
    final operation = OperationState(
      id: generateOperationId(),
      type: type,
      destination: destination,
      amountSat: amountSat,
      status: OperationStatus.pending,
      startedAt: DateTime.now(),
      metadata: metadata,
    );

    _operations.add(operation);
    await _saveState();

    SecureLogger.operation(operation.id, 'created', details: type.name);
    return operation;
  }

  /// Update operation status to preparing (calling SDK prepare method)
  Future<void> markPreparing(String operationId) async {
    await _updateStatus(operationId, OperationStatus.preparing);
  }

  /// Update operation status to executing (calling SDK send/receive method)
  Future<void> markExecuting(String operationId) async {
    await _updateStatus(operationId, OperationStatus.executing);
  }

  /// Mark operation as successfully completed
  Future<void> markCompleted(String operationId, {String? txId}) async {
    final index = _operations.indexWhere((op) => op.id == operationId);
    if (index != -1) {
      _operations[index] = _operations[index].copyWith(
        status: OperationStatus.completed,
        completedAt: DateTime.now(),
        txId: txId,
      );
      await _saveState();
      SecureLogger.operation(operationId, 'completed');
    }
  }

  /// Mark operation as failed
  Future<void> markFailed(String operationId, String error) async {
    final index = _operations.indexWhere((op) => op.id == operationId);
    if (index != -1) {
      _operations[index] = _operations[index].copyWith(
        status: OperationStatus.failed,
        completedAt: DateTime.now(),
        error: error,
      );
      await _saveState();
      SecureLogger.operation(operationId, 'failed');
    }
  }

  /// Mark operation as unknown (interrupted, need to check)
  Future<void> markUnknown(String operationId) async {
    await _updateStatus(operationId, OperationStatus.unknown);
  }

  /// Get all incomplete operations (for resume on app start)
  List<OperationState> getIncompleteOperations() {
    return _operations.where((op) => op.isIncomplete).toList();
  }

  /// Get incomplete send operations specifically (highest risk)
  List<OperationState> getIncompleteSends() {
    return _operations
        .where((op) => op.isIncomplete && op.isSend)
        .toList();
  }

  /// Get operation by ID
  OperationState? getOperation(String operationId) {
    try {
      return _operations.firstWhere((op) => op.id == operationId);
    } catch (_) {
      return null;
    }
  }

  /// Get all operations (for history/debugging)
  List<OperationState> getAllOperations() => List.unmodifiable(_operations);

  /// Clear completed operations older than specified duration
  Future<void> cleanupOldOperations({
    Duration maxAge = const Duration(days: 7),
  }) async {
    final cutoff = DateTime.now().subtract(maxAge);
    _operations.removeWhere((op) =>
        !op.isIncomplete && op.completedAt != null && op.completedAt!.isBefore(cutoff));
    await _saveState();
  }

  /// Remove a specific operation (after user acknowledges)
  Future<void> removeOperation(String operationId) async {
    _operations.removeWhere((op) => op.id == operationId);
    await _saveState();
  }

  /// Clear all operations (for testing/reset)
  Future<void> clearAll() async {
    _operations.clear();
    await _saveState();
  }

  Future<void> _updateStatus(String operationId, OperationStatus status) async {
    final index = _operations.indexWhere((op) => op.id == operationId);
    if (index != -1) {
      _operations[index] = _operations[index].copyWith(status: status);
      await _saveState();
      SecureLogger.operation(operationId, status.name);
    }
  }

  Future<void> _loadState() async {
    try {
      final fileBytes = await _stateFile!.readAsBytes();
      final decrypted = await _decryptAesGcm(fileBytes);
      final content = utf8.decode(decrypted);
      final List<dynamic> jsonList = json.decode(content);
      _operations = jsonList
          .map((e) => OperationState.fromJson(e as Map<String, dynamic>))
          .toList();
      SecureLogger.info('Loaded ${_operations.length} operations (AES-256-GCM)', tag: 'OpState');
    } catch (e) {
      SecureLogger.error('Failed to load operation state', error: e, tag: 'OpState');
      _operations = [];
      // If decryption fails (corrupted or wrong key), delete the file
      try {
        await _stateFile!.delete();
      } catch (_) {}
    }
  }

  Future<void> _saveState() async {
    if (_stateFile == null || _secretKey == null) return;

    try {
      final jsonList = _operations.map((op) => op.toJson()).toList();
      final plaintext = utf8.encode(json.encode(jsonList));
      final encrypted = await _encryptAesGcm(plaintext);
      await _stateFile!.writeAsBytes(encrypted);
    } catch (e) {
      SecureLogger.error('Failed to save operation state', error: e, tag: 'OpState');
    }
  }

  /// Encrypt data using AES-256-GCM (authenticated encryption)
  /// Format: [12-byte nonce][ciphertext][16-byte auth tag]
  Future<List<int>> _encryptAesGcm(List<int> plaintext) async {
    // Generate random 96-bit nonce (recommended for GCM)
    final nonce = List.generate(12, (_) => _secureRandom.nextInt(256));

    final secretBox = await _cipher.encrypt(
      plaintext,
      secretKey: _secretKey!,
      nonce: nonce,
    );

    // Combine nonce + ciphertext + mac for storage
    return [...secretBox.nonce, ...secretBox.cipherText, ...secretBox.mac.bytes];
  }

  /// Decrypt AES-256-GCM encrypted data
  /// Throws if authentication fails (tampered data)
  Future<List<int>> _decryptAesGcm(List<int> ciphertext) async {
    if (ciphertext.length < 12 + 16) {
      throw Exception('Invalid encrypted data: too short');
    }

    // Extract components: [12-byte nonce][ciphertext][16-byte mac]
    final nonce = ciphertext.sublist(0, 12);
    final mac = Mac(ciphertext.sublist(ciphertext.length - 16));
    final encryptedData = ciphertext.sublist(12, ciphertext.length - 16);

    final secretBox = SecretBox(
      encryptedData,
      nonce: nonce,
      mac: mac,
    );

    // Decrypt and verify authentication tag
    return await _cipher.decrypt(
      secretBox,
      secretKey: _secretKey!,
    );
  }
}
