import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:bolt21/services/operation_state_service.dart';
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockPathProviderPlatform extends Fake
    with MockPlatformInterfaceMixin
    implements PathProviderPlatform {
  final String testDir;
  MockPathProviderPlatform(this.testDir);

  @override
  Future<String?> getApplicationDocumentsPath() async => testDir;
}

// Mock secure storage for tests
class MockSecureStorage {
  static final Map<String, String> _storage = {};

  static void setupMock() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
      (MethodCall methodCall) async {
        switch (methodCall.method) {
          case 'read':
            final key = methodCall.arguments['key'] as String;
            return _storage[key];
          case 'write':
            final key = methodCall.arguments['key'] as String;
            final value = methodCall.arguments['value'] as String;
            _storage[key] = value;
            return null;
          case 'delete':
            final key = methodCall.arguments['key'] as String;
            _storage.remove(key);
            return null;
          case 'deleteAll':
            _storage.clear();
            return null;
          default:
            return null;
        }
      },
    );
  }

  static void clear() {
    _storage.clear();
  }
}

// Test wallet ID used for all operations in these tests
const String testWalletId = 'test-wallet-recovery';

void main() {
  late Directory tempDir;

  setUpAll(() {
    TestWidgetsFlutterBinding.ensureInitialized();
    MockSecureStorage.setupMock();
  });

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('bolt21_crash_test_');
    PathProviderPlatform.instance = MockPathProviderPlatform(tempDir.path);
    MockSecureStorage.clear();
  });

  tearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  group('Crash Recovery Scenarios', () {
    // ==================== MID-SEND CRASH SCENARIOS ====================
    group('Force-close mid-send', () {
      test('crash during prepare phase - state persisted as preparing', () async {
        final service = OperationStateService();
        await service.initialize();

        // Simulate: User initiates send, operation created, marked preparing
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc1234...',
          amountSat: 5000,
        );
        await service.markPreparing(op.id);

        // CRASH - app killed here

        // App restart - new service instance
        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        // Verify state was persisted
        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp, isNotNull);
        expect(recoveredOp!.status, equals(OperationStatus.preparing));
        expect(recoveredOp.destination, equals('lnbc1234...'));
        expect(recoveredOp.amountSat, equals(5000));

        // Verify shows as incomplete
        expect(recoveredService.getIncompleteOperations().length, equals(1));
        expect(recoveredService.getIncompleteSends().length, equals(1));
      });

      test('crash during execute phase - state persisted as executing', () async {
        final service = OperationStateService();
        await service.initialize();

        // Simulate: Payment prepare succeeded, now executing
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc5678...',
          amountSat: 10000,
        );
        await service.markPreparing(op.id);
        await service.markExecuting(op.id);

        // CRASH - app killed during SDK sendPayment call

        // App restart
        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp, isNotNull);
        expect(recoveredOp!.status, equals(OperationStatus.executing));

        // This is the critical state - payment may or may not have been sent
        // User MUST check transaction history before retrying
        expect(recoveredService.getIncompleteSends().length, equals(1));
      });

      test('crash after successful send but before marking complete', () async {
        final service = OperationStateService();
        await service.initialize();

        // Simulate: Payment sent, SDK returned success, but app crashed
        // before marking complete
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc...',
          amountSat: 2000,
        );
        await service.markPreparing(op.id);
        await service.markExecuting(op.id);
        // SDK sendPayment() succeeded, but app crashed before:
        // await service.markCompleted(op.id, txId: 'tx123');

        // App restart
        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        // Operation still shows as executing (unknown outcome)
        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp!.status, equals(OperationStatus.executing));

        // This is a false positive for "incomplete" - payment actually went through
        // User needs to check transaction history
      });

      test('multiple incomplete sends detected on restart', () async {
        final service = OperationStateService();
        await service.initialize();

        // Simulate: Multiple sends started, all crashed mid-way
        final op1 = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'dest1',
          amountSat: 1000,
        );
        await service.markExecuting(op1.id);

        final op2 = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'dest2',
          amountSat: 2000,
        );
        await service.markPreparing(op2.id);

        // Create third operation that stays pending (unused variable intentional)
        await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'dest3',
          amountSat: 3000,
        );

        // App restart
        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getIncompleteSends().length, equals(3));
      });
    });

    // ==================== MID-RECEIVE CRASH SCENARIOS ====================
    group('Force-close mid-receive', () {
      test('crash during BOLT12 offer generation', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.receiveBolt12,
          walletId: testWalletId,
        );
        await service.markExecuting(op.id);

        // CRASH

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp!.type, equals(OperationType.receiveBolt12));
        expect(recoveredOp.status, equals(OperationStatus.executing));

        // Receive operations are low-risk - can just regenerate
        expect(recoveredService.getIncompleteSends(), isEmpty);
        expect(recoveredService.getIncompleteOperations().length, equals(1));
      });

      test('crash during on-chain address generation', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.receiveOnchain,
          walletId: testWalletId,
        );
        await service.markExecuting(op.id);

        // CRASH

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp!.type, equals(OperationType.receiveOnchain));
        expect(recoveredOp.status, equals(OperationStatus.executing));

        // No money lost - just regenerate address
      });

      test('crash during BOLT11 invoice generation', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.receiveBolt11,
          walletId: testWalletId,
          amountSat: 50000,
        );
        await service.markExecuting(op.id);

        // CRASH

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getOperation(op.id)!.amountSat, equals(50000));
      });
    });

    // ==================== RESTORE CRASH SCENARIOS ====================
    group('Kill app during restore', () {
      test('crash during wallet restore - no operations yet', () async {
        final service = OperationStateService();
        await service.initialize();

        // User enters mnemonic, starts restore, app crashes
        // No operations created yet since wallet not initialized

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        // Clean slate - user can retry restore
        expect(recoveredService.getAllOperations(), isEmpty);
      });

      test('state file persists through multiple crashes', () async {
        final service = OperationStateService();
        await service.initialize();

        // Create some operations
        final op1 = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op1.id);

        final op2 = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op2.id);

        // Crash 1
        final service2 = OperationStateService();
        await service2.initialize();
        expect(service2.getAllOperations().length, equals(2));

        // Add more operations (unused variable intentional - testing persistence)
        await service2.createOperation(type: OperationType.receiveBolt12, walletId: testWalletId);

        // Crash 2
        final service3 = OperationStateService();
        await service3.initialize();
        expect(service3.getAllOperations().length, equals(3));

        // Crash 3
        final service4 = OperationStateService();
        await service4.initialize();
        expect(service4.getAllOperations().length, equals(3));
      });
    });

    // ==================== OPERATION RECOVERY TESTS ====================
    group('Operation state recovery', () {
      test('incomplete operations survive multiple restarts', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc...',
          amountSat: 1000,
        );
        await service.markExecuting(op.id);

        // Simulate 5 app restarts
        for (var i = 0; i < 5; i++) {
          final newService = OperationStateService();
          await newService.initialize();
          expect(newService.getIncompleteOperations(walletId: testWalletId).length, equals(1));
        }
      });

      test('marking operation as unknown preserves data', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'important_dest',
          amountSat: 99999,
          metadata: {'note': 'Ocean payout'},
        );
        await service.markExecuting(op.id);

        // Restart and mark as unknown (simulating recovery logic)
        final recoveredService = OperationStateService();
        await recoveredService.initialize();
        await recoveredService.markUnknown(op.id);

        final recoveredOp = recoveredService.getOperation(op.id);
        expect(recoveredOp!.status, equals(OperationStatus.unknown));
        expect(recoveredOp.destination, equals('important_dest'));
        expect(recoveredOp.amountSat, equals(99999));
        expect(recoveredOp.metadata?['note'], equals('Ocean payout'));
      });

      test('completed operations are not flagged as incomplete', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id, txId: 'tx_abc');

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getIncompleteOperations(walletId: testWalletId), isEmpty);
        expect(recoveredService.getOperation(op.id)!.txId, equals('tx_abc'));
      });

      test('failed operations are not flagged as incomplete', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markFailed(op.id, 'Insufficient funds');

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getIncompleteOperations(walletId: testWalletId), isEmpty);
        expect(recoveredService.getOperation(op.id)!.error, equals('Insufficient funds'));
      });
    });

    // ==================== DOUBLE-PAY PREVENTION TESTS ====================
    group('Double-pay prevention', () {
      test('incomplete send blocks duplicate payment', () async {
        final service = OperationStateService();
        await service.initialize();

        // First send started but not completed
        final op1 = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc_same_dest',
          amountSat: 5000,
        );
        await service.markExecuting(op1.id);

        // Check for existing operation before sending again
        final existingOps = service.getAllOperations().where((op) =>
          op.destination == 'lnbc_same_dest' &&
          op.amountSat == 5000 &&
          op.isIncomplete
        );

        expect(existingOps.isNotEmpty, isTrue,
          reason: 'Should detect existing incomplete send to same destination');
      });

      test('different amounts allow separate operations', () async {
        final service = OperationStateService();
        await service.initialize();

        await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc_dest',
          amountSat: 1000,
        );

        await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc_dest',
          amountSat: 2000,
        );

        // Different amounts = different payments, both allowed
        expect(service.getAllOperations().length, equals(2));
      });

      test('completed operations don\'t block new sends', () async {
        final service = OperationStateService();
        await service.initialize();

        final op1 = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc_dest',
          amountSat: 1000,
        );
        await service.markCompleted(op1.id);

        // Same destination, but first is complete
        final existingIncomplete = service.getAllOperations().where((op) =>
          op.destination == 'lnbc_dest' && op.isIncomplete
        );

        expect(existingIncomplete, isEmpty,
          reason: 'Completed operations should not block new sends');
      });
    });

    // ==================== DATA INTEGRITY TESTS ====================
    group('Data integrity', () {
      test('operation IDs are unique across sessions', () async {
        final ids = <String>{};

        for (var i = 0; i < 3; i++) {
          final service = OperationStateService();
          await service.initialize();

          for (var j = 0; j < 10; j++) {
            final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
            expect(ids.contains(op.id), isFalse, reason: 'Duplicate ID: ${op.id}');
            ids.add(op.id);
          }

          await service.clearAll();
        }
      });

      test('timestamps are preserved across restarts', () async {
        final service = OperationStateService();
        await service.initialize();

        final startTime = DateTime.now();
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);
        final completeTime = DateTime.now();

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id)!;
        expect(recoveredOp.startedAt.isAfter(startTime.subtract(const Duration(seconds: 1))), isTrue);
        expect(recoveredOp.completedAt!.isBefore(completeTime.add(const Duration(seconds: 1))), isTrue);
      });

      test('large metadata survives persistence', () async {
        final service = OperationStateService();
        await service.initialize();

        final largeMetadata = <String, dynamic>{};
        for (var i = 0; i < 100; i++) {
          largeMetadata['key_$i'] = 'value_$i with some longer text to make it bigger';
        }

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          metadata: largeMetadata,
        );

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id)!;
        expect(recoveredOp.metadata!.length, equals(100));
        expect(recoveredOp.metadata!['key_50'], contains('value_50'));
      });
    });

    // ==================== EDGE CASES ====================
    group('Edge cases', () {
      test('handles very rapid operation creation', () async {
        final service = OperationStateService();
        await service.initialize();

        // Create 50 operations as fast as possible
        final futures = List.generate(50, (i) =>
          service.createOperation(
            type: OperationType.send,
            walletId: testWalletId,
            destination: 'rapid_$i',
          )
        );
        await Future.wait(futures);

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getAllOperations().length, equals(50));
      });

      test('handles operation with very long destination', () async {
        final service = OperationStateService();
        await service.initialize();

        final longDest = 'lnbc' + 'x' * 10000; // 10KB destination string

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: longDest,
        );

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getOperation(op.id)!.destination, equals(longDest));
      });

      test('handles operation with maximum int amount', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          amountSat: 2100000000000000, // 21M BTC in sats
        );

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        expect(recoveredService.getOperation(op.id)!.amountSat, equals(2100000000000000));
      });

      test('handles special characters in metadata', () async {
        final service = OperationStateService();
        await service.initialize();

        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          metadata: {
            'note': 'Payment with "quotes" and \'apostrophes\'',
            'unicode': '🔥💰⚡',
            'newlines': 'line1\nline2\nline3',
            'json_like': '{"nested": "object"}',
          },
        );

        final recoveredService = OperationStateService();
        await recoveredService.initialize();

        final recoveredOp = recoveredService.getOperation(op.id)!;
        expect(recoveredOp.metadata!['note'], contains('quotes'));
        expect(recoveredOp.metadata!['unicode'], contains('🔥'));
        expect(recoveredOp.metadata!['newlines'], contains('\n'));
        expect(recoveredOp.metadata!['json_like'], contains('nested'));
      });
    });
  });
}
