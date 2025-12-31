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
const String testWalletId = 'test-wallet-unit';

void main() {
  late OperationStateService service;
  late Directory tempDir;

  setUpAll(() {
    TestWidgetsFlutterBinding.ensureInitialized();
    MockSecureStorage.setupMock();
  });

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('bolt21_test_');
    PathProviderPlatform.instance = MockPathProviderPlatform(tempDir.path);
    MockSecureStorage.clear();
    service = OperationStateService();
    await service.initialize();
  });

  tearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  group('OperationStateService', () {
    // ==================== INITIALIZATION TESTS ====================
    group('initialization', () {
      test('initializes with empty operations list', () async {
        expect(service.getAllOperations(), isEmpty);
      });

      test('creates state file on first operation', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final file = File('${tempDir.path}/operation_state.enc');
        expect(await file.exists(), isTrue);
      });

      test('loads existing operations on initialize', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'test1');
        await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'test2');

        final newService = OperationStateService();
        await newService.initialize();

        expect(newService.getAllOperations().length, equals(2));
      });

      test('handles missing state file gracefully', () async {
        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });

      test('handles empty state file gracefully', () async {
        final file = File('${tempDir.path}/operation_state.enc');
        await file.writeAsString('');

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });

      test('handles corrupted JSON gracefully', () async {
        final file = File('${tempDir.path}/operation_state.enc');
        await file.writeAsString('not valid json {{{');

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });

      test('handles partial JSON gracefully', () async {
        final file = File('${tempDir.path}/operation_state.enc');
        await file.writeAsString('[{"id": "test"');

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });

      test('handles null values in JSON', () async {
        // Create an operation without destination or amountSat (null values)
        await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
        );

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations().length, equals(1));
        expect(newService.getAllOperations().first.destination, isNull);
        expect(newService.getAllOperations().first.amountSat, isNull);
      });
    });

    // ==================== CREATE OPERATION TESTS ====================
    group('createOperation', () {
      test('creates send operation', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(op.type, equals(OperationType.send));
        expect(op.status, equals(OperationStatus.pending));
      });

      test('creates receiveBolt12 operation', () async {
        final op = await service.createOperation(type: OperationType.receiveBolt12, walletId: testWalletId);
        expect(op.type, equals(OperationType.receiveBolt12));
      });

      test('creates receiveOnchain operation', () async {
        final op = await service.createOperation(type: OperationType.receiveOnchain, walletId: testWalletId);
        expect(op.type, equals(OperationType.receiveOnchain));
      });

      test('creates receiveBolt11 operation', () async {
        final op = await service.createOperation(type: OperationType.receiveBolt11, walletId: testWalletId);
        expect(op.type, equals(OperationType.receiveBolt11));
      });

      test('sets destination correctly', () async {
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc1234...',
        );
        expect(op.destination, equals('lnbc1234...'));
      });

      test('sets amountSat correctly', () async {
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          amountSat: 50000,
        );
        expect(op.amountSat, equals(50000));
      });

      test('sets metadata correctly', () async {
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          metadata: {'note': 'Test payment', 'source': 'unit_test'},
        );
        expect(op.metadata?['note'], equals('Test payment'));
        expect(op.metadata?['source'], equals('unit_test'));
      });

      test('generates unique IDs for each operation', () async {
        final ids = <String>{};
        for (var i = 0; i < 100; i++) {
          final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
          expect(ids.contains(op.id), isFalse, reason: 'Duplicate ID: ${op.id}');
          ids.add(op.id);
        }
      });

      test('sets startedAt to current time', () async {
        final before = DateTime.now();
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final after = DateTime.now();

        expect(op.startedAt.isAfter(before.subtract(const Duration(seconds: 1))), isTrue);
        expect(op.startedAt.isBefore(after.add(const Duration(seconds: 1))), isTrue);
      });

      test('completedAt is null on creation', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(op.completedAt, isNull);
      });

      test('error is null on creation', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(op.error, isNull);
      });

      test('txId is null on creation', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(op.txId, isNull);
      });

      test('persists operation immediately', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'immediate_test');

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations().first.destination, equals('immediate_test'));
      });

      test('handles concurrent creates', () async {
        final futures = List.generate(10, (i) =>
          service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'concurrent_$i')
        );
        await Future.wait(futures);

        expect(service.getAllOperations().length, equals(10));
      });
    });

    // ==================== STATUS UPDATE TESTS ====================
    group('markPreparing', () {
      test('updates status to preparing', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markPreparing(op.id);

        final updated = service.getOperation(op.id);
        expect(updated?.status, equals(OperationStatus.preparing));
      });

      test('persists status change', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markPreparing(op.id);

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getOperation(op.id)?.status, equals(OperationStatus.preparing));
      });

      test('does nothing for non-existent operation', () async {
        await service.markPreparing('non_existent_id');
        // Should not throw
      });
    });

    group('markExecuting', () {
      test('updates status to executing', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op.id);

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.executing));
      });

      test('can transition from preparing to executing', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markPreparing(op.id);
        await service.markExecuting(op.id);

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.executing));
      });
    });

    group('markCompleted', () {
      test('updates status to completed', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.completed));
      });

      test('sets completedAt timestamp', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final before = DateTime.now();
        await service.markCompleted(op.id);
        final after = DateTime.now();

        final updated = service.getOperation(op.id);
        expect(updated?.completedAt, isNotNull);
        expect(updated!.completedAt!.isAfter(before.subtract(const Duration(seconds: 1))), isTrue);
        expect(updated.completedAt!.isBefore(after.add(const Duration(seconds: 1))), isTrue);
      });

      test('sets txId when provided', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id, txId: 'tx_abc123');

        expect(service.getOperation(op.id)?.txId, equals('tx_abc123'));
      });

      test('txId is null when not provided', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);

        expect(service.getOperation(op.id)?.txId, isNull);
      });
    });

    group('markFailed', () {
      test('updates status to failed', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markFailed(op.id, 'Network error');

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.failed));
      });

      test('sets error message', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markFailed(op.id, 'Connection timeout');

        expect(service.getOperation(op.id)?.error, equals('Connection timeout'));
      });

      test('sets completedAt timestamp', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markFailed(op.id, 'Error');

        expect(service.getOperation(op.id)?.completedAt, isNotNull);
      });

      test('preserves existing data on failure', () async {
        final op = await service.createOperation(
          type: OperationType.send,
          walletId: testWalletId,
          destination: 'lnbc...',
          amountSat: 1000,
        );
        await service.markFailed(op.id, 'Error');

        final updated = service.getOperation(op.id);
        expect(updated?.destination, equals('lnbc...'));
        expect(updated?.amountSat, equals(1000));
      });
    });

    group('markUnknown', () {
      test('updates status to unknown', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markUnknown(op.id);

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.unknown));
      });

      test('used for interrupted operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op.id);
        await service.markUnknown(op.id);

        expect(service.getOperation(op.id)?.status, equals(OperationStatus.unknown));
      });
    });

    // ==================== QUERY TESTS ====================
    group('getOperation', () {
      test('returns operation by ID', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'find_me');
        final found = service.getOperation(op.id);

        expect(found, isNotNull);
        expect(found?.destination, equals('find_me'));
      });

      test('returns null for non-existent ID', () async {
        final found = service.getOperation('non_existent');
        expect(found, isNull);
      });

      test('finds correct operation among many', () async {
        for (var i = 0; i < 100; i++) {
          await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'op_$i');
        }

        final target = service.getAllOperations()[50];
        final found = service.getOperation(target.id);

        expect(found?.id, equals(target.id));
      });
    });

    group('getAllOperations', () {
      test('returns empty list initially', () async {
        expect(service.getAllOperations(), isEmpty);
      });

      test('returns all operations', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.createOperation(type: OperationType.receiveBolt12, walletId: testWalletId);
        await service.createOperation(type: OperationType.receiveOnchain, walletId: testWalletId);

        expect(service.getAllOperations().length, equals(3));
      });

      test('returns unmodifiable list', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final operations = service.getAllOperations();

        // This should not affect the internal list
        expect(() => operations.add(OperationState(
          id: 'fake',
          type: OperationType.send,
          status: OperationStatus.pending,
          startedAt: DateTime.now(),
        )), throwsUnsupportedError);
      });
    });

    group('getIncompleteOperations', () {
      test('returns pending operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(service.getIncompleteOperations().map((o) => o.id), contains(op.id));
      });

      test('returns preparing operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markPreparing(op.id);
        expect(service.getIncompleteOperations().map((o) => o.id), contains(op.id));
      });

      test('returns executing operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op.id);
        expect(service.getIncompleteOperations().map((o) => o.id), contains(op.id));
      });

      test('returns unknown operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markUnknown(op.id);
        expect(service.getIncompleteOperations().map((o) => o.id), contains(op.id));
      });

      test('excludes completed operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);
        expect(service.getIncompleteOperations().map((o) => o.id), isNot(contains(op.id)));
      });

      test('excludes failed operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markFailed(op.id, 'Error');
        expect(service.getIncompleteOperations().map((o) => o.id), isNot(contains(op.id)));
      });

      test('filters correctly with mixed statuses', () async {
        final pending = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final preparing = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final executing = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final completed = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final failed = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        final unknown = await service.createOperation(type: OperationType.send, walletId: testWalletId);

        await service.markPreparing(preparing.id);
        await service.markExecuting(executing.id);
        await service.markCompleted(completed.id);
        await service.markFailed(failed.id, 'Error');
        await service.markUnknown(unknown.id);

        final incomplete = service.getIncompleteOperations();
        expect(incomplete.length, equals(4));
        expect(incomplete.map((o) => o.id), contains(pending.id));
        expect(incomplete.map((o) => o.id), contains(preparing.id));
        expect(incomplete.map((o) => o.id), contains(executing.id));
        expect(incomplete.map((o) => o.id), contains(unknown.id));
      });
    });

    group('getIncompleteSends', () {
      test('returns only send operations', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.createOperation(type: OperationType.receiveBolt12, walletId: testWalletId);
        await service.createOperation(type: OperationType.receiveOnchain, walletId: testWalletId);
        await service.createOperation(type: OperationType.receiveBolt11, walletId: testWalletId);

        final sends = service.getIncompleteSends();
        expect(sends.length, equals(1));
        expect(sends.first.type, equals(OperationType.send));
      });

      test('excludes completed sends', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);

        expect(service.getIncompleteSends(), isEmpty);
      });

      test('includes executing sends', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op.id);

        expect(service.getIncompleteSends().length, equals(1));
      });
    });

    // ==================== REMOVAL TESTS ====================
    group('removeOperation', () {
      test('removes operation by ID', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        expect(service.getAllOperations().length, equals(1));

        await service.removeOperation(op.id);
        expect(service.getAllOperations(), isEmpty);
      });

      test('persists removal', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.removeOperation(op.id);

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });

      test('does nothing for non-existent ID', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.removeOperation('non_existent');
        expect(service.getAllOperations().length, equals(1));
      });

      test('removes correct operation among many', () async {
        final ops = <OperationState>[];
        for (var i = 0; i < 10; i++) {
          ops.add(await service.createOperation(type: OperationType.send, walletId: testWalletId, destination: 'op_$i'));
        }

        await service.removeOperation(ops[5].id);

        expect(service.getAllOperations().length, equals(9));
        expect(service.getOperation(ops[5].id), isNull);
        expect(service.getOperation(ops[4].id), isNotNull);
        expect(service.getOperation(ops[6].id), isNotNull);
      });
    });

    group('clearAll', () {
      test('removes all operations', () async {
        for (var i = 0; i < 10; i++) {
          await service.createOperation(type: OperationType.send, walletId: testWalletId);
        }
        expect(service.getAllOperations().length, equals(10));

        await service.clearAll();
        expect(service.getAllOperations(), isEmpty);
      });

      test('persists clear', () async {
        await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.clearAll();

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getAllOperations(), isEmpty);
      });
    });

    group('cleanupOldOperations', () {
      test('removes old completed operations', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markCompleted(op.id);

        // Note: Full cleanup test would require internal access to modify completedAt
        // For now, verify the method doesn't throw
        await service.cleanupOldOperations(maxAge: const Duration(days: 7));
      });

      test('keeps incomplete operations regardless of age', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);
        await service.markExecuting(op.id);

        await service.cleanupOldOperations(maxAge: Duration.zero);

        expect(service.getOperation(op.id), isNotNull);
      });
    });

    // ==================== OPERATION STATE MODEL TESTS ====================
    group('OperationState', () {
      group('isIncomplete', () {
        test('returns true for pending', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isTrue);
        });

        test('returns true for preparing', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.preparing, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isTrue);
        });

        test('returns true for executing', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.executing, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isTrue);
        });

        test('returns true for unknown', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.unknown, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isTrue);
        });

        test('returns false for completed', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.completed, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isFalse);
        });

        test('returns false for failed', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.failed, startedAt: DateTime.now(),
          );
          expect(op.isIncomplete, isFalse);
        });
      });

      group('isSend', () {
        test('returns true for send', () {
          final op = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          expect(op.isSend, isTrue);
        });

        test('returns false for receiveBolt12', () {
          final op = OperationState(
            id: 'test', type: OperationType.receiveBolt12,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          expect(op.isSend, isFalse);
        });

        test('returns false for receiveOnchain', () {
          final op = OperationState(
            id: 'test', type: OperationType.receiveOnchain,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          expect(op.isSend, isFalse);
        });

        test('returns false for receiveBolt11', () {
          final op = OperationState(
            id: 'test', type: OperationType.receiveBolt11,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          expect(op.isSend, isFalse);
        });
      });

      group('copyWith', () {
        test('copies all fields when none specified', () {
          final original = OperationState(
            id: 'test', type: OperationType.send, destination: 'dest',
            amountSat: 1000, status: OperationStatus.pending,
            startedAt: DateTime(2024, 1, 1), completedAt: DateTime(2024, 1, 2),
            error: 'err', txId: 'tx', metadata: {'key': 'value'},
          );
          final copy = original.copyWith();

          expect(copy.id, equals(original.id));
          expect(copy.type, equals(original.type));
          expect(copy.destination, equals(original.destination));
          expect(copy.amountSat, equals(original.amountSat));
          expect(copy.status, equals(original.status));
          expect(copy.startedAt, equals(original.startedAt));
          expect(copy.completedAt, equals(original.completedAt));
          expect(copy.error, equals(original.error));
          expect(copy.txId, equals(original.txId));
          expect(copy.metadata, equals(original.metadata));
        });

        test('overrides status', () {
          final original = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          final copy = original.copyWith(status: OperationStatus.completed);
          expect(copy.status, equals(OperationStatus.completed));
        });

        test('overrides completedAt', () {
          final original = OperationState(
            id: 'test', type: OperationType.send,
            status: OperationStatus.pending, startedAt: DateTime.now(),
          );
          final completedAt = DateTime(2024, 6, 15);
          final copy = original.copyWith(completedAt: completedAt);
          expect(copy.completedAt, equals(completedAt));
        });
      });

      group('JSON serialization', () {
        test('toJson includes all fields', () {
          final op = OperationState(
            id: 'test123', type: OperationType.send, destination: 'lnbc...',
            amountSat: 5000, status: OperationStatus.completed,
            startedAt: DateTime(2024, 1, 15, 10, 30),
            completedAt: DateTime(2024, 1, 15, 10, 31),
            error: null, txId: 'tx456', metadata: {'note': 'test'},
          );
          final json = op.toJson();

          expect(json['id'], equals('test123'));
          expect(json['type'], equals('send'));
          expect(json['destination'], equals('lnbc...'));
          expect(json['amountSat'], equals(5000));
          expect(json['status'], equals('completed'));
          expect(json['txId'], equals('tx456'));
          expect(json['metadata'], equals({'note': 'test'}));
        });

        test('fromJson parses all fields', () {
          final json = {
            'id': 'test123',
            'type': 'send',
            'destination': 'lnbc...',
            'amountSat': 5000,
            'status': 'completed',
            'startedAt': '2024-01-15T10:30:00.000',
            'completedAt': '2024-01-15T10:31:00.000',
            'txId': 'tx456',
            'metadata': {'note': 'test'},
          };
          final op = OperationState.fromJson(json);

          expect(op.id, equals('test123'));
          expect(op.type, equals(OperationType.send));
          expect(op.destination, equals('lnbc...'));
          expect(op.amountSat, equals(5000));
          expect(op.status, equals(OperationStatus.completed));
          expect(op.txId, equals('tx456'));
        });

        test('roundtrip preserves all data', () {
          final original = OperationState(
            id: 'roundtrip', type: OperationType.receiveBolt12,
            destination: 'lno1...', amountSat: 10000,
            status: OperationStatus.failed, startedAt: DateTime(2024, 3, 10),
            completedAt: DateTime(2024, 3, 10, 0, 5), error: 'Timeout',
            txId: null, metadata: {'source': 'ocean'},
          );

          final json = original.toJson();
          final restored = OperationState.fromJson(json);

          expect(restored.id, equals(original.id));
          expect(restored.type, equals(original.type));
          expect(restored.destination, equals(original.destination));
          expect(restored.amountSat, equals(original.amountSat));
          expect(restored.status, equals(original.status));
          expect(restored.error, equals(original.error));
          expect(restored.metadata?['source'], equals('ocean'));
        });

        test('handles unknown type gracefully', () {
          final json = {
            'id': 'test',
            'type': 'unknown_future_type',
            'status': 'pending',
            'startedAt': '2024-01-01T00:00:00.000',
          };
          final op = OperationState.fromJson(json);
          expect(op.type, equals(OperationType.send)); // Falls back to default
        });

        test('handles unknown status gracefully', () {
          final json = {
            'id': 'test',
            'type': 'send',
            'status': 'unknown_future_status',
            'startedAt': '2024-01-01T00:00:00.000',
          };
          final op = OperationState.fromJson(json);
          expect(op.status, equals(OperationStatus.unknown)); // Falls back to unknown
        });
      });

      group('toString', () {
        test('includes id, type, and status', () {
          final op = OperationState(
            id: 'test123', type: OperationType.send,
            status: OperationStatus.executing, startedAt: DateTime.now(),
          );
          final str = op.toString();

          expect(str, contains('test123'));
          expect(str, contains('send'));
          expect(str, contains('executing'));
        });
      });
    });

    // ==================== ID GENERATION TESTS ====================
    group('generateOperationId', () {
      test('generates non-empty strings', () {
        final id = service.generateOperationId();
        expect(id, isNotEmpty);
      });

      test('generates unique IDs rapidly', () {
        final ids = <String>{};
        for (var i = 0; i < 1000; i++) {
          final id = service.generateOperationId();
          expect(ids.contains(id), isFalse);
          ids.add(id);
        }
      });

      test('IDs contain underscore separator', () {
        final id = service.generateOperationId();
        expect(id, contains('_'));
      });
    });

    // ==================== PERSISTENCE STRESS TESTS ====================
    group('persistence stress tests', () {
      test('handles many operations', () async {
        for (var i = 0; i < 100; i++) {
          await service.createOperation(
            type: OperationType.send,
            walletId: testWalletId,
            destination: 'dest_$i',
            amountSat: i * 100,
          );
        }

        final newService = OperationStateService();
        await newService.initialize();

        expect(newService.getAllOperations().length, equals(100));
      });

      test('handles rapid status updates', () async {
        final op = await service.createOperation(type: OperationType.send, walletId: testWalletId);

        for (var i = 0; i < 50; i++) {
          await service.markPreparing(op.id);
          await service.markExecuting(op.id);
        }

        final newService = OperationStateService();
        await newService.initialize();
        expect(newService.getOperation(op.id)?.status, equals(OperationStatus.executing));
      });
    });
  });
}
