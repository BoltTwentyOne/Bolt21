# Security Fix Implementation Guide
**For Developers** | Quick Reference

---

## 🔴 CRITICAL FIX #1: Integer Overflow Protection

**File:** `lib/services/lnd_service.dart`
**Time:** 4 hours
**Priority:** P0 (MUST FIX BEFORE LAUNCH)

### Step 1: Add Helper Function

Add this to `lib/services/lnd_service.dart` after the class definition:

```dart
/// SECURITY: Safe satoshi parsing with bounds checking
/// Prevents integer overflow and negative values
int parseSatoshis(String value, {String context = 'value'}) {
  final parsed = int.tryParse(value);

  if (parsed == null) {
    throw LndApiException('Invalid $context: "$value" is not a valid integer');
  }

  // Bitcoin max supply: 21M BTC = 2,100,000,000,000,000 sats
  const maxSatoshis = 2100000000000000;

  if (parsed < 0) {
    throw LndApiException('Invalid $context: $parsed (negative values not allowed)');
  }

  if (parsed > maxSatoshis) {
    throw LndApiException('Invalid $context: $parsed exceeds max supply (${maxSatoshis} sats)');
  }

  return parsed;
}
```

### Step 2: Replace All `int.parse()` Calls

**Location 1: Line 60-65 (getBalance)**
```dart
// BEFORE:
return LndBalance(
  onChainConfirmed: int.parse(walletBalance['confirmed_balance'] ?? '0'),
  onChainUnconfirmed: int.parse(walletBalance['unconfirmed_balance'] ?? '0'),
  channelLocal: int.parse(channelBalance['local_balance']?['sat'] ?? '0'),
  channelRemote: int.parse(channelBalance['remote_balance']?['sat'] ?? '0'),
  channelPending: int.parse(channelBalance['pending_open_local_balance']?['sat'] ?? '0'),
);

// AFTER:
return LndBalance(
  onChainConfirmed: parseSatoshis(walletBalance['confirmed_balance'] ?? '0', context: 'on-chain confirmed'),
  onChainUnconfirmed: parseSatoshis(walletBalance['unconfirmed_balance'] ?? '0', context: 'on-chain unconfirmed'),
  channelLocal: parseSatoshis(channelBalance['local_balance']?['sat'] ?? '0', context: 'channel local'),
  channelRemote: parseSatoshis(channelBalance['remote_balance']?['sat'] ?? '0', context: 'channel remote'),
  channelPending: parseSatoshis(channelBalance['pending_open_local_balance']?['sat'] ?? '0', context: 'channel pending'),
);
```

**Location 2: Line 113-114 (payInvoice)**
```dart
// BEFORE:
feeSat: int.parse(response['payment_route']?['total_fees'] ?? '0'),
amountSat: int.parse(response['payment_route']?['total_amt'] ?? '0'),

// AFTER:
feeSat: parseSatoshis(response['payment_route']?['total_fees'] ?? '0', context: 'fee'),
amountSat: parseSatoshis(response['payment_route']?['total_amt'] ?? '0', context: 'amount'),
```

**Location 3: Line 125-128 (decodeInvoice)**
```dart
// BEFORE:
amountSat: int.parse(response['num_satoshis'] ?? '0'),
expiry: int.parse(response['expiry'] ?? '3600'),
timestamp: int.parse(response['timestamp'] ?? '0'),

// AFTER:
amountSat: parseSatoshis(response['num_satoshis'] ?? '0', context: 'invoice amount'),
expiry: int.parse(response['expiry'] ?? '3600'),  // Not a satoshi value - leave as is
timestamp: int.parse(response['timestamp'] ?? '0'),  // Not a satoshi value - leave as is
```

**Location 4: Line 299-301 (LndInvoice.fromJson)**
```dart
// BEFORE:
amountSat: int.parse(json['value_sat'] ?? '0'),
feeSat: int.parse(json['fee_sat'] ?? '0'),

// AFTER:
amountSat: parseSatoshis(json['value_sat'] ?? '0', context: 'invoice amount'),
feeSat: parseSatoshis(json['fee_sat'] ?? '0', context: 'invoice fee'),
```

**Location 5: Line 332-335 (LndPayment.fromJson)**
```dart
// BEFORE:
amountSat: int.parse(json['value'] ?? '0'),
amountPaidSat: int.parse(json['amt_paid_sat'] ?? '0'),

// AFTER:
amountSat: parseSatoshis(json['value'] ?? '0', context: 'payment amount'),
amountPaidSat: parseSatoshis(json['amt_paid_sat'] ?? '0', context: 'amount paid'),
```

### Step 3: Add Tests

Add to `test/unit/services/lnd_service_test.dart`:

```dart
group('parseSatoshis security', () {
  test('rejects negative values', () {
    expect(
      () => parseSatoshis('-100'),
      throwsA(isA<LndApiException>()),
    );
  });

  test('rejects values exceeding max supply', () {
    expect(
      () => parseSatoshis('9223372036854775807'),  // int64 max
      throwsA(isA<LndApiException>()),
    );
  });

  test('rejects invalid format', () {
    expect(
      () => parseSatoshis('abc123'),
      throwsA(isA<LndApiException>()),
    );
  });

  test('accepts valid values', () {
    expect(parseSatoshis('0'), equals(0));
    expect(parseSatoshis('1000'), equals(1000));
    expect(parseSatoshis('2100000000000000'), equals(2100000000000000));
  });
});
```

---

## 🔴 CRITICAL FIX #2: Defensive JSON Parsing

**Files:** `lib/services/lnd_service.dart`, `lib/services/community_node_service.dart`
**Time:** 6 hours
**Priority:** P0 (MUST FIX BEFORE LAUNCH)

### Step 1: Add Safe Parsing Wrapper

Add to `lib/services/lnd_service.dart`:

```dart
/// SECURITY: Defensive JSON parsing with comprehensive error handling
/// Prevents app crashes from malformed API responses
T safeParse<T>(
  String jsonString,
  T Function(Map<String, dynamic>) parser, {
  required String source,
}) {
  try {
    // Attempt to decode JSON
    final decoded = jsonDecode(jsonString);

    // Validate it's a JSON object (not array, string, etc.)
    if (decoded is! Map<String, dynamic>) {
      throw LndApiException(
        '$source: Expected JSON object, got ${decoded.runtimeType}',
      );
    }

    // Parse using provided function
    return parser(decoded);

  } on FormatException catch (e) {
    throw LndApiException('$source: Invalid JSON format - $e');
  } on TypeError catch (e) {
    throw LndApiException('$source: JSON structure mismatch - $e');
  } catch (e) {
    throw LndApiException('$source: Unexpected parsing error - $e');
  }
}
```

### Step 2: Update `_get()` Method

```dart
// BEFORE (line 148-162):
Future<Map<String, dynamic>> _get(String path) async {
  _ensureConfigured();

  final response = await http.get(
    Uri.parse('$_restUrl$path'),
    headers: _headers,
  ).timeout(const Duration(seconds: 30));

  if (response.statusCode != 200) {
    throw LndApiException('GET $path failed: ${response.statusCode} ${response.body}');
  }

  return jsonDecode(response.body) as Map<String, dynamic>;
}

// AFTER:
Future<Map<String, dynamic>> _get(String path) async {
  _ensureConfigured();

  final response = await http.get(
    Uri.parse('$_restUrl$path'),
    headers: _headers,
  ).timeout(const Duration(seconds: 30));

  if (response.statusCode != 200) {
    // SECURITY: Don't include full response body in error (could contain sensitive data)
    throw LndApiException('GET $path failed: ${response.statusCode}');
  }

  // SECURITY: Safe JSON parsing
  return safeParse(
    response.body,
    (json) => json,
    source: 'LND GET $path',
  );
}
```

### Step 3: Update `_post()` Method

```dart
// BEFORE (line 164-179):
Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body) async {
  _ensureConfigured();

  final response = await http.post(
    Uri.parse('$_restUrl$path'),
    headers: _headers,
    body: jsonEncode(body),
  ).timeout(const Duration(seconds: 60));

  if (response.statusCode != 200) {
    throw LndApiException('POST $path failed: ${response.statusCode} ${response.body}');
  }

  return jsonDecode(response.body) as Map<String, dynamic>;
}

// AFTER:
Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body) async {
  _ensureConfigured();

  final response = await http.post(
    Uri.parse('$_restUrl$path'),
    headers: _headers,
    body: jsonEncode(body),
  ).timeout(const Duration(seconds: 60));

  if (response.statusCode != 200) {
    // SECURITY: Don't include full response body in error
    throw LndApiException('POST $path failed: ${response.statusCode}');
  }

  // SECURITY: Safe JSON parsing
  return safeParse(
    response.body,
    (json) => json,
    source: 'LND POST $path',
  );
}
```

### Step 4: Apply to Community Node Service

Update `lib/services/community_node_service.dart`:

**Line 106:**
```dart
// BEFORE:
final json = jsonDecode(response.body);
_cachedStatus = CommunityNodeStatus.fromJson(json);

// AFTER:
_cachedStatus = safeParse(
  response.body,
  (json) => CommunityNodeStatus.fromJson(json),
  source: 'Community Node Status',
);
```

**Line 139:**
```dart
// BEFORE:
final json = jsonDecode(response.body);

// AFTER:
final json = safeParse(
  response.body,
  (json) => json,
  source: 'Community Node Payment',
);
```

### Step 5: Add Tests

```dart
group('safeParse security', () {
  test('handles malformed JSON', () {
    expect(
      () => safeParse('{not valid json]', (j) => j, source: 'test'),
      throwsA(isA<LndApiException>()),
    );
  });

  test('handles JSON array instead of object', () {
    expect(
      () => safeParse('[1,2,3]', (j) => j, source: 'test'),
      throwsA(isA<LndApiException>()),
    );
  });

  test('handles type mismatch', () {
    expect(
      () => safeParse('{"balance":"not_a_number"}',
          (j) => LndBalance.fromJson(j), source: 'test'),
      throwsA(isA<LndApiException>()),
    );
  });

  test('parses valid JSON', () {
    final result = safeParse('{"test": 123}', (j) => j, source: 'test');
    expect(result['test'], equals(123));
  });
});
```

---

## ⚠️ HIGH PRIORITY FIX: Atomic File Writes

**File:** `lib/services/operation_state_service.dart`
**Time:** 4 hours
**Priority:** P1 (Fix before beta)

### Replace `_saveState()` Method (Line 351-362)

```dart
// BEFORE:
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

// AFTER:
Future<void> _saveState() async {
  if (_stateFile == null || _secretKey == null) return;

  try {
    final jsonList = _operations.map((op) => op.toJson()).toList();
    final plaintext = utf8.encode(json.encode(jsonList));
    final encrypted = await _encryptAesGcm(plaintext);

    // SECURITY: Atomic write pattern (prevents corruption on crash)
    // 1. Write to temporary file
    final tempFile = File('${_stateFile!.path}.tmp');
    await tempFile.writeAsBytes(encrypted, flush: true);

    // 2. Atomic rename (OS-level operation, cannot be interrupted)
    await tempFile.rename(_stateFile!.path);
    // If crash occurs before rename: original file unchanged
    // If crash occurs after rename: new file complete

    SecureLogger.debug('Operation state saved (${_operations.length} ops)', tag: 'OpState');

  } catch (e) {
    SecureLogger.error('Failed to save operation state', error: e, tag: 'OpState');

    // SECURITY: Clean up temp file if it exists
    try {
      final tempFile = File('${_stateFile!.path}.tmp');
      if (await tempFile.exists()) {
        await tempFile.delete();
        SecureLogger.debug('Cleaned up temp state file', tag: 'OpState');
      }
    } catch (cleanupError) {
      // Ignore cleanup errors
    }
  }
}
```

---

## ✅ VERIFICATION CHECKLIST

After implementing fixes, verify:

### P0-05 Verification
- [ ] All `int.parse()` calls in LND service use `parseSatoshis()`
- [ ] Negative values throw exception
- [ ] Values > 21M BTC throw exception
- [ ] Invalid formats throw exception
- [ ] Tests pass for boundary cases

### P0-06 Verification
- [ ] All JSON parsing uses `safeParse()`
- [ ] Malformed JSON throws exception (doesn't crash app)
- [ ] JSON arrays rejected (expecting objects)
- [ ] Type mismatches throw exception
- [ ] Error messages don't leak sensitive data

### P1-07 Verification
- [ ] State file writes use atomic pattern
- [ ] Temp file cleaned up on error
- [ ] Kill app during save → file not corrupted
- [ ] Operation history survives crashes

---

## 🧪 TESTING COMMANDS

```bash
# Run unit tests
flutter test test/unit/services/lnd_service_test.dart

# Run all security tests
flutter test test/unit/security_validation_test.dart

# Run edge case tests
flutter test test/unit/edge_cases_test.dart

# Generate coverage report
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html
```

---

## 📊 ESTIMATED TIMELINE

| Task | Time | Cumulative |
|------|------|------------|
| P0-05: Integer overflow | 4 hours | 4 hours |
| P0-06: JSON parsing | 6 hours | 10 hours |
| P1-07: Atomic writes | 4 hours | 14 hours |
| Testing & verification | 4 hours | 18 hours |

**Total:** ~2.5 days (with testing)

---

## 🆘 HELP & SUPPORT

**Questions?**
- Security concerns: Review `security-report.md` (BlackKeys) or `security-report-burgundy.md` (Burgundy)
- Implementation issues: Check existing test files for patterns
- Testing: See `test/unit/security_validation_test.dart` for examples

**After Fixes:**
- Run full test suite
- Test with malicious LND node (fuzzing)
- Verify crash recovery scenarios
- Update `SECURITY_SUMMARY.md` with completion status

---

**Good luck! You're making the Lightning Network safer. ⚡🔒**
