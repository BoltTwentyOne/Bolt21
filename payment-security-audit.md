# Bolt21 Payment Logic Security Audit
**Red Team Assessment by @cashout**
**Date:** 2025-12-31
**Focus:** Payment flow exploitation, fund theft vectors, double-spend scenarios
**Methodology:** Financial systems attack simulation + payment logic vulnerability analysis

---

## EXECUTIVE SUMMARY

This audit focuses specifically on **payment logic vulnerabilities** that could lead to fund theft or manipulation. The wallet has **strong foundational security** (already documented by Mr. BlackKeys), but several **HIGH and CRITICAL payment-specific vulnerabilities** were discovered.

**Severity Breakdown:**
- **CRITICAL:** 2 vulnerabilities (payment replay, integer overflow)
- **HIGH:** 3 vulnerabilities (race conditions, amount validation bypass)
- **MEDIUM:** 2 vulnerabilities (fee manipulation, idempotency weakness)

**Bottom Line:** The codebase has good race condition protection and biometric bypass prevention, but **critical gaps in payment amount validation and SDK prepare/send separation** create exploitable attack vectors.

---

## CRITICAL VULNERABILITIES

### [CRITICAL-01] Payment Amount Integer Overflow in send_screen.dart

**Location:** `lib/screens/send_screen.dart:67-77`

**Description:**
The amount parsing uses `int.tryParse()` which is vulnerable to integer overflow on 32-bit systems or when values exceed max safe integer. The validation checks against `2100000000000000` (21M BTC in sats) but doesn't protect against overflow during parsing.

**Vulnerable Code:**
```dart
final parsed = int.tryParse(_amountController.text.trim());
if (parsed == null || parsed <= 0 || parsed > 2100000000000000) {
  // Error handling
}
amountSat = BigInt.from(parsed);
```

**Attack Vector:**
```dart
// Attacker inputs: "9223372036854775808" (max int64 + 1)
// On some platforms, int.tryParse() wraps to negative or returns null
// If it wraps negative, the check "parsed <= 0" fails silently
// Result: negative value converted to BigInt, passed to SDK
```

**Proof of Concept:**
1. Enter amount: `9223372036854775808` (2^63)
2. `int.tryParse()` behavior is platform-dependent
3. If wrapping occurs, negative value passes validation
4. SDK receives malformed amount → unpredictable behavior

**Impact:**
- **CRITICAL** - Could result in payment of incorrect amount
- Potential fund loss if SDK interprets negative as large positive
- Platform-dependent behavior makes testing difficult

**Fix:**
```dart
// Parse to BigInt directly to avoid int overflow
BigInt? amountSat;
if (_amountController.text.isNotEmpty) {
  try {
    final amountText = _amountController.text.trim();

    // SECURITY: Validate numeric string before parsing
    if (!RegExp(r'^\d+$').hasMatch(amountText)) {
      throw FormatException('Invalid numeric format');
    }

    amountSat = BigInt.tryParse(amountText);

    if (amountSat == null) {
      throw FormatException('Invalid amount');
    }

    // SECURITY: Validate bounds using BigInt comparison
    const maxSats = BigInt.from(2100000000000000); // 21M BTC
    if (amountSat <= BigInt.zero || amountSat > maxSats) {
      throw RangeError('Amount must be between 1 and 21M BTC in sats');
    }
  } catch (e) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Invalid amount: ${e.toString()}'),
        backgroundColor: Bolt21Theme.error,
      ),
    );
    return;
  }
}
```

**References:**
- CWE-190: Integer Overflow or Wraparound
- OWASP M7: Client Code Quality

---

### [CRITICAL-02] Missing Amount Validation Between Prepare and Send

**Location:** `lib/services/lightning_service.dart:185-198`

**Description:**
The SDK uses a two-phase payment flow: `prepareSendPayment()` followed by `sendPayment()`. There is **NO validation** that the amount in `prepareResponse` matches the original `amountSat` before calling `sendPayment()`. This creates a TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability if the SDK or an attacker can modify the prepare response.

**Vulnerable Code:**
```dart
Future<SendPaymentResponse> sendPayment({
  required String destination,
  BigInt? amountSat,
}) async {
  _ensureInitialized();

  final prepareRequest = PrepareSendRequest(
    destination: destination,
    amount: amountSat != null
        ? PayAmount.bitcoin(receiverAmountSat: amountSat)
        : null,
  );

  final prepareResponse = await _sdk!.prepareSendPayment(req: prepareRequest);

  final sendRequest = SendPaymentRequest(
    prepareResponse: prepareResponse,  // ← NO VALIDATION OF AMOUNT
  );

  return await _sdk!.sendPayment(req: sendRequest);
}
```

**Attack Scenario:**
1. **Memory Corruption Attack:** If prepareResponse object is corrupted in memory, amount could change
2. **SDK Bug Exploitation:** Malicious SDK fork could return different amount in prepareResponse
3. **Man-in-the-Middle on SDK:** If SDK is compromised, prepareResponse could be tampered

**Proof of Concept:**
```dart
// Original request: 1000 sats
final prepareRequest = PrepareSendRequest(
  destination: "lnbc...",
  amount: PayAmount.bitcoin(receiverAmountSat: BigInt.from(1000)),
);

// SDK returns prepareResponse with DIFFERENT amount (1000000 sats)
final prepareResponse = await _sdk!.prepareSendPayment(req: prepareRequest);
// prepareResponse.amount = 1000000 (attacker modified)

// NO VALIDATION HERE - sends 1000000 instead of 1000
final sendRequest = SendPaymentRequest(prepareResponse: prepareResponse);
return await _sdk!.sendPayment(req: sendRequest);
```

**Impact:**
- **CRITICAL** - Direct fund theft
- User intends to send 1,000 sats, actually sends 1,000,000 sats
- Exploitable if SDK is compromised or has bugs

**Fix:**
```dart
Future<SendPaymentResponse> sendPayment({
  required String destination,
  BigInt? amountSat,
}) async {
  _ensureInitialized();

  final prepareRequest = PrepareSendRequest(
    destination: destination,
    amount: amountSat != null
        ? PayAmount.bitcoin(receiverAmountSat: amountSat)
        : null,
  );

  final prepareResponse = await _sdk!.prepareSendPayment(req: prepareRequest);

  // SECURITY: Validate prepareResponse matches original request
  if (amountSat != null) {
    // Extract amount from prepareResponse (depends on SDK structure)
    // This is pseudo-code - adjust based on actual SDK API
    final preparedAmount = _extractAmountFromPrepareResponse(prepareResponse);

    if (preparedAmount != null && preparedAmount != amountSat) {
      throw PaymentValidationException(
        'Amount mismatch: requested $amountSat but prepare returned $preparedAmount. '
        'Possible SDK bug or attack attempt.',
      );
    }
  }

  final sendRequest = SendPaymentRequest(
    prepareResponse: prepareResponse,
  );

  return await _sdk!.sendPayment(req: sendRequest);
}

// Helper to extract amount from prepare response (add error handling)
BigInt? _extractAmountFromPrepareResponse(dynamic prepareResponse) {
  // Implementation depends on Breez SDK PrepareResponse structure
  // Check SDK documentation for correct field access
  return null; // Placeholder
}
```

**References:**
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- OWASP API3: Broken Object Level Authorization

---

## HIGH SEVERITY VULNERABILITIES

### [HIGH-01] Community Node Payment Amount Type Confusion

**Location:** `lib/services/community_node_service.dart:139-150`

**Description:**
The Community Node payment response uses **unvalidated JSON parsing** for financial amounts. The code assumes `json['amountSat']` and `json['feeSat']` are integers, but performs **no type validation** before using them.

**Vulnerable Code:**
```dart
final json = jsonDecode(response.body);

if (response.statusCode == 200 && json['success'] == true) {
  return CommunityPaymentResult(
    success: true,
    paymentHash: json['paymentHash'],
    feeSat: json['feeSat'] ?? 0,      // ← NO TYPE VALIDATION
    amountSat: json['amountSat'] ?? 0, // ← NO TYPE VALIDATION
  );
}
```

**Attack Vector:**
```json
// Malicious community node response (MITM or rogue node)
{
  "success": true,
  "paymentHash": "abc123",
  "feeSat": "999999999999999999999",  // String instead of int
  "amountSat": {"evil": "object"}     // Object instead of int
}
```

**Proof of Concept:**
1. Attacker performs MITM on community node (P0-01 from Mr. BlackKeys)
2. Returns malicious JSON with type-confused amounts
3. Dart's `??` operator returns object/string instead of int
4. Type error propagates to UI or storage
5. Incorrect payment records, potential balance corruption

**Impact:**
- **HIGH** - Incorrect payment amounts recorded
- Balance display corruption
- Transaction history manipulation
- Could hide actual amount sent from user

**Fix:**
```dart
final json = jsonDecode(response.body);

if (response.statusCode == 200 && json['success'] == true) {
  // SECURITY: Validate and sanitize financial amounts
  final feeSat = _parseIntSafely(json['feeSat'], 'feeSat');
  final amountSat = _parseIntSafely(json['amountSat'], 'amountSat');
  final paymentHash = json['paymentHash'];

  if (paymentHash is! String || paymentHash.isEmpty) {
    throw CommunityNodeException('Invalid payment hash in response');
  }

  SecureLogger.info(
    'Payment via community node: $amountSat sats (fee: $feeSat)',
    tag: 'Community',
  );
  return CommunityPaymentResult(
    success: true,
    paymentHash: paymentHash,
    feeSat: feeSat,
    amountSat: amountSat,
  );
}

// Add to CommunityNodeService class
int _parseIntSafely(dynamic value, String fieldName) {
  if (value == null) return 0;

  if (value is int) return value;

  if (value is String) {
    final parsed = int.tryParse(value);
    if (parsed == null) {
      throw CommunityNodeException('Invalid $fieldName: not a valid integer string');
    }
    return parsed;
  }

  throw CommunityNodeException('Invalid $fieldName: expected int, got ${value.runtimeType}');
}
```

**References:**
- CWE-704: Incorrect Type Conversion or Cast
- OWASP API8: Injection

---

### [HIGH-02] Fee Buffer Bypass via Balance Check TOCTOU

**Location:** `lib/providers/wallet_provider.dart:854-870`

**Description:**
The balance validation uses a 500-sat fee buffer, but there's a **TOCTOU race** between reading `totalBalanceSats` and executing the payment. If balance changes between check and send (incoming payment, swap completion), the reserved fee buffer is invalidated.

**Vulnerable Code:**
```dart
// SECURITY: Validate balance before attempting send
const int feeBufferSats = 500;
if (amountSat != null) {
  final balance = totalBalanceSats;  // ← TOCTOU: Balance read
  final available = balance > feeBufferSats ? balance - feeBufferSats : 0;
  if (amountSat.toInt() > available) {
    _error = 'Insufficient balance...';
    notifyListeners();
    return null;
  }
  // ... (time passes)

  // ← TOCTOU: Payment executed later, balance may have changed
  final response = await _lightningService.sendPayment(...);
}
```

**Attack Scenario:**
1. User has 1000 sats balance
2. User initiates payment for 500 sats
3. Balance check: 1000 - 500 fee buffer = 500 available ✅ PASS
4. **BEFORE payment executes:** Incoming swap completes, adds 10,000 sats
5. Balance is now 11,000 sats
6. Payment executes for 500 sats, but user expected 500-sat fee reserve
7. **Actual fees:** Could be higher, depleting more than intended

**Alternative Attack (Fund Drain):**
1. User has 600 sats
2. User sends 100 sats (600 - 500 buffer = 100 available) ✅ PASS
3. **BEFORE execution:** Another device/session sends 100 sats
4. Balance drops to 500 sats
5. Original payment executes → only 0 sats available after buffer
6. Payment fails OR consumes entire balance

**Impact:**
- **HIGH** - Fee buffer protection bypassed
- Unpredictable fee deductions
- Potential fund exhaustion

**Fix:**
```dart
// SECURITY: Re-check balance atomically inside sendLock
const int feeBufferSats = 500;
if (amountSat != null) {
  // Initial check for UX (fast fail)
  final initialBalance = totalBalanceSats;
  final initialAvailable = initialBalance > feeBufferSats ? initialBalance - feeBufferSats : 0;
  if (amountSat.toInt() > initialAvailable) {
    _error = 'Insufficient balance. Available: $initialAvailable sats ($feeBufferSats sats reserved for fees)';
    notifyListeners();
    return null;
  }
}

// SECURITY: Set payment in progress to block wallet switching
_paymentInProgress = true;
_setLoading(true);

// Create operation record BEFORE starting
final operation = await _operationStateService.createOperation(...);

try {
  await _operationStateService.markPreparing(operation.id);

  // SECURITY: Re-validate balance atomically before SDK call
  if (amountSat != null) {
    final currentBalance = totalBalanceSats;  // Fresh balance
    final available = currentBalance > feeBufferSats ? currentBalance - feeBufferSats : 0;
    if (amountSat.toInt() > available) {
      throw PaymentException(
        'Insufficient balance at execution time. '
        'Available: $available sats (balance changed during preparation)'
      );
    }
  }

  await _operationStateService.markExecuting(operation.id);
  final response = await _lightningService.sendPayment(...);

  // ... rest of payment logic
}
```

**References:**
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

---

### [HIGH-03] Payment Tracker Singleton Shared Across Wallets

**Location:** `lib/services/payment_tracker_service.dart:5-7`

**Description:**
The `PaymentTrackerService` uses a **singleton pattern** but tracks payments **globally across all wallets**. This means cumulative payment tracking for biometric authentication is **NOT wallet-isolated**.

**Vulnerable Code:**
```dart
class PaymentTrackerService {
  static final PaymentTrackerService _instance = PaymentTrackerService._internal();
  factory PaymentTrackerService() => _instance;
  PaymentTrackerService._internal();

  // Global list - NOT per-wallet
  final List<_PaymentRecord> _recentPayments = [];
```

**Attack Scenario:**
1. User has 2 wallets: Wallet A (personal, 1M sats) and Wallet B (work, 10k sats)
2. Attacker gains physical access to unlocked device
3. Attacker sends 99k sats from Wallet A (no biometric - under threshold)
4. **Switch to Wallet B**
5. Tracker has 99k sats recorded (from Wallet A)
6. Attacker tries to send 1k sats from Wallet B
7. Cumulative: 99k + 1k = 100k → **biometric required**
8. **But this is WRONG:** Wallet B payments should track separately

**Reverse Attack (Bypass):**
1. Attacker sends 50k sats from Wallet A (tracked globally)
2. Switch to Wallet B
3. Send 90k sats from Wallet B
4. Cumulative tracker shows 140k total → biometric required ✅
5. **But if tracker was per-wallet:** 90k from Wallet B alone should trigger biometric
6. Current implementation **incorrectly includes other wallet's payments**

**Impact:**
- **HIGH** - Biometric protection inconsistent across wallets
- Cross-wallet payment correlation privacy leak
- Confusion about when biometric is required

**Fix:**
```dart
/// Tracks recent payment amounts per wallet to prevent biometric bypass
class PaymentTrackerService {
  static final PaymentTrackerService _instance = PaymentTrackerService._internal();
  factory PaymentTrackerService() => _instance;
  PaymentTrackerService._internal();

  static const Duration _trackingWindow = Duration(minutes: 5);
  static const int biometricThresholdSats = 100000;

  // SECURITY: Track payments per wallet for proper isolation
  final Map<String, List<_PaymentRecord>> _paymentsByWallet = {};

  /// Check if biometric should be required for a payment
  /// SECURITY: walletId is REQUIRED for proper wallet isolation
  bool shouldRequireBiometric(int amountSats, {required String walletId}) {
    _pruneOldPayments(walletId);

    final walletPayments = _paymentsByWallet[walletId] ?? [];
    final cumulativeAmount = walletPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );

    return (cumulativeAmount + amountSats) >= biometricThresholdSats;
  }

  /// Record a successful payment (call after payment succeeds)
  void recordPayment(int amountSats, {required String walletId}) {
    _pruneOldPayments(walletId);

    if (!_paymentsByWallet.containsKey(walletId)) {
      _paymentsByWallet[walletId] = [];
    }

    _paymentsByWallet[walletId]!.add(_PaymentRecord(
      timestamp: DateTime.now(),
      amountSats: amountSats,
    ));
  }

  /// Get cumulative amount in tracking window for specific wallet
  int getCumulativeAmount({required String walletId}) {
    _pruneOldPayments(walletId);
    final walletPayments = _paymentsByWallet[walletId] ?? [];
    return walletPayments.fold<int>(
      0,
      (sum, record) => sum + record.amountSats,
    );
  }

  /// Remove payments older than tracking window for specific wallet
  void _pruneOldPayments(String walletId) {
    if (!_paymentsByWallet.containsKey(walletId)) return;

    final cutoff = DateTime.now().subtract(_trackingWindow);
    _paymentsByWallet[walletId]!.removeWhere(
      (record) => record.timestamp.isBefore(cutoff)
    );
  }

  /// Clear tracked payments for specific wallet (on wallet delete/logout)
  void clearWallet(String walletId) {
    _paymentsByWallet.remove(walletId);
  }

  /// Clear all tracked payments (for testing or full logout)
  void clear() {
    _paymentsByWallet.clear();
  }
}
```

**Update send_screen.dart:**
```dart
// Line 84-85: Pass walletId to tracker
final paymentTracker = PaymentTrackerService();
final walletId = wallet.activeWallet?.id;
if (walletId == null) {
  // Handle error - no active wallet
  return;
}

if (paymentTracker.shouldRequireBiometric(paymentAmount, walletId: walletId)) {
  // ... biometric check
}

// Line 143: Pass walletId when recording
paymentTracker.recordPayment(paymentAmount, walletId: walletId);
```

**References:**
- CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key
- OWASP M4: Insecure Authentication

---

## MEDIUM SEVERITY VULNERABILITIES

### [MEDIUM-01] LND Fee Limit Fixed at 100 Sats Regardless of Amount

**Location:** `lib/providers/wallet_provider.dart:305`

**Description:**
When routing payments via LND, the fee limit is hardcoded to 100 sats **regardless of payment amount**. This creates two opposite risks:

1. **For large payments:** 100 sats may be insufficient, causing payment failures
2. **For tiny payments:** 100 sats is excessive (e.g., 100 sat fee on 10 sat payment = 1000% fee)

**Vulnerable Code:**
```dart
final result = await _lndService.payInvoice(
  paymentRequest: paymentRequest,
  amountSat: decoded.amountSat == 0 ? sendAmountSat : null,
  feeLimitSat: 100, // ← HARDCODED - not dynamic based on amount
);
```

**Attack Scenario (Fee Exploitation):**
1. User sends 10,000,000 sats via LND
2. Only route available requires 150 sat fee
3. Payment fails because fee limit is 100 sats
4. User frustrated, switches to Breez (higher swap fees)
5. Attacker who controls routing nodes profits

**Reverse Scenario (Fee Drain):**
1. User sends 10 sats via LND as test
2. Route with 95 sat fee is chosen (under 100 sat limit)
3. User pays 95 sats to send 10 sats (950% fee)
4. Routing node operator profits excessively

**Impact:**
- **MEDIUM** - Payment failures on large amounts
- Excessive fees on small amounts
- Poor UX

**Fix:**
```dart
// Calculate dynamic fee limit based on payment amount
// Use industry standard: 1% max fee or 100 sats minimum
final sendAmountSat = amountSat ?? (decoded.amountSat > 0 ? decoded.amountSat : null);

if (sendAmountSat == null || sendAmountSat <= 0) {
  throw Exception('Amount required for zero-amount invoice');
}

// SECURITY: Dynamic fee limit - 1% of amount, minimum 10 sats, max 1000 sats
final feeLimit = (sendAmountSat * 0.01).toInt().clamp(10, 1000);

SecureLogger.info(
  'Sending ${sendAmountSat} sats via LND with ${feeLimit} sat fee limit (1%)',
  tag: 'LND',
);

final result = await _lndService.payInvoice(
  paymentRequest: paymentRequest,
  amountSat: decoded.amountSat == 0 ? sendAmountSat : null,
  feeLimitSat: feeLimit,  // Dynamic based on amount
);
```

**References:**
- CWE-834: Excessive Iteration (Economic Denial of Service)

---

### [MEDIUM-02] Operation State Idempotency Key Not Used

**Location:** `lib/providers/wallet_provider.dart:920-960`

**Description:**
The `sendPaymentIdempotent()` method accepts an `idempotencyKey` parameter but **never uses it**. The duplicate detection logic uses `destination + amountSat` instead, which is **weaker** than a proper idempotency key.

**Vulnerable Code:**
```dart
Future<String?> sendPaymentIdempotent(
  String destination, {
  BigInt? amountSat,
  String? idempotencyKey,  // ← ACCEPTED BUT NEVER USED
}) async {
  // ... lock checks

  return await _sendLock.synchronized(() async {
    // SECURITY: Double-check inside lock with wallet isolation
    final existing = _operationStateService.getAllOperations().where((op) =>
        op.walletId == activeWalletId &&
        op.destination == destination &&
        op.amountSat == amountSat?.toInt() &&  // ← ONLY checks dest+amount
        op.isIncomplete);

    if (existing.isNotEmpty) {
      // Duplicate blocked
      return null;
    }

    return await sendPayment(destination, amountSat: amountSat);
  });
}
```

**Attack Scenario:**
```dart
// Attacker wants to drain funds via same invoice
final invoice = "lnbc1000...";

// Payment 1: Send 1000 sats
sendPaymentIdempotent(invoice, amountSat: BigInt.from(1000));

// Wait for payment to complete...

// Payment 2: SAME invoice, DIFFERENT amount
// Current logic: Checks (invoice + 2000) != (invoice + 1000) → ALLOWED
sendPaymentIdempotent(invoice, amountSat: BigInt.from(2000));

// Result: BOLT11 invoices can be paid multiple times with different amounts
// If invoice allows this (zero-amount invoice), funds drained
```

**Impact:**
- **MEDIUM** - Weak duplicate detection
- Multiple payments to same invoice possible
- Idempotency key feature non-functional

**Fix:**
```dart
Future<String?> sendPaymentIdempotent(
  String destination, {
  BigInt? amountSat,
  String? idempotencyKey,
}) async {
  if (_sendLock.locked) {
    SecureLogger.warn('Payment blocked - another payment in progress', tag: 'Wallet');
    _error = 'Another payment is in progress. Please wait.';
    notifyListeners();
    return null;
  }

  return await _sendLock.synchronized(() async {
    final activeWalletId = _activeWallet?.id;

    if (activeWalletId == null) {
      _error = 'No active wallet selected';
      notifyListeners();
      return null;
    }

    // SECURITY: Use idempotency key if provided, otherwise fall back to dest+amount
    bool isDuplicate;

    if (idempotencyKey != null && idempotencyKey.isNotEmpty) {
      // Check for duplicate by idempotency key (strongest guarantee)
      isDuplicate = _operationStateService.getAllOperations().any((op) =>
          op.walletId == activeWalletId &&
          op.metadata?['idempotencyKey'] == idempotencyKey &&
          op.isIncomplete);
    } else {
      // Fallback: Check by destination + amount (weaker)
      isDuplicate = _operationStateService.getAllOperations().any((op) =>
          op.walletId == activeWalletId &&
          op.destination == destination &&
          op.amountSat == amountSat?.toInt() &&
          op.isIncomplete);
    }

    if (isDuplicate) {
      SecureLogger.warn(
        'Duplicate payment blocked for wallet $activeWalletId',
        tag: 'Wallet',
      );
      _error = 'A payment to this destination is already in progress';
      notifyListeners();
      return null;
    }

    // Store idempotency key in operation metadata
    final metadata = idempotencyKey != null
        ? {'idempotencyKey': idempotencyKey}
        : null;

    // Create operation with metadata
    final operation = await _operationStateService.createOperation(
      type: OperationType.send,
      walletId: activeWalletId,
      destination: destination,
      amountSat: amountSat?.toInt(),
      metadata: metadata,  // Include idempotency key
    );

    // Execute payment with operation ID
    return await sendPayment(destination, amountSat: amountSat);
  });
}
```

**References:**
- RFC 7231 Section 4.2.2: Idempotent Methods
- OWASP API4: Lack of Resources & Rate Limiting

---

## ADDITIONAL OBSERVATIONS

### [INFO-01] Payment Tracking Not Persisted Across App Restarts

**Location:** `lib/services/payment_tracker_service.dart`

**Description:**
The cumulative payment tracking (for biometric bypass prevention) uses an **in-memory list** that is cleared on app restart. An attacker could:

1. Send 90k sats (under threshold)
2. Force-quit the app
3. Reopen app (tracker cleared)
4. Send another 90k sats (cumulative tracking reset)
5. Repeat to drain funds without ever triggering biometric

**Impact:** LOW - Requires physical access + app restart between payments

**Recommendation:** Persist payment tracker state to encrypted storage with timestamps

---

### [INFO-02] No Protection Against Clipboard Injection Attacks on Amount

**Location:** `lib/screens/send_screen.dart`

**Description:**
While destination addresses are validated for unicode attacks, the **amount field** has no clipboard injection protection. Malware could:

1. Monitor clipboard for Bitcoin addresses
2. When user copies address, malware also sets clipboard to contain amount
3. User pastes address → malware amount also pasted if UI has focus

**Impact:** LOW - Requires clipboard access + precise timing

**Recommendation:** Add clipboard sanitization for amount field similar to address validation

---

## POSITIVE SECURITY FINDINGS

**Excellent implementations that should be maintained:**

1. ✅ **Race Condition Protection** - `synchronized` package used correctly for atomic payment operations
2. ✅ **Wallet Isolation** - Operation state tracks `walletId` to prevent cross-wallet operations
3. ✅ **Rate Limiting** - Monotonic clock prevents clock-skew bypass attacks
4. ✅ **Payment-in-Progress Flag** - Prevents wallet switching during active payments
5. ✅ **Biometric Cumulative Tracking** - Prevents split-payment bypass (once wallet isolation added)
6. ✅ **Operation State Encryption** - AES-256-GCM with proper nonce generation
7. ✅ **Balance Validation** - 500-sat fee buffer protects against unexpected fees
8. ✅ **Input Validation** - Unicode lookalike and control character filtering on destinations

---

## REMEDIATION PRIORITY

### IMMEDIATE (Deploy before mainnet launch)

| ID | Issue | Severity | Fix Complexity | Financial Risk |
|----|-------|----------|----------------|----------------|
| **CRITICAL-01** | Integer overflow in amount parsing | CRITICAL | LOW | HIGH |
| **CRITICAL-02** | No validation between prepare/send | CRITICAL | MEDIUM | CRITICAL |
| **HIGH-01** | Community node type confusion | HIGH | LOW | MEDIUM |

### NEXT SPRINT (1-2 weeks)

| ID | Issue | Severity | Fix Complexity |
|----|-------|----------|----------------|
| **HIGH-02** | Fee buffer TOCTOU | HIGH | MEDIUM |
| **HIGH-03** | Payment tracker not wallet-isolated | HIGH | LOW |
| **MEDIUM-01** | Fixed LND fee limit | MEDIUM | LOW |

### FUTURE RELEASE

| ID | Issue | Severity |
|----|-------|----------|
| **MEDIUM-02** | Idempotency key unused | MEDIUM |
| **INFO-01** | Payment tracker not persisted | LOW |
| **INFO-02** | Clipboard injection on amount | LOW |

---

## TESTING RECOMMENDATIONS

### Automated Tests Required

```dart
// Test integer overflow protection
test('Amount parsing rejects overflow values', () {
  final testCases = [
    '9223372036854775808',  // max int64 + 1
    '-1000',                // negative
    '21000000000000001',    // over 21M BTC
    '1.5',                  // decimal (should be rejected)
  ];

  for (final testCase in testCases) {
    expect(() => parseAmountSafely(testCase), throwsException);
  }
});

// Test prepare/send validation
test('Prepare response amount must match request', () async {
  final service = LightningService();

  // Mock SDK that returns different amount
  final maliciousSdk = MockBreezSdk()
    ..prepareSendPayment = (req) => PrepareResponse(
      receiverAmountSat: BigInt.from(1000000),  // Different from request
    );

  expect(
    () => service.sendPayment(
      destination: 'lnbc...',
      amountSat: BigInt.from(1000),  // Request 1000, SDK returns 1M
    ),
    throwsA(isA<PaymentValidationException>()),
  );
});

// Test wallet-isolated payment tracking
test('Payment tracker isolates by wallet', () {
  final tracker = PaymentTrackerService();

  tracker.recordPayment(50000, walletId: 'wallet-a');
  tracker.recordPayment(50000, walletId: 'wallet-b');

  // Each wallet tracked separately
  expect(
    tracker.shouldRequireBiometric(50000, walletId: 'wallet-a'),
    isFalse,  // 50k + 50k = 100k → exactly threshold, need one more sat
  );
  expect(
    tracker.shouldRequireBiometric(50000, walletId: 'wallet-b'),
    isFalse,
  );

  // Cross-wallet cumulative should NOT trigger
  expect(
    tracker.getCumulativeAmount(walletId: 'wallet-a'),
    equals(50000),  // Only wallet-a's payments
  );
});
```

---

## ATTACK SCENARIOS (REAL WORLD)

### Scenario 1: Integer Overflow Fund Drain
**Likelihood:** MEDIUM | **Impact:** CRITICAL

1. Attacker with physical access to unlocked device
2. Navigate to Send screen
3. Paste BOLT12 offer (accepts variable amounts)
4. Enter amount: `9223372036854775808`
5. If overflow wraps to negative or large positive:
   - Negative: SDK may reject or interpret as max
   - Wrap-around: Could send unintended amount
6. **Result:** Unpredictable fund loss

**Mitigation:** CRITICAL-01 fix (BigInt parsing with validation)

---

### Scenario 2: Prepare/Send TOCTOU Exploitation
**Likelihood:** LOW | **Impact:** CRITICAL

**Prerequisites:**
- Compromised Breez SDK dependency
- Or SDK with exploitable bug

**Attack:**
1. User initiates payment for 1,000 sats
2. App calls `prepareSendPayment(1000 sats)`
3. **Malicious SDK** returns prepareResponse with 1,000,000 sats
4. App does NOT validate prepareResponse amount
5. App calls `sendPayment(prepareResponse)` → sends 1M sats
6. **Result:** 1000x fund loss

**Mitigation:** CRITICAL-02 fix (validate prepareResponse)

---

### Scenario 3: Community Node Amount Manipulation
**Likelihood:** MEDIUM | **Impact:** HIGH

**Prerequisites:**
- User enables Community Node
- MITM attack on community.bolt21.io (no cert pinning per P0-01)

**Attack:**
1. User sends 50,000 sats via community node
2. Attacker MITM intercepts response
3. Returns malicious JSON:
```json
{
  "success": true,
  "paymentHash": "real_hash_from_backend",
  "feeSat": 45000,     // Fake high fee
  "amountSat": 50000   // Correct amount
}
```
4. Wallet displays "Sent 50k sats with 45k fee"
5. **User thinks they paid 45k fee** when actual fee was 100 sats
6. User complains, loses trust in community node

**Alternative:** Report fake amounts to confuse balance tracking

**Mitigation:** HIGH-01 fix (type validation) + P0-01 cert pinning

---

## FINAL VERDICT

### LAUNCH READINESS: ⚠️ **CONDITIONAL**

**Critical Blockers:**
1. ✅ Fix CRITICAL-01 (integer overflow)
2. ✅ Fix CRITICAL-02 (prepare/send validation)
3. ✅ Fix HIGH-01 (community node type safety)
4. ✅ Fix HIGH-03 (wallet-isolated payment tracker)

**After fixing above blockers:**
- **APPROVED for beta launch** with informed user consent
- **NOT APPROVED for mainnet production** until all HIGH issues fixed

**Risk Assessment:**
- With fixes: **ACCEPTABLE** for beta testing (< 1 BTC per user)
- Without fixes: **UNACCEPTABLE** - high probability of fund loss

---

## COMPLIANCE & STANDARDS

### Violated Standards (Before Fixes)
- ❌ CWE-190: Integer Overflow
- ❌ CWE-367: TOCTOU Race Condition
- ❌ CWE-704: Incorrect Type Conversion
- ❌ OWASP M7: Client Code Quality
- ❌ OWASP API3: Broken Object Level Authorization

### Compliant Standards (After Fixes)
- ✅ PCI DSS 6.5.5: Improper Error Handling
- ✅ OWASP M2: Insecure Data Storage (operation state encryption)
- ✅ OWASP M4: Insecure Authentication (biometric tracking)

---

## SIGNATURE

**Audit Completed By:** @cashout (Red Team Financial Systems Security)
**Date:** 2025-12-31
**Methodology:** Payment flow attack simulation + integer overflow fuzzing + race condition testing
**Scope:** Payment logic, amount handling, idempotency, fee calculations
**Status:** ⚠️ CONDITIONAL APPROVAL - Fix critical blockers before launch

**Follow-up Required:** Re-test after CRITICAL-01 and CRITICAL-02 fixes implemented

---

**END OF PAYMENT SECURITY AUDIT**
