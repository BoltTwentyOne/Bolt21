import 'package:flutter/foundation.dart';

/// Secure logger that sanitizes sensitive data before logging
///
/// SECURITY: Prevents leakage of sensitive information in logs including:
/// - Mnemonics (seed phrases)
/// - Private keys
/// - API keys
/// - Transaction amounts
/// - Wallet addresses
/// - Payment destinations
class SecureLogger {
  // Patterns to detect and redact sensitive data
  static final List<_SanitizationRule> _rules = [
    // Mnemonic words (BIP39) - 12 or 24 word phrases
    _SanitizationRule(
      RegExp(r'\b([a-z]+\s+){11,23}[a-z]+\b', caseSensitive: false),
      '[REDACTED_MNEMONIC]',
    ),
    // Hex private keys (64 chars)
    _SanitizationRule(
      RegExp(r'\b[0-9a-fA-F]{64}\b'),
      '[REDACTED_KEY]',
    ),
    // Bitcoin addresses (legacy, segwit, taproot)
    _SanitizationRule(
      RegExp(r'\b(bc1|tb1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b'),
      '[REDACTED_ADDRESS]',
    ),
    // BOLT11 invoices
    _SanitizationRule(
      RegExp(r'\b(lnbc|lntb|lnbcrt)[a-z0-9]+\b', caseSensitive: false),
      '[REDACTED_INVOICE]',
    ),
    // BOLT12 offers
    _SanitizationRule(
      RegExp(r'\blno[a-z0-9]+\b', caseSensitive: false),
      '[REDACTED_OFFER]',
    ),
    // Lightning addresses
    _SanitizationRule(
      RegExp(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
      '[REDACTED_LN_ADDRESS]',
    ),
    // API keys (common patterns)
    _SanitizationRule(
      RegExp(r'\b[A-Za-z0-9_-]{32,}\b'),
      '[REDACTED_API_KEY]',
    ),
    // Amounts in sats (redact large values to prevent correlation)
    _SanitizationRule(
      RegExp(r'\b\d{6,}\s*sats?\b', caseSensitive: false),
      '[REDACTED_AMOUNT] sats',
    ),
  ];

  /// Log a debug message with sensitive data sanitized
  static void debug(String message, {String? tag}) {
    if (kDebugMode) {
      final sanitized = _sanitize(message);
      final prefix = tag != null ? '[$tag] ' : '';
      debugPrint('$prefix$sanitized');
    }
  }

  /// Log an info message (only in debug mode)
  static void info(String message, {String? tag}) {
    if (kDebugMode) {
      debug('[INFO] $message', tag: tag);
    }
  }

  /// Log a warning message
  static void warn(String message, {String? tag}) {
    if (kDebugMode) {
      debug('[WARN] $message', tag: tag);
    }
  }

  /// Log an error message with optional stack trace
  static void error(String message, {Object? error, StackTrace? stackTrace, String? tag}) {
    if (kDebugMode) {
      final sanitizedMessage = _sanitize(message);
      final sanitizedError = error != null ? _sanitize(error.toString()) : null;
      final prefix = tag != null ? '[$tag] ' : '';

      debugPrint('$prefix[ERROR] $sanitizedMessage');
      if (sanitizedError != null) {
        debugPrint('$prefix  Error: $sanitizedError');
      }
      if (stackTrace != null) {
        // Only show first 5 frames to reduce noise
        final frames = stackTrace.toString().split('\n').take(5).join('\n');
        debugPrint('$prefix  Stack: $frames');
      }
    }
  }

  /// Log operation state changes (sanitized)
  static void operation(String operationId, String status, {String? details}) {
    if (kDebugMode) {
      // Only log truncated operation ID
      final shortId = operationId.length > 8 ? '${operationId.substring(0, 8)}...' : operationId;
      final detailStr = details != null ? ' - ${_sanitize(details)}' : '';
      debugPrint('[OP] $shortId -> $status$detailStr');
    }
  }

  /// Sanitize a string by redacting sensitive patterns
  static String _sanitize(String input) {
    var result = input;
    for (final rule in _rules) {
      result = result.replaceAll(rule.pattern, rule.replacement);
    }
    return result;
  }

  /// Check if a string contains potentially sensitive data
  static bool containsSensitiveData(String input) {
    for (final rule in _rules) {
      if (rule.pattern.hasMatch(input)) {
        return true;
      }
    }
    return false;
  }
}

class _SanitizationRule {
  final RegExp pattern;
  final String replacement;

  _SanitizationRule(this.pattern, this.replacement);
}

/// Extension to use secure logging from debugPrint calls
extension SecureDebugPrint on String {
  /// Print this string with sensitive data sanitized
  void secureDebugPrint({String? tag}) {
    SecureLogger.debug(this, tag: tag);
  }
}
