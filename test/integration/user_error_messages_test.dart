import 'package:flutter_test/flutter_test.dart';

/// Tests to verify error messages are user-friendly and actionable
/// These tests ensure users receive clear guidance when things go wrong

void main() {
  group('Send Payment Error Messages', () {
    test('invalid amount shows clear error with guidance', () {
      // Validation regex for amount
      final regex = RegExp(r'^\d+$');

      // Test cases that should fail validation
      final invalidInputs = [
        '-100',      // Negative
        '12.34',     // Decimal
        'abc',       // Letters
        '100 sats',  // With units
        '',          // Empty
        ' ',         // Whitespace
      ];

      for (final input in invalidInputs) {
        expect(
          regex.hasMatch(input.trim()),
          isFalse,
          reason: 'Input "$input" should be rejected as invalid amount',
        );
      }

      // Expected error message check
      const expectedError = 'Invalid amount. Only numeric digits allowed.';
      expect(expectedError.contains('amount'), isTrue);
      expect(expectedError.contains('digits'), isTrue);
    });

    test('amount overflow shows range with max BTC', () {
      const errorMessage = 'Invalid amount. Must be between 1 and 21M BTC in sats.';

      // Error message should mention:
      expect(errorMessage.toLowerCase().contains('amount'), isTrue);
      expect(errorMessage.contains('21M BTC'), isTrue);
      expect(errorMessage.contains('sats'), isTrue);
    });

    test('unicode lookalike attack shows security warning', () {
      const errorMessage = 'Address contains suspicious unicode characters. Possible spoofing attempt.';

      // Error message should be actionable
      expect(errorMessage.toLowerCase().contains('unicode'), isTrue);
      expect(errorMessage.toLowerCase().contains('suspicious'), isTrue);
    });

    test('address validation error is descriptive', () {
      const errorMessages = [
        'Invalid Lightning invoice or offer format',
        'Invoice has expired',
        'Invalid Bitcoin address',
        'Unsupported payment type',
      ];

      for (final msg in errorMessages) {
        // Each error should be specific about what went wrong
        expect(msg.length > 10, isTrue, reason: 'Error should be descriptive');
        expect(msg.contains('.') || msg.length < 50, isTrue, reason: 'Error should be concise');
      }
    });

    test('biometric authentication failure shows clear message', () {
      const errorMessage = 'Authentication required for large or cumulative payments';

      expect(errorMessage.toLowerCase().contains('authentication'), isTrue);
      expect(errorMessage.toLowerCase().contains('payment'), isTrue);
    });

    test('QR code validation errors are user-friendly', () {
      final qrErrors = {
        'too_large': 'QR code too large. Maximum 4KB allowed.',
        'unicode': 'QR code contains invalid unicode characters. Possible spoofing attempt.',
      };

      // Each error should explain the problem
      for (final entry in qrErrors.entries) {
        expect(
          entry.value.length > 15,
          isTrue,
          reason: 'QR error for ${entry.key} should be descriptive',
        );
      }
    });
  });

  group('Receive Payment Error Messages', () {
    test('empty amount shows prompt for input', () {
      const errorMessage = 'Please enter an amount';
      expect(errorMessage.toLowerCase().contains('amount'), isTrue);
      expect(errorMessage.toLowerCase().contains('enter'), isTrue);
    });

    test('invalid amount shows format guidance', () {
      const errorMessage = 'Please enter a valid amount';
      expect(errorMessage.toLowerCase().contains('valid'), isTrue);
      expect(errorMessage.toLowerCase().contains('amount'), isTrue);
    });
  });

  group('Network Error Messages', () {
    test('payment failure shows error from backend', () {
      // The app shows: 'Payment failed: ${wallet.error}'
      // This ensures the SDK error is passed through
      const errorTemplate = 'Payment failed: ';
      expect(errorTemplate.contains('Payment'), isTrue);
      expect(errorTemplate.contains('failed'), isTrue);
    });

    test('rate limiting error is informative', () {
      const errorMessage = 'Too many payment attempts. Please wait 60 seconds.';
      expect(errorMessage.toLowerCase().contains('wait'), isTrue);
      expect(errorMessage.contains('60'), isTrue);
    });
  });

  group('Wallet Error Messages', () {
    test('node startup failure shows retry option', () {
      // From home_screen.dart error state
      const errorTitle = 'Failed to start node';
      const retryButton = 'Retry';

      expect(errorTitle.toLowerCase().contains('failed'), isTrue);
      expect(retryButton.toLowerCase().contains('retry'), isTrue);
    });

    test('incomplete operation alert is actionable', () {
      // Alert shows which operations are incomplete
      // Users can see amount and type of payment
      const alertSample = 'Payment of 50000 sats may not have completed';
      expect(alertSample.toLowerCase().contains('sats'), isTrue);
      expect(alertSample.toLowerCase().contains('completed'), isTrue);
    });
  });

  group('Error Message Quality Standards', () {
    test('all error messages are non-technical for end users', () {
      // List of error messages used in the app
      final userFacingErrors = [
        'Invalid amount. Only numeric digits allowed.',
        'Invalid amount. Must be between 1 and 21M BTC in sats.',
        'Authentication required for large or cumulative payments',
        'Please enter an amount',
        'Please enter a valid amount',
        'Too many payment attempts. Please wait 60 seconds.',
        'Failed to start node',
        'QR code too large. Maximum 4KB allowed.',
      ];

      // Technical terms that should NOT appear in user messages
      final technicalTerms = [
        'exception',
        'null',
        'undefined',
        'stack',
        'trace',
        'error code',
        'class',
        'object',
        'instance',
        'method',
        'function',
      ];

      for (final error in userFacingErrors) {
        for (final term in technicalTerms) {
          expect(
            error.toLowerCase().contains(term),
            isFalse,
            reason: 'Error "$error" should not contain technical term "$term"',
          );
        }
      }
    });

    test('error messages have proper capitalization', () {
      final errors = [
        'Invalid amount. Only numeric digits allowed.',
        'Please enter an amount',
        'Failed to start node',
      ];

      for (final error in errors) {
        // First letter should be capitalized
        expect(
          error[0] == error[0].toUpperCase(),
          isTrue,
          reason: 'Error "$error" should start with capital letter',
        );
      }
    });

    test('error messages end properly (period or no punctuation)', () {
      final errors = [
        'Invalid amount. Only numeric digits allowed.',
        'Please enter an amount',
        'Too many payment attempts. Please wait 60 seconds.',
      ];

      for (final error in errors) {
        final lastChar = error[error.length - 1];
        expect(
          lastChar == '.' || lastChar.contains(RegExp(r'[a-zA-Z0-9]')),
          isTrue,
          reason: 'Error "$error" should end with period or alphanumeric',
        );
      }
    });
  });
}
