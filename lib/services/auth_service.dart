import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:local_auth/error_codes.dart' as auth_error;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Service for biometric authentication
class AuthService {
  static final _auth = LocalAuthentication();
  static const _storage = FlutterSecureStorage();
  static const _biometricEnabledKey = 'bolt21_biometric_enabled';

  /// Check if device supports biometrics
  static Future<bool> canUseBiometrics() async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final isSupported = await _auth.isDeviceSupported();
      return canCheck && isSupported;
    } on PlatformException {
      return false;
    }
  }

  /// Get available biometric types
  static Future<List<BiometricType>> getAvailableBiometrics() async {
    try {
      return await _auth.getAvailableBiometrics();
    } on PlatformException {
      return [];
    }
  }

  /// Check if biometric auth is enabled by user
  static Future<bool> isBiometricEnabled() async {
    final value = await _storage.read(key: _biometricEnabledKey);
    return value == 'true';
  }

  /// Enable or disable biometric auth
  static Future<void> setBiometricEnabled(bool enabled) async {
    await _storage.write(
      key: _biometricEnabledKey,
      value: enabled ? 'true' : 'false',
    );
  }

  /// Authenticate with biometrics only (for app unlock, payments)
  /// SECURITY: biometricOnly: true prevents PIN/pattern fallback
  static Future<bool> authenticate({
    String reason = 'Authenticate to access Bolt21',
  }) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true,
        ),
      );
    } on PlatformException catch (e) {
      // Log error for debugging
      print('Auth error: ${e.code} - ${e.message}');
      return false;
    }
  }

  /// Authenticate allowing device credentials (for enabling biometric setting)
  /// This is less secure but needed for the initial "enable biometrics" flow
  /// since we can't require biometrics before biometrics is enabled
  static Future<bool> authenticateWithDeviceCredentials({
    String reason = 'Authenticate to enable biometric lock',
  }) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: false,  // Allow PIN/pattern for this one-time setup
          stickyAuth: true,
        ),
      );
    } on PlatformException catch (e) {
      // Log error for debugging
      print('Auth error: ${e.code} - ${e.message}');
      return false;
    }
  }

  /// Get a friendly name for available biometrics
  static Future<String> getBiometricTypeName() async {
    final types = await getAvailableBiometrics();
    if (types.contains(BiometricType.face)) {
      return 'Face ID';
    } else if (types.contains(BiometricType.fingerprint)) {
      return 'Fingerprint';
    } else if (types.contains(BiometricType.iris)) {
      return 'Iris';
    }
    return 'Biometrics';
  }
}
