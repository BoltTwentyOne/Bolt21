import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
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

  /// Authenticate with biometrics
  static Future<bool> authenticate({
    String reason = 'Authenticate to access Bolt21',
  }) async {
    try {
      // SECURITY: biometricOnly: true prevents PIN/pattern fallback
      // For a Bitcoin wallet, physical biometric is required - device PIN
      // can be shoulder-surfed or obtained through social engineering
      return await _auth.authenticate(
        localizedReason: reason,
        biometricOnly: true,
      );
    } on PlatformException {
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
