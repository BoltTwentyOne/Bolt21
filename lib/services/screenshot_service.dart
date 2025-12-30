import 'package:flutter/services.dart';

/// Service to control screenshot and screen recording permissions
/// SECURITY: Block screenshots by default to protect sensitive wallet info
class ScreenshotService {
  static const _channel = MethodChannel('bolt21/screenshot');

  /// Allow screenshots (e.g., on receive screen for QR sharing)
  static Future<void> allowScreenshots() async {
    try {
      await _channel.invokeMethod('allowScreenshots');
    } catch (e) {
      // Platform may not support this - fail silently
    }
  }

  /// Block screenshots (default state for security)
  static Future<void> blockScreenshots() async {
    try {
      await _channel.invokeMethod('blockScreenshots');
    } catch (e) {
      // Platform may not support this - fail silently
    }
  }
}
