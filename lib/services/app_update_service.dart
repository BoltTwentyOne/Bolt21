import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../utils/secure_logger.dart';
import 'secure_storage_service.dart';

/// Service to check for required app updates
///
/// Fetches version info from GitHub and shows blocking dialog if update required.
/// Also checks GitHub releases for optional updates with dismissible prompts.
/// Update the version.json file in the repo to trigger forced updates.
class AppUpdateService {
  static const String _versionUrl =
    'https://raw.githubusercontent.com/CaliforniaHodl/Bolt21/main/version.json';
  static const String _releasesUrl =
    'https://api.github.com/repos/CaliforniaHodl/Bolt21/releases/latest';
  static const String _dismissedVersionKey = 'bolt21_dismissed_update_version';

  /// Check if app update is required and show blocking dialog if so
  static Future<void> checkForUpdate(BuildContext context) async {
    try {
      final response = await http.get(Uri.parse(_versionUrl))
          .timeout(const Duration(seconds: 10));

      if (response.statusCode != 200) {
        SecureLogger.warn('Version check failed: ${response.statusCode}', tag: 'Update');
        return; // Don't block app if check fails
      }

      final versionInfo = VersionInfo.fromJson(jsonDecode(response.body));
      final packageInfo = await PackageInfo.fromPlatform();
      final currentVersion = packageInfo.version;

      SecureLogger.info(
        'Version check: current=$currentVersion, min=${versionInfo.minVersion}',
        tag: 'Update',
      );

      if (_isVersionLower(currentVersion, versionInfo.minVersion)) {
        if (context.mounted) {
          await _showUpdateDialog(context, versionInfo);
        }
      }
    } catch (e) {
      SecureLogger.warn('Version check error: $e', tag: 'Update');
      // Don't block app on error - let them continue
    }
  }

  /// Compare semantic versions, returns true if current < required
  static bool _isVersionLower(String current, String required) {
    final currentParts = current.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final requiredParts = required.split('.').map((e) => int.tryParse(e) ?? 0).toList();

    // Pad to same length
    while (currentParts.length < 3) currentParts.add(0);
    while (requiredParts.length < 3) requiredParts.add(0);

    for (int i = 0; i < 3; i++) {
      if (currentParts[i] < requiredParts[i]) return true;
      if (currentParts[i] > requiredParts[i]) return false;
    }
    return false; // Equal versions
  }

  /// Show blocking update dialog
  static Future<void> _showUpdateDialog(BuildContext context, VersionInfo info) async {
    await showDialog(
      context: context,
      barrierDismissible: false, // Can't dismiss by tapping outside
      builder: (ctx) => PopScope(
        canPop: false, // Can't use back button
        child: AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.system_update, color: Colors.orange),
              SizedBox(width: 12),
              Text('Update Required'),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(info.message),
              const SizedBox(height: 16),
              Text(
                'Minimum version: ${info.minVersion}',
                style: const TextStyle(
                  color: Colors.grey,
                  fontSize: 12,
                ),
              ),
            ],
          ),
          actions: [
            ElevatedButton(
              onPressed: () => _openStore(info),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.orange,
              ),
              child: const Text('Update Now'),
            ),
          ],
        ),
      ),
    );
  }

  static Future<void> _openStore(VersionInfo info) async {
    // Try platform-specific store URL first, fallback to GitHub releases
    final url = info.storeUrl ??
        'https://github.com/CaliforniaHodl/Bolt21/releases';

    final uri = Uri.parse(url);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  /// Check GitHub releases for optional updates (non-blocking)
  static Future<void> checkForOptionalUpdate(BuildContext context) async {
    try {
      final response = await http.get(
        Uri.parse(_releasesUrl),
        headers: {'Accept': 'application/vnd.github.v3+json'},
      ).timeout(const Duration(seconds: 10));

      if (response.statusCode != 200) {
        return;
      }

      final release = jsonDecode(response.body);
      final tagName = release['tag_name'] as String?;
      if (tagName == null) return;

      // Parse version from tag (e.g., "v1.0.1" -> "1.0.1")
      final latestVersion = tagName.replaceFirst(RegExp(r'^v'), '');
      final packageInfo = await PackageInfo.fromPlatform();
      final currentVersion = packageInfo.version;

      // Check if we've already dismissed this version
      final dismissedVersion = await SecureStorageService.read(_dismissedVersionKey);
      if (dismissedVersion == latestVersion) {
        return;
      }

      if (_isVersionLower(currentVersion, latestVersion)) {
        SecureLogger.info(
          'Optional update available: $currentVersion -> $latestVersion',
          tag: 'Update',
        );

        if (context.mounted) {
          _showUpdateSnackbar(
            context,
            latestVersion,
            release['html_url'] as String?,
          );
        }
      }
    } catch (e) {
      SecureLogger.warn('Optional update check error: $e', tag: 'Update');
    }
  }

  /// Show non-blocking update snackbar
  static void _showUpdateSnackbar(
    BuildContext context,
    String version,
    String? releaseUrl,
  ) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Update available: v$version'),
        backgroundColor: Colors.orange.shade800,
        duration: const Duration(seconds: 10),
        action: SnackBarAction(
          label: 'UPDATE',
          textColor: Colors.white,
          onPressed: () async {
            final url = releaseUrl ?? 'https://github.com/CaliforniaHodl/Bolt21/releases/latest';
            final uri = Uri.parse(url);
            if (await canLaunchUrl(uri)) {
              await launchUrl(uri, mode: LaunchMode.externalApplication);
            }
          },
        ),
      ),
    );
  }

  /// Dismiss update prompt for a specific version
  static Future<void> dismissUpdate(String version) async {
    await SecureStorageService.write(_dismissedVersionKey, version);
  }
}

/// Version information from server
class VersionInfo {
  final String minVersion;
  final String message;
  final String? storeUrl;
  final String? latestVersion;

  VersionInfo({
    required this.minVersion,
    required this.message,
    this.storeUrl,
    this.latestVersion,
  });

  factory VersionInfo.fromJson(Map<String, dynamic> json) {
    return VersionInfo(
      minVersion: json['minVersion'] ?? '0.0.0',
      message: json['message'] ?? 'Please update to the latest version.',
      storeUrl: json['storeUrl'],
      latestVersion: json['latestVersion'],
    );
  }
}
