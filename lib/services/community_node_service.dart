import 'dart:convert';
import 'package:http/http.dart' as http;
import 'secure_storage_service.dart';
import '../utils/secure_logger.dart';

/// Service for routing payments through the Bolt21 Community Node
///
/// This allows users to route payments through a community-operated
/// Lightning node for potentially lower fees, with fallback to Breez.
class CommunityNodeService {
  static const _communityNodeUrlKey = 'bolt21_community_node_url';
  static const _communityNodeEnabledKey = 'bolt21_community_node_enabled';

  // Default community node URL
  // Set up community.bolt21.io to point to your node's proxy
  // Users can override this in settings
  static const String defaultNodeUrl = 'https://community.bolt21.io';

  String? _nodeUrl;
  bool _isEnabled = false;
  CommunityNodeStatus? _cachedStatus;

  bool get isEnabled => _isEnabled;
  String? get nodeUrl => _nodeUrl;
  CommunityNodeStatus? get status => _cachedStatus;

  /// Initialize and check if community node is enabled
  Future<void> initialize() async {
    _isEnabled = await SecureStorageService.read(_communityNodeEnabledKey) == 'true';
    _nodeUrl = await SecureStorageService.read(_communityNodeUrlKey) ?? defaultNodeUrl;

    if (_isEnabled) {
      await checkStatus();
    }
  }

  /// Enable community node routing
  Future<void> enable() async {
    await SecureStorageService.write(_communityNodeEnabledKey, 'true');
    _isEnabled = true;
    await checkStatus();
  }

  /// Disable community node routing
  Future<void> disable() async {
    await SecureStorageService.write(_communityNodeEnabledKey, 'false');
    _isEnabled = false;
    _cachedStatus = null;
  }

  /// Set custom node URL (for advanced users)
  Future<void> setNodeUrl(String url) async {
    await SecureStorageService.write(_communityNodeUrlKey, url);
    _nodeUrl = url;
  }

  /// Check community node status
  Future<CommunityNodeStatus?> checkStatus() async {
    if (_nodeUrl == null) return null;

    try {
      final response = await http.get(
        Uri.parse('$_nodeUrl/status'),
      ).timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final json = jsonDecode(response.body);
        _cachedStatus = CommunityNodeStatus.fromJson(json);
        SecureLogger.info('Community node online: ${_cachedStatus?.alias}', tag: 'Community');
        return _cachedStatus;
      }
    } catch (e) {
      SecureLogger.warn('Community node offline: $e', tag: 'Community');
      _cachedStatus = null;
    }

    return null;
  }

  /// Pay invoice via community node
  /// Returns payment result or null if failed
  Future<CommunityPaymentResult?> payInvoice({
    required String invoice,
    int? amountSat,
  }) async {
    if (!_isEnabled || _nodeUrl == null) return null;

    try {
      final body = <String, dynamic>{'invoice': invoice};
      if (amountSat != null) {
        body['amount'] = amountSat;
      }

      final response = await http.post(
        Uri.parse('$_nodeUrl/pay'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(body),
      ).timeout(const Duration(seconds: 65)); // LND timeout is 60s

      final json = jsonDecode(response.body);

      if (response.statusCode == 200 && json['success'] == true) {
        SecureLogger.info(
          'Payment via community node: ${json['amountSat']} sats (fee: ${json['feeSat']})',
          tag: 'Community',
        );
        return CommunityPaymentResult(
          success: true,
          paymentHash: json['paymentHash'],
          feeSat: json['feeSat'] ?? 0,
          amountSat: json['amountSat'] ?? 0,
        );
      } else {
        SecureLogger.warn('Community node payment failed: ${json['error']}', tag: 'Community');
        return CommunityPaymentResult(
          success: false,
          error: json['error'] ?? 'Unknown error',
        );
      }
    } catch (e) {
      SecureLogger.warn('Community node request failed: $e', tag: 'Community');
      return null; // Return null to trigger fallback
    }
  }

  /// Generate invoice via community node
  Future<String?> createInvoice({
    required int amountSat,
    String? memo,
  }) async {
    if (!_isEnabled || _nodeUrl == null) return null;

    try {
      final response = await http.post(
        Uri.parse('$_nodeUrl/invoice'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'amount': amountSat,
          'memo': memo ?? 'Bolt21',
        }),
      ).timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final json = jsonDecode(response.body);
        return json['invoice'];
      }
    } catch (e) {
      SecureLogger.warn('Community node invoice failed: $e', tag: 'Community');
    }

    return null;
  }
}

/// Community node status info
class CommunityNodeStatus {
  final bool online;
  final String? alias;
  final int channels;
  final int spendable;
  final int receivable;
  final int feeRatePpm;

  CommunityNodeStatus({
    required this.online,
    this.alias,
    this.channels = 0,
    this.spendable = 0,
    this.receivable = 0,
    this.feeRatePpm = 0,
  });

  factory CommunityNodeStatus.fromJson(Map<String, dynamic> json) {
    return CommunityNodeStatus(
      online: json['online'] ?? false,
      alias: json['alias'],
      channels: json['channels'] ?? 0,
      spendable: json['spendable'] ?? 0,
      receivable: json['receivable'] ?? 0,
      feeRatePpm: json['feeRatePpm'] ?? 0,
    );
  }
}

/// Result of a community node payment
class CommunityPaymentResult {
  final bool success;
  final String? paymentHash;
  final int feeSat;
  final int amountSat;
  final String? error;

  CommunityPaymentResult({
    required this.success,
    this.paymentHash,
    this.feeSat = 0,
    this.amountSat = 0,
    this.error,
  });
}
