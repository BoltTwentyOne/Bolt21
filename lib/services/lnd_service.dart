import 'dart:convert';
import 'package:http/http.dart' as http;
import '../utils/secure_logger.dart';

/// Service for connecting to a remote LND node via REST API
class LndService {
  String? _restUrl;
  String? _macaroon;
  bool _isConnected = false;

  bool get isConnected => _isConnected;
  String? get restUrl => _restUrl;

  /// Configure the LND connection
  void configure({
    required String restUrl,
    required String macaroon,
  }) {
    // Normalize URL (remove trailing slash)
    _restUrl = restUrl.endsWith('/') ? restUrl.substring(0, restUrl.length - 1) : restUrl;
    _macaroon = macaroon;
    _isConnected = false;
  }

  /// Test the connection and get node info
  Future<LndNodeInfo> connect() async {
    _ensureConfigured();

    try {
      final info = await getInfo();
      _isConnected = true;
      SecureLogger.info('Connected to LND: ${info.alias}', tag: 'LND');
      return info;
    } catch (e) {
      _isConnected = false;
      SecureLogger.error('LND connection failed', error: e, tag: 'LND');
      rethrow;
    }
  }

  /// Disconnect from LND
  void disconnect() {
    _restUrl = null;
    _macaroon = null;
    _isConnected = false;
  }

  /// Get node info
  Future<LndNodeInfo> getInfo() async {
    final response = await _get('/v1/getinfo');
    return LndNodeInfo.fromJson(response);
  }

  /// Get wallet balance (on-chain + channels)
  Future<LndBalance> getBalance() async {
    final walletBalance = await _get('/v1/balance/blockchain');
    final channelBalance = await _get('/v1/balance/channels');

    return LndBalance(
      onChainConfirmed: int.parse(walletBalance['confirmed_balance'] ?? '0'),
      onChainUnconfirmed: int.parse(walletBalance['unconfirmed_balance'] ?? '0'),
      channelLocal: int.parse(channelBalance['local_balance']?['sat'] ?? '0'),
      channelRemote: int.parse(channelBalance['remote_balance']?['sat'] ?? '0'),
      channelPending: int.parse(channelBalance['pending_open_local_balance']?['sat'] ?? '0'),
    );
  }

  /// Create a BOLT11 invoice
  Future<String> createInvoice({
    required int amountSat,
    String? memo,
    int expiry = 3600,
  }) async {
    final response = await _post('/v1/invoices', {
      'value': amountSat.toString(),
      'memo': memo ?? '',
      'expiry': expiry.toString(),
    });

    return response['payment_request'] as String;
  }

  /// Pay a BOLT11 invoice
  Future<LndPaymentResult> payInvoice({
    required String paymentRequest,
    int? amountSat, // For zero-amount invoices
    int? feeLimitSat,
    int timeoutSeconds = 60,
  }) async {
    final body = <String, dynamic>{
      'payment_request': paymentRequest,
      'timeout_seconds': timeoutSeconds,
    };

    if (amountSat != null) {
      body['amt'] = amountSat.toString();
    }

    if (feeLimitSat != null) {
      body['fee_limit'] = {'fixed': feeLimitSat.toString()};
    }

    final response = await _post('/v1/channels/transactions', body);

    final error = response['payment_error'] as String?;
    if (error != null && error.isNotEmpty) {
      throw LndPaymentException(error);
    }

    return LndPaymentResult(
      paymentHash: response['payment_hash'] as String,
      paymentPreimage: response['payment_preimage'] as String,
      feeSat: int.parse(response['payment_route']?['total_fees'] ?? '0'),
      amountSat: int.parse(response['payment_route']?['total_amt'] ?? '0'),
    );
  }

  /// Decode a payment request
  Future<LndDecodedInvoice> decodeInvoice(String paymentRequest) async {
    final response = await _get('/v1/payreq/$paymentRequest');

    return LndDecodedInvoice(
      destination: response['destination'] as String,
      paymentHash: response['payment_hash'] as String,
      amountSat: int.parse(response['num_satoshis'] ?? '0'),
      description: response['description'] as String? ?? '',
      expiry: int.parse(response['expiry'] ?? '3600'),
      timestamp: int.parse(response['timestamp'] ?? '0'),
    );
  }

  /// List recent payments
  Future<List<LndPayment>> listPayments({int maxPayments = 50}) async {
    final response = await _get('/v1/payments?max_payments=$maxPayments&reversed=true');

    final payments = response['payments'] as List<dynamic>? ?? [];
    return payments.map((p) => LndPayment.fromJson(p)).toList();
  }

  /// List invoices
  Future<List<LndInvoice>> listInvoices({int numMaxInvoices = 50}) async {
    final response = await _get('/v1/invoices?num_max_invoices=$numMaxInvoices&reversed=true');

    final invoices = response['invoices'] as List<dynamic>? ?? [];
    return invoices.map((i) => LndInvoice.fromJson(i)).toList();
  }

  /// HTTP GET request
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

  /// HTTP POST request
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

  Map<String, String> get _headers => {
    'Grpc-Metadata-macaroon': _macaroon!,
    'Content-Type': 'application/json',
  };

  void _ensureConfigured() {
    if (_restUrl == null || _macaroon == null) {
      throw LndNotConfiguredException();
    }
  }
}

// Data classes

class LndNodeInfo {
  final String pubkey;
  final String alias;
  final int numActiveChannels;
  final int numPeers;
  final int blockHeight;
  final bool syncedToChain;

  LndNodeInfo({
    required this.pubkey,
    required this.alias,
    required this.numActiveChannels,
    required this.numPeers,
    required this.blockHeight,
    required this.syncedToChain,
  });

  factory LndNodeInfo.fromJson(Map<String, dynamic> json) {
    return LndNodeInfo(
      pubkey: json['identity_pubkey'] as String? ?? '',
      alias: json['alias'] as String? ?? 'Unknown',
      numActiveChannels: json['num_active_channels'] as int? ?? 0,
      numPeers: json['num_peers'] as int? ?? 0,
      blockHeight: json['block_height'] as int? ?? 0,
      syncedToChain: json['synced_to_chain'] as bool? ?? false,
    );
  }
}

class LndBalance {
  final int onChainConfirmed;
  final int onChainUnconfirmed;
  final int channelLocal;
  final int channelRemote;
  final int channelPending;

  LndBalance({
    required this.onChainConfirmed,
    required this.onChainUnconfirmed,
    required this.channelLocal,
    required this.channelRemote,
    required this.channelPending,
  });

  int get totalOnChain => onChainConfirmed + onChainUnconfirmed;
  int get spendableBalance => channelLocal;
  int get totalBalance => onChainConfirmed + channelLocal;
}

class LndPaymentResult {
  final String paymentHash;
  final String paymentPreimage;
  final int feeSat;
  final int amountSat;

  LndPaymentResult({
    required this.paymentHash,
    required this.paymentPreimage,
    required this.feeSat,
    required this.amountSat,
  });
}

class LndDecodedInvoice {
  final String destination;
  final String paymentHash;
  final int amountSat;
  final String description;
  final int expiry;
  final int timestamp;

  LndDecodedInvoice({
    required this.destination,
    required this.paymentHash,
    required this.amountSat,
    required this.description,
    required this.expiry,
    required this.timestamp,
  });

  bool get isExpired {
    final expiryTime = DateTime.fromMillisecondsSinceEpoch((timestamp + expiry) * 1000);
    return DateTime.now().isAfter(expiryTime);
  }
}

class LndPayment {
  final String paymentHash;
  final int amountSat;
  final int feeSat;
  final int creationTime;
  final String status;

  LndPayment({
    required this.paymentHash,
    required this.amountSat,
    required this.feeSat,
    required this.creationTime,
    required this.status,
  });

  factory LndPayment.fromJson(Map<String, dynamic> json) {
    return LndPayment(
      paymentHash: json['payment_hash'] as String? ?? '',
      amountSat: int.parse(json['value_sat'] ?? '0'),
      feeSat: int.parse(json['fee_sat'] ?? '0'),
      creationTime: int.parse(json['creation_time_ns'] ?? '0') ~/ 1000000000,
      status: json['status'] as String? ?? 'UNKNOWN',
    );
  }

  bool get isSucceeded => status == 'SUCCEEDED';
}

class LndInvoice {
  final String paymentRequest;
  final String paymentHash;
  final int amountSat;
  final int amountPaidSat;
  final String memo;
  final int creationDate;
  final bool settled;

  LndInvoice({
    required this.paymentRequest,
    required this.paymentHash,
    required this.amountSat,
    required this.amountPaidSat,
    required this.memo,
    required this.creationDate,
    required this.settled,
  });

  factory LndInvoice.fromJson(Map<String, dynamic> json) {
    return LndInvoice(
      paymentRequest: json['payment_request'] as String? ?? '',
      paymentHash: json['r_hash'] as String? ?? '',
      amountSat: int.parse(json['value'] ?? '0'),
      amountPaidSat: int.parse(json['amt_paid_sat'] ?? '0'),
      memo: json['memo'] as String? ?? '',
      creationDate: int.parse(json['creation_date'] ?? '0'),
      settled: json['settled'] as bool? ?? false,
    );
  }
}

// Exceptions

class LndNotConfiguredException implements Exception {
  @override
  String toString() => 'LND not configured. Call configure() first.';
}

class LndApiException implements Exception {
  final String message;
  LndApiException(this.message);

  @override
  String toString() => 'LND API Error: $message';
}

class LndPaymentException implements Exception {
  final String message;
  LndPaymentException(this.message);

  @override
  String toString() => 'LND Payment Error: $message';
}
