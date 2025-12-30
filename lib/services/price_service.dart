import 'dart:convert';
import 'package:http/http.dart' as http;
import '../utils/secure_logger.dart';

/// Service for fetching Bitcoin price
class PriceService {
  static final PriceService instance = PriceService._();
  PriceService._();

  double? _btcPriceUsd;
  DateTime? _lastFetch;

  double? get btcPriceUsd => _btcPriceUsd;

  /// Fetch current BTC price in USD
  Future<void> fetchBtcPrice() async {
    // Cache for 5 minutes
    if (_lastFetch != null &&
        DateTime.now().difference(_lastFetch!) < const Duration(minutes: 5)) {
      return;
    }

    try {
      // Use CoinGecko API (free, no API key needed)
      final response = await http.get(
        Uri.parse('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd'),
      ).timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        _btcPriceUsd = (data['bitcoin']['usd'] as num).toDouble();
        _lastFetch = DateTime.now();
        SecureLogger.info('BTC price updated: \$$_btcPriceUsd', tag: 'Price');
      }
    } catch (e) {
      SecureLogger.warn('Failed to fetch BTC price: $e', tag: 'Price');
      // Keep old price if fetch fails
    }
  }

  /// Convert sats to USD
  double? satsToUsd(int sats) {
    if (_btcPriceUsd == null) return null;
    return (sats / 100000000) * _btcPriceUsd!;
  }

  /// Convert USD to sats
  int? usdToSats(double usd) {
    if (_btcPriceUsd == null) return null;
    return ((usd / _btcPriceUsd!) * 100000000).round();
  }

  /// Convert sats to BTC
  double satsToBtc(int sats) {
    return sats / 100000000;
  }

  /// Format BTC value
  String formatBtc(double btc) {
    if (btc >= 1) {
      return '${btc.toStringAsFixed(4)} BTC';
    } else if (btc >= 0.001) {
      return '${(btc * 1000).toStringAsFixed(4)} mBTC';
    } else {
      return '${(btc * 100000000).toInt()} sats';
    }
  }

  /// Format USD value
  String formatUsd(double usd) {
    return '\$${usd.toStringAsFixed(2)}';
  }
}
