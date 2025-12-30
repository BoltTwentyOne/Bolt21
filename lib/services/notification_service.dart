import 'dart:async';
import 'package:flutter_breez_liquid/flutter_breez_liquid.dart';
import '../utils/secure_logger.dart';

/// Service for handling payment notifications
class NotificationService {
  static final NotificationService instance = NotificationService._();
  NotificationService._();

  StreamSubscription? _subscription;

  /// Subscribe to SDK events for payment notifications
  void subscribeToPayments(Stream<SdkEvent> eventStream) {
    _subscription?.cancel();
    _subscription = eventStream.listen((event) {
      _handleEvent(event);
    });
    SecureLogger.info('Subscribed to payment notifications', tag: 'Notify');
  }

  void _handleEvent(SdkEvent event) {
    // Handle payment-related events
    if (event is SdkEvent_PaymentSucceeded) {
      SecureLogger.info(
        'Payment succeeded: ${event.details.amountSat} sats',
        tag: 'Notify',
      );
    } else if (event is SdkEvent_PaymentFailed) {
      SecureLogger.warn(
        'Payment failed: ${event.details.amountSat} sats',
        tag: 'Notify',
      );
    }
  }

  /// Unsubscribe from payment events
  void unsubscribe() {
    _subscription?.cancel();
    _subscription = null;
  }
}
