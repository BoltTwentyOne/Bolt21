package com.bolt21.bolt21

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// NOTE: Must use FlutterFragmentActivity (not FlutterActivity) for local_auth plugin
class MainActivity : FlutterFragmentActivity() {
    private val CHANNEL = "bolt21/screenshot"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // SECURITY: Prevent screenshots and screen recording by default
        // This protects sensitive data like recovery phrases from being captured
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "allowScreenshots" -> {
                    // SECURITY: Allow screenshots (for QR code sharing on receive screen)
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    result.success(null)
                }
                "blockScreenshots" -> {
                    // SECURITY: Block screenshots (default secure state)
                    window.setFlags(
                        WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE
                    )
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }
}
