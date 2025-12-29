package com.bolt21.bolt21

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity

// NOTE: Must use FlutterFragmentActivity (not FlutterActivity) for local_auth plugin
class MainActivity : FlutterFragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // SECURITY: Prevent screenshots and screen recording
        // This protects sensitive data like recovery phrases from being captured
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
