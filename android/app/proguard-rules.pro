# Flutter-specific rules
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Breez SDK - keep all native bridge classes
-keep class breez_sdk_liquid.** { *; }
-keep class technology.breez.** { *; }

# Keep JSON serialization classes
-keepattributes *Annotation*
-keepattributes Signature

# Keep TrustKit for certificate pinning
-keep class com.datatheorem.android.trustkit.** { *; }

# Keep LocalAuthentication for biometrics
-keep class androidx.biometric.** { *; }

# Prevent stripping of native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Ignore missing Play Core classes (not used in this app)
-dontwarn com.google.android.play.core.**

# Flutter deferred components (not used)
-dontwarn io.flutter.embedding.engine.deferredcomponents.**
