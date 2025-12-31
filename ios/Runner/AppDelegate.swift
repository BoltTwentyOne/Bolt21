import Flutter
import UIKit
import TrustKit
import os.log

@main
@objc class AppDelegate: FlutterAppDelegate {
  private var securityOverlay: UIView?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)

    // SECURITY: Initialize certificate pinning with TrustKit
    setupCertificatePinning()

    // SECURITY: Add screenshot/screen recording protection
    setupScreenshotProtection()

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  // SECURITY: TrustKit certificate pinning for all HTTPS connections
  // Uses Let's Encrypt certificate chain pins (same as Android)
  private func setupCertificatePinning() {
    let trustKitConfig: [String: Any] = [
      kTSKSwizzleNetworkDelegates: true,
      kTSKPinnedDomains: [
        // Breez API domains
        "api.breez.technology": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            // ISRG Root X1 (Let's Encrypt)
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
            // ISRG Root X2 (Let's Encrypt)
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
            // Let's Encrypt E1 intermediate
            "J2/oqMTsdhFWW/n85tys6b4yDBtb6idZayIEBx7QTxA=",
            // Let's Encrypt R3 intermediate
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
          ],
        ],
        "breez.technology": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
            "J2/oqMTsdhFWW/n85tys6b4yDBtb6idZayIEBx7QTxA=",
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
          ],
        ],
        "greenlight.blockstream.com": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
            "J2/oqMTsdhFWW/n85tys6b4yDBtb6idZayIEBx7QTxA=",
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
          ],
        ],
        // Community Node (Let's Encrypt)
        "community.bolt21.io": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
            "J2/oqMTsdhFWW/n85tys6b4yDBtb6idZayIEBx7QTxA=",
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
          ],
        ],
        // GitHub (app updates) - DigiCert CA chain
        "raw.githubusercontent.com": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "r/mIkJVsUSitA1b1FtRGF+vJlczCzKPct4TGaFOCmJk=",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
            "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
            "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJhPw=",
          ],
        ],
        "api.github.com": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "r/mIkJVsUSitA1b1FtRGF+vJlczCzKPct4TGaFOCmJk=",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
            "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
            "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJhPw=",
          ],
        ],
        "github.com": [
          kTSKEnforcePinning: true,
          kTSKIncludeSubdomains: true,
          kTSKExpirationDate: "2026-12-31",
          kTSKPublicKeyHashes: [
            "r/mIkJVsUSitA1b1FtRGF+vJlczCzKPct4TGaFOCmJk=",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
            "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
            "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJhPw=",
          ],
        ],
      ]
    ]

    TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
  }

  private func setupScreenshotProtection() {
    // Listen for screenshot notifications
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(userDidTakeScreenshot),
      name: UIApplication.userDidTakeScreenshotNotification,
      object: nil
    )

    // Listen for screen capture (recording) - iOS 11+
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(screenCaptureStatusDidChange),
      name: UIScreen.capturedDidChangeNotification,
      object: nil
    )
  }

  @objc private func userDidTakeScreenshot() {
    // SECURITY: Use os_log instead of print() to prevent system log exposure
    // os_log with .fault level goes to private logs only, not accessible to other apps
    os_log("Screenshot detected", log: .default, type: .fault)
  }

  @objc private func screenCaptureStatusDidChange() {
    if UIScreen.main.isCaptured {
      // Screen is being recorded - show security overlay
      showSecurityOverlay()
    } else {
      // Recording stopped - remove overlay
      hideSecurityOverlay()
    }
  }

  private func showSecurityOverlay() {
    guard securityOverlay == nil, let window = self.window else { return }

    let overlay = UIView(frame: window.bounds)
    overlay.backgroundColor = .black
    overlay.tag = 999

    let label = UILabel()
    label.text = "Screen recording detected.\nContent hidden for security."
    label.textColor = .white
    label.textAlignment = .center
    label.numberOfLines = 0
    label.translatesAutoresizingMaskIntoConstraints = false

    overlay.addSubview(label)
    NSLayoutConstraint.activate([
      label.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
      label.centerYAnchor.constraint(equalTo: overlay.centerYAnchor),
      label.leadingAnchor.constraint(greaterThanOrEqualTo: overlay.leadingAnchor, constant: 20),
      label.trailingAnchor.constraint(lessThanOrEqualTo: overlay.trailingAnchor, constant: -20)
    ])

    window.addSubview(overlay)
    securityOverlay = overlay
  }

  private func hideSecurityOverlay() {
    securityOverlay?.removeFromSuperview()
    securityOverlay = nil
  }

  override func applicationWillResignActive(_ application: UIApplication) {
    // SECURITY: Hide content when app goes to background (app switcher)
    showSecurityOverlay()
    super.applicationWillResignActive(application)
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    // Show content again when app becomes active (unless screen is being recorded)
    if !UIScreen.main.isCaptured {
      hideSecurityOverlay()
    }
    super.applicationDidBecomeActive(application)
  }
}
