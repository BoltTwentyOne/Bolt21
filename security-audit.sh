#!/bin/bash
# Bolt21 Security Audit Script
# Automated security checks for pre-release verification
# Usage: ./security-audit.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

echo -e "${BLUE}🔍 Running Bolt21 Security Audit...${NC}"
echo ""

# 1. Check for debugPrint
echo "1️⃣  Checking for debugPrint..."
if grep -rn "debugPrint(" lib/ --include="*.dart" 2>/dev/null | grep -v "secure_logger.dart" > /dev/null; then
  echo -e "   ${RED}❌ FAIL: debugPrint found outside SecureLogger${NC}"
  grep -rn "debugPrint(" lib/ --include="*.dart" | grep -v "secure_logger.dart" | head -5
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  echo -e "   ${GREEN}✅ PASS: No raw debugPrint calls${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
fi
echo ""

# 2. Check biometricOnly
echo "2️⃣  Checking biometric settings..."
if grep -rn "biometricOnly.*false" lib/ --include="*.dart" 2>/dev/null > /dev/null; then
  echo -e "   ${RED}❌ FAIL: biometricOnly: false found${NC}"
  grep -rn "biometricOnly.*false" lib/
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  echo -e "   ${GREEN}✅ PASS: biometricOnly: true enforced${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
fi
echo ""

# 3. Check certificate pins (Android)
echo "3️⃣  Checking Android certificate pins..."
if [ -f "android/app/src/main/res/xml/network_security_config.xml" ]; then
  if grep -q "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=" android/app/src/main/res/xml/network_security_config.xml; then
    echo -e "   ${GREEN}✅ PASS: Valid Android certificate pins${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "   ${RED}❌ FAIL: Android certificate pins missing or invalid${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
else
  echo -e "   ${RED}❌ FAIL: network_security_config.xml not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# 4. Check certificate pins (iOS)
echo "4️⃣  Checking iOS certificate pins..."
if [ -f "ios/Runner/AppDelegate.swift" ]; then
  if grep -q "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=" ios/Runner/AppDelegate.swift; then
    echo -e "   ${GREEN}✅ PASS: Valid iOS certificate pins${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "   ${RED}❌ FAIL: iOS certificate pins missing or invalid${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
else
  echo -e "   ${RED}❌ FAIL: AppDelegate.swift not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# 5. Check config.json bundling
echo "5️⃣  Checking config.json bundling..."
# Check if config.json is in the assets section (not just comments)
if grep -A10 "^  assets:" pubspec.yaml 2>/dev/null | grep -v "^\s*#" | grep -q "config.json"; then
  echo -e "   ${RED}❌ FAIL: config.json listed in pubspec.yaml assets${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  echo -e "   ${GREEN}✅ PASS: config.json NOT bundled in app${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
fi
echo ""

# 6. Check git dependency pinning
echo "6️⃣  Checking git dependency pinning..."
if grep -A3 "flutter_breez_liquid:" pubspec.yaml 2>/dev/null | grep -q "ref: main"; then
  echo -e "   ${RED}❌ FAIL: Git dependency not pinned (using ref: main)${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
elif grep -A3 "flutter_breez_liquid:" pubspec.yaml 2>/dev/null | grep -q "ref: [a-f0-9]"; then
  echo -e "   ${GREEN}✅ PASS: Git dependencies pinned to commit hash${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${YELLOW}⚠️  WARN: Could not verify git dependency pinning${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 7. Check for print() in Swift
echo "7️⃣  Checking Swift print() statements..."
if [ -d "ios/Runner" ]; then
  SWIFT_PRINTS=$(grep -rn "print(" ios/Runner/*.swift 2>/dev/null | grep -v "os_log" | grep -v "//" || true)
  if [ -n "$SWIFT_PRINTS" ]; then
    echo -e "   ${YELLOW}⚠️  WARN: print() found in Swift (should use os_log)${NC}"
    echo "$SWIFT_PRINTS" | head -3
    WARN_COUNT=$((WARN_COUNT + 1))
  else
    echo -e "   ${GREEN}✅ PASS: No raw print() in Swift files${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
else
  echo -e "   ${YELLOW}⚠️  WARN: ios/Runner directory not found${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 8. Check .gitignore
echo "8️⃣  Checking .gitignore configuration..."
if [ -f ".gitignore" ]; then
  if grep -q "assets/config.json" .gitignore 2>/dev/null; then
    echo -e "   ${GREEN}✅ PASS: config.json in .gitignore${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "   ${YELLOW}⚠️  WARN: config.json NOT in .gitignore${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
  fi
else
  echo -e "   ${YELLOW}⚠️  WARN: .gitignore not found${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 9. Check security documentation
echo "9️⃣  Checking security documentation..."
if [ -f "SECURITY.md" ]; then
  echo -e "   ${GREEN}✅ PASS: SECURITY.md exists${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${YELLOW}⚠️  WARN: SECURITY.md missing${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 10. Check for FLAG_SECURE (Android)
echo "🔟 Checking Android screen capture protection..."
if [ -f "android/app/src/main/kotlin/com/bolt21/bolt21/MainActivity.kt" ]; then
  if grep -q "FLAG_SECURE" android/app/src/main/kotlin/com/bolt21/bolt21/MainActivity.kt 2>/dev/null; then
    echo -e "   ${GREEN}✅ PASS: FLAG_SECURE enabled${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "   ${RED}❌ FAIL: FLAG_SECURE not found${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
else
  echo -e "   ${YELLOW}⚠️  WARN: MainActivity.kt not found${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 11. Check for TrustKit in Podfile
echo "1️⃣1️⃣  Checking iOS TrustKit dependency..."
if [ -f "ios/Podfile" ]; then
  if grep -q "TrustKit" ios/Podfile 2>/dev/null; then
    echo -e "   ${GREEN}✅ PASS: TrustKit pod added${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "   ${RED}❌ FAIL: TrustKit not in Podfile${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
else
  echo -e "   ${YELLOW}⚠️  WARN: Podfile not found${NC}"
  WARN_COUNT=$((WARN_COUNT + 1))
fi
echo ""

# 12. Check for AES-256-GCM
echo "1️⃣2️⃣  Checking encryption implementation..."
if grep -q "AesGcm.with256bits()" lib/services/operation_state_service.dart 2>/dev/null; then
  echo -e "   ${GREEN}✅ PASS: AES-256-GCM encryption used${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${RED}❌ FAIL: AES-256-GCM not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# 13. Check for synchronized lock
echo "1️⃣3️⃣  Checking atomic lock implementation..."
if grep -q "synchronized" lib/providers/wallet_provider.dart 2>/dev/null; then
  echo -e "   ${GREEN}✅ PASS: Atomic lock (synchronized) implemented${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${RED}❌ FAIL: synchronized lock not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# 14. Check for payment re-auth
echo "1️⃣4️⃣  Checking payment re-authentication..."
if grep -q "_paymentReauthThresholdSats" lib/screens/send_screen.dart 2>/dev/null; then
  echo -e "   ${GREEN}✅ PASS: Payment re-auth threshold set${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${RED}❌ FAIL: Payment re-auth not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# 15. Check for balance validation
echo "1️⃣5️⃣  Checking balance validation..."
if grep -q "Insufficient balance" lib/providers/wallet_provider.dart 2>/dev/null; then
  echo -e "   ${GREEN}✅ PASS: Balance validation implemented${NC}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo -e "   ${RED}❌ FAIL: Balance validation not found${NC}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}✨ Audit Complete!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "Results:"
echo -e "  ${GREEN}✅ PASS: $PASS_COUNT${NC}"
echo -e "  ${YELLOW}⚠️  WARN: $WARN_COUNT${NC}"
echo -e "  ${RED}❌ FAIL: $FAIL_COUNT${NC}"
echo ""

# Determine grade
if [ $FAIL_COUNT -eq 0 ] && [ $WARN_COUNT -eq 0 ]; then
  echo -e "${GREEN}🎉 GRADE A - EXCELLENT! All checks passed.${NC}"
  EXIT_CODE=0
elif [ $FAIL_COUNT -eq 0 ] && [ $WARN_COUNT -le 2 ]; then
  echo -e "${YELLOW}⭐ GRADE B+ - GOOD! Minor warnings present.${NC}"
  echo -e "   Fix warnings to achieve Grade A."
  EXIT_CODE=0
elif [ $FAIL_COUNT -eq 0 ]; then
  echo -e "${YELLOW}⚠️  GRADE B - ACCEPTABLE. Address warnings.${NC}"
  EXIT_CODE=1
elif [ $FAIL_COUNT -le 2 ]; then
  echo -e "${RED}❌ GRADE C - NEEDS WORK! Fix failures before release.${NC}"
  EXIT_CODE=1
else
  echo -e "${RED}🚨 GRADE D or F - CRITICAL ISSUES! DO NOT RELEASE!${NC}"
  EXIT_CODE=2
fi

echo ""
echo "Required for Grade A:"
echo "  - All checks must PASS (✅)"
echo "  - Zero warnings (⚠️)"
echo "  - Zero failures (❌)"
echo ""

if [ $EXIT_CODE -eq 0 ]; then
  echo -e "${GREEN}✅ Safe to proceed with release.${NC}"
else
  echo -e "${RED}⚠️  Fix issues before releasing.${NC}"
fi

echo ""
echo "For detailed findings, see: security-report-post-P0-fixes.md"
echo "For fix instructions, see: GRADE-A-FIXES.md"
echo ""

exit $EXIT_CODE
