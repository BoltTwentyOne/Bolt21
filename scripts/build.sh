#!/bin/bash
# Build script for Bolt21 - loads API keys from .env.local

set -e

# Load environment variables from .env.local
if [ -f ".env.local" ]; then
    export $(grep -v '^#' .env.local | xargs)
    echo "Loaded API keys from .env.local"
else
    echo "Warning: .env.local not found. Build may fail without API keys."
    echo "Create .env.local with: BREEZ_API_KEY=your_key_here"
fi

# Check for required keys
if [ -z "$BREEZ_API_KEY" ]; then
    echo "Error: BREEZ_API_KEY not set"
    exit 1
fi

# Build type (default: release)
BUILD_TYPE=${1:-release}

echo "Building Bolt21 ($BUILD_TYPE)..."

flutter build apk --$BUILD_TYPE \
    --dart-define=BREEZ_API_KEY="$BREEZ_API_KEY"

echo ""
echo "Build complete!"
echo "APK: build/app/outputs/flutter-apk/app-$BUILD_TYPE.apk"
