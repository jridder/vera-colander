#!/usr/bin/env bash
# Builds a universal (Apple Silicon + Intel) "Vera Colander.app" and wraps it in
# a drag-to-Applications DMG: dist/VeraColander-<version>.dmg
set -euo pipefail

cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

APP_NAME="Vera Colander"
BUNDLE_ID="io.github.jridder.veracolander"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

rustup target add "${TARGETS[@]}" >/dev/null
for t in "${TARGETS[@]}"; do
  MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target "$t"
done

BUILD=target/macos
APP="$BUILD/$APP_NAME.app"
rm -rf "$BUILD"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

for b in sievectl-gui sievectl; do
  lipo -create -output "$APP/Contents/MacOS/$b" \
    "target/aarch64-apple-darwin/release/$b" "target/x86_64-apple-darwin/release/$b"
done

# Icon
ICONSET="$BUILD/AppIcon.iconset"
mkdir -p "$ICONSET"
swift packaging/macos/make-icon.swift "$BUILD/icon.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$BUILD/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s * 2)) $((s * 2)) "$BUILD/icon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleExecutable</key><string>sievectl-gui</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
EOF

# Signing. Without SIGN_IDENTITY the app gets an ad-hoc signature (runs locally,
# Gatekeeper warns elsewhere). With a "Developer ID Application: ..." identity
# it is signed for distribution; add NOTARY_PROFILE (a notarytool
# store-credentials profile) to notarize and staple the DMG as well.
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
SIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
[[ "$SIGN_IDENTITY" != "-" ]] && SIGN_ARGS+=(--timestamp)
# Inside-out: nested executables first, then the bundle.
codesign "${SIGN_ARGS[@]}" "$APP/Contents/MacOS/sievectl"
codesign "${SIGN_ARGS[@]}" "$APP"
codesign --verify --deep --strict "$APP"

# DMG with an Applications shortcut to drag onto
STAGE="$BUILD/dmg"
mkdir -p "$STAGE" dist
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="dist/VeraColander-$VERSION.dmg"
rm -f "$DMG"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null

if [[ "$SIGN_IDENTITY" != "-" ]]; then
  codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG"
fi
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
  spctl -a -vv -t install "$DMG"
fi
echo "Built $DMG"
