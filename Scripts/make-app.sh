#!/bin/sh
# Builds LabDC.app from the SwiftPM executable `LabDCApp` (no Xcode project):
#   Scripts/make-app.sh                  # release build → build/LabDC.app
#   CONFIG=debug Scripts/make-app.sh     # faster, debug build
#   Scripts/make-app.sh /Applications/LabDC.app
# The bundle: Contents/MacOS/LabDC (the executable), Contents/Info.plist
# (dev.labdc.app, LSMinimumSystemVersion 26.0), Contents/Resources/AppIcon.icns; ad-hoc signed.
set -eu
cd "$(dirname "$0")/.."
config="${CONFIG:-release}"
app="${1:-build/LabDC.app}"
bundle_src="Sources/LabDCApp/Bundle"

echo "make-app: swift build -c $config --product LabDCApp"
swift build -c "$config" --product LabDCApp
bin="$(swift build -c "$config" --show-bin-path)/LabDCApp"
[ -x "$bin" ] || { echo "make-app: $bin missing" >&2; exit 1; }

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/LabDC"
# Info.plist also registers the certificate document types (UI-3): .pem/.crt/.cer/.der
# (public.x509-certificate), .p12/.pfx (com.rsa.pkcs-12), .p7b/.p7c, .key and .jks (imported
# dev.labdc.app.* types), so files dropped on the Dock icon open the Certificate Converter.
cp "$bundle_src/Info.plist" "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null || { echo "make-app: Info.plist is not a valid plist" >&2; exit 1; }
printf 'APPL????' > "$app/Contents/PkgInfo"

# AppIcon.icns from the 1024 px placeholder (Scripts/make-icon.swift draws it).
iconset="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$iconset"
for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$bundle_src/AppIcon.png" --out "$iconset/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$bundle_src/AppIcon.png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns -o "$app/Contents/Resources/AppIcon.icns" "$iconset"
rm -rf "$(dirname "$iconset")"

codesign --force --sign - --timestamp=none "$app" >/dev/null 2>&1 || echo "make-app: ad-hoc signing failed (the app still runs locally)"
# Tell Launch Services about the document types (Dock drops, Open With) right away.
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
[ -x "$lsregister" ] && "$lsregister" -f "$app" >/dev/null 2>&1 || true
echo "make-app: built $app"
echo "make-app: open it with: open '$app'   (data: ~/Library/Application Support/LabDC)"
