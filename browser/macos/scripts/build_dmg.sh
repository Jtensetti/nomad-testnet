#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
macos_root="$repo_root/macos"
dist="$repo_root/dist"
version="${NOMAD_VERSION:-0.1.0-alpha.2}"
build_number="${NOMAD_BUILD_NUMBER:-1}"
identity="${CODESIGN_IDENTITY:--}"
team_id="${APPLE_TEAM_ID:-N0MADTEST1}"
app="$dist/Nomad Browser.app"

if [[ ! "$team_id" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "APPLE_TEAM_ID must be exactly 10 uppercase ASCII letters/digits" >&2
    exit 1
fi
if [[ "$identity" != "-" && -z "${APPLE_TEAM_ID:-}" ]]; then
    echo "Developer ID signing requires APPLE_TEAM_ID; refusing to sign with the CI test App Group" >&2
    exit 1
fi
app_group_id="${team_id}.nomad.browser-cache"

rm -rf "$dist"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

bash "$macos_root/scripts/security_gate.sh"
swift build --package-path "$macos_root" -c release --arch arm64 --arch x86_64

binary="$(find "$macos_root/.build" -type f -name NomadBrowser -perm -111 | grep -E '/(release|Release)/NomadBrowser$' | head -n 1)"
if [[ -z "$binary" ]]; then
    echo "universal NomadBrowser executable was not produced" >&2
    exit 1
fi
binary_description="$(file "$binary")"
if [[ "$binary_description" != *arm64* || "$binary_description" != *x86_64* ]]; then
    echo "release executable is not universal: $binary_description" >&2
    exit 1
fi
cp "$binary" "$app/Contents/MacOS/NomadBrowser"

resource_bundle="$(find "$macos_root/.build" -type d -name 'NomadBrowser_NomadBrowser.bundle' | head -n 1)"
if [[ -z "$resource_bundle" ]]; then
    echo "SwiftPM resource bundle was not produced" >&2
    exit 1
fi
cp -R "$resource_bundle" "$app/Contents/Resources/"

cp "$macos_root/Info.plist" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build_number" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Delete :NomadAppGroupIdentifier' "$app/Contents/Info.plist" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Add :NomadAppGroupIdentifier string $app_group_id" "$app/Contents/Info.plist"

icon_png="$dist/AppIcon-1024.png"
swift "$macos_root/scripts/make_icon.swift" "$icon_png"
iconset="$dist/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$icon_png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    doubled=$((size * 2))
    sips -z "$doubled" "$doubled" "$icon_png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

# Never sign directly from the checked-in entitlement template. Generate a
# release-specific copy whose browser-cache group is bound to the signing Team
# ID. The transport domain will use a different .nomad.fabric-cache group.
signing_entitlements="$dist/NomadBrowser.signing.entitlements"
cp "$macos_root/NomadBrowser.entitlements" "$signing_entitlements"
/usr/libexec/PlistBuddy -c "Set :com.apple.security.application-groups:0 $app_group_id" "$signing_entitlements"

app_sign_args=(
    --force
    --deep
    --strict
    --options runtime
    --entitlements "$signing_entitlements"
)
if [[ "$identity" != "-" ]]; then
    app_sign_args+=(--timestamp)
fi
codesign "${app_sign_args[@]}" --sign "$identity" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
codesign --display --entitlements - --xml "$app" >"$dist/effective-entitlements.plist"
if ! grep -Eq 'com\.apple\.security\.app-sandbox' "$dist/effective-entitlements.plist"; then
    echo "signed application lost its sandbox entitlement" >&2
    exit 1
fi
if grep -Eq 'com\.apple\.security\.network\.(client|server)' "$dist/effective-entitlements.plist"; then
    echo "signed application unexpectedly has network capability" >&2
    exit 1
fi
signed_group="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' "$dist/effective-entitlements.plist")"
if [[ "$signed_group" != "$app_group_id" ]]; then
    echo "signed application App Group '$signed_group' does not match release group '$app_group_id'" >&2
    exit 1
fi
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:1' "$dist/effective-entitlements.plist" >/dev/null 2>&1; then
    echo "signed browser contains an unexpected additional App Group" >&2
    exit 1
fi
configured_group="$(/usr/libexec/PlistBuddy -c 'Print :NomadAppGroupIdentifier' "$app/Contents/Info.plist")"
if [[ "$configured_group" != "$signed_group" ]]; then
    echo "runtime shared-cache identifier does not match signed App Group entitlement" >&2
    exit 1
fi
if [[ "$signed_group" == *'.nomad.fabric-cache' ]]; then
    echo "browser must never receive the transport fabric-cache App Group" >&2
    exit 1
fi

linked="$(otool -L "$app/Contents/MacOS/NomadBrowser")"
if printf '%s\n' "$linked" | grep -Eq '/(WebKit|CFNetwork|Network)\.framework/'; then
    echo "release binary links an ordinary-network or web engine framework" >&2
    printf '%s\n' "$linked" >&2
    exit 1
fi

dmg_root="$dist/dmg-root"
mkdir -p "$dmg_root"
cp -R "$app" "$dmg_root/"
ln -s /Applications "$dmg_root/Applications"
dmg="$dist/Nomad-Browser-${version}-macOS-universal.dmg"
hdiutil create -volname "Nomad Browser" -srcfolder "$dmg_root" -ov -format UDZO "$dmg" >/dev/null
if [[ "$identity" != "-" ]]; then
    codesign --force --timestamp --sign "$identity" "$dmg"
fi
hdiutil verify "$dmg"
dmg_name="$(basename "$dmg")"
(
    cd "$dist"
    shasum -a 256 "$dmg_name" >"$dmg_name.sha256"
)
printf '%s\n' "$dmg"
