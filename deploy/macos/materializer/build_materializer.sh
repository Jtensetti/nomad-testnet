#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
materializer_root="$repo_root/deploy/macos/materializer"
dist="$repo_root/dist-materializer"
version="${NOMAD_MATERIALIZER_VERSION:-0.1.0-alpha.1}"
build_number="${NOMAD_BUILD_NUMBER:-1}"
identity="${CODESIGN_IDENTITY:--}"
team_id="${APPLE_TEAM_ID:-N0MADTEST1}"

if [[ ! "$team_id" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "APPLE_TEAM_ID must be exactly 10 uppercase ASCII letters/digits" >&2
    exit 1
fi
if [[ "$identity" != "-" && -z "${APPLE_TEAM_ID:-}" ]]; then
    echo "Developer ID signing requires APPLE_TEAM_ID" >&2
    exit 1
fi

fabric_group="${team_id}.nomad.fabric-cache"
browser_group="${team_id}.nomad.browser-cache"
app="$dist/Nomad Materializer.app"
binary="$app/Contents/MacOS/NomadMaterializer"

rm -rf "$dist"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# The materializer is the deliberately networkless bridge between two storage
# domains. Reject an accidental direct socket/HTTP import at the command layer.
direct_imports="$(go list -f '{{join .Imports "\n"}}' ./cmd/nomad-materializer)"
if printf '%s\n' "$direct_imports" | grep -Eq '^(net|net/http|net/url)$'; then
    echo "materializer command gained a direct networking dependency" >&2
    exit 1
fi

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$dist/materializer-arm64" ./cmd/nomad-materializer
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o "$dist/materializer-amd64" ./cmd/nomad-materializer
lipo -create -output "$binary" "$dist/materializer-arm64" "$dist/materializer-amd64"
rm -f "$dist/materializer-arm64" "$dist/materializer-amd64"

description="$(file "$binary")"
if [[ "$description" != *arm64* || "$description" != *x86_64* ]]; then
    echo "materializer is not universal: $description" >&2
    exit 1
fi

cp "$materializer_root/Info.plist" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build_number" "$app/Contents/Info.plist"

signing_entitlements="$dist/NomadMaterializer.signing.entitlements"
cp "$materializer_root/NomadMaterializer.entitlements" "$signing_entitlements"
/usr/libexec/PlistBuddy -c "Set :com.apple.security.application-groups:0 $fabric_group" "$signing_entitlements"
/usr/libexec/PlistBuddy -c "Set :com.apple.security.application-groups:1 $browser_group" "$signing_entitlements"

sign_args=(
    --force
    --strict
    --options runtime
    --entitlements "$signing_entitlements"
)
if [[ "$identity" != "-" ]]; then
    sign_args+=(--timestamp)
fi
codesign "${sign_args[@]}" --sign "$identity" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
codesign --display --entitlements - "$app" >"$dist/effective-entitlements.plist"

if ! grep -Eq 'com\.apple\.security\.app-sandbox' "$dist/effective-entitlements.plist"; then
    echo "materializer lost App Sandbox" >&2
    exit 1
fi
if grep -Eq 'com\.apple\.security\.network\.(client|server)' "$dist/effective-entitlements.plist"; then
    echo "materializer unexpectedly has network capability" >&2
    exit 1
fi
first_group="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' "$dist/effective-entitlements.plist")"
second_group="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:1' "$dist/effective-entitlements.plist")"
if [[ "$first_group" != "$fabric_group" || "$second_group" != "$browser_group" ]]; then
    echo "materializer App Group boundary does not match expected two-domain bridge" >&2
    exit 1
fi
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:2' "$dist/effective-entitlements.plist" >/dev/null 2>&1; then
    echo "materializer has an unexpected third App Group" >&2
    exit 1
fi

# Launch the exact signed binary. -h exits before touching campaign inputs, but
# proves the packaged universal executable starts under its signed sandbox.
"$binary" -h >/dev/null 2>&1

(
    cd "$dist"
    shasum -a 256 "Nomad Materializer.app/Contents/MacOS/NomadMaterializer" > NomadMaterializer.sha256
)

printf 'materializer boundary: %s -> networkless materializer -> %s\n' "$fabric_group" "$browser_group"
printf '%s\n' "$app"
