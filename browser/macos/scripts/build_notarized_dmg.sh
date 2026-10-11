#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
dist="$repo_root/dist"

required=(
    APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64
    APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD
    APPLE_NOTARY_KEY_P8_BASE64
    APPLE_NOTARY_KEY_ID
    APPLE_NOTARY_ISSUER_ID
    APPLE_TEAM_ID
)
for name in "${required[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        echo "required signing secret is not configured: $name" >&2
        exit 1
    fi
done

credential_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/nomad-notary.XXXXXX")"
certificate_path="$credential_root/developer-id.p12"
notary_key_path="$credential_root/AuthKey_${APPLE_NOTARY_KEY_ID}.p8"
keychain_path="$credential_root/signing.keychain-db"
keychain_password="$(openssl rand -hex 32)"
mounted_path=""

cleanup() {
    if [[ -n "$mounted_path" ]]; then
        hdiutil detach "$mounted_path" -quiet >/dev/null 2>&1 || true
    fi
    security delete-keychain "$keychain_path" >/dev/null 2>&1 || true
    rm -f "$certificate_path" "$notary_key_path" "$keychain_path"
    rmdir "$credential_root" >/dev/null 2>&1 || true
}
trap cleanup EXIT

umask 077
printf '%s' "$APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D >"$certificate_path"
printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | /usr/bin/base64 -D >"$notary_key_path"
unset APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64 APPLE_NOTARY_KEY_P8_BASE64

security create-keychain -p "$keychain_password" "$keychain_path"
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security import "$certificate_path" \
    -k "$keychain_path" \
    -P "$APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD" \
    -A -t cert -f pkcs12
unset APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s -k "$keychain_password" "$keychain_path" >/dev/null
security list-keychains -d user -s "$keychain_path"

identity="$(security find-identity -v -p codesigning "$keychain_path" | awk '/Developer ID Application/ {print $2; exit}')"
if [[ ! "$identity" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "the imported archive contains no valid Developer ID Application identity" >&2
    exit 1
fi

CODESIGN_IDENTITY="$identity" bash "$repo_root/macos/scripts/build_dmg.sh"

app="$dist/Nomad Browser.app"
dmg="$(find "$dist" -maxdepth 1 -type f -name 'Nomad-Browser-*-macOS-universal.dmg' -print -quit)"
if [[ -z "$dmg" ]]; then
    echo "signed DMG was not produced" >&2
    exit 1
fi

signature="$(codesign --display --verbose=4 "$app" 2>&1)"
if ! grep -Fq 'Authority=Developer ID Application:' <<<"$signature"; then
    echo "application is not signed by a Developer ID Application certificate" >&2
    exit 1
fi
if ! grep -Fqx "TeamIdentifier=$APPLE_TEAM_ID" <<<"$signature"; then
    echo "application TeamIdentifier does not match APPLE_TEAM_ID" >&2
    exit 1
fi
if ! grep -Fq 'Timestamp=' <<<"$signature"; then
    echo "application signature has no secure timestamp" >&2
    exit 1
fi
if ! grep -Eq 'flags=.*\(runtime\)' <<<"$signature"; then
    echo "application signature does not enable the hardened runtime" >&2
    exit 1
fi

notary_result="$dist/notarization-result.json"
xcrun notarytool submit "$dmg" \
    --key "$notary_key_path" \
    --key-id "$APPLE_NOTARY_KEY_ID" \
    --issuer "$APPLE_NOTARY_ISSUER_ID" \
    --wait --timeout 30m --output-format json >"$notary_result"

status="$(plutil -extract status raw -o - "$notary_result")"
submission_id="$(plutil -extract id raw -o - "$notary_result")"
if [[ "$status" != "Accepted" ]]; then
    echo "Apple notarization was not accepted (status: $status, id: $submission_id)" >&2
    xcrun notarytool log "$submission_id" \
        --key "$notary_key_path" \
        --key-id "$APPLE_NOTARY_KEY_ID" \
        --issuer "$APPLE_NOTARY_ISSUER_ID" || true
    exit 1
fi

xcrun notarytool log "$submission_id" \
    --key "$notary_key_path" \
    --key-id "$APPLE_NOTARY_KEY_ID" \
    --issuer "$APPLE_NOTARY_ISSUER_ID" \
    >"$dist/notarization-log.json"
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
spctl --assess --type open --context context:primary-signature --verbose=4 "$dmg"

mounted_path="$(mktemp -d "${RUNNER_TEMP:-/tmp}/nomad-mounted.XXXXXX")"
hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mounted_path" -quiet
codesign --verify --deep --strict --verbose=2 "$mounted_path/Nomad Browser.app"
spctl --assess --type execute --verbose=4 "$mounted_path/Nomad Browser.app"
hdiutil detach "$mounted_path" -quiet
rmdir "$mounted_path"
mounted_path=""

dmg_name="$(basename "$dmg")"
(
    cd "$dist"
    shasum -a 256 "$dmg_name" >"$dmg_name.sha256"
)

printf 'accepted notarization id: %s\n' "$submission_id"
printf '%s\n' "$dmg"
