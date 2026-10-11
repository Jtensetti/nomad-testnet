#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source_root="$repo_root/macos/Sources/NomadBrowser"
entitlements="$repo_root/macos/NomadBrowser.entitlements"
test_app_group="N0MADTEST1.nomad.browser-cache"

forbidden='import[[:space:]]+(WebKit|Network|FoundationNetworking|Darwin)|URLSession|WKWebView|WKURLSchemeHandler|NWConnection|NWBrow|CFNetwork|CFStream|NSStream|NSAppleScript|SFSafariApplication|NSWorkspace\.shared\.open|openURL\(|Process[[:space:]]*\(|(^|[^[:alnum:]_])(socket|connect|sendto|recvfrom|getaddrinfo|dlopen|dlsym)[[:space:]]*\('
if LC_ALL=C grep -ERnE "$forbidden" "$source_root"; then
    echo "forbidden ordinary-network or external-navigation capability in macOS client" >&2
    exit 1
fi

# The browser-cache App Group is a materializer -> browser data plane only.
# Browser source must not gain a generic filesystem write primitive. More
# importantly, the network domain uses a different fabric-cache App Group, so
# browser membership cannot become a browser->network command path.
write_capability='createDirectory[[:space:]]*\(|removeItem[[:space:]]*\(|moveItem[[:space:]]*\(|copyItem[[:space:]]*\(|replaceItem[[:space:]]*\(|FileHandle|OutputStream|\.write[[:space:]]*\(to:'
if LC_ALL=C grep -ERnE "$write_capability" "$source_root"; then
    echo "browser source contains a filesystem write capability; shared cache must remain read-only from the reader side" >&2
    exit 1
fi

if ! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "$entitlements" | grep -qx true; then
    echo "app sandbox entitlement is required" >&2
    exit 1
fi

if /usr/libexec/PlistBuddy -c 'Print' "$entitlements" | grep -Eq 'com\.apple\.security\.network\.(client|server)'; then
    echo "network client/server entitlements are forbidden" >&2
    exit 1
fi

# The checked-in entitlement is a harmless CI template. build_dmg.sh replaces
# this exact value with <APPLE_TEAM_ID>.nomad.browser-cache in the signing copy
# and writes the same value into the signed Info.plist.
app_group="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' "$entitlements")"
if [[ "$app_group" != "$test_app_group" ]]; then
    echo "Nomad browser-cache App Group entitlement template changed unexpectedly" >&2
    exit 1
fi
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:1' "$entitlements" >/dev/null 2>&1; then
    echo "browser must belong to exactly one App Group" >&2
    exit 1
fi

if ! grep -RFn 'static let appGroupInfoKey = "NomadAppGroupIdentifier"' "$source_root" >/dev/null; then
    echo "browser no longer binds shared-cache lookup to signed release configuration" >&2
    exit 1
fi
if ! grep -RFn 'static let appGroupSuffix = ".nomad.browser-cache"' "$source_root" >/dev/null; then
    echo "browser source is not pinned to the browser-cache group suffix" >&2
    exit 1
fi
if grep -ERn 'nomad\.(shared|fabric-cache)' "$source_root"; then
    echo "browser source references a shared/fabric cache group and could cross the network boundary" >&2
    exit 1
fi

swift test --package-path "$repo_root/macos"
