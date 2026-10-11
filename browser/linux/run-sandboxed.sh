#!/usr/bin/env bash
#
# Runs the Nomad Linux client in an empty network namespace, for people who are
# not using systemd. It is the same enforcement as nomad-browser.service:
# the client cannot reach the network because there is no network to reach.
#
# Usage: linux/run-sandboxed.sh -trust <base64 publisher key> [-objects DIR]
set -euo pipefail

client="${NOMAD_BROWSER_BIN:-nomad-browser}"
if ! command -v "$client" >/dev/null 2>&1 && [ ! -x "$client" ]; then
  echo "run-sandboxed: $client not found; set NOMAD_BROWSER_BIN or install it" >&2
  exit 1
fi

if command -v bwrap >/dev/null 2>&1; then
  # bubblewrap where it exists: an empty network namespace plus a read-only
  # filesystem view, so the client sees the object directory and little else.
  objects="${NOMAD_OBJECT_DIR:-$HOME/.local/share/nomad/objects}"
  exec bwrap \
    --unshare-net --unshare-pid --unshare-ipc --unshare-uts \
    --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
    --ro-bind "$objects" "$objects" \
    --ro-bind "$(command -v "$client" 2>/dev/null || echo "$client")" /usr/local/bin/nomad-browser \
    --proc /proc --dev /dev --tmpfs /tmp \
    --die-with-parent --new-session \
    /usr/local/bin/nomad-browser "$@"
fi

if unshare --user --map-root-user --net true 2>/dev/null; then
  exec unshare --user --map-root-user --net "$client" "$@"
fi

# No silent fallback: running without the namespace would leave the networkless
# claim resting on the program alone, which is not what this script promises.
echo "run-sandboxed: neither bubblewrap nor unprivileged network namespaces are" >&2
echo "available, so the sandbox cannot be established. Refusing to run without it." >&2
exit 1
