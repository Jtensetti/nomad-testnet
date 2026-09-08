#!/usr/bin/env bash
#
# Remove Nomad Browser and everything it stored.
#
# This script removes what the application controls. It deliberately does not
# claim to remove what macOS retains outside the app's reach -- crash reports,
# local snapshots, the Spotlight index, unified log entries, swap. It prints
# those at the end with the command for each, so a user who needs them gone
# makes that decision themselves rather than having a whole-volume operation
# done to them by an uninstaller.
#
# docs/DATA_RETENTION.md explains each one.
set -euo pipefail

bundle_id="io.nomad.browser"
app_name="Nomad Browser.app"

dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
    dry_run=1
fi

removed=0
remove() {
    local path="$1" description="$2"
    if [ ! -e "$path" ]; then
        printf '  absent  %s\n' "$path"
        return
    fi
    if [ "$dry_run" -eq 1 ]; then
        printf '  would remove  %s (%s)\n' "$path" "$description"
        return
    fi
    rm -rf -- "$path"
    printf '  removed  %s (%s)\n' "$path" "$description"
    removed=$((removed + 1))
}

if pgrep -x NomadBrowser >/dev/null 2>&1; then
    echo "Nomad Browser is running. Quit it first: removing its container while it" >&2
    echo "is open lets the app recreate what this script deletes." >&2
    exit 1
fi

echo "Removing the application and its container:"

# The sandbox container. Under com.apple.security.app-sandbox every standard
# directory API resolves inside this path, so it holds all application state:
# the objects directory, saved window state, and preferences.
remove "$HOME/Library/Containers/$bundle_id" "sandbox container: saved state, preferences"

# The App Group container, which is where the objects actually live.
#
# The sandbox container above used to hold them. It does not any more: the
# browser reads verified objects from a Team-scoped shared container so the
# materializer can be the only thing that writes into it, and that container is
# outside the app's own. An uninstaller that removed only the sandbox container
# left every object a reader had materialised on disk -- which is a record of
# what they read.
#
# Matched by suffix rather than by Team ID, because the Team ID is a build-time
# value this script does not have and the app may already be gone by the time
# anyone runs this. macos/scripts/security_gate.sh pins the suffix and fails the
# build on a second group, so the glob cannot match anything but a Nomad
# browser-cache group.
group_containers=0
for container in "$HOME/Library/Group Containers/"*.nomad.browser-cache; do
    [ -e "$container" ] || continue
    group_containers=$((group_containers + 1))
    remove "$container" "shared object cache: everything materialised for this reader"
done
if [ "$group_containers" -eq 0 ]; then
    printf '  absent  %s\n' "$HOME/Library/Group Containers/<TeamID>.nomad.browser-cache"
fi

# The bundle itself, wherever the user put it.
remove "/Applications/$app_name" "application bundle"
remove "$HOME/Applications/$app_name" "application bundle in the user's Applications"

# An unsandboxed build -- a local `swift run`, or a bundle built without the
# entitlement -- writes here instead of into the container. Removing it costs
# nothing and forgetting it would leave objects behind on exactly the machines
# where a developer tested.
remove "$HOME/Library/Application Support/NomadBrowser" "unsandboxed object store, if this machine ever ran one"

# Preferences and saved state outside the container, for the same reason.
remove "$HOME/Library/Preferences/$bundle_id.plist" "unsandboxed preferences"
remove "$HOME/Library/Saved Application State/$bundle_id.savedState" "unsandboxed saved window state"
remove "$HOME/Library/Caches/$bundle_id" "unsandboxed cache"

if [ "$dry_run" -eq 1 ]; then
    echo
    echo "Dry run: nothing was removed."
else
    echo
    printf 'Removed %d item(s).\n' "$removed"
fi

cat <<'NOTICE'

The following are retained by macOS outside this application's control. This
script does not touch them, because each is either shared with the rest of the
system or a decision only you should make. See docs/DATA_RETENTION.md.

  Crash reports may contain fragments of objects you read, as raw stack words.
  They are written by the system, outside the container, and survive uninstall.
      rm -f ~/Library/Logs/DiagnosticReports/NomadBrowser-*

  Local APFS snapshots and Time Machine backups hold earlier copies of the
  container. Deleting snapshots affects the whole volume, not just this app.
      tmutil listlocalsnapshots /
      tmutil deletelocalsnapshot <date>

  The Spotlight index can hold extracted text until its next pass.
      sudo mdutil -E /

  Unified log entries record that the app launched, never what was read. They
  age out on the system's schedule and are not individually removable.

  Memory can reach disk through swap or the hibernation image. FileVault is
  the only mitigation, and it is a whole-disk setting.

  Any .nomadobject files you copied outside the container are yours to find.
NOTICE
