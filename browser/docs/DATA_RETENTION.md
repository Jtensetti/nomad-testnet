# What Nomad Browser leaves behind, and what macOS keeps anyway

This document answers two different questions and is careful not to blur them.

1. What does the application itself store, and does uninstalling remove it?
2. What does macOS retain about the application outside its control, which no
   uninstaller can remove?

The second list is the important one. A privacy tool that only answers the
first is telling its users the comfortable half.

## 1. What the application stores

Nomad Browser is sandboxed (`com.apple.security.app-sandbox`, and nothing
else). Under the sandbox `NSHomeDirectory()` and every standard directory API
resolve inside the app's container, so the app cannot write outside it even by
accident. Everything it stores is therefore under one path:

```
~/Library/Containers/io.nomad.browser/
```

Within that container the application writes exactly one place:

| Path (inside the container) | Contents |
|---|---|
| `Data/Library/Application Support/NomadBrowser/objects/*.nomadobject` | Signed object envelopes materialised for reading |

macOS also writes into the same container on the app's behalf:

| Path (inside the container) | Written by | Why it matters |
|---|---|---|
| `Data/Library/Saved Application State/io.nomad.browser.savedState/` | AppKit window restoration | Can hold window titles, which are document titles |
| `Data/Library/Preferences/io.nomad.browser.plist` | `UserDefaults` / AppKit | Window frames and system-set keys |
| `Data/Library/Caches/` | Foundation | Empty in practice; the app caches nothing itself |

`macos/scripts/uninstall.sh` removes the container in full, which removes
every row in both tables. A test in this repository (`uninstall_test.go`)
checks that the script still names every directory the Swift sources
construct, so adding a new data location without updating the uninstaller
fails the build.

There is no group container, because the app declares no app-groups
entitlement. There are no login items, launch agents or daemons, and no
privileged helper: the bundle installs nothing outside itself.

## 2. What macOS keeps that the uninstaller cannot remove

Each of these survives deleting the app and its container. None of them is a
defect in Nomad Browser; all of them are things a user reasoning about their
own exposure needs to know, and several need a deliberate action to clear.

### Crash reports — the one that can contain object bytes

`~/Library/Logs/DiagnosticReports/NomadBrowser-*.ips`

A macOS crash report records thread stacks with frame arguments as raw machine
words, plus register state. For this process those words can be fragments of a
materialised object. The reports are written **outside the container**, by the
system, and they survive uninstall.

The application cannot prevent their creation. What it can do, and does, is
carry no crash-reporting or telemetry capability of its own: nothing is ever
uploaded by the app, and `egress.Policy` refuses `crash-reporting` and
`telemetry` as denied capabilities. Whether Apple receives a copy is governed
by the user's setting in System Settings → Privacy & Security → Analytics &
Improvements → Share Mac Analytics, which is off by default and is the user's
to decide.

To clear them: delete `~/Library/Logs/DiagnosticReports/NomadBrowser-*`.

### Local snapshots and backups

APFS local snapshots and Time Machine backups hold copies of the container as
it was. Deleting the container does not reach into them.

To clear them: `tmutil listlocalsnapshots /` then
`tmutil deletelocalsnapshot <date>` for each, and thin or exclude the relevant
Time Machine backups. This deletes snapshots of the *whole volume*, so it is
the user's decision, not an uninstaller's.

### Spotlight index

The container is indexed. Deleting the files removes them from the index on the
next pass, but the index can hold extracted text in the interval.

To clear it immediately: `mdutil -E /` reindexes the volume.

### Unified logging and LaunchServices

The application emits no log lines of its own — it calls no `os_log`, `NSLog`
or `print`, which `bundle_test.go` enforces by scanning the Swift sources. The
system nevertheless records that the process launched and when, in the unified
log and in the LaunchServices database, along with the quarantine attribute
recording where the app was downloaded from.

This records *that* the browser ran, never what was read. Unified log entries
age out on the system's own schedule, typically within days, and are not
individually removable.

### Swap and hibernation

Object contents live in memory while a document is open, and memory can reach
disk through swap or the hibernation image. FileVault is the only mitigation,
and it is a whole-disk setting rather than anything this application controls.

### Finder residue outside the container

If the user copies `.nomadobject` files anywhere themselves — the Desktop, a
Downloads folder, a USB volume — those copies are outside the container and
outside the uninstaller's reach by construction. `.DS_Store` files in such
directories can retain the file names after the files are gone.

## 3. What this means for the readiness criteria

H-10 asks for a clean uninstall test and documented OS retention. The
uninstall procedure exists, and the cross-check that it stays complete runs on
every push. The retention analysis is the section above.

What is **not** evidenced: the uninstall script has not been executed on a real
macOS system with a real installed bundle by this project, and the residue
lists above have not been verified empirically against a running install. They
are derived from the platform's documented behaviour and from the app's own
declared capabilities. Verifying them requires a macOS host with the signed
bundle installed, which is the same boundary H-01 and F-09 sit behind.
