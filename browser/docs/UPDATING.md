# Updating Nomad Browser

## Why there is no auto-updater

Every other browser ships a background updater that polls a server. Nomad
cannot, and the reason is not caution — it is that an updater which fetches is
a network client living inside the binary that is supposed to have none.

The whole security story rests on one sentence: this process cannot open a
socket. That is enforced by the sandbox entitlement, checked on every push
(`bundle_test.go`), and it is what makes every other control in the browser
defence in depth rather than the last line. An auto-updater would put a
deliberate exception inside that sentence, and from then on the guarantee would
read "cannot open a socket, except this component, which we believe behaves".
Exceptions of that shape are how networkless designs stop being networkless.

So updates are out of band. You fetch a release the way you fetch anything
else, with whatever tool you already trust, and the browser's job is narrower
and more useful: decide whether what you have may be installed over what you
are running.

## Updating

1. Obtain `NomadBrowser-<version>.dmg` and its `release.json` manifest.
2. Verify and record the install:

   ```
   nomad-browser-verify \
       -manifest release.json \
       -artifact NomadBrowser-<version>.dmg \
       -watermark ~/Library/Containers/io.nomad.browser/Data/installed.json
   ```

   The verifier refuses and prints why if anything is wrong. It never warns and
   proceeds.
3. If it accepts, mount the image and replace the application.

## What the verifier refuses

Three attacks, each refused by name rather than by accident.

**Rollback.** A validly signed *older* release, replayed to move you back to a
version whose flaws are known. The installed version is recorded in a watermark
and anything not strictly newer is refused. Pre-release ordering is part of
this: `1.2.0-alpha.1` is older than `1.2.0`, so a signed alpha cannot be
installed over the final build of the same version.

**Equivocation.** Two validly signed releases carrying the same version number
and different artefacts. This is refused rather than resolved, because
resolving it silently — taking the newer file, or the one that arrived last —
is exactly how a build made for one person reaches that person. If you see
this, you have two different things claiming to be one release and you should
find out why before installing either.

**Substitution.** A genuine manifest paired with a different file. The
artefact's size and SHA-256 must match what the signature covers.

Beyond those, everything about verification fails closed: an unknown manifest
version is refused rather than downgraded to one this build understands, an
unknown field or trailing data is refused, an artefact name containing a path
separator is refused, and a manifest signed by a key this build does not trust
is refused even though its own signature is internally consistent. Trust comes
from the build, never from the manifest naming its own key.

## Recovery

**The verifier refuses an update you believe is genuine.** It prints which
check failed. A signature failure means the file is not what the release key
signed — do not install it. A rollback refusal means you already run something
newer.

**The watermark is corrupt or unreadable.** The verifier refuses the install
rather than treating the watermark as absent. That is deliberate: treating an
unreadable watermark as "no install recorded" would let anyone able to corrupt
one file switch rollback protection off. Recovery is to restore the watermark
from a backup, or — if you accept losing rollback protection for one install —
delete it and re-verify, which the tool treats as a first install.

Note that a *refused* install never rewrites the watermark, so one rejection
cannot wedge future updates. The watermark is written by rename, so an
interrupted write leaves the previous one intact rather than a truncated file.

**You installed a release you now want off.** Rollback protection is doing its
job, so the verifier will not let you install the older version over it.
Uninstall (`macos/scripts/uninstall.sh`, see `docs/DATA_RETENTION.md`) and
install the version you want as a fresh install. That removes your objects
along with everything else, which is the honest cost of the protection.

## What is not built

The verifier exists and is tested. What does not exist yet:

- No macOS installer integration: nothing calls the verifier automatically
  when a user mounts a disk image, so today this is a manual step.
- No release key. `docs/` carries no public key because none has been
  generated; see `EXTERNAL_BLOCKERS.md` in nomad-protocol (EB-7). Until then
  the mechanism is exercised only against test keys.
- No OS-backed key storage for the trusted release key (H-09). It is a build
  constant, which is the right place for a *public* key, but the private half
  has no documented custody.
