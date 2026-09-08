# Releasing Nomad Browser

PROD-30 asks for a release approved through a documented two-person process.
This document exists, but it is not what enforces the rule. A process that
lives only in a document holds exactly as long as everyone remembers it and
nobody is in a hurry, and "nobody is in a hurry" is false precisely when a
release matters most — a security fix, an incident, a deadline.

So the rule is a control. A release manifest carries **approvals**, and
`update.Decode` refuses one that does not carry signatures from at least two
**distinct** trusted approver keys. The refusal happens on the machine that
would otherwise install the release, which is the one party with no incentive
to skip the step.

## What is enforced, and what is not

Enforced by code, each with an adversarial test:

- fewer than two approvals — refused;
- two approvals from the same key — refused, because one person signing twice
  is one person;
- an approval from a key this build does not trust — refused;
- a build whose trusted set is one key, or one key listed twice — refused
  before any manifest is even read, because such a build cannot express a
  two-person rule at all;
- an approval moved from one release to another — refused, since approvals
  cover the version, channel, artifact name, digest and size.

Not enforced by code, and it cannot be:

- **that the two approvers are two people.** Two keys held by one person
  satisfy every check above. Key custody is what makes this a two-person
  process, and it is an operational property, not a cryptographic one.
- **that the approvers read anything before approving.** The signature says a
  person approved this exact artifact; it does not say they were right to.

## The steps

1. **Build reproducibly.** `scripts/check-reproducible.sh` must pass. Record
   the digests. See `REPRODUCIBILITY.md` for what determinism does and does not
   establish, and why a second builder (EB-2) is a separate claim.
2. **Generate the SBOM and provenance** for the exact artifact.
3. **Prepare the manifest** with `update.Prepare`, naming the release, channel,
   artifact name, SHA-256 and byte count.
4. **Each approver signs separately**, with `update.Approve`, on their own
   machine, with their own key. `Approve` takes one key by design: a function
   that took two at once would be a two-person process one person can run.
5. **Verify as a user would**, with the shipped binary:
   ```
   nomad-browser-verify -manifest manifest.json -artifact NomadBrowser-X.dmg \
     -watermark installed.json -dry-run
   ```
   A build with fewer than two compiled-in approver keys refuses here and says
   so.
6. **Record the decision** — approvers, digests, CI run, and what each approver
   checked — in `nomad-protocol production/EVIDENCE_INDEX.md`.

## The Linux client

The steps above are written for the macOS disk image, which is what this
project has released. The Linux client is built by `linux-release.yml` --
reproducibly for amd64 and arm64, with an SBOM and provenance -- and until
2026-09-02 that workflow had never run, because its tag pattern matched no tag
this project creates and `workflow_dispatch` cannot fire from a non-default
branch. So the question of how a Linux artifact reaches anyone had never come
up.

**The mechanism is the same one.** A manifest names an artifact, a digest and
a byte count; nothing in `update/` mentions macOS, a disk image or an
application bundle. `update/linux_release_test.go` drives the whole path with a
real gzipped tarball: two distinct approvals required, one approver signing
twice refused, a padded archive refused on length before its hash, and a
manifest for the amd64 tarball refusing the arm64 one. That last case matters
here more than on macOS, because a release has two Linux artifacts and a
manifest must not authorise the other.

**What differs, and what an operator has to know.**

1. **Tag.** `nomad-browser-linux-v<version>`, which is what `linux-release.yml`
   now triggers on. The macOS tag is `nomad-browser-macos-v<version>`. They are
   separate tags because they are separate artifacts with separate digests, and
   one manifest cannot cover both.
2. **No notarization, and no equivalent.** macOS artifacts are Developer
   ID-signed and notarized (EB-1). Linux has no platform-level equivalent, so
   the two approvals and the digest in the manifest are the *whole* of the
   authenticity story. On macOS they are one layer of two.
3. **Verification is the same command.** `nomad-browser-verify` takes the
   artifact path and does not care what is in it:
   ```
   nomad-browser-verify -manifest manifest.json \
     -artifact nomad-browser-linux-amd64.tar.gz \
     -watermark installed.json -dry-run
   ```
   A build with fewer than two compiled-in approver keys refuses here and says
   so, exactly as on macOS.
4. **Both architectures, or neither.** A release publishes amd64 and arm64
   together, each with its own manifest. Publishing one is a release that
   silently drops a platform.

**Not yet true.** No Linux release has been made, and per DEC-027 the client
stays a build target until there is a decision to offer it. What has changed is
that the process no longer stops that decision: the gap DEC-027 recorded was
that there was no process, and there now is one.

## Rollback

There is no automatic rollback, and that is deliberate. An updater that can
move a user backwards is an updater an attacker can move a user backwards, and
`update.AcceptMonotonic` therefore refuses any release at or below the
installed version, and refuses two different artifacts claiming one version
rather than choosing between them.

**To withdraw a bad release, roll *forward*.** Publish a new version, higher
than the bad one, containing the previous good build. It needs two approvals
like any other release, including under incident pressure — that is when the
rule is worth having.

**A user already on the bad release** cannot be reached by the project: the
browser fetches nothing (see `UPDATING.md`). Withdrawal is an announcement plus
a roll-forward, and its reach is bounded by who reads the announcement. Say so
in the advisory rather than implying recall.

**If an approver key is compromised**, a release approved by that key and one
other is still a valid release to every installed copy, because trust is
compiled in. There is no revocation channel. Rotating the trusted set requires
shipping a new binary, which requires a release, which requires the compromised
set — so the recovery path runs through whichever approver keys remain
uncompromised, and a build must never trust exactly two keys if losing one is
meant to be survivable. This is a real limitation of a fetch-nothing design and
is recorded rather than solved.

## What is missing for PROD-30

- **A monitored multi-operator beta.** Nothing has been given to users at all.
- **A release red team.** An internal adversarial exercise is not one; PROD-30
  wants a red team, which is EB-4.
- **Two people.** The mechanism is ready and no release keys exist (EB-7), nor
  a second approver (EB-6). Until then the process is exercised only against
  test keys, which the tool says out loud every time it is used that way.
- **A decision about the Linux client.** The process now covers it and the
  build now runs, but nothing has been offered to anyone; DEC-027 records that
  it stays a build target until that is decided.
