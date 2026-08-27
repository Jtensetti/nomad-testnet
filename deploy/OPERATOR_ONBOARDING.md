# Nomad operator onboarding

> **Draft handoff, not yet an operator-ready release.** The lifecycle
> controller, read-only artifact exchange and automatic READY/import path are
> implemented on draft PR #16. Exact-head hosted CI, independent operators,
> and WAN execution are still absent. Epoch-scoped key rotation and the live
> later-compromise experiment are implemented locally but are not release
> evidence until their exact commit passes the required CI matrix.
> Operators may use this document to estimate requirements, but must not
> collect production evidence against it yet.

You are being asked to run a Nomad mix operator. This document is written
for you, the operator's administrator, and is meant to be followed without
reading the rest of the project.

**What "independent" means here, and why it matters.** Nomad's privacy
depends on at least one committee member being honest, and its key custody
depends on no single party holding enough shares to decrypt. Neither
property survives if one person administers every operator. So the thing
that makes you valuable is precisely that the Nomad maintainers **cannot**
log into your machine, cannot read your private keys, and cannot act on your
behalf. Any instruction that would require otherwise is wrong — please
refuse it and tell us.

## What you are committing to

| | |
|---|---|
| Hardware | One always-on Linux host, 2 vCPU / 4 GB RAM / 40 GB disk is ample |
| Network | A stable public IPv4 or IPv6 address, four open inbound ports |
| Time | About an hour to set up; a few minutes per epoch rotation thereafter |
| Duration | Ideally 6+ months, since replacing an operator is a protocol event |
| Not required | Any access to Nomad infrastructure, any shared account |

You will hold private keys that only you ever see. You will be asked to
attest documents — read them before you sign; that reading *is* the security
control you provide.

## Before you start

1. **Full-disk encryption is mandatory.** Key erasure at epoch retirement
   guarantees destruction of files within an encrypted volume, and nothing
   stronger. Without FDE the erasure claim does not hold.
2. **Do not back up shares or epoch secret files.** Backups defeat erasure.
   Loss is handled as an operator-replacement event; never preserve retired
   KEX or DKG private material merely to preserve the stable identity.
3. Have your own admin account on your own host. Do not share credentials
   with any other operator or with the maintainers.

## Step 1 — Create your identity, locally

```
nomad-operator init \
  --id <your-operator-id> \
  --endpoint <public-host>:4200 \
  --partial-endpoint http://<public-host>:8080/ \
  --dkg-endpoint https://<public-host>:8443/ \
  --secret /etc/nomad/secrets/epoch-00000000000000000001.secrets.json \
  --enrollment ./epoch-1.enrollment.json
```

This generates three private keys — an Ed25519 identity, an X25519
key-agreement key, and a DKG identity — and writes them to
the epoch-1 secret file with mode 0600. **That file never leaves your host.**
Nobody else, including the maintainers, ever needs it or should be given it.

`enrollment.json` is public and self-signed. Send that one, and only that
one, to the coordinator.

Confirm what you created without opening the secret by hand:

```
nomad-operator inspect \
  --secret /etc/nomad/secrets/epoch-00000000000000000001.secrets.json
```

It prints your public keys only.

## Step 2 — Read and attest the topology draft

The coordinator assembles everyone's enrollments into a draft topology and
sends it back. **Read it before attesting.** Check that:

- your own entry matches what `inspect` printed;
- the operator set is who you expect, and no unexpected party is present;
- the threshold and validity window are what was agreed;
- the DKG schedule gives you enough notice.

Then:

```
nomad-operator attest \
  --secret /etc/nomad/secrets/epoch-00000000000000000001.secrets.json \
  --draft ./draft.json \
  --out ./attestation.json
```

Send `attestation.json` back. It commits to the exact draft digest, so if
anyone alters a single byte afterwards your attestation stops verifying.
This is deliberate: your signature is what stops the coordinator changing
membership unilaterally.

## Step 3 — Verify the signed topology

Once the authority has collected every attestation and signed the result:

```
nomad-operator verify \
  --secret /etc/nomad/secrets/epoch-00000000000000000001.secrets.json \
  --topology ./topology.json \
  --authority-key ./authority.pub
```

This confirms your keys really are in the activated topology and that every
other operator attested the same document. If it fails, stop and report it
rather than proceeding.

## Step 4 — Run genesis DKG; stage successor attempts

The topology names an absolute start time. Run:

```
nomad-dkg --topology ./topology.json --authority-key ./authority.pub \
  --secrets /etc/nomad/secrets/epoch-00000000000000000001.secrets.json \
  --state /var/lib/nomad/dkg \
  --share-out /var/lib/nomad/shares/epoch-N.share.json \
  --certificate-out ./certificate.json --listen :8443 \
  --tls-certificate /etc/nomad/tls/dkg.crt \
  --tls-private-key /etc/nomad/tls/dkg.key
```

Every configured operator must be online and complete the ceremony; there is
no partial success. The standalone command above is used for genesis and
diagnosis. For normal successors, stage each authority/operator-attested
topology as
`topologies/epoch-000000000000000000NN/attempt-AA/topology.json`; the rotation
controller below owns the DKG invocation. If an attempt aborts, do not
improvise or restart it — wait for the next public retry offset. A retry must
keep every membership, endpoint, key, peer-plan, traffic, validity, threshold
and phase-duration field identical, while using a fresh session ID and a
strictly later signed start. The controller enforces this before opening a
ceremony.

## Step 5 — Rotate epoch keys and run automatic descriptor coordination

Before an N+1 enrollment or topology exists, generate its private material in
a **new** file. This keeps the Ed25519 operator identity but replaces both the
X25519 hop key and dedicated DKG identity:

```
nomad-operator rotate \
  --from-secret /etc/nomad/secrets/epoch-000000000000000000NN.secrets.json \
  --endpoint <public-host>:4200 \
  --partial-endpoint http://<public-host>:8080/ \
  --dkg-endpoint https://<public-host>:8443/ \
  --secret /etc/nomad/secrets/epoch-000000000000000000PP.secrets.json \
  --enrollment ./epoch-PP.enrollment.json
```

Here `PP = NN+1`; filenames use 20 decimal digits. Never overwrite N. Retry
attempts for the same N+1 reuse the N+1 file, while every later epoch gets new
KEX and DKG keys. Descriptor verification rejects reuse of any earlier
epoch's KEX or DKG key, even after an intervening epoch. Keep both files until
N retires because the controller uses N to approve and N+1 to activate. A
leaving operator still creates a fresh local custody file so it can sign N's erasure, even if its enrollment is
not selected for N+1.

Create separate private state, share and signature-journal directories and a
public exchange directory. The lifecycle service is always the signed DKG
endpoint's TCP port plus one, with the same HTTP/TLS mode. Thus the example
`https://<public-host>:8443` reserves
`https://<public-host>:8444`. Both TLS files are required for HTTPS; HTTP is
accepted only on loopback test topologies.

```
install -d -m 0700 \
  /var/lib/nomad/epoch-chain /var/lib/nomad/revocations \
  /etc/nomad/secrets \
  /var/lib/nomad/rotation/state /var/lib/nomad/rotation/shares \
  /var/lib/nomad/rotation/certificates /var/lib/nomad/rotation/exchange \
  /var/lib/nomad/rotation/signature-journal

nomad-rotation-controller \
  --chain /var/lib/nomad/epoch-chain \
  --revocations /var/lib/nomad/revocations \
  --authority-key ./authority.pub --network <network-id> \
  --operator-id <your-operator-id> \
  --topology-dir /etc/nomad/rotation/topologies \
  --secrets-dir /etc/nomad/secrets \
  --listen :8443 --control-listen :8444 \
  --state /var/lib/nomad/rotation/state \
  --share-dir /var/lib/nomad/rotation/shares \
  --certificate-dir /var/lib/nomad/rotation/certificates \
  --exchange /var/lib/nomad/rotation/exchange \
  --signature-journal /var/lib/nomad/rotation/signature-journal \
  --tls-certificate /etc/nomad/tls/dkg.crt \
  --tls-private-key /etc/nomad/tls/dkg.key \
  --prepare-lead 6h --retry-offsets 1h,2h --escalate-after 3h \
  --control-interval 30s
```

The public lifecycle server has no upload or listing method. It serves exact,
immutable certificate, draft, approval, activation and descriptor paths; each
peer fetch is one direct request to the endpoint derived from the signed
topology. The client ignores proxy environment variables, refuses redirects,
does not retry inside a round and waits for the next UTC-aligned public tick
after failure. Missing artifacts never produce a burst or fallback.

Each operator independently derives the identical draft, signs through its
durable anti-equivocation journal, gathers the previous-epoch approval quorum
and all incoming activations, assembles the descriptor and imports it locally
as READY. If that is not complete before `activate_at`, the controller does
not import late: the outgoing epoch retires and the network is down. A missed
tick is skipped rather than replayed as catch-up traffic.

The detached commands below remain the inspectable offline/recovery equivalent
of that automatic path. Do not run them concurrently with the controller or
use them to bypass its public schedule.

After the DKG, the coordinator creates one unsigned descriptor from the exact
signed topology and certified DKG result:

```
nomad-lifecycle descriptor-init \
  --chain /var/lib/nomad/epoch-chain \
  --revocations /var/lib/nomad/revocations \
  --authority-key ./authority.pub --network <network-id> \
  --transition scheduled \
  --activate-at <previous-retire-at> --retire-at <new-public-boundary> \
  --topology ./topology.json --dkg-certificate ./certificate.json \
  --out ./epoch-draft.json
```

Every required operator receives the same `epoch-draft.json` and checks its
digest and public boundaries out of band. An operator in epoch N approves the
transition:

```
nomad-lifecycle descriptor-approve \
  --chain /var/lib/nomad/epoch-chain \
  --revocations /var/lib/nomad/revocations \
  --authority-key ./authority.pub --network <network-id> \
  --secret /etc/nomad/secrets/epoch-000000000000000000NN.secrets.json \
  --journal /var/lib/nomad/signature-journal \
  --in ./epoch-draft.json --out ./approval-<operator>.json
```

An operator in N+1 activates it with the corresponding N+1 secret and
`descriptor-activate` command and an `activation-<operator>.json` output. An
operator present in both epochs performs both roles. The journal is durable
security state: never delete it, roll it back from a snapshot or use a second
journal for the same identity. It permits an idempotent repeat for the same
digest and permanently refuses a different digest for the same epoch and
role.

The coordinator combines the detached public artifacts. Assembly fails unless
the previous committee reaches its required quorum, every incoming operator
activated, every signature targets the exact draft and no signer is duplicated
or revoked:

```
nomad-lifecycle descriptor-assemble \
  --chain /var/lib/nomad/epoch-chain \
  --revocations /var/lib/nomad/revocations \
  --authority-key ./authority.pub --network <network-id> \
  --in ./epoch-draft.json --out ./epoch-descriptor.json \
  ./approval-*.json ./activation-*.json
```

Obtain the fully signed `epoch-descriptor.json` through the public lifecycle
channel. Import it into the same persisted chain the share service will read:

```
install -d -m 0700 /var/lib/nomad/epoch-chain /var/lib/nomad/revocations
nomad-lifecycle epoch-import \
  --chain /var/lib/nomad/epoch-chain \
  --revocations /var/lib/nomad/revocations \
  --authority-key ./authority.pub \
  --network <network-id> \
  ./epoch-descriptor.json
```

This verifies the complete descriptor, including the signed topology, DKG
certificate, previous-epoch approvals and successor activations. It does not
activate early: before `activate_at` the chain reports READY, and after the
public boundary it reports ACTIVE.

Start the node, share service and partial-fetch endpoints per
`deploy/MULTI_OPERATOR.md`, including `nomad-node --epoch-chain` against this
same chain. The node's hot send path refuses the current epoch at its public
retirement boundary; a fixed one-second chain watcher can only shorten that
deadline for an already verified emergency successor. The share service exits
cleanly at the same boundary. Configure the service manager with
`Restart=on-failure`, not an unconditional restart policy, and schedule the
successor services from the descriptor's public `activate_at`; never trigger
that handoff from queue, cache, publication or reader state.

Your host now carries fixed-cadence traffic whether or not anyone is reading
anything; that constancy is the privacy property, so please do not "optimize"
it.

## Step 6 — Epoch rotation, and erasure

Epochs rotate on a public schedule. You will be asked to attest the next
epoch's draft (step 2) while the current one is still serving. When an epoch
retires:

```
nomad-operator erase \
  --secret /etc/nomad/secrets/epoch-000000000000000000PP.secrets.json \
  --chain /var/lib/nomad/epoch-chain --epoch N \
  --authority-key ./authority.pub \
  --network <network-id> --filesystem ext4 \
  --share /var/lib/nomad/shares/epoch-N.share.json \
  --retired-secret /etc/nomad/secrets/epoch-000000000000000000NN.secrets.json \
  --out ./erasure-N.json
```

`--share` is mandatory and must decode as this operator's threshold share for
the selected retired epoch. `--retired-secret` is also mandatory and must
cryptographically match that epoch's operator entry; the later `--secret`
supplies the same stable identity for the signed evidence and is protected
from erasure. A dummy, foreign or current file cannot satisfy the normal tool
path. Additional positional targets must be regular files. Directories,
symlinks, duplicate paths, the signing secret, authority key, epoch chain,
output files and hard-link aliases to protected state are refused. The command
writes a signed intent before destruction, overwrites/unlinks the named files,
fsyncs parent directories, persists the statement and records the retirement
acknowledgement. A retry resumes from the original signed intent.

`TestRetainedDealResistsLaterEpochCredentialCompromise` retains the exact deal
envelope written by the live DKG store. The retired DKG identity decrypts its
addressed ciphertext as a positive control; a complete later-epoch secret file
cannot decrypt it or enter the retired membership. This is local adversarial
evidence, not independent witnessed erasure or WAN evidence.

## What your host may retain, and for how long

A Nomad process is built to emit almost nothing. Enforcing that stops at the
process boundary, so the last part is yours.

**Set `GOTRACEBACK=none` for every Nomad service.** Without it a panic prints
goroutine stacks whose frame arguments are raw machine words, which for a
process holding your identity key or a threshold share can be key material,
and your init system keeps it. The compose file sets it; a systemd unit needs
`Environment=GOTRACEBACK=none` written in. Every Nomad binary checks at startup
and warns on stderr if it is missing, so grep your logs for
`will print goroutine stacks` after any deployment change. Note that no
in-process call can do this for you: `debug.SetTraceback("none")` looks like it
does and measurably does not.

**What the software writes.** One health file per node, rewritten in place,
containing only fields on a published allowlist with a written reason for each;
fourteen counters are named as forbidden with the reason they are forbidden.
There is no append-only log. A node that ran for a month writes the same number
of bytes as one that ran for an hour.

**What your platform writes anyway.** Service stdout and stderr, which for a
healthy Nomad process is a startup line and nothing else; systemd journal
metadata; and any crash output, which is the reason for the setting above.

**Retention we ask for.** Cap the journal for Nomad units at seven days
(`MaxRetentionSec=1week` in `journald.conf`, or a unit-level
`LogRateLimitIntervalSec`/rotation policy). Do not ship Nomad logs to a central
collector that retains longer, and do not enable systemd core dumps for these
units (`LimitCORE=0`, and `Storage=none` in `coredump.conf` if the host allows
it). A core file is the whole address space, which is every secret the process
holds; nothing in the protocol survives that.

**What we will not do for you.** We cannot verify your retention settings from
here, and no claim in this project's evidence covers them. If you run Nomad on
a platform that retains crash output indefinitely, the crash-data property is
not true on your host regardless of what the code does.

## If something goes wrong

`deploy/RECOVERY_RUNBOOK.md` covers ceremony failure, credential compromise,
operator replacement, observed equivocation, retirement and interrupted
ceremonies. Two things are worth knowing in advance:

- **If you believe your key is compromised, say so immediately.** Recovery
  is a normal protocol flow. A quorum of your peers can revoke a
  compromised operator without your cooperation, and you can self-revoke
  with one command. Nothing about this requires rebuilding the network.
- **If your node halts reporting equivocation, do not clear it.** That means
  two conflicting signed documents exist for one epoch, which is a
  governance failure, not a bug. Preserve the `HALTED` file — it is the
  evidence — and report it.

## What we will never ask you for

- Your operator secret, your threshold share, or any private key.
- SSH access to your host.
- To attest a document you have not read, or to sign two different documents
  for the same epoch.
- To disable a verification step "temporarily".

If you receive such a request, treat it as an attack regardless of who it
appears to come from.
