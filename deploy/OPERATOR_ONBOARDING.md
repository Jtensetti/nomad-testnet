# Nomad operator onboarding

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
| Network | A stable public IPv4 or IPv6 address, three open inbound ports |
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
2. **Do not back up the share directory.** Backups defeat erasure. Back up
   your operator secret (step 1 below) once, offline, and nothing else.
3. Have your own admin account on your own host. Do not share credentials
   with any other operator or with the maintainers.

## Step 1 — Create your identity, locally

```
nomad-operator init \
  --id <your-operator-id> \
  --endpoint <public-host>:4200 \
  --partial-endpoint http://<public-host>:8080/ \
  --dkg-endpoint https://<public-host>:8443/ \
  --secret /etc/nomad/operator-secret.json \
  --enrollment ./enrollment.json
```

This generates three private keys — an Ed25519 identity, an X25519
key-agreement key, and a DKG identity — and writes them to
`operator-secret.json` with mode 0600. **That file never leaves your host.**
Nobody else, including the maintainers, ever needs it or should be given it.

`enrollment.json` is public and self-signed. Send that one, and only that
one, to the coordinator.

Confirm what you created without opening the secret by hand:

```
nomad-operator inspect --secret /etc/nomad/operator-secret.json
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
  --secret /etc/nomad/operator-secret.json \
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
  --secret /etc/nomad/operator-secret.json \
  --topology ./topology.json \
  --authority-key ./authority.pub
```

This confirms your keys really are in the activated topology and that every
other operator attested the same document. If it fails, stop and report it
rather than proceeding.

## Step 4 — Run the DKG at the scheduled time

The topology names an absolute start time. Run:

```
nomad-dkg --topology ./topology.json --authority-key ./authority.pub \
  --secret /etc/nomad/operator-secret.json \
  --state /var/lib/nomad/dkg --share /etc/nomad/share.json \
  --certificate ./certificate.json --listen :8443
```

Every configured operator must be online and complete the ceremony; there is
no partial success. If it aborts, do not improvise — wait for the next
public retry offset. `/etc/nomad/share.json` is your threshold share and is
as private as your operator secret.

## Step 5 — Serve

Start the node, share service and partial-fetch endpoints per
`deploy/MULTI_OPERATOR.md`. Your host now carries fixed-cadence traffic
whether or not anyone is reading anything; that constancy is the privacy
property, so please do not "optimize" it.

## Step 6 — Epoch rotation, and erasure

Epochs rotate on a public schedule. You will be asked to attest the next
epoch's draft (step 2) while the current one is still serving. When an epoch
retires:

```
nomad-operator erase \
  --secret /etc/nomad/operator-secret.json \
  --epoch-descriptor ./epoch-N.json --authority-key ./authority.pub \
  --network <network-id> --filesystem ext4 \
  --out ./erasure-N.json \
  /etc/nomad/share.json /var/lib/nomad/dkg
```

This overwrites and unlinks the retired epoch's private material and emits a
signed statement of exactly what was destroyed. It refuses to run before the
retirement boundary. Send the statement; keep nothing else.

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
