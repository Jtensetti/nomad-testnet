# Nomad: first real-world network test

This is the shortest useful description of what we are about to test.

## The question

Can the current Nomad implementation run between real machines in different
European regions while keeping its reader-side network traffic on the public,
fixed schedule?

The first run is deliberately **not** a claim that Nomad is anonymous or
production-ready. It is the first step out of the one-host lab.

## The setup

Three small Linux servers are created temporarily:

- **Paris** — `operator-a`
- **Amsterdam** — `operator-b`
- **Warsaw** — `operator-c`

They are all paid for and administered by the same project owner, so they count
as **one administrative trust domain**. Geographic separation is real;
operator independence is not.

Each machine creates its own Nomad operator keys locally. The orchestration job
never downloads those private keys or threshold shares.

## What happens during the run

1. The three machines agree on one signed Nomad topology.
2. They perform Nomad's real networked distributed key-generation ceremony.
3. All three must independently arrive at the same public DKG certificate.
4. The three Nomad nodes start their fixed-cadence reader-side traffic.
5. Every machine captures what it sends and what actually arrives over the WAN.
6. The evidence is checked automatically.
7. A readable `RESULT.md` and the raw packet captures are saved together.
8. The machines are destroyed after the experiment.

## What counts as PASS in this first run

The run fails unless all of these are true:

- the distributed DKG completes on all three machines;
- all three public DKG certificates are identical;
- every observed Nomad UDP payload is exactly **1200 bytes**;
- each sender keeps its signed destination;
- sender timing shows no catch-up burst after a missed slot;
- average sender cadence remains inside the registered baseline tolerance;
- the clean WAN path delivers traffic inside the deliberately broader WAN
  arrival tolerance.

A successful run therefore means:

> The tested Nomad build completed its distributed key ceremony and maintained
> its configured fixed-size/fixed-cadence reader-side fabric across three real
> public-internet regions for the recorded interval.

## What PASS does not mean

It does **not** yet mean:

- “Nomad anonymity is proven”;
- independent operators exist;
- publishing is anonymous;
- a global observer cannot classify user activity;
- the network survives every failure mode;
- the system has passed a 72-hour soak;
- an independent security reviewer has approved it.

Those are later tests. We should not claim them early.

## What the result will look like

A successful evidence artifact contains a `RESULT.md` with a table like this:

| Operator | Region | Emission mean | Emission min–max | Arrival mean | Arrival min–max | Delivery ratio |
|---|---|---:|---:|---:|---:|---:|
| operator-a | Paris | measured | measured | measured | measured | measured |
| operator-b | Amsterdam | measured | measured | measured | measured | measured |
| operator-c | Warsaw | measured | measured | measured | measured | measured |

The real values are inserted by the test. Raw pcaps, public DKG/topology
artifacts, health data, logs and SHA-256 hashes remain beside that readable
summary so a reviewer can verify it.

## If the first run passes

Continue in this order:

1. **Repeat the same baseline.** A result that cannot be repeated is not useful.
2. **Run longer.** Establish a boring clean-WAN baseline.
3. **Two-world test.** Compare idle Nomad against private search/read activity
   over the same real WAN without telling the classifier which is which.
4. **Fault campaign.** Add controlled loss, jitter, latency, clock problems and
   node failures and verify that Nomad fails closed rather than producing
   private-dependent catch-up traffic.
5. **72-hour soak.** Only after short runs are boring and repeatable.
6. **Independent operators.** Give operator custody to different humans or
   organizations. More VPSs under the same account do not create independence.
7. **External review.** Give the frozen evidence package to people whose job is
   to find reasons the privacy claim is wrong.

## If the first run fails

That is a useful result too. Do not weaken thresholds just to make the run
pass. Keep the evidence, identify whether the failure is deployment, DKG,
scheduler, host, or WAN behavior, fix the cause, and rerun the exact same
registered test.

## Cost and safety

The lab uses the smallest fixed Scaleway instance type selected for this
measurement fixture. Billable creation is manual; normal pushes only validate
code. A failed apply attempts Terraform cleanup automatically, and every host
also has a public TTL/poweroff backstop. **Poweroff is not destruction**: the
explicit destroy step is still required to release billed IP resources.

The cloud credentials live only in GitHub Actions secrets. They are never
stored in this repository or in Terraform variable files.
