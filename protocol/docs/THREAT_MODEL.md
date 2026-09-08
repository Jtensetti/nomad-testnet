# Threat model

The threat model distinguishes **participation visibility** from **activity visibility**. A network observer may know that an endpoint participates in Nomad; the reader-side goal is to prevent that observer from learning which local object the endpoint is selecting or reconstructing from activity-dependent traffic.

## Adversary capabilities considered

Depending on the experiment, the adversary may:

- observe links globally,
- operate many intermediate nodes,
- correlate observations over long periods,
- drop, delay, replay or inject traffic around a modeled honest mixing boundary,
- probe public availability and cache state,
- know the protocol and all public scheduling inputs.

The adversary is not assumed able to break standard cryptographic primitives.

### Where each capability stands

Every capability below states what is assumed, what is excluded, and where the
evidence is. `production/CLAIM_TEST_MATRIX.md` carries the per-claim rows; a
capability marked *not defended* has no row above `none` there, and the
project must not claim it.

| Capability | Position | Evidence |
|---|---|---|
| Global passive observation | Targeted. Cell size and destination are independent of private activity, and so is the emission *schedule*; **cell timing is not** — a reproducible difference is measured. Cell *count* follows the schedule except where the host fails to send a scheduled cell, which is local state, not private activity — bounded below. **Cell *contents* are not opaque at the operator relay layer** — see below. | CLAIM_TEST_MATRIX reader path; the timing row is CONTRADICTED, see EVIDENCE_INDEX E-08 |
| Malicious peers | Targeted. A peer that is not in the signed topology gains nothing by existing, and abusive peers are refused per reason at no storage cost. | eclipse, Sybil and abusive-peer rows, adversarial |
| Compromised minority mixers | Targeted, under the anytrust assumption: privacy holds while at least one mixer in the chain is honest, and correctness holds against a minority under the `t`-of-`n` threshold. A majority-compromised committee is **excluded** — it can decrypt, and no protocol mechanism here prevents that. | shuffle-chain forgery, substituted-signer, non-re-randomising and partial-chain rows, adversarial |
| Replay | Targeted, at three boundaries: cells, shuffle chains across epochs and committees, and decoder admissions. | chain-replay, abusive-peer and duplicate-budget rows, adversarial |
| Delay and drop | Targeted for the invariant that matters: loss never produces catch-up traffic. Availability under sustained loss is **not claimed**. | burst-ceiling row; ADMISSION_AND_RATE_CONTROL.md |
| Injection | Targeted. Systematic pollution is refused before admission against signed commitments; dense coded pollution is **not preventable** over GF(2^8) and is bounded by budget and caught at object verification. | pollution rows, adversarial; POLLUTION_AND_RESOURCES.md |
| Sybil pressure | Targeted structurally rather than economically: admission consults a signed topology, never a population, so identities cannot be bought into relevance. Fair *allocation* among admitted sessions is **not claimed**. | Sybil and per-session quota rows, adversarial |
| Endpoint fallbacks | Targeted at the shipping client and the adapter: no Nomad failure mode is permitted to fall back to ordinary networking. Whole-binary egress capture now exists for the **Linux** release binary -- it runs in a network namespace with no interface, with a probe that reaches a host listener from outside and must fail inside -- and by system-call trace. macOS is denied network by App Sandbox entitlement and is **not** captured: no macOS runner executes that test. | adapter failure-mode row, adversarial; `TestTheClientEmitsNoPacketsAndNoDNS`, `scripts/verify-networkless.sh`; macOS capture remains open |
| Long-horizon correlation | **Not defended, and not claimed.** The adversary is assumed capable of it; no mechanism here bounds intersection over repeated sessions, and no measurement has been run. Requirement E-10 is NOT_STARTED. | none |

The last row is the one most likely to be over-read. Fixed-rate cover bounds
what a single observation reveals; it says nothing about what many
observations reveal in aggregate, and Nomad has not measured that.

### A scheduled cell that the host cannot send

A node does not stop when a local condition breaks its emission path: an
exhausted socket buffer, a route flap, a full disk under the hop sequence
reservation. Stopping was the previous behaviour and was worse — a node going
permanently silent is the loudest event a passive observer can see, from a
cause that is local and ordinary. Such a failure now costs the cell it
interrupted and nothing else.

The residue is that emitted **count** is not purely the schedule: it is the
schedule minus the cells the host could not send. That quantity is host state
and an adversary's own pressure, not private user activity, and the operator
relay path this applies to schedules its work from public replication policy.
It is stated rather than buried because the claim in the table above is about
*private activity*, and a reader is entitled to know exactly which other
inputs can move an observable.

Two things bound it. A condition that does not clear is not treated as
weather: a node stops after a bounded run of consecutive lost cells and says
what was failing, so a permanent misconfiguration surfaces instead of hiding.
And conditions that are permanent by nature — a firewall verdict, a
destination the kernel will never accept, an exhausted or unreadable sequence
space — are not lost-cell conditions at all; they stop the node immediately.

### The operator-to-operator hop cell is encrypted per link

Version 1 of the hop header authenticated the 48 bytes after the mix
ciphertext and sent them in the clear, and left the mix ciphertext itself
untouched. A passive observer of a link read, without attacking anything, the
work flag, the stream ID, the batch coordinates and the hop sequence — and
could separate work from cover a second way, because mix ciphertext parses as
compressed group elements while a cover cell's uniform random bytes do not.

Both leaks were measured before they were fixed, and the measurements are kept:

- the **stream ID** is 16 bytes derived from the batch payloads, so it was the
  same value at every hop a batch took. `live/node/linkability_test.go` sent a
  marked batch into a live relay and found the identifier in the cells the
  relay emitted. It now runs the same experiment and requires zero, with a
  positive control that finds the identifier when it is present.
- the **work flag and payload structure** separated work from cover perfectly
  by two independent classifiers. `live/uplink/distinguisher_test.go` keeps
  both measurements: perfect separation on a cell in memory, and neither
  classifier better than guessing once the cell is sealed.

Version 2 encrypts the whole cell — payload and routing metadata — under the
pairwise link key, with a keystream bound to the topology digest, epoch,
receiver, network identifier and hop sequence. What crosses a link is a uniform
pseudorandom 1200-byte string apart from two fields:

- the **magic**, four bytes, so a peer can refuse a version it was not built
  for rather than downgrade to it.
- the **hop sequence**, a per-sender per-link counter. It is public by
  construction — an observer counting datagrams on a link has it anyway — and
  it is the keystream input, so it must be readable before decryption. It must
  stay a count of what was *sent*: a number issued to a cell that then failed
  at the socket would leave a gap, and a gap is an exact per-cell count of the
  sender's local send failures, readable by the receiving peer. A sequence
  number is therefore returned when a cell does not reach the socket;
  `live/node/resourcelimit_test.go` reads the sequences off the wire and
  requires an unbroken run across a run with drops in it.

The sequence does not link hops. A relay draws a fresh number from the
outbound link's own sequence and re-encrypts under that link's key, so nothing
in what leaves an operator resembles what arrived.

**What this does not claim.** Encryption is per link, so any operator on the
path sees the plaintext payload and the routing metadata: this is unlinkability
against a passive observer of a link, not against a participating operator, and
the anytrust argument for the committee is what covers that. It says nothing
about traffic volume or timing, which the constant-rate fabric covers
separately. And an observer who watches two links and correlates arrival and
departure *times* is not addressed here at all; that is the correlation
question `PROD-17` tracks, and cover traffic rather than encryption is what
bears on it.

## Reader-side target

For two private reader states `R0` and `R1` under the same public traffic-class state, the target is that observable network behavior does not depend on which reader state is active.

Achieving this requires more than fixed packet sizes. Cadence, peer selection, congestion behavior, retransmission, cache maintenance, speculative browser networking and failure handling must also avoid private-reader inputs.

## Publisher-side target

After a publication crosses the constant-rate publication airlock, threshold mixing and the protocol-defined release boundary, and has been independently replicated, protocol metadata should not provide a direct mapping from public object to original endpoint.

This does **not** claim perfect pre-deposit publisher anonymity. Selective isolation before first deposit can create an availability oracle. The publication path and correlation campaign that exist are evidence for part of that target only: they run as separate processes on one host, so they do not establish distributed WAN publisher anonymity, and they do not address long-horizon correlation, a compromised mixer observing between hops, or unbounded descriptor-distribution delay.

## Endpoint boundary

The following are outside the network-protocol claim and require separate endpoint security:

- compromised OS or hardware,
- forensic seizure of plaintext or keys,
- malware in the trusted browser/process domain,
- identifying metadata or prose inside published content,
- extensions or browser services that make ordinary network requests.

## Work required before deployment claims

- independent review of the Kyber shuffle, DKG and threshold-decryption
  integration, and of the cryptographic parameter choices,
- packet-capture tests under WAN loss, congestion, churn, active delay/drop,
  suspend/resume and process stalls,
- long-horizon intersection analysis,
- cache/availability side-channel analysis,
- basin inversion and membership-inference analysis,
- release-binary packet and DNS egress capture on every supported client
  platform: this exists for Linux and does not for macOS,
- distributed publication-airlock experiments across separately administered
  hosts and regions,
- bounded SiteID descriptor distribution with transparency and equivocation
  evidence,
- independent cryptographic, systems, browser and privacy assessment.

The Firefox and Chromium forks are not production targets unless they are
explicitly reactivated (DEC-013). Their integration-contract documents are not
evidence about a shipping client.

## Bounded v0.1 evidence

The v0.1 loopback testnet captures actual 1200-byte UDP datagrams sent to four
publicly planned peer slots. It compares idle/active reader worlds and two
distinct query worlds, then reconstructs only from captured cells. This is
useful regression evidence for the reference implementation; it is not a
global-observer, congestion, browser-engine or deployment experiment.
