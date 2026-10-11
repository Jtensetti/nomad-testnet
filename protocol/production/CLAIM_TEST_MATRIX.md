# Claim-to-test matrix

Maps every security claim to the tests that exercise it and states the
boundary each reached. A claim without a boundary-level row is not evidenced
at that boundary, however much code exists. Feeds PROD-02.

Levels, weakest first:

- `structural` — enforced by API shape or a CI dependency gate, not by a test
  of behavior;
- `unit` — in-process test;
- `adversarial` — negative and attack tests at the same boundary as the claim;
- `integration` — composed processes, loopback or Compose;
- `boundary` — real interface, process, or release artifact;
- `independent` — verified by an external assessor. **Nothing is here yet.**

## Reader path

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| Emission plan takes no private input | planner API + package graph | selection-firewall tests; Selection Firewall CI gates | structural |
| Cells are exactly 1200 bytes at fixed cadence | real interface | Compose pcap gate (run 32301972409) | boundary, single host |
| A resource limit does not change what a node emits | real interface, two windows, one loaded | Compose load gate (run 33374193549): 3000 datagrams/s from an unrecognised sender at 150x the emission rate moves all three operators 0.01% against a 50 ms cadence. The flood is required visible on the wire (17,961 datagrams) and in the process (24,960 peer-lookup refusals), so a flood that never arrived cannot read as a pass | boundary, single host |
| Lost cells never cause catch-up bursts | real interface under loss/suspension | scheduler unit tests; one-second burst ceiling asserted on every captured world in the node wire campaign | adversarial, loopback |
| Cell size and destination do not depend on private activity | real socket, work queue empty vs full | `TestWireContentIsIndependentOfPrivateActivity`, mutation-verified | adversarial, loopback |
| Cell timing does not depend on private activity | real interface, two worlds, blind | **CONTRADICTED — a reproducible difference is measured. See EVIDENCE_INDEX.md. Under a two-sample KS test over inter-arrivals, with a Latin-square rotation removing the position confound, idle and active differ at 1−p = 0.993 against a 0.517 control spread, reproduced on a second measurement.** | finding |
| Private reader activity does not change wire behavior | real interface, two worlds, blind | as above; the blind evaluator and the WAN environment are both missing | integration |
| Cache maintenance independent of reads | wire trace comparison | CI dependency gates only | structural |
| Per-cell work fits inside the cadence with margin | measured cost vs the deployed interval | `TestTheRelayPathFitsInsideTheCadence`, `TestCapacityReport`; **shared container, costs measured in isolation** | unit |
| The analysis rule detects the differences it claims to | both-direction self-tests | `scripts/test-two-world-analysis.py`, in CI: identical worlds accepted, each preregistered difference rejected, parser fails closed on any unparsed line | adversarial |

## Epoch and key lifecycle

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| Descriptor digests and signatures are canonical and reproducible | published vectors | epoch vectors incl. real signatures from a published key | adversarial |
| No single previous operator can force a membership transition | negative tests | quorum-forgery regression (index aliasing + approver binding) | adversarial |
| Split-brain fails closed, halt survives persistence failure | negative tests | equivocation, halt-fails-open, cross-process regressions | adversarial |
| Rollback to a burned epoch is rejected | negative tests | high-water-mark regression | adversarial |
| Rotation timing takes no private input | determinism test | `TestPlanIsDeterministicAndPublicOnly` | unit |
| Retired shares are refused | production path | share-service guard tests; `Chain.ServesEpoch` | unit |
| Retired epoch material is unrecoverable after erasure | adversarial experiment | `TestForwardSecrecyAfterErasure` | adversarial |
| Compromise recovery works end to end | drill | `TestRecoveryDrill` (5-operator, 3-of-5) | integration |
| No machine holds a complete decryption key | process + host separation | Compose share isolation | integration, single host |

## Admission and directory

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| A topology must be attested by every operator it lists | negative tests | stripped attestation and dropped operator both refused; each survivor's attestation covers the whole document | adversarial |
| A superseded topology version is refused | negative test | version-downgrade case | adversarial |
| Traffic class and threshold cannot be weakened below the profile | negative tests | off-profile cell size, sub-floor threshold, sub-floor operator count | adversarial |
| A node will not accept a topology older than one it has served | rollback across restart | persisted per-network watermark; refusal verified at the binary boundary | adversarial |
| Two topologies for one network epoch fail closed | negative test | equivocation refused rather than last-writer-wins | adversarial |
| A watermark the node cannot parse is not permission to proceed | negative tests | truncated, wrong-version, zero-epoch, short-digest and unknown-field states all refuse | adversarial |
| The admission format is described well enough to interoperate | a consumer that is not this codebase | signed-topology golden vectors exist; **nothing outside this repository has parsed them** | none |

## Publisher identity

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| SiteID derivation is deterministic and domain-separated | published vectors | site vectors | adversarial |
| Theft of a signing key does not confer recovery authority | negative tests | recovery-policy seizure regression | adversarial |
| A superseded descriptor cannot be reinstated | negative tests | rollback and absorbing-revocation property test | adversarial |
| Equivocation yields a transferable proof | third-party verification | forged-proof rejection + genuine-proof acceptance | adversarial |
| A foreign descriptor cannot poison a site | negative tests | foreign-genesis regression | adversarial |
| Encodings are unambiguous across implementations | parser differential | strict-parsing table, base64 malleability regression | adversarial |
| Identity resolution creates no query-dependent traffic | capture | pure function, no I/O; **no capture** | structural |
| Browser distinguishes integrity from identity | release binary | states defined; **not integrated** | none |
| A descriptor outside the log cannot enter a chain | negative tests | `TestAnUnloggedDescriptorCannotEnterAWitnessedChain`, drill step 6a | adversarial |
| An unwitnessed chain cannot reach a publisher verdict | API shape + negative tests | `TestAnUnwitnessedChainCannotReachAPublisherVerdict`, `TestTheWitnessedAndUnwitnessedPathsDoNotSubstituteForEachOther` | adversarial |
| A partitioned reader loses the verdict within one window | negative tests | `TestAPartitionedReaderLosesThePublisherVerdict`, drill step 6b | adversarial |
| A log cannot rewrite its own history | negative tests | `TestAForkedLogCannotProveConsistency` (both seeded and complete-subtree routes), `TestConsistencyFailsClosed` | adversarial |
| Log equivocation yields a transferable proof | third-party verification | `TestAForkedLogIsCaughtAndTheEvidenceIsTransferable` (proof relayed through JSON and checked with only the log key), `TestVerifySplitViewFailsClosed` | adversarial |
| Log hashing agrees with other implementations | published vectors | `TestRootsMatchRFC6962` over sizes 0..8, `TestTheSplitIsRFC6962sAndNotTheMidpoint` | adversarial |
| A leaf cannot be presented as an interior node | negative test with positive control | `TestAnInteriorNodeCannotBePresentedAsALeaf` | adversarial |
| Proof verifiers terminate on hostile sizes | negative tests with a deadline | `TestHostileSizesTerminate` | adversarial |
| Distribution creates no read-dependent traffic | capture | proofs travel with the publication; refresh takes no read-derived argument; **no capture** | structural |

## Publication

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| The entry operator terminates uplinks as a separate process | two binaries, real socket | `TestThePublicationPathAcrossRealProcesses` | boundary, single host |
| The publication path emits fixed-size cells at cadence on a real interface | packet capture | same test, judged by `scripts/verify-pcap.py` | boundary, single host |
| A refused deposit can be retried | idempotence contract | **CONTRADICTED - `live/deposit/retransmit_test.go` shows only a byte-identical retransmission is idempotent, and the publisher retains nothing to retransmit. See DEC-020.** | finding |
| Publish cannot reach a socket, transport or scheduler | package graph, transitively | in-package architectural test + CI gate | structural |
| The queue is bounded, crash-safe, idempotent, encrypted at rest | unit + restart | publish queue tests | unit |
| A stolen disk does not open the publication queue | unit, every file on the disk tried as the key | `TestAPassphraseQueueKeepsNothingOnDiskThatOpensIt` | **holds only under `Passphrase`; `UnprotectedKeyFile` writes the key beside the fragments and `TestTheUnprotectedKeyFileOpensItsOwnQueue` demonstrates it** |
| Drain order leaks no publication timing | unit | content-derived order test | unit |
| Uplink work and cover are indistinguishable to an observer | classifier | two independent classifiers fail against uplink | adversarial, cell level |
| Uplink work and cover are indistinguishable to the entry operator | design + test | cover is a real committee encryption on the identical path | unit |
| Publish/no-publish wire equivalence | blind two-world capture | **none** | none |
| One operator cannot link ingress to released plaintext | composition tests | permutation uniformity across trials, recovered with threshold authority (replaces a withdrawn byte-similarity matcher that passed against an order-preserving chain) | adversarial, in-process |
| Only the certified committee can produce a chain | forgery tests | rounds carry receipts signed by certified identity keys; a chain from a non-member, and one with a substituted signer, are refused | adversarial |
| A chain cannot replay into another epoch or committee | negative tests | sealed digest + release-epoch commitment; cross-epoch, cross-committee and cross-committee-epoch replays refused | adversarial |
| A round that does not re-randomise is refused | negative tests | zero-blinding detector over every column pair | adversarial |
| A partial or reordered shuffle chain is refused | negative tests | twelve deviations, each failing the epoch closed | adversarial |
| Cover is indistinguishable from a deposit before decryption | classifier over the wire form | whole-cell padding comparison at every occupancy | adversarial |
| Sealing leaks no publication volume through timing | duration + lock-contention measurement | seal duration and concurrent-deposit blocking compared empty vs full | adversarial |
| One bad deposit cannot censor an epoch | negative tests | malformed and small-order deposits refused at the boundary; an undecryptable column is dropped, not fatal | adversarial |
| Release timing takes no private input | determinism test | pure function of four public parameters; seal refused early at every occupancy | unit |
| Batch size and shape do not reveal the deposit count | unit + decryption | identical size and shape at 0, 1, n-1, n deposits; every column including cover decrypts | adversarial |
| Deposits are idempotent and capacity does not grow | negative tests | resend, conflict, over-capacity and restart regressions | adversarial |
| A depositor learns nothing about the epoch's occupancy | oracle tests | a full epoch drops silently; probing past capacity is indistinguishable from acceptance | adversarial |
| One depositor cannot name or squat another's slot | derivation + negative tests | IDs derived from (session, sequence); a foreign session cannot collide across 16 sequences | adversarial |
| One session cannot occupy the whole batch | quota test | per-session bound enforced silently, other sessions unaffected | adversarial |
| The airlock cannot reach a socket or scheduler | package graph, transitively | in-package architectural test (mutation-verified) + CI gate | structural |
| Failure and retry add no traffic | capture under failure, four conditions | success, timeout, restart with a durable queue, adversarial loss: every world emits the same cell count, size and destination as an idle publisher | adversarial, in-process |
| Failure and retry do not shift emission timing | capture under failure, four conditions | judged by the full preregistered rule in CI, with a measured noise floor of 0.0003 to 0.0038 against a 0.02 tolerance; restart is compared against restart-without-work, since a restart is observable by construction | adversarial, in-process |
| A publisher can hold the cadence it is given | per-cell cost against the cell interval | **CONTRADICTED — sealing one cell takes ~87 ms against a 50 ms deployed interval and a 5 ms permitted minimum; half the cost is a discarded companion mix column. See EVIDENCE_INDEX.** | finding |
| A queued object reaches a sealed batch across the uplink | end-to-end path | queue to drain to ingress to airlock to seal, with the fixed batch size preserved | integration |
| Emission count does not depend on having work | busy versus idle publisher | a full queue and no queue at all emit the same number of identically sized cells over the same ticks; the test fails if either run was not actually mixed | adversarial, in-process |
| The queue is never read on the emission path | design + package graph | a filling goroutine holds a one-slot buffer; the tick does a non-blocking receive and touches no disk | structural |
| The entry operator cannot separate work from cover | cell inspection | one cell size, one inner-layer size, only threshold decryption distinguishes them | adversarial |
| Deposit order does not predict release position | correlation experiment with positive control | no defence 1.00, seal only 0.231, full path 0.250, chance 0.250 over 40 trials; fails at 74 of 160 hits, a threshold from the exact null at a 1e-6 false-failure budget | adversarial, in-process |
| The shuffle chain's own contribution to unlinkability | adversary inside the committee, handed every corrupt mixer's permutation | every mixer corrupt 1.000, one honest mixer 0.131, chance 0.125, over 20 trials of 8 publishers and 5 mixers; fails at 46 of 160 hits | adversarial, in-process |
| A publisher does not emit work into a shut deposit window | queue sampled every 50 ms across two real processes | 0 fragments lost over 83 intervals inside shut windows; 19 lost across four shut windows with the gate removed | adversarial, cross-process |

## Accountability

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| A mixer that signs an unsound round can be named | forgery + attribution tests | `AttributeFault` names the signer; the receipt covers context, input, output and proof digests together | adversarial |
| Blame is verifiable by a third party, not testimony | independent re-derivation | `VerifyFaultReport` re-derives the fault from the transcript; a fabricated report against an honest chain is refused | adversarial |
| Blame cannot be moved onto an honest mixer | negative test | a genuine report re-pointed at a neighbour fails verification | adversarial |
| An impersonated mixer is not blamed for the forgery | negative test | a receipt failing under the key it names marks that mixer a victim | adversarial |
| Broken linkage is not pinned on one neighbour | negative test | charged to the chain assembler; linkage checked before soundness so a mixer handed the wrong input is not accused | adversarial |
| A stopped mixer can be reported | availability report | a quorum of distinct certified observers each sign a non-receipt bound to a deadline the public timetable fixes | adversarial |
| An availability report cannot evict an honest operator | negative tests | below quorum establishes nothing; a repeated signer, an uncertified key and self-accusation do not count; an accusation cannot be re-pointed | adversarial |
| Statements cannot be moved to another round or deadline | negative tests | the round context and deadline are inside the signed message; verified by rewriting a report *and* every statement in it consistently, which the report-level consistency check alone does not catch | adversarial |
| A falsely accused operator can answer, and the answer names its accusers | refutation | the accused produces its own sound round for that exact position; a round from another position, another mixer's round and an unsound round are all refused | adversarial |
| A stopped mixer can be shown to have *withheld* | — | **not decidable: asynchrony makes withholding and a dropped packet indistinguishable, so the report is deliberately non-attributable** | n/a |
| Reporting availability does not leak reader activity | privacy boundary | every certified operator is judged at every deadline so report volume cannot track load; two observations of one position are byte-identical; CI holds the observer's graph to mix and topology | adversarial |
| Selective failure above the quorum is reported | two-world at the observers | an operator starving a quorum of peers is reported exactly as a total failure is | adversarial |
| Selective failure below the quorum is detected | — | **not detectable by this mechanism: the same threshold that stops a coalition evicting an honest operator lets a minority be starved indefinitely, rotating which minority** | n/a |
| Faults are attributed against a live committee | active-adversary injection | **none — constructed transcripts and a unit-tested delivery source only; needs a running committee where an operator actually stops** | none |
| A vanished operator's share is not rerouted to a survivor | two-world at the surviving peer | the survivor receives exactly its half of a two-peer rotation with the other operator absent, and the sender counts every scheduled emission as sent | adversarial |
| Private activity during an outage does not change what a peer sees | two-world at the surviving peer | idle and busy outage worlds deliver identical counts, sizes and destinations | adversarial |
| An outage is survivable across regions | regional outage test | **none — B-09 NOT_STARTED; loopback only** | none |

| An encryption key outside the prime-order subgroup is refused | negative test | the identity and small-order points are rejected in publicPoint, covering every encryption entry point | adversarial |
| A single-cell encryption is indistinguishable from a batch column | structural + mutation | layout decrypted row by row in place; six mutations that previously passed now fail, including plaintext written into the padding | adversarial |

## Network coding and resources

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| Inconsistent dependent symbols are rejected | unit | rlnc tests | unit |
| Polluted systematic symbols never enter the basis | negative tests | commitment-mismatch test | adversarial |
| A malicious symbol cannot exceed the generation budget | Byzantine campaign | 50/90/100% campaigns, all budgets asserted | adversarial |
| Replay drains no budget | unit | duplicate test | unit |
| A mixer that cheats mid-session is attributed, and honest mixers downstream are not | live chain, adversary at its own turn | `mix/livefault_test.go`: a real committee runs every round through `ShuffleAndSign`; one mixer substitutes or drops a cell in its own output and re-signs, and the rest shuffle the poisoned batch honestly. Attribution names the culprit, a third party confirms it, and the report cannot be re-pointed at any of the honest mixers. Mutation-verified, including blaming the last round instead | adversarial, single process |
| Coded-symbol pollution is prevented | per-symbol verification | **not claimed; see POLLUTION_AND_RESOURCES.md** | none |
| Eclipse is structurally impossible | invariant test | no peer discovery exists; peer set is a function of the signed topology and is byte-identical after a flood from unnamed addresses and correctly sealed cells from the wrong socket | adversarial |
| Sybil identities buy nothing | invariant test | 64 fresh identities leave the peer set unchanged; admission consults a signed document, never a population | adversarial |
| Amplification is bounded well below 1 | flood campaign | 0.0003-0.0008 outbound/inbound across four flood types, up to 396 MB in for 118 KB out | adversarial |
| Abusive peers are rejected for their own reason at no cost | negative tests | malformed, unauthenticated, misdirected, cross-epoch and replayed each rejected, nothing stored | adversarial |
| Availability under flood | sustained campaign | **not claimed — a flood can push a small node past its lateness budget; see ADMISSION_AND_RATE_CONTROL.md** | none |
| Backpressure does not alter private-sensitive cadence | wire trace under load | **partial. The emission *schedule* is never altered by load: a cell the host cannot send is lost, never retried, deferred or caught up, and the next tick keeps its absolute deadline and its planned peer (`fabric` scheduler tests; `TestATransientSendFailureCostsOneCellAndNotTheNode`, `TestADroppedCellStillConsumesItsPlaceInThePeerPlan`, mutation-verified). What is not established is a wire trace under load on a real interface, which is what this row asks for.** | adversarial, loopback |
| A receive-side limit does not change emitted size, burst or destination set | two worlds at and below the limit, real sockets | `TestAReceiveSideLimitChangesNothingStructuralAboutWhatIsEmitted`: one world's cache rejects nearly every stream and relays almost nothing, the other stores and relays; both emit one cell size, stay under the absolute burst ceiling, and use both destinations of the rotating plan. Deterministic; 15/15 under `-race` | adversarial, loopback |
| A resource limit does not change the emission *rate* | two worlds, measured control floor | `TestAResourceLimitDoesNotChangeTheEmissionRate`, campaign-gated. A rate comparison against a floor measured from three worlds that differ by nothing; run per-push it failed CI intermittently in both directions, reporting a node that missed its lateness budget as a count divergence. It belongs with the other wall-clock campaigns and is **not evidence from a per-push run** | adversarial, campaign only |
| A resource limit does not change the *work/cover mix* | — | not claimed at the operator relay layer, and not observable there either since hop cell v2: `live/uplink/distinguisher_test.go` runs both classifiers against sealed cells and requires both to fail, keeping the pre-v2 measurement as the before. Relay work is public replication policy; the publisher uplink uses a pseudorandom profile as well. | adversarial |
| A link observer cannot tell a work cell from a cover cell | sealed cells, two independent classifiers | header-flag and payload-structure classifiers, perfect before sealing and at chance after | adversarial |
| A link observer cannot follow a batch across a hop | live relay, marked stream, passive capture | `TestARelayedCellDoesNotCarryItsStreamIDOnward`: 0 of 34 emitted cells carry the ingress identifier, with a positive control that finds it when present | adversarial, loopback |
| A hop cell cannot be spliced, replayed into another context, or downgraded | the receiver's own accept path | header-splice from another cell on the link, five context bindings, and a correctly re-tagged future version, each refused; 10 mutations killed | adversarial |
| A relayed cell carries no cleartext identifier linking it to its ingress | ingress/egress comparison at a real socket | `TestARelayedCellDoesNotCarryItsStreamIDOnward` marks a stream nothing else could produce, relays it through a running node, and requires the identifier to be absent from everything the node emits. `TestTheMarkedStreamIsFoundWhenItIsPresent` is its positive control: the same search over version 1's cleartext layout must find the mark, so finding nothing is not looking nowhere. **This row read "measured false" against version 1, which carried the stream ID in the clear; version 2 encrypts the whole cell under the pairwise link key. Unlinkability against timing, volume or ordering correlation is a different claim and is not made here.** | adversarial, loopback |
| A local send failure costs one cell, not the schedule | real socket, refused destination and unwritable state | `TestATransientSendFailureCostsOneCellAndNotTheNode` (30 drops over 30 ticks, cadence held), `TestAFullDiskUnderTheSequenceReservationCostsCellsNotTheNode`, `TestADroppedCellStillConsumesItsPlaceInThePeerPlan` (15/15 over a two-peer rotation), `fabric` scheduler tests; all mutation-verified | adversarial, loopback |
| Remote input cannot drive unbounded allocation | sustained flood, live heap + exact bounds | `TestASustainedFloodCannotGrowTheHeapWithoutBound`: 234,978 datagrams between two heap marks moved it 347 KiB to 747 KiB; cache streams, queue depth, peer and replay tables asserted at their configured bounds. Mutation-verified: a per-datagram retention grows the heap by 107 MB | adversarial, loopback |
| A failing node is visible to a supervisor | health file + healthcheck | `nomad-node --check-health` fails a node that is up but has emitted nothing; `cmd/nomad-node` table over five states; Compose healthcheck and `compose-e2e.sh` assert `send_dropped`, `health_deferred` and `last_sent_at` | unit + integration |

## Operational output

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| A process may emit only fields with a written public rationale | schema allowlist | `live/telemetry` fails closed on any unlisted field; fourteen forbidden counters named with reasons | adversarial |
| Operational output contains no secret in any encoding | scan of everything written | production node run with known secrets; every file under its state directory scanned in raw, hex, upper hex and three base64 forms; instrument rehearsed against all five secrets first | adversarial |
| Operational output does not accumulate | retention test | health file rewritten in place, no append-only log | unit |

## Browser and release

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| Browser has no network entitlement | release binary inspection | CI entitlement gates at build | integration |
| A failed load never falls back to ordinary networking | negative tests at the adapter | thirteen failure modes, each ending in a local 4xx with no redirect header and an intact CSP; adapter graph holds no socket | adversarial |
| The renderer admits only local, non-scriptable URLs | negative tests | scheme, traversal, encoding and data: media-type table; the URL gate and the adapter share one path rule and a test fails if their verdicts diverge | adversarial |
| Zero browser egress including DNS | packet/DNS capture of the binary | **none** | none |
| The engine egress surfaces are enumerated and anchored | inventory verified against the tree | 31 Gecko and 18 Blink surfaces, each with what the integration owes it; a verifier fails when an anchor stops existing | structural |
| An engine fork routes renderer paths through verified local data | engine implementation + browser tests | **none — no engine code is modified in either fork** | none |
| Partial write cannot render | filesystem adversarial tests | materializer boundary tests | adversarial |
| Symlink, traversal, overwrite rejected | filesystem adversarial tests | materializer boundary tests | adversarial |
| The build is deterministic | two builds from different source paths | byte-identical across three targets on every push; removing -trimpath fails it | integration |
| Release is reproducible by a second builder | two independent builders | **none — determinism is not independence (EB-2)** | none |
| The shipped .dmg is reproducible | unsigned-payload comparison | **none — codesign and hdiutil embed timestamps; not implemented** | none |
| An embedding model that changed is detected | behavioural attestation | a fixed public probe set fingerprinted by basin, refused when it moves; degenerate probe sets rejected at attestation time | adversarial |
| The embedding service is running the model it claims | attestation of the model itself | **not establishable: a service willing to lie about its model is willing to lie about a hash of it** | n/a |
| A process without the service key never receives the query | recording listener on the configured port | `TestQueryIsNotDisclosedToAProcessWithoutTheServiceKey`: neither the text, nor a fragment, nor a credential header, nor the key; positive control is the full client-shim-model chain succeeding | adversarial, loopback |
| A vector from a process without the key is refused | the client's own accept path | sealed under another key, plain OpenAI-shaped JSON, empty and invented replies all refused; a genuine reply replayed onto a second request refused | adversarial, loopback |
| The shim never reaches the model server with a request it could not open | the shim's HTTP boundary | ten malformed and unauthenticated request shapes, each asserting the upstream was not called and that every refusal reads the same | adversarial, loopback |
| The embedding service cannot reach off the host | systemd unit + binary refusals | binary refuses a non-loopback listen or upstream, with the reason asserted; unit directives pinned by test | structural — **the unit has never been escaped, only read** |
| The semantic service is sandboxed with authenticated IPC | sandbox + mutual auth + egress capture | **none — bounded loopback adapter only** | none |
| Dependencies are scanned and gated | CI | govulncheck reachability gate in all nine repositories and all nine vendored modules, verified by exit code | integration |
| A release artifact is approved by two people, on either platform | the manifest and the shipped verifier | the same two-approval path driven by a real Linux tarball as well as a disk image: two distinct approvals required, one approver twice refused, a padded archive refused on length, and an amd64 manifest refusing the arm64 artifact | adversarial — **exercised against test keys only; no release key exists (EB-7)** |
| Uninstalling removes what the reader materialised | the script against the sources | the shared App Group container is removed, matched by the suffix the signing gate pins; the scanner resolves constants, so a directory that moves into one is still compared. Both mutation-checked | structural — **the script has never been run against a real installed bundle (H-10)** |
| The client's trust can be rotated and revoked | the shipped sources | no compiled-in publisher key anywhere in the Swift sources; the client verifies a signed SiteID descriptor. The scan carries a control that recognises a real key | structural |
| The scheduler never waits for a producer | the queue's own boundary | reserving a slot without publishing it returns cover immediately; making the consumer wait, which is what the old lock did, deadlocks the test | adversarial |
| A directory write survives a crash | the flush the platform provides | one implementation in `live/durable`; the unix build flushes, the Windows build cannot and says so (DEC-026). `TestNoOtherPackageKeepsItsOwnDirectoryFlush` stops the nine copies returning, with a control | structural — **the unix flush is called, never crash-tested** |
| A checkout is the commit | byte comparison after checkout | `* -text` in all nine repositories; the rule and the sealed artefacts are both tested, each scan with a control. Found by the first Windows run failing a byte-for-byte vector comparison on identical bytes | adversarial |
| Cells cross the wire over IPv6 | two nodes on a real socket | a sealed cell stored, an unnamed IPv6 source refused, a replay refused, over `::1`, with the addresses asserted to be IPv6 first | integration — **loopback, not a WAN** |
| A dependency arriving is a decision somebody wrote down | the module graph of every repository | six repositories assert a graph with no dependencies; `Nomad-browser` names the three sibling repositories it cannot ship without; `nomad-anytrust-mix-sim` pins the four modules whose code compiles and the seventeen `go.sum` holds; `nomad-testnet` requires module, version and a written reason in `DEPENDENCY_POLICY.json` | adversarial — each gate mutation-checked in both directions, and the shared scan crippled to find nothing |
| The versions that compile are the versions approved | the toolchain's own resolution, not `go.mod` text | `TestTheModulesThatActuallyCompileAreTheApprovedVersions` reads what `go list -deps` resolves; the components exception is refused there. A root downgrade to a components-only version previously passed the text checks while changing what shipped | adversarial |
| The toolchain still receives security fixes | CI pin against Go's support window | every repository on 1.25, after a 1.23 pin aged out and left 20 reachable stdlib vulnerabilities in the one repo that was scanning | integration |
| Dependencies are not malicious | provenance or attestation of the dependency itself | **none — govulncheck answers whether an advisory is reachable, not whether a dependency is what it claims to be** | none |
| Build has an SBOM and provenance | release artifacts | both generated in CI; provenance stamps itself unsigned outside a protected identity, and no release key exists (EB-7) | integration |
| Update cannot roll back | updater tests | a persisted watermark refuses anything not strictly newer, pre-release ordering included, so a signed 1.2.0-alpha.1 cannot install over 1.2.0 | adversarial |
| Two signed artefacts for one version are refused, not resolved | negative test | equivocation is an error rather than a choice, because resolving it silently is how a build made for one person reaches them | adversarial |
| A genuine manifest does not authorise a different file | negative test | size checked before hash, so a padded artefact fails on length | adversarial |
| Corrupting the watermark does not disable rollback protection | negative test | an unreadable watermark refuses the install rather than reading as absent | adversarial |
| The updater cannot give the browser network access | dependency direction | the update package fetches nothing, and a test fails if its graph gains net, net/http, net/url or os/exec | adversarial |
| Updates are verified against a genuine release key | release key custody | **none — no release key exists (EB-7); the mechanism is exercised against test keys only** | none |
| A user is protected without doing this manually | installer integration | **none — nothing invokes the verifier when a disk image is mounted** | none |

## Long-horizon correlation

The threat model assumes an adversary that correlates observations over long
periods. Nothing here bounds it.

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| Repeated sessions do not intersect to identify a reader | long-horizon campaign over many sessions | **none — E-10 NOT_STARTED** | none |
| Repeated publications do not intersect to identify a publisher | long-horizon campaign across epochs | **none — E-10 NOT_STARTED** | none |
| Cover traffic bounds aggregate leakage, not just per-observation leakage | analysis + campaign | **none; no analysis exists** | none |

Fixed-rate cover bounds what one observation reveals. It says nothing about
what many reveal in aggregate. This is the largest unmeasured area in the
project and the easiest to over-read from the per-observation results above.

| Every supported target builds | cross-compilation matrix | eight targets including windows/amd64 and windows/arm64, gated in CI | integration |
| The Windows cross-process lock works | a Windows runner | **none — it compiles and has never run** | none |

## How to read the gaps

Every row at `none` is a claim the project must not make. Several of them —
publish/no-publish equivalence, browser egress capture, reproducibility with
a second builder, blind two-world classification, and every row in the
long-horizon section — are gated on external resources (EB-1, EB-3, EB-4) or
on unstarted work rather than on further design.

They are also why the great majority of PROD gates are not MET. Two gates
(PROD-08, PROD-12) are MET because their criteria name harms this matrix has
rows for at `adversarial` level; that is not a statement about the others.

## Fair access under a flooding operator

| Claim | Boundary required | Tests | Level |
|---|---|---|---|
| One operator cannot take another's relay-queue share | the queue's own accept and serve paths | a flooder enqueuing 6400 cells keeps its share of 16 and is served 4 times in 16 emissions; every other source keeps all of its cells and loses none | adversarial |
| One operator cannot take another's cache stream share | the cache's admission rule | a sender asking for 64 streams gets its exact share of 4; three other senders keep all of theirs; the share survives a reopen | adversarial |
| A flood does not stop another operator's work being admitted | a live node under continuous flood | `TestAFloodFromOnePeerDoesNotStarveAnother`: 4527 rejections driven, the second operator's batch still admitted and completed | adversarial, loopback |
| A sender outside the signed set gets no share of either | queue and cache accept paths | refused with no line created and no drop counted, so a stranger cannot write to this node's diagnostics either | structural |
| Fair allocation does not change emission timing | — | the scheduler asks for one cell per tick whatever the queue holds; the rotation decides which cell, and relay work is public replication policy | structural |
