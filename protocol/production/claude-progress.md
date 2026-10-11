# Progress journal

Newest first. Each checkpoint: completed work, commits, evidence, risks, next
priority, blockers.

## Checkpoint 2026-09-03c: the campaign is green

The seven inconclusive arms are fixed, and the gate reports 24 compared, 0
inconclusive, 0 findings. It has never done that before.

**The experiment was being run at a cadence the system does not ship.** 20 ms
with a 200 ms lateness budget. Under cpu-starvation the node missed its budget
and stopped -- correctly, by design -- after 2 to 50 cells, and the rule needs
20 in a flow. A shorter interval has less slack per tick, and the topology's
own bound caps lateness at ten intervals, so 20 ms could not be given more
without moving a normative limit. At the deployed 50 ms the node survives the
identical stressor: 39, 39, 40, 39 cells.

**Two calibrations were rejected on measurement before that.** Reserving a
processor made the stressor vacuous -- sd 0.1452 against a 0.1552 baseline, a
second baseline wearing the starvation label. Duty-cycling was non-monotonic
across a sweep, on a host whose own baseline sd moved 0.155 to 0.423 between
two runs. Tuning severity there would have been tuning to noise, and I would
not have been able to tell.

**A statistic computed on every run and never judged.** worldGap carries the
relative difference in emitted cell counts. It was printed in the log line and
never reached decide(): the two decisions were cadence and the inter-arrival
distribution. So a world emitting materially fewer cells than another would
have been logged and passed -- and that is exactly the statistic that survives
when a stressor is severe enough that there is no cadence left to compare. It
is judged now, and verified to reject rather than assumed to.

**The check on that nearly passed for the wrong reason.** My first injection
sat before the narrow loop that takes the minimum across control pairs, so it
was overwritten before it was judged, and the test passed. Recorded because
"the mutation did not fail" and "the mutation never happened" look identical
from the exit code.

**A duplicated constant that would have failed silently.** The workflow passed
a literal 20 to the rule. Moving the campaign to 50 would have left it judging
windows against an interval nothing emitted at, with no error. It reads the
constant from the campaign now and exits if it cannot.

What is still true: green means the rule could not separate the worlds at this
sample size on this host. Under cpu-starvation the cadence statistic is still
UNDECIDABLE here, and early termination is still reported rather than gated.
Both need E-03 and E-09.

Next: the rest of step 10.

## Checkpoint 2026-09-03b: the campaign was right for eight runs

The timing campaign had rejected on every run since it first executed, and
the last thing I did before this was record that it was red without saying
what it had found. It found a real leak, and it is fixed.

**The cadence was perfect and that is why it hid.** Mean inter-arrival was
exactly the configured interval in every world -- 20.010, 20.003, 19.995
against 20. Every summary an operator would look at said the schedule was
being met. The separation was in the shape: idle emission was bimodal with a
hole in the middle of the distribution, and emission with private work was
smooth across the same range. No statistics needed to see it once plotted,
and the preregistered rule had been rejecting at p ~ 0 for a week.

**A sleep does not end when it is asked to.** In twenty lines of Go with no
Nomad code in them: a 20 ms timer woke a median 585 us late on a quiet
process and 446 us late with one unrelated goroutine sleeping on a 2 ms
cycle, every percentile shifted, reverting when it stopped. The wake instant
is a function of ambient process activity, and a node with private work to do
is not ambiently identical to one without. Sending immediately after the wake
put that straight onto the wire.

The scheduler now sleeps to just short of each deadline and spins the
remainder, so the send instant belongs to the deadline. Idle-to-active median
gap 348 us before and 4 us after; standard deviation down from 0.74 and 0.42
to 0.10 and 0.045; the rule goes from 10 rejected comparisons to 0.

**The first fix was wrong and the measurement is what said so.** I moved cell
construction off the deadline path first, reasoning that building a work cell
costs more than a cover cell. It changed nothing. Measured afterwards, the
reasoning was quantitatively wrong by an order of magnitude: 8.4 us against
8.8 us for NextCell, 74.0 against 75.3 for Send, against a grid that moved by
a millisecond. Kept as defence in depth, not claimed as the fix.

**Method note worth keeping.** What broke this open was reproducing the
finding outside the system -- a standalone timer loop with and without a
competing goroutine. The leak was not in any line of Nomad; it was in what
Nomad inherited by sending at the moment a timer happened to fire. Nothing in
the codebase would have pointed at it.

Still red and not this: 7 of 24 comparisons are inconclusive because the
cpu-starvation stressor stops the node. That fails the gate deliberately.

Next: the inconclusive arms, then the rest of step 10.

## Checkpoint 2026-09-03: the file with the socket had no tests

Step 9 of the ordered plan -- discovery, sessions and Sybil resistance,
PROD-19 and PROD-20 -- run with the mutation probe that produced F-37 through
F-41. Eleven guards across `live/uplink`, `live/topology`, `live/node` and
`live/deposit` neutralised in turn; six failed the suite, five did not.

**The finding was not among the survivors.** `live/entry` is the process an
operator actually runs: it holds the socket, the responder and the session
table. It had no test file, so the sweep could not have found anything there
because nothing there was being run. Reading it instead turned up a real
defect: a source address bound to exactly one session, and a cell from a bound
address never offered to the responder again. A publisher restarting behind a
NAT that kept its mapping came back on the same address with a new ephemeral
key, its handshake was tried as a data cell against a session it no longer
held, and it was locked out of that operator for the life of the process. The
same is available on purpose to anyone who can spoof a source address.

This is F-37's cross-boundary gap in a new shape, and worth stating as a
pattern rather than an incident: **every guard the uplink library provides was
tested from the library, and the composition that decides which of them a
datagram meets was tested from nowhere.** Coverage by package hides this,
because the library's numbers are excellent.

**A comment that described a different bound than the code.** `SessionLimit`
was documented as sessions held at once. The responder cannot work that way --
it must remember every ephemeral key it has accepted, or a replayed handshake
reuses that key's AEAD nonces -- so nothing frees a slot and the number is a
budget spent for the life of the process. An operator sizing it as an
occupancy would have sized it far too small. Both comments now say what the
code does, and the exhaustion that follows is written into
`ADMISSION_AND_RATE_CONTROL.md` as an accepted denial of service, because the
alternative trades a bounded availability loss for a key-reuse break.

**Three survivors were genuinely unheld, two were shadowed, and the difference
is recorded rather than smoothed over.** Unheld: a signed topology with epoch
zero (the value the watermark uses to mean absent, so accepting one writes a
record the node cannot read back and cannot start again without), an
unparseable `not_before` (which parses as the zero time -- a window with no
lower edge, and the field an epoch descriptor checks its activation against),
and arbitrary bytes in an uplink cell's reserved padding (a channel from a
publisher to the entry operator it is anonymous to, since the AEAD stops
everyone else from reaching it). Shadowed: the authentication failure in
`Session.Open`, refused by the length check behind it, and the `not_after`
parse, refused by the validity window whenever the caller passes a real clock.

**A second definition of cover, with no callers.** `uplink.IsCoverPayload`
duplicated `airlock.IsCover` byte for byte, unreferenced in any repository,
specification or corpus. Two definitions that could have drifted apart in
silence. Removed.

Next: step 10, whole-system failure campaigns.

## Checkpoint 2026-09-02k: a citation of my own that pointed at nothing

**F-34, and it is mine.** F-21 built a gate because this index cited tests that
do not exist. It checks names. It never checked paths -- and the F-18 entry,
written earlier in this same session, cited a vectors directory that is
gitignored in nomad-testnet, was never committed to any repository, and existed
only on the container that made it. A reader following that citation would have
found nothing, and the container is ephemeral.

The vectors are in `production/reports/` now, digested like the other reports.
The gate checks cited evidence paths against **git** rather than the
filesystem, which is the whole point: the directory that caused this was
present on disk and in no repository. Scoped to paths with an `evidence` or
`reports` segment, because a first version that checked every backticked path
produced eight false positives against one real one, and a check people learn
to ignore is worse than none.

**The shaper, measured properly for the first time.** The structural candidate
for the timing blocker gates on median cadence only -- `grep -c KS` on its
campaign returns zero -- and this project has already established the median is
too weak to see this finding. So the fix has never been evaluated against the
statistic that shows the problem, and its PASS results are on the arm that
already passes without it.

That was checkable. Retaining the timestamps its boundary test already collects
lets the preregistered rule judge the architecture. One of four treatment pairs
rejected, none of three controls, one control at p = 0.025. Recorded with its
limits and as no part of any claim: one experiment, a noisy shared container,
seven comparisons at alpha 0.01, a different harness and host from the campaign
it invites comparison with. What it produces is an acceptance test the
integration did not have -- before this, the shaper's own gate would have
passed it on a statistic that cannot see the finding.

**Workstream H: the Linux release process.** DEC-027 recorded that there was
none, so the client could not be offered even if someone wanted to. There is
one now. The mechanism was already platform-neutral -- nothing in `update/`
mentions macOS, a disk image or a bundle -- and neutral is not the same as
exercised: every test drove it with a `.dmg`. It is now driven by a real
tarball, including the case that matters more on Linux than macOS, where a
release has two artifacts and one manifest must not authorise the other.

The first version of that test was vacuous. The helper built both architectures
from identical bytes, so they shared a digest and the refusal could not happen.
It now varies the content and asserts the two differ before asserting either is
refused.

**Nothing was promoted.** DEC-027's decision stands unchanged: nothing has been
offered to anyone. PROD-30 records the process half as closed and the deciding
half as open.

Commits: nomad-protocol 32607da, e7b64b9; Nomad-browser 79ad4da.

Evidence: F-34, the shaper distribution probe, one claim row.

Next: the shaper integration now has a defined acceptance test and is the
remaining structural candidate for the timing blocker; workstream B governance
(EB-2 bounded); EB-10 needs the owner.

## Checkpoint 2026-09-02j: what was stranded on branches

Having found this branch behind `main` twice, the obvious next question was
whether anything was stranded on branches that reached neither. A sweep of all
nine repositories found nineteen unmerged branches. Most are experiment
harnesses whose results are already recorded -- the Scaleway WAN runs are in
this index with their outcomes, so the branch is the instrument, not the
finding. Three were not.

**F-32: a second-party review.** PROD-02 and PROD-27 both carry the blocker "a
review by a party that did not author this". One existed: another agent
reviewed the threat model, the claim matrix and the telemetry instrumentation
on 2026-08-27, concluded PROD-02 PASS and PROD-27 NOT YET PASS, and corrected
stale future-state wording. None of it reached here, so both blockers read as
though no review had happened.

It does not close PROD-02, for a concrete reason rather than a judgement about
who counts as a second party: it reviewed the documents as they stood that
day, and they have changed substantially since -- including while writing this
entry. A review of an older version does not cover the current one.

The threat-model corrections are taken. One went the other way: the
endpoint-fallback row said whole-binary egress capture was "missing", and this
branch has had it for the Linux release binary since F-22. Both versions were
stale, in opposite directions.

**F-33: the control PROD-27 was waiting for.** A no-core-dump Compose boundary,
written the same day, never merged. Taken and tightened twice -- the original
test would have passed with `soft: 0` under a different limit, and a file
saying so is not a container having it, so the limit is now read back from each
running container. It still does not close PROD-27, and codex's own registry
agrees: same two blockers, word for word.

**EB-10: the licence.** Two repositories adopted the Nomad Restricted Source
License on their `main`; seven are MIT. Re-vendoring the fabric component for
its queue fix brought the restricted licence into an MIT repository. The
vendoring is faithful on purpose -- the manifest pins the tree by content --
so the conflict is recorded rather than hidden inside a snapshot, and a test
now fails on any vendored licence that differs without being written down.
Which licence applies where is a decision with legal consequences and belongs
to the owner.

**What was left, and why.** About 8,500 lines of automatic epoch rotation sit
on the same codex branch. Not integrated: on its own branch PROD-05 and
PROD-08 remain PARTIAL with unchanged blockers, so it did not close its
criteria there either, and PROD-08 is recorded worse there than here.
Integrating it is an evaluation of a large change rather than a merge. Naming
it is what stops it being lost a second time.

Commits: nomad-testnet 0b06ca2, 1f0a866; nomad-protocol 1477e5f, e1f31b5.

Evidence: F-32, F-33, EB-10.

Next: the shaper process, still the remaining structural candidate for the
timing blocker and still never measured; workstream B governance (EB-2
bounded); workstream H, where the Linux release path is a named gap (DEC-027).

## Checkpoint 2026-09-02i: the branch was behind main on its own blocker

The question that found the last three findings -- has this ever run? -- has a
sibling: **is this branch the code the registry describes?** It was not.

**F-30.** This index records a release blocker, private activity perturbing
emission timing, and names the mechanism: a producer mutex held across an O(n)
copy on the scheduler path. That was fixed on nomad-constant-rate-fabric's
main, with tests, and this branch never picked it back up. The campaign had
been measuring a queue whose defect was already known and already repaired
somewhere else. A sweep found two of nine repositories meaningfully behind
main; the rest only by licence and merge commits.

The merge itself hid a semantic conflict -- git resolved cell.go cleanly and
left a method referring to fields the new type does not have -- and the
campaign's path filter did not include components/, so the one change it
exists to evaluate would not have fired it.

**And the finding survives.** Baseline 8 of 8 idle-vs-active comparisons
rejected before the fix and 8 of 8 after; controls fire in neither. The queue
was one channel and closing it did not close the finding, which agrees with
the root-cause document's own reading: removing a lock is not resource
isolation. The structural candidate is the dedicated shaper process on
agent/operator-shaper-process, still unmerged and still never measured against
this campaign. Nothing here claims it works.

**F-31.** Nomad-browser was twenty-five commits behind main, on the
Team-scoped App Group work that Workstream F is about. Merging it failed three
of this branch's guards, and one was hiding a real defect: the objects moved
into a group container and the uninstaller only ever removed the sandbox
container, so uninstalling left everything a reader had materialised on disk.

The test did not name it. It went vacuous -- the object directory had moved
into a constant its scanner could not see -- and failed because it refuses to
pass on an empty comparison. Without that refusal it would have compared two
empty sets and reported success, and the defect would have shipped behind a
green test. That is the single clearest return this session's discipline has
paid.

**What the guards cost and returned.** Every vacuity check written earlier
fired on this merge and every one was right: an entitlement with no written
reason, a scanner comparing nothing, a cross-check whose marker was gone
because the client had moved to something better.

Commits: nomad-constant-rate-fabric 70a5438; nomad-testnet ed87f7d, d41b0db;
Nomad-browser 0d9b760.

Evidence: F-30, F-31, three claim rows.

Risks: the timing blocker is unchanged and now better characterised. Next:
whether to integrate the shaper process, which is the remaining structural
candidate; workstream B governance (EB-2 bounded); workstream H, where the
Linux release path is a named gap (DEC-027).

## Checkpoint 2026-09-02h: three gates that had never run

The Windows job's payoff was not the Windows job. It was the question, which
turns out to have several more answers here: *has this ever executed?*

**The Go suite had never run on macOS.** The only thing that ran on a macOS
runner was the DMG build; the client, the renderer decisions and the update
path were tested on Linux and shipped to macOS. It runs there now and passes.
The capability declaration had to change first: it was one flag meaning "every
gate can run here", and the macOS runner has python3 and no strace, so it
could declare neither -- and the parser-differential gate PROD-16 rests on
would have become a silent skip on exactly the platform that ships. Named
capabilities, with ten cases testing the declaration itself, because a typo in
a workflow would otherwise disarm it with nothing to notice.

**F-28: the timing campaign had never run, and could not be made to.** Both
its triggers fire only from the default branch -- `schedule` is read from
there, and the dispatch API answers 404 for a workflow that is not on it --
and it has only ever existed on a feature branch. Its tests skip unless a
variable is set, so the wire two-world campaign, the hostile-peer flood, the
capacity measurement, the cross-process publication capture and the airlock
sealing measurements had no automated runner at all.

Its first run reported the finding this project already records -- the
inter-arrival distribution distinguishes idle from active, KS 1.0000 against a
0.9900 tolerance, reproduced across both attempts -- which is the first time
that verdict has come from an automated run. It also exposed a defect in the
gate: `cpu-starvation` stops the node, which is the designed behaviour, so
that arm produced too few cells to score, and the rule exited before comparing
`disk-pressure` at all. One unmeasurable arm hid every verdict after it.
Counted and carried on now; still fails, and now says what it found.

Worth recording alongside the finding: the control spread on that statistic is
0.73-0.82 of its range. A control that noisy limits what the KS arm can
resolve. Calibrating it is open work, and saying so is not the same as
explaining the finding away.

**F-29: the Linux release build had never produced anything.** Its tag pattern
was `v*` and this project tags `nomad-browser-macos-v<version>`, and its
dispatch was 404 for the same default-branch reason. So no Linux tarball, SBOM
or provenance had ever existed. DEC-027 records what that turned up rather
than papering over it: there is no release process for Linux at all, so the
client stays a build target and is not published because a workflow now
produces a tarball.

**The shape.** Fourteen findings now, F-14 through F-29. The first eleven came
from "if this check were deleted, what would fail?" The last three came from
"has this ever run?", and the answer was no three times in a row -- once for a
platform, twice for a workflow that no trigger could reach.

Commits: Nomad-browser 5404939, ee0aeef; nomad-testnet bc6419b, 71f426d;
nomad-protocol d2d4487.

Evidence: F-28, F-29, DEC-027.

Next: workstream B governance protocol (EB-2 bounded), workstream F
browser/materializer boundary, workstream H release engineering -- where the
Linux release path is now a named gap rather than an unnoticed one.

## Checkpoint 2026-09-02g: the first Windows run

PROD-16 recorded that Windows was "built but not tested: no Windows runner
executes the suite, so the LockFileEx path compiles and has never run." A
runner now does, scoped to `live/epoch`, and it gated a release on its first
push. It found two things on that first run, neither of them the lock.

**F-26: the epoch chain store had never worked on Windows.** Twenty-two tests
failed, every one that mutates the store, all on `sync ...: Access is denied.`
`os.File.Sync` on a directory handle is `ERROR_ACCESS_DENIED` there; Windows
has no equivalent of fsync on a directory, so this was never going to work and
nothing had ever asked. Nine places did that flush -- five named helpers, no
two alike, and four inlined inside larger functions, which is why grep found
five and a gate looking for the shape found nine. `live/durable` is the only
copy now, the Windows build's weaker guarantee is stated rather than implied,
and DEC-026 records the position instead of leaving it to be inferred.

The lock tests, which were the reason the job existed, passed. `LockFileEx`
has now executed.

**F-27: a Windows checkout was not the commit.** The same run failed the epoch
vector comparison on bytes that are identical in the repository:
`core.autocrlf=true` rewrites LF to CRLF on checkout. The test failure is the
small consequence; the large one is that `conformance/wire-vectors.json` is
sealed by a digest and cited as PROD-01 and PROD-03 evidence, so a second
implementer verifying it on Windows would have got a different digest for the
same commit with nothing to explain why. `* -text` in all nine repositories.

**IPv6 reached the wire.** PROD-21 said "no live IPv6 run anywhere", which was
accurate: `live/topology` has thorough IPv6 tests and every one is about a
document. Two nodes now exchange cells over `::1` -- a sealed cell stored, an
unnamed IPv6 source refused, a replay refused -- and the test asserts the
addresses are IPv6 before asserting anything about them. It skips where there
is no IPv6 stack, which is this development container, and fails where
`NOMAD_REQUIRE_CAPABILITY_GATES=1` says the environment has one. CI was the
first place it ran.

**F-23 and F-24, earlier the same day**, in `nomad-testnet`'s dependency
policy: an exception written for requirements nobody builds also licensed the
root module, and every check read `go.mod` as text rather than asking the
toolchain what compiles.

**The pattern this checkpoint adds.** The previous two came from asking "if
this check were deleted, what would fail?" This one came from a different
question: *has this ever executed?* A build target is not a tested target, and
the gap between them held a store that could not write and a corpus that was
not portable.

Commits: nomad-testnet 5845278, d0f9d7f, 85d461d, 2598f2b; nomad-protocol
d0973f8; Nomad-browser 9a18a05; nomad-rlnc 3ecedbf; nomad-selection-firewall
a1ed9cd; nomad-semantic-basins df45010; nomad-local-reconstruction 3650c28;
nomad-constant-rate-fabric 2269a68; nomad-anytrust-mix-sim 1d99367.

Evidence: F-23 through F-27 and DEC-026.

Next: workstream B governance protocol (EB-2 bounded), workstream F
browser/materializer boundary, workstream H release engineering.

## Checkpoint 2026-09-02f: the controls were not controlling

The module-graph gates added at the end of the last checkpoint each carried a
control, on the principle that a scan finding nothing must not be able to pass
by finding nothing. Turning that principle on the controls themselves is where
this checkpoint started, and none of the six survived it.

**F-25: the controls did not run the scan they were controlling.** Each gate
parsed `go list -m all` and filtered; each control ran the same command and did
a `strings.Contains` on the raw output. So the control proved the *command*
reports a dependency and said nothing about the gate's parsing -- a filter that
dropped everything would have passed both. They could also skip: the fixture
named a real module, so it needed the cache or the network, and skipped when it
had neither, which is to say it vanished in exactly the environments nobody
watches. The scan is now shared code, the fixture resolves under `GOPROXY=off`,
and crippling the scan fails the control.

Rewriting them exposed two gaps. `Nomad-browser` filtered out sibling modules
before counting, so it asserted no third-party code while saying nothing about
the three repositories the binary cannot ship without. And the first draft of
the `nomad-anytrust-mix-sim` gate pinned one list, built from captured output,
described as "modules the build can reach": it omitted `bitset`, and thirteen
of its seventeen entries compile into nothing. It failed on its first run
against its own author. Two lists now -- four modules whose code runs, and the
seventeen-name graph `go.sum` pins -- and the mutation that proves keeping them
apart is worth it fails each on a different module.

**F-23 and F-24 are the ones that matter.** `nomad-testnet` already had a real
dependency policy, stronger than what was being added around it: module and
version, a written reason, every component's `go.mod`, replaces confined to the
repository, `go.sum` pinning, checksum-database environment. It had two holes.

Its two policy lists were merged into one set and applied to every `go.mod`, so
`allowed_older_in_components` -- an exception written for requirements nobody
builds -- also licensed the root. Downgrading the root's `golang.org/x/sys`
from `v0.47.0` to `v0.42.0` left the gate green while `go list -m` confirmed
`v0.42.0` was what the build selected. Five releases of unreviewed code in the
shipped binary, no diff to the policy file, nothing red.

Underneath that: every check there read `go.mod` as text. Text is what a
reviewer sees and not what compiles, since version selection picks across the
whole graph and a `replace` substitutes wholesale. They agreed; nothing made
them agree. The build is now asked of the toolchain -- the modules that provide
compiled packages, at the versions selected -- and each must be approved at
exactly that version, with the components exception given no standing.

**The shape of both checkpoints.** Eleven findings now, F-14 through F-25, from
one question asked repeatedly: if this check were deleted, what would fail? The
last three came from asking it of checks written in the previous checkpoint,
which is the argument for asking it of new work rather than only of old.

Commits: nomad-testnet 5845278; Nomad-browser 2c8179a; nomad-anytrust-mix-sim
de88b21; nomad-rlnc a02f415; nomad-selection-firewall fd23af0;
nomad-semantic-basins 3c12524; nomad-local-reconstruction d9bfefe;
nomad-constant-rate-fabric b927124.

Evidence: F-23, F-24, F-25 in `production/EVIDENCE_INDEX.md`.

Risks unchanged. Next: workstream B governance protocol (EB-2 bounded),
workstream F browser/materializer boundary, workstream H release engineering.

## Checkpoint 2026-09-02e: the registry was wrong about itself

The coverage sweep finished the remaining repositories and then turned on the
execution artifacts, which is where the last two findings came from.

**F-20: the release verifier's untested branch is the one every build takes.**
`cmd/nomad-browser-verify` decides whether a release may be installed over what
is installed now, and had no test at all -- while the `update` package beneath
it sits at 66-91%. The wrapper is where a build with no compiled-in release key
must refuse rather than proceed with an empty trust set, and no release key has
been generated (EB-7), so the untested branch was the live one. Anti-rollback
and dry-run are now asserted end to end through the binary.

**F-21: the claim matrix cited tests that do not exist.** Three citations had
gone stale through renames. One was worse than a rename: the row read *"not
claimed, and measured false"* because version 1 carried the stream ID in the
cleartext hop header. Version 2 encrypts the whole cell and the test was
renamed to assert the opposite -- and the matrix went on recording the property
as broken. The registry that decides what this system claims was understating a
privacy property, and had been for as long as the encryption work has been
done.

That is the sharpest form of the session's recurring shape. Every earlier
finding was a check that could not fail; this was a *record* that could not
fail, because nothing read it against the code it describes.
`scripts/check-cited-tests.py` now does, in CI, with the eight repositories
cloned and the capability declared so a failed clone fails the run rather than
reporting nothing to check. It caught the evidence entry describing it, on its
first use, against its own author.

**What the whole sweep amounts to.** Eight findings, F-14 through F-21, from
one method: for each check, delete it and see whether anything fails. Two were
defects rather than gaps -- a cross-implementation disagreement about a signed
topology, and a cover-cell generator returning a half-filled cell alongside its
error. One was a stale record. The rest were checks with nothing watching them.

Three guards were added because the thing they guard against happened during
the sweep: the repin script refusing this repository's own HEAD (which fired
again, in another repository, within hours), the mutation harness verifying
that a mutation applied (after reporting a survivor that had never run), and
the citation gate.

Commits: Nomad-browser a210e22; nomad-testnet 2460a8d; nomad-protocol 9301917,
d4e86c7.

Next priority: Workstream H's non-blocked items, and Workstream B's, which is
where most of the remaining PARTIAL rows that are not waiting on an external
party live.

## Checkpoint 2026-09-02d: the sweep finds a real interoperability defect

The coverage-directed sweep continued into the remaining packages, and this
time it turned up something that was not a missing test but a live
disagreement between the two implementations.

**F-18: a signed topology Go accepted and the reference refused.** Go's base64
decoder ignores CR and LF wherever they appear, and `Strict()` does not change
that -- it constrains the final quantum's padding bits and nothing else. The
Python reference uses `validate=True` and refuses them. Eighteen decode sites
used the Go form. A topology carrying the JSON escape `\n` inside its
authority signature -- still valid JSON, so both parsers read it -- verified
here and was refused there. Shown on the same bytes, with the vectors stored.

The signature could not object: verification re-serialises what it parsed, so
a newline inside a field that is *part of* the document breaks the signature,
but the signature field is excluded from what it signs. Same shape as the
duplicate-key ambiguity `strictjson` was written for, which is where the fix
went.

Not a forgery. A split view of the operator set, decided by whoever hands over
the file, which is what PROD-01 and PROD-03 exist to rule out. Both
implementations now refuse it on the same corpus vector, and the Go mirror was
checked against the lenient decoder it exists for.

**F-17 and F-19: four more packages with no tests at all.**
`live/fetchplan`'s signature check, `live/bundle`'s stream commitment, the
fabric's `Scheduler.Run` -- the entry point `cmd/nomad-publish` and the node
both call, where every existing test used the finite `RunCells` -- and
`RandomCell`, which fills the cover cell. Writing the last of those found
`RandomCellFrom` returning the half-filled cell alongside its error, so a
caller ignoring the error would emit cover with a constant tail. Every caller
checks, so it is depth rather than a live defect, and it is one line either
way.

**Two process corrections, both made after being caught by the thing they
now guard.**

The mutation harness now verifies that each mutation actually applied before
running the test. It reported a surviving mutation that had never been
applied: the string replace matched nothing. A harness that cannot tell
"survived" from "never ran" reports the first as the second.

The repin guard added in F-15 fired for real within hours, on the same stale
shell variable, on a different repository. That is the argument for writing
the guard rather than resolving to be careful.

**Four vacuous assertions were caught by tests failing rather than by review:**
a base64 padding case against a payload divisible by three; a URL-safe alphabet
case against bytes that encode without + or /; an upper-case hex case against
an all-digit identifier; and a regular-file case that a directory fails anyway.
Each now asserts the variant differs from the canonical form before asserting
it is refused.

Commits: nomad-testnet a68fd2d, 644daf3; nomad-constant-rate-fabric af4ba45;
nomad-protocol a81dba3, a5f5014.

Next priority: the topology refusal lists are not mirrored one for one between
the implementations the way the cell lists are, which is the remaining half of
F-18. Then Workstream H's non-blocked items.

## Checkpoint 2026-09-02c: four checks that looked tested and were not

This checkpoint is one method applied repeatedly: for each security check,
delete it and see whether anything fails. Four did not.

**Cache discovery was implemented in the other client.** F-04 read as done on
the strength of a comment in the Swift client. The Linux client scanned its
object directory once at startup and never again, so an object the
materializer wrote during a session never appeared. It now rescans on a fixed
interval, measured across three worlds -- searching continuously, idle, and
idle holding nothing. The third world exists because the two-world version
missed a mutation that quartered the interval once the directory had objects,
which would be a cadence set by this reader's own materialized objects.
(F-13.)

**Two cross-implementation checks skipped rather than failed.** A runner image
that stopped shipping python3 would have retired PROD-03's evidence in
silence. Both repositories now declare `NOMAD_REQUIRE_CAPABILITY_GATES=1`, the
mechanism the browser and semantic-basins already used. (F-14.)

**`VerifyEquivocationProof`'s refusals had no negative tests.** A proof is an
accusation anyone can publish, and a chain that accepts one stops accepting
the site's descriptors -- so a proof format that only checks shape is an
attacker-controlled kill switch. Three forgeries now fail: one descriptor
named twice, a proof relabelled to accuse another site, and a genesis-sequence
proof built from another site's descriptors. Two remaining checks turned out
to be entailed by `VerifyDescriptor` and are now labelled as depth rather than
tested by a test that would pass for the wrong reason -- which the first
attempt did. (F-14.)

**A test of a rule exercised the side an attacker does not use.**
`TestAnOperatorCannotReportItselfUnavailable` tested `SignNonReceipt`
refusing. A non-receipt is a struct; an attacker builds and signs one
directly, and `VerifyNonReceipt` is what must refuse it. That check had no
test. (F-15.)

The shape is worth carrying forward: **a test that exercises the producing
side of a rule proves nothing about the verifying side.**

Also this batch: the component repin scripts now refuse a commit equal to the
repository's own HEAD, after a stale shell variable nearly recorded
nomad-testnet's HEAD as the mix snapshot's upstream commit. Caught by reading
the diff; nothing downstream would have caught it.

Commits: Nomad-browser 04312b0, b5e6605; nomad-testnet a9d752d;
nomad-local-reconstruction 4bdd45a, 746cc01; nomad-anytrust-mix-sim e54a0f5;
nomad-protocol d92e8e6, 2e94d8d.

Next priority: Workstream H's remaining PARTIAL items, and B's non-blocked
ones. The coverage-directed sweep that produced this batch is worth repeating
on live/topology, live/epoch and live/committee.

## Checkpoint 2026-09-02b: two loss terms, both found by measuring first

Both items this checkpoint covers started as a feature to build and turned out
to be a defect to fix, which is the pattern worth noting rather than either
result on its own.

**DEC-022's re-submission became DEC-024.** The plan was confirmation-driven
re-submission for the three losses DEC-022 left open. Measuring the terms
before building showed the largest one needed no feedback at all: every
in-window cell is a deposit, cover included, because the operator cannot tell
them apart. At the deployed defaults a publisher emits roughly 1,800 cells into
a 45-second window and the airlock accepts 8 -- and the drain kept taking work
from the queue on every tick, unlinking fragments the airlock then refused in
silence. Six work cells emitted for a bound of two, four destroyed. The bound
is in the signed epoch descriptor the publisher already reads, so the fix asks
nothing of anyone: `Emit` counts its in-window cells and declines work once the
bound is spent, exactly as it declines outside the window.

The re-submission itself is rejected, with the argument recorded because it
generalises: an entry operator that drops one session's cells in epoch E and
reads the release of E+1 learns which object belongs to that session, because
retry makes an object's presence depend on its earlier absence and the operator
controls the absence. Fixed cross-epoch redundancy fails identically. The
property that fails in all of them is the same one, and it is worth carrying
forward: an object's presence in a release must not depend on whether it was
present in an earlier one.

**H-09 was a false claim before it was a missing feature.** `publish.Open`
documented itself as protecting pending content "so that a stolen disk does not
reveal what a user was about to publish", with the key in `queue.key` beside
the fragments it encrypted, at the same mode and owner. The claim matrix
carried "encrypted at rest" against it. `Options.Key` is now a required
`KeySource`: `Passphrase` (Argon2id, per-queue salt) leaves nothing on the disk
that opens the queue, and `UnprotectedKeyFile` is the old behaviour named for
what it is. Both directions are asserted, so the weak mode's weakness is a
passing test rather than a caveat.

**Two tests caught things review had not, and both were the F-09 lesson
again.** The never-overwritten test called the create helper directly, so a
rename-over mutation survived it -- it was testing the helper, not the
behaviour. The concurrency test that kills that mutation then failed against
the real code on its first run: `O_EXCL` gives no-clobber but not atomicity, so
a concurrent opener could read an empty salt file. And a guard I wrote for the
quota gate in the filling goroutine was removed rather than shipped, because
measured with and without it changed nothing observable and no test could
distinguish it from its absence.

Also corrected before it shipped: a comment attributing the Argon2id parameters
to a specific published recommendation they do not match. Citing a standard
from memory is the same failure as an unmeasured number.

Commits: nomad-testnet 9069372, 9df9cfa; nomad-protocol 2b24952, b4073e9,
0ce89ce, 7a97f82. CI green on nomad-testnet 9069372 (unit and live-compose).

Next priority: Workstream F's browser/materializer boundary and Workstream H's
release engineering, both of which are mostly PARTIAL rather than blocked.

## Checkpoint 2026-09-02: a cleanup pass, and what it found

Not a feature checkpoint. The instruction was to remove what a human reviewer
would stop at, and the interesting part is that two of the finds were defects
rather than untidiness.

**Two copies of the strict JSON walk had drifted.** The site descriptor and the
transparency checkpoint each carried their own duplicate-key scan. The
checkpoint's had no bound on members per object or elements per array and did
not call UseNumber. Both documents are hashed and signed as bytes, so a
document two parsers read differently is a differential in the SiteID or the
checkpoint digest -- the exact property the walk exists to protect. The
checkpoint's own 4096-byte cap meant the missing element bound was not
reachable, so this was latent, not exploitable; it is still two chances to
weaken one copy and not notice. One walk now, in
`nomad-local-reconstruction/internal/strictjson`, with the stronger bounds and
depth as a parameter.

**Writing its tests found a fail-open in the promoted copy.** It accepted
truncated input: `json.Decoder.More` reports false once the stream breaks, so
both loops exit quietly, and the swallowed `io.EOF` on the closing delimiter
was the last thing that could have objected. The descriptor decode caught such
documents on the schema afterwards, so this was depth rather than an open hole
-- but the walk itself was not doing what its name says.

**A test whose headline claim could not fail.** `mix`'s
TestWireRoundTripIsExactly1200BytesPerCell asserted `len(wire[i]) ==
WireCellSize` on a `[WireCellSize]byte`: a compile-time constant compared to
itself. The rest of it round-tripped through ParseWire and Decrypt, which read
only the first `cipherSize` bytes, so nothing in the test looked at the padding
at all. Deleting the padding write from `MarshalWireWithPadding` entirely left
it green -- verified, not assumed. Three tests replace it, each killing a
distinct mutation: padding never written, ciphertext offset by one, short read
tolerated. This is the seventh instrument found reporting on something it was
not measuring, and the same shape as the other six.

**The demo publisher key was a literal in four places** -- three Go packages
and Swift -- with nothing checking them against each other. Rotating the Swift
anchor would have left every Go test verifying against the retired key and
still green. `internal/demotrust` holds it once and its test reads
`Models.swift`.

The rest is untidiness with no defect behind it, and is listed here so the
claim stays bounded: dead exported API with no caller (`HealthJSON`,
`EncodePublication`/`DecodePublication`, `Manager.Fingerprints`, and four in
the model package), three hand-written insertion sorts and three hand-written
byte-order encodings where the standard library has both, compiled Python
bytecode tracked in two repositories, and `nomad-testnet`'s repin script
copied into `Nomad-browser` so its lock is no longer hand-maintained.

**A judgement recorded because it went the other way.** Three near-identical
ten-line `strictJSON` helpers in `nomad-testnet`, and the parallel durable
sequence files in `live/hop` and `live/uplink`, were left alone. The first is
ordinary Go; the second differs in width and semantics for reasons its own
comments give. Unifying either would have been refactoring for its own sake,
which is the same failure as the slop it would be cleaning up.

Also measured before acting: comment density across the repositories is 0.42
to 0.70 in the pre-existing code and 0.30 to 0.63 in what this session added,
so there was nothing to trim there and the instinct to trim it was wrong.

Commits: nomad-local-reconstruction 37a39c9, 8b2cb55; nomad-anytrust-mix-sim
b086377, f381273; nomad-semantic-basins 1c08c6d; nomad-rlnc 2aaafe6;
nomad-testnet 8a5f7a5, 0c1f82e; Nomad-browser 13d2363.

Next priority: unchanged -- publication confirmation and re-submission for
undetectable deposit loss, then the browser/materializer boundary.

## Checkpoint 2026-08-26d: capacity, and a flake that was telling the truth

**PROD-28's capacity blocker is closed as far as code closes it.** The blocker
said cells per second per operator, objects per epoch and concurrent publishers
had no numbers. Two of the three turned out not to be measurements at all, and
saying so is most of the value.

A fixed-cadence fabric has no throughput in the usual sense: an operator emits
one cell per interval per link whether it has work or not. So cells per second
per operator is a fact about the signed topology (40 at the deployed cadence),
and objects per epoch is arithmetic on top of it (1,660 at 1 MiB per 24-hour
epoch) and an explicit ceiling no deployment reaches, because cover traffic is
the mechanism rather than waste. What the hardware actually decides is the
margin by which per-cell work fits inside the interval, and that is now measured
for every operation on the operator's path.

Three findings worth keeping:

- **The raw-cache write is the operator's expensive step**, several times the
  entire cryptographic relay path. Still ~100x inside the interval, so not a
  problem -- but it is the one that touches a disk, and therefore the one whose
  container number is least likely to survive contact with real hardware.
- **The publisher's seal at ~9.5 ms cannot hold the 5 ms cadence the topology
  permits.** That is PROD-18's existing blocker with a current number on it.
- **Concurrent publishers has no deployed value to measure.** No command in
  `cmd/` constructs an uplink responder: `live/deposit` accepts an
  already-established session and the session limit is a parameter nothing sets.
  The entry-operator role has no capacity figure because it has no deployment.
  That is a gap the capacity question surfaced rather than one it answered.

**The report cannot drift from the deployment it describes.** The assumed
cadence, operator count and cache-stream default are checked against
`deploy/compose.yaml` and `cmd/nomad-node`, and all three drift cases were
confirmed to fire. Without that, halving the cadence would leave every derived
number in SLO.md describing a deployment that no longer exists, with nothing
red.

**A flake that was reporting something true.** The fair-allocation test failed
under the full parallel `-race` sweep and passed five times in isolation, which
is the shape of a test everyone learns to re-run. It was not: the failing run
received 55 datagrams where a healthy one receives ~1,300. The receive loop had
been starved of CPU and the quiet peer's cells were lost in the kernel before
the node could refuse them -- which says nothing about fairness, and the test
was reporting it as a fairness defect. It now resends until the batch is
admitted rather than for a fixed number of attempts, stops as soon as it
succeeds, and its failure message reports delivery so the two situations are
told apart. Healthy runs are also slightly faster than before.

Ten full `-race` sweeps have passed since. One sweep failed between them whose
output I did not capture, so this is good evidence and not a confirmed fix, and
the commit says so rather than claiming the flake is gone.

**Not claimed.** These are not capacity targets. Every figure comes from a
shared container running other work, each cost is measured in isolation rather
than with the scheduler, socket and cache contending for one core, and nothing
runs long enough to speak to drift. PROD-28 keeps four blockers: the soak, the
regional-failure exercise, incident history, and now an explicit one saying
these numbers are costs rather than targets.

## Checkpoint 2026-08-26c: descriptor distribution, and the log's own failure modes

**PROD-15's open blocker is closed in code.** The blocker said descriptor
distribution was neither specified nor implemented, and pointed at the recovery
drill's step 6: a reader who had not seen a recovery still accepted the
attacker, with nothing bounding how long that lasted.

Descriptors now go into an RFC 6962 append-only log. A verifier accepts a
descriptor only with an inclusion proof against a checkpoint it has verified,
moves between checkpoints only with a consistency proof from the size it itself
holds, and stops issuing a publisher verdict once its checkpoint is older than
its freshness window. `docs/SITE_IDENTITY.md` gains a normative "Descriptor
distribution" section with rules 5 to 8; DEC-019 records the three choices worth
arguing about.

The drill's step 6 is rewritten and now measures the bound instead of noting its
absence. It distinguishes two following profiles, because they buy different
things: a reader that mirrors the log's entries gets the recovery as soon as it
syncs, and a reader that follows only checkpoints keeps losing to the attacker
until its window lapses. Both are privacy-safe for the same reason, and the
reason is the load-bearing part of the design: the inclusion proof travels with
the publication, and checkpoint refresh runs on a cadence that takes no argument
describing what anyone is reading. A refresh that failed is never retried harder
because a user is waiting -- that is exactly the private-state-dependent
catch-up traffic the core invariant forbids.

**The gate is structural.** A chain built without a log view can never return
PUBLISHER_VERIFIED, and the witnessed and unwitnessed append paths refuse to do
each other's job. The alternative -- an optional distribution argument -- would
have meant any deployment that forgot to wire it up silently returned to the
unbounded case, invisibly, in exactly the deployments that needed the property.

**Six defects found while building it, all mine, all fixed.**

1. *Both proof verifiers consumed the path in the wrong order.* RFC 6962 emits
   proofs leaf-to-root; both verifiers walked them root-to-leaf. A hand-traced
   seven-entry example passed because its decision sequence happened to be a
   palindrome. The exhaustive all-sizes test failed on `3 -> 4`.
2. *An integer overflow reachable by anyone who can hand a reader a document.*
   The RFC 6962 split was a doubling loop; on a size near the top of the uint64
   range the counter goes negative, the comparison never ends, and the verifier
   spins allocating until it is killed. Sizes come out of proofs. Replaced with
   `bits.Len64`, with a deadline-guarded regression test.
3. *`Distribution` was not safe for concurrent use* -- in the deployment shape
   its own documentation describes, where a refresh runs on a cadence in one
   goroutine and reads happen in another.
4. *The split-view memory was unbounded*, in the one component designed to run
   for months against a log that advances continuously. Now bounded, always
   retaining the held size, because that is the head the escalation demands.
5. *`Log.Append` was O(n^2)* on a structure whose purpose is to keep growing.
6. *Log equivocation was not absorbing.* The specification said a verifier
   "stops trusting the log"; the code returned an error and would happily
   continue at another size, which is the same attack run once more with a
   different number. Now absorbing on both paths, and it resolves
   PUBLISHER_INVALID rather than PUBLISHER_UNKNOWN: the reader holds evidence,
   not a gap.

**A mutation campaign took the survivors from 21 of 131 to 3, and those three
are provably equivalent mutants.** The 18 that died were nearly all the same
failure: a refusal that was being caught by a *later* check, so the test passed
with the check under test deleted. An edited root also breaks the signature; a
malformed time also breaks the signature; a short root also breaks the
signature. The table now asserts the reason, not just that something errored.

**Second implementation and published corpus.** `conformance/reference/
nomadsitelog.py` reads the log objects with no shared Go, from the
specification and RFC 6962. `site/testdata/site-log-corpus.json` publishes the
preimages -- log entries, checkpoint signing messages, every inclusion and
consistency proof, and fourteen documents that must be refused. The crosscheck
runs both directions plus negative controls, and Go verifies proofs the Python
side built over a tree Go has never seen. Two things came out of writing it:
the corpus's refusal reasons had to become machine tags rather than English
prose, because comparing messages across implementations tests translation
rather than agreement; and the container's `cryptography` is present but panics,
so rather than report a pass while silently checking no signatures, the tool
falls back to an RFC 8032 reference verifier used for conformance only.

**Process failure, recorded.** The mutation harness was killed twice mid-run and
left a mutation applied both times. The second time cost about forty minutes:
`descend`'s loop guard had been flipped from `> 1` to `>= 1`, which makes it
allocate forever, and the resulting hang looked like a defect in code I had just
written. A per-mutation `finally` does not run when the process group is killed.
The harness now writes pristine copies outside the repo before touching
anything, restores from them at startup, and has a `--restore-only` mode.
Related: it restores the files it was given, so editing them mid-run silently
reverts the edit -- which is how an export I had added disappeared and turned up
as a compiler error in another package.

**Not claimed.** None of this makes the log honest. A single log that
equivocates is caught only by a reader that sees both heads; the mechanism
produces the proof rather than preventing the act. Preventing it needs more than
one log, or cosigning witnesses, and that is recorded as a deployment decision
rather than claimed as a property. PROD-15's remaining blocker is that the
specification, implementation and drill are all authored here -- a second party,
not more code.

## Checkpoint 2026-08-25b: an evaluator did not approve, and was right

**The single-cell encryption change was reviewed and rejected.** Not the code —
the reviewer verified every property it claims and found no defect in it — but
the evidence and the tests around it, which is the more uncomfortable outcome.

- **A false evidence claim, written by me, sitting in EVIDENCE_INDEX.md.** I had
  led with "the published conformance corpus digest is unchanged" as proof the
  wire had not moved. The corpus contains **zero bytes of mix ciphertext**: its
  only uplink vector is eight bytes of cleartext counter whose own fields say
  the sealed body is randomised and only the frame is pinned. The digest would
  be unchanged if the encryption emitted 1152 zeros. It was not weak evidence;
  it was none. Struck, with a CORRECTION where the claim stood.
- **A test whose central assertion could not fail.** `len(individual) !=
  len(fromBatch[0])` over two `[1200]byte` values folds to `1200 != 1200` at
  compile time. It built and marshalled a two-column batch to read a constant.
- **Six mutations passed the whole file**, including copying the first 48 bytes
  of the private fragment into the padding — publishing plaintext in cleartext
  in every cell. All six now fail on named tests. "Not all zero" is not
  "carries nothing".
- **A real pre-existing vulnerability.** `Encrypt` never called
  `rejectSmallOrder`, which this package has had for as long as
  `validateThresholdCommittee`. Encrypting to the identity gives `y = m + r·0 =
  m`; the reviewer recovered a full 504-byte fragment off the wire with no key
  material. `uplink.Session` holds a bare `PublicKey` that never passes
  committee validation, so it was precisely the exposed caller.
- **The change was incomplete.** The airlock's `coverColumn` still carried the
  two-column workaround, and runs once per cover column up to the batch size —
  the larger consumer of the discarded work than the seal ever was.

**A classification correction that matters more than it reads.** No `cmd/`
binary calls `uplink.NewSession` or `deposit.NewDrain`. The only non-test caller
is the conformance vector generator. So the whole publication path is
implemented and integration tested, **not** production-boundary tested, and the
seal-cost figures describe something nothing deploys. PROD-17 and PROD-18 now
say so.

**Also closed this checkpoint.** The `windows/amd64` build gap (a `LockFileEx`
implementation behind a build tag; eight targets in the matrix, and an honest
replacement blocker that it compiles and has never run). Threshold-share
permissions at rest, which had implementations on both sides and tests on
neither — the same combination that shipped a 0644 node-secrets file to the WAN
campaign.

**The pattern, stated plainly.** Every significant finding in the last two
checkpoints came from turning the project's own instruments on the project, and
several came from a reviewer rather than from me. The recurring failure is not
bad code; it is claims that outrun their evidence, and gates that report a
boundary as fine without having looked. That rate is the argument for PROD-04
and PROD-29, and it is an argument about what has not been looked at yet.

**Gate counts unchanged**: 2 MET, 24 PARTIAL, 3 NOT_MET, 1 BLOCKED.

## Checkpoint 2026-08-25: the vulnerability gate, and what determinism is not

**The largest finding.** PROD-25 cited a "govulncheck reachability gate on every
push". That gate existed in exactly one of nine Go repositories, and running it
there reports **20 reachable standard-library vulnerabilities**. The cause is not
a missed dependency bump: every repository pinned Go 1.23, and Go backports
security fixes only to the two newest minors, so 1.23 had aged out. Several
findings name fixes that exist only in 1.24.9 and 1.25.11-13. The other eight
repositories had no gate, so nothing was looking. `nomad-semantic-basins` was
the sharpest: its HTTP embedder makes `crypto/tls`, `crypto/x509`, `net/url`,
`encoding/asn1` and `net/textproto` all reachable, including a TLS Encrypted
Client Hello privacy leak, in the component that handles query text.

All nine repositories are now on 1.25 and scan clean by exit code, including the
nine vendored modules a root scan never reaches. The vendored snapshots also
turned out to differ from their upstreams by a blank line and a trailing
newline, so "byte-for-byte snapshot" is now true rather than approximate.

**Determinism, measured, and carefully not called reproducibility.**
`compare-builds.sh` existed to compare two build trees and nothing ever produced
two. `check-reproducible.sh` now builds the release binaries twice from two
source copies at different path lengths and requires byte-identical results;
removing `-trimpath` fails it. Independence remains what it always was —
somebody else's machine — and the matrix now splits the claim three ways so a
determinism result cannot be read as a reproducibility one. `docs/REPRODUCIBILITY.md`
records the trap a second builder meets first: Go stamps the commit hash and
dirty flag by default, so a git checkout and an exported tarball differ from
identical source.

**Also closed.** The recorded `windows/amd64` build gap: `live/epoch`'s
cross-process chain lock called `unix.Flock` unconditionally and is now split by
build tag with a `LockFileEx` implementation. All eight targets build and
Windows is in the CI matrix. The honest replacement blocker is that it compiles
and has never run.

**The doc gate audited on its own terms.** `check_docs.py` had the same
weaknesses as everything else: its PRODUCTION_STATUS breakdown check ran only if
its sentence matched, so rewording it turned the check off; `workstreams.json`
had no schema check at all; nothing verified the execution artifacts existed or
that a cited EB-N was defined. Running the strengthened version found 23 real
gaps, including fifteen BLOCKED or PARTIAL requirements with no note and a
PROD-29 blocker that pointed at no external dependency.

**Two mistakes worth recording.** Summarising the external test report while it
was still being written, and reporting "no failures" from a log set that was two
thirds finished — the exact failure this session spent its time on, committed by
the person fixing it. And copying `check-reproducible.sh` to `/tmp` to
mutation-test it, where its repo root resolved to `/` and it tarred the
filesystem until the disk filled. The script now refuses to run unless its root
really is the repository.

**Scope.** DEC-013: Nomad-browser is the browser and the engine forks are
parked. F-11 stays PARTIAL and PROD-22 keeps its blocker; neither is promoted
and neither is deleted.

**Evidence.** `production/reports/2026-08-24-gate-integrity/`: 55 checks, every
one exit=0, logs digested. First run in which nomad-testnet's `go test -race
./...` completes rather than timing out, and in which govulncheck passes in all
nine repositories.

**Gate counts unchanged**: 2 MET, 24 PARTIAL, 3 NOT_MET, 1 BLOCKED. Everything
this checkpoint did was make existing claims true rather than make new ones.

## Checkpoint 2026-08-24: four gates that were not gating, and the seal cost

**What this checkpoint is mostly about.** A full sweep across every repository
was run to verify the deposit-path work. It found that four of the gates this
project counts as evidence were not doing their jobs. That is the material
result, more than any feature added alongside it.

- **`go test -race ./...` was failing outright in nomad-testnet**, timing out
  at Go's ten-minute package default. Two statistical experiments were running
  under a race detector that changes the cost of the thing they measure: the
  publication campaign times emissions against an interval calibrated on the
  real seal cost, and under `-race` a seal costs more than the interval, so the
  loop falls off its ticker entirely. Both now run on a dedicated non-race CI
  step; the race build keeps the concurrency coverage and discards its captures
  so CI cannot apply a timing rule to them.
- **The publication campaign logged its own precondition and returned**, while
  CI went on to apply the full preregistered timing rule to whatever captures
  the run had produced. Its two comments also contradicted each other about
  whether a timing claim was being made. Both preconditions are now enforced,
  each verified by setting its tolerance to an impossible value.
- **`COMPONENTS.sha256` pinned 29 of 46 vendored files.** `sha256sum --check`
  verifies what is listed and never asks whether everything shipped is listed.
  Among the seventeen unpinned were `mix/blame.go` and `rlnc/bounded.go` — the
  budget enforcement the materializer relies on to bound a pollution attack.
  Either could have been edited in place with the gate green.
- **The browser's entitlement check ran on no branch it was pushed to.** It
  needs PlistBuddy and `swift`, so only a macOS runner can run it, and the only
  macOS workflow triggered on push for `branches: [agent/macos-browser]`.
  PROD-23 and F-01 both cited "entitlement gates in CI". The checks are now Go
  tests that parse the plists directly and run everywhere, as an allowlist with
  a written reason per entitlement rather than a denylist.

Two defects in the code those gates watch: a fabric cadence test that failed
when the scheduler *correctly* refused to burst on a stalled host, and topology
admission comparing endpoint strings, so two operators could occupy one address
under different spellings — sharpest as `127.0.0.1:4200` against
`[::ffff:127.0.0.1]:4200` — and be counted as two independent operators. The
same weakness applied to the HTTP endpoints via trailing slash, host case and
scheme case.

**The seal cost, halved.** The previous checkpoint recorded that a publisher
cannot seal cells as fast as it must emit them, named the single-column fix,
and deliberately did not make it. It is made. `mix.Encrypt` refuses fewer than
two cells, correctly — a shuffle of one element is the identity — but that is a
property of a mix input, and a publisher has one fragment. `mix.EncryptCell`
halves the cost from 87 ms to 42 ms with the conformance corpus digest
unchanged. The finding is reduced rather than closed: 42 ms fits inside the
deployed 50 ms with no headroom and is far beyond the permitted 5 ms minimum,
and what remains is the fragment's own encryption rather than waste, so the
next reduction would be a protocol change.

**Built alongside.** Availability accountability, the half of PROD-07 that did
not exist: signed non-receipts bound to a deadline the public timetable fixes,
a quorum of distinct certified operators, and a refutation that names the
observers the transcript contradicts. It refuses to claim withholding, which
asynchrony makes undecidable. Also B-08 (a vanished operator's share is not
rerouted, and private activity during the outage changes nothing a surviving
peer sees), H-08 (an update verifier that cannot fetch, refusing rollback,
equivocation and substitution by name), and H-10 (uninstall plus a retention
analysis covering what macOS keeps that no uninstaller can remove).

**Method note.** Mutation testing earned its place twice. Four mutants against
the availability suite let two live on the first pass, both because the tests
checked something weaker than they claimed. And the browser's Swift symbol scan
has a test that runs it over samples of each forbidden construct, which caught
a word boundary I had added that made the `CFNetwork` pattern miss
`CFNetworkCopySystemProxySettings`.

**Risk.** Every one of these was found by a party that is not independent. The
rate at which this project's own gates have turned out to be wrong is the
strongest argument for PROD-04 and PROD-29 that exists, and it is an argument
about what has not yet been looked at.

**Next.** Gate counts are unchanged at 2 MET, 24 PARTIAL, 3 NOT_MET, 1 BLOCKED.
All three NOT_MET remain non-engineering (a second implementer, thirty days of
soak, a monitored beta). The largest remaining engineering item is F-11: the
engine forks still carry integration contracts only.

## 2026-08-20 — C1 implemented and hardened; D1 implemented; A spike done

**Completed**

- **Workstream C sprint C1** (`nomad-testnet/live/epoch`): EpochDescriptor
  v1 wrapping the unchanged topology v3 and DKG certificate, canonical
  binary encoding with published vectors, chained approval quorum,
  activation signatures, envelope-vs-active windows, persisted fail-closed
  chain store, enforced signature journal, 3-of-5 profile tests.
- **Independent review of C1 found five must-fix defects, each with a
  working exploit.** The most serious: `Approval.Index` was narrowed to
  uint16 for lookup but deduplicated on the full uint32, and the approval
  message bound nothing about the approver, so ONE previous-epoch operator
  could mint a full 3-of-5 quorum and force a membership change alone.
  Also: the equivocation halt failed open on any persistence error; the
  signature journal was implemented but unreachable; revocation was applied
  retroactively and bricked the store exactly when recovery was needed; and
  `Append` returned success for bytes `Verify` rejects. All fixed with
  regressions (`318845a`), plus cross-process locking (`0ad1e35`).
- **Workstream D sprint D1** (`nomad-local-reconstruction/site`):
  self-certifying SiteID, rotation/recovery/revocation with offline
  recovery authority, rollback and equivocation handling, four identity
  states, strict parsing. Spec in `docs/SITE_IDENTITY.md`. Not yet
  independently reviewed.
- **Workstream A ingress spike** (`live/publish`, `live/uplink`): measured
  that the current operator cell profile leaks work-vs-cover perfectly
  under two independent classifiers, so it cannot carry publisher traffic;
  built and tested an uplink profile that defeats both, where cover is a
  real committee encryption on the identical code path so the entry
  operator cannot distinguish it either. Report in
  `docs/PUBLICATION_INGRESS.md`.

**Risks discovered**

- The cleartext hop header (work flag, stream ID, batch coordinates) is a
  publisher-traffic blocker and should be reviewed for what it reveals
  about operator relay patterns over long horizons, even though it does
  not break the reader claim.
- Publication cover cells must be mixed and threshold decrypted like real
  ones; that cost is accepted but affects capacity planning.

**Next priority** Workstream C sprint C2: revocation statements, key
erasure with the forward-secrecy experiment, retired-share refusal, and
automatic rotation; then re-review C before any MET claim.

**External blockers** unchanged (EB-1..EB-6).

## 2026-08-20 — Evaluator critique incorporated; C1 ready

**Completed**

- Independent evaluator agent reviewed the execution plan against the actual
  code (17 findings). All must-fix findings incorporated:
  - envelope-vs-active-window semantics resolve prepare-while-active without
    a topology v3 schema break (DEC-004);
  - canonical binary encoding for all new signed objects; existing objects
    frozen and embedded by exact bytes, so no digest cascade (DEC-005);
  - membership transition defined once, in C (DEC-006);
  - public rotation-failure policy incl. Pedersen abort/bias note (DEC-007);
  - publication ingress spike scheduled before descriptor freeze; client
    uplink + online distributed mix registered as new protocol surface
    (A-14, A-15; DEC-008);
  - single two-world harness rule (DEC-009);
  - registry corrections: baseline count fixed (18 PARTIAL/11 NOT_MET),
    C-01/C-07 notes corrected, A-11 downgraded to NOT_STARTED, G-13 evidence
    cited, workstream M added (PROD-01/02/03/28), B-13 accountability,
    E-12 durability, F-12 semantic-service rows added. 118 requirements now
    tracked.
- Spec revised: `docs/EPOCH_LIFECYCLE.md` (draft v1) and sprint contract
  `production/sprints/C1.md`.
- Deep code audit of topology/DKG/committee/threshold/hop/rawcache stack:
  epoch/context binding at the crypto layer is strong (recorded in C-03).

**Next priority** Implement sprint C1 (epoch descriptor, canonical binary
encoding, chain store, state machine core, vectors, negative tests) in
nomad-testnet `live/epoch`.

**External blockers** unchanged (EB-1..EB-6); user should initiate EB-1,
EB-2, EB-4 now — they are wall-clock bound and independent of engineering.

## 2026-08-20 — Session start: artifacts + baseline

**Completed**

- Committed authoritative goal as `production/GOAL.md`.
- Created persistent artifacts: `CLAUDE.md`, `production/EXECUTION_PLAN.md`,
  `production/workstreams.json` (all GOAL requirements + PROD ownership map,
  honest initial states), `production/CLAIM_TEST_MATRIX.md`,
  `production/EVIDENCE_INDEX.md`, `production/DECISIONS.md`,
  `production/EXTERNAL_BLOCKERS.md` (EB-1..EB-6).
- Baseline: all eight Go repos green on `go build`, `go vet`,
  `go test -race`; `scripts/check_docs.py` passes. No pre-existing failures
  to record.

**Registry state** 0/30 MET, 18 PARTIAL, 11 NOT_MET, 1 BLOCKED (PROD-29).

**Risks discovered**

- Mix proofs bind key+batch digests but epoch/committee binding of the mix
  layer needs audit (C-03).
- Fixture threshold semantics: DKG requires full QUAL of all three operators;
  production 3-of-5 profile with t<n rotation is unbuilt.
- RLNC pollution is a known unmitigated resource-exhaustion vector (G).

**Next priority** Evaluator critique of the execution plan, then Workstream C
(epoch/key lifecycle) sprint 1: canonical EpochDescriptor + lifecycle state
machine spec and vectors.

**External blockers** EB-1 (Apple credentials), EB-2 (independent operators),
EB-3 (WAN infra), EB-4 (assessors/red team), EB-5 (second implementation),
EB-6 (second release approver). Details in EXTERNAL_BLOCKERS.md.

## Checkpoint: airlock built, reviewed, and remediated

**Workstream A (publication airlock)** — built the deposit boundary that the
claim matrix previously carried with no evidence at all: a public release
schedule, a fixed-size batch padded with real committee cover, a shuffle chain
authenticated to the certified committee, and per-column threshold release.

An adversarial review under the evaluator-separation rule found **four Sev1 and
three Sev2 defects, each with a working exploit**, in code whose own tests were
green. All seven are now fixed with a regression each:

1. Shuffle rounds were unauthenticated — a party holding no committee share
   forged the entire "certified" chain and knew the whole ingress-to-egress
   map. The anytrust assumption inverted.
2. A chain that never re-randomised verified; the map was readable off the
   bytes.
3. Wire padding identified every cover column before any decryption. The
   existing tests missed it by slicing comparisons to `[:DepositSize]`.
4. `Seal` ran in time linear in the number of *empty* slots, reading out
   publication volume at 190x, remotely observable by a concurrent depositor.
5. Nothing bound a chain to an epoch, committee or batch; whole chains replayed.
6. One malformed or poisoned deposit destroyed the epoch for every publisher.
7. `ErrEpochFull` was an exact occupancy oracle, and the deposit-ID namespace
   was unauthenticated (membership oracle plus targeted squatting).

**Two claims were retracted, not amended**, because the review invalidated
them: "a partial or reordered chain is refused" and "one operator cannot link
ingress to release". The second is the sharper lesson — the unlinkability
*measurement* passed against a chain with zero anonymity, because a
byte-similarity matcher scores chance whenever re-randomisation happens
regardless of whether the permutation hides anything. It was rebuilt to
measure permutation uniformity instead.

**Workstream E** — the preregistered two-world rule is now executable with
both-direction self-tests in CI, plus a wire-level campaign against the
production node. Two defects found while building it, both of which made the
tooling agree that two worlds matched when they did not: a KS walk that charged
tied values as ECDF gaps (a sample against itself scored p=9e-35 on exactly the
quantized inter-arrivals a fixed-cadence capture produces), and a capture regex
that silently skipped VLAN-tagged packets, shared with a live CI gate.

**Workstream G** — amplification measured at 0.0003–0.0008 under floods of up
to 396 MB, with cadence unaffected, and a check that the flood is not a
private-state oracle.

**Workstream F** — the missing F-07 negative test, plus two non-exploitable
defects it surfaced: the renderer URL gate and the local adapter disagreed on
what a resource path may be, and the gate admitted scriptable `data:` URLs.

**Process finding:** `components/nomad-anytrust-mix-sim` inside nomad-testnet
has diverged from its standalone repository in both directions. A security fix
made in the standalone repo would not reach what ships. Fixes landed in both;
reconciling the vendoring is outstanding.

Still **0 of 30 PROD gates MET**. Three adversarial reviews have now each found
exploitable defects in finished-looking code, which is the strongest available
argument against promoting any gate on internal confidence.

## Checkpoint 2026-08-21: multi-region WAN campaign

Six campaigns on real hosts in fr-par-1 (FR), nl-ams-1 (NL) and pl-waw-1 (PL),
1200-byte cells at 50 ms in a signed ring. All six deployments verified
destroyed by direct API query; the campaign buckets keep results only, staged
key material removed.

**The measurement.** Runs 5 and 6 are controlled (two idle series plus one
active, order rotated so exactly one host is active per position) and
synchronised on shared absolute world boundaries. Across those two runs, 18
comparisons at a registered alpha of 0.01, no treatment pair was rejected. Cell
counts were exactly equal within every pair on every host, and mean
inter-arrival drift stayed at 1e-6 to 1e-7 of the cadence against a 2e-2
tolerance. The single rejection landed on a *control* pair -- two idle worlds,
where a leak is impossible by construction.

**Four instrument defects, found in order, each hiding the next.**

1. The analysis pooled every packet in a capture into one series, when the
   preregistration extracts features per direction and per peer. A capture
   holds the host's emissions and its peers' arrivals, and restarting the node
   re-randomises their relative phase, so pooled it rejects whatever the node
   does. It rejected all three hosts. PREREGISTRATION v2 writes the sample
   definition down and voids that run; no threshold changed.
2. The in-process campaign wrote one file per series spanning four rounds, with
   multi-second pauses inside it where the other worlds ran. The rule compares
   equal-length windows of a continuous stream. Captures are now per round, and
   with that fixed the campaign's own controls pass (KS p=0.62, 0.95, 0.95)
   while the treatment is still rejected in two of three evaluable rounds --
   the E-08 finding survives a correct instrument and a passing control.
3. The CI gate accumulated each comparison's exit status and then ended the
   step without consulting it. It had been reporting green while the rule
   rejected its own idle-versus-idle control. It now fails on a finding, fails
   when nothing was compared, and keeps "could not run" distinct from a
   verdict.
4. The WAN campaign had no negative control at all, so its first verdict --
   one host rejected at KS p=0.00988 -- could not be interpreted. Adding the
   control is what made run 5's operator-a result readable as noise floor
   rather than as a leak.

**A fifth defect was the node being right.** The first run captured zero
packets on all three hosts because `curl` wrote the operator secret at the
inherited umask and `nomad-node` refuses a group-readable secret. The check was
correct; the payload was wrong.

**Boundary.** One administrator, one provider, one account. Three geographic
failure domains, one administrative. This is not evidence of independent
operation and does not support PROD-05 or PROD-21. One run per host against a
registered screening design of 30 captures per world is a single screening
sample, not the screening.

E-01 moves BLOCKED to PARTIAL; E-02, E-06 and E-11 stay PARTIAL with WAN
evidence attached. Still **0 of 30 PROD gates MET**. Nothing here promotes a
gate, and PROD-28's 30-day soak is untouched.

## Checkpoint 2026-08-21b: defects, gates, and what a freeze needs

**Three defects found and fixed, each of which had passing tests around it.**

1. *A silent wrong-decode on the production path.* A flaky RLNC round-trip
   test (~1 run in 14) was a real defect: `Decoder.Add` inserted a symbol
   without reducing it against pivots discovered at later columns, after which
   the basis reported full rank and `Decode` returned a mixture of source
   symbols as one symbol, with a nil error. The materializer uses this decoder.
2. *A duplicate JSON key accepted in a signed topology.* Go keeps the last
   occurrence; other parsers keep the first. A signature cannot catch it, since
   each implementation verifies against whatever it parsed, so one accepts a
   document another refuses. Refused outright now.
3. *A replayable stale topology.* A signature and an unexpired window do not
   make a topology current, and nothing remembered which epoch had been
   served. A persisted watermark now refuses to move backwards.

**The structural defect was worse than any of them.** `components/*` in
nomad-testnet and the pinned snapshots in Nomad-browser are separate modules
behind replace directives, invisible to `go test ./...`, and none of the nine
carried a single test file. What ships was untested by the repository that
ships it. All nine now carry their standalone suites and are gated in CI.

**A control that did nothing.** `debug.SetTraceback("none")` reads like it
turns off crash dumps and does not: measured on two Go versions, a process
calling it still prints goroutine stacks with frame arguments as raw machine
words. Only `GOTRACEBACK=none` works, and the runtime reads it at startup, so
it is a deployment control the program can verify but not impose. Setting it on
the compose anchor was not enough either -- a YAML merge key replaces a mapping
rather than deep-merging it, so the three DKG services silently dropped it.

**Gates: 0/30 to 2/30, with five more moved off NOT_MET.** PROD-08 and PROD-12
are MET. PROD-01, PROD-16, PROD-19, PROD-20 and PROD-27 moved to PARTIAL with
specific blockers rather than general ones. The promotions rest on external
test reports, which the evidence rule permits in the same clause as Actions --
an earlier reading that the outage capped every promotion was wrong.

**What a freeze still needs.** The formats are published and enforced: nine
golden vectors identical on 32-bit and 64-bit, a compatibility matrix covering
58 frozen labels that a test keeps honest, and the downgrade rule written down.
What is missing is a signature over it (EB-7, a custody problem), one normative
document for state transitions and timeouts, and a schema a second
implementation could validate against.

**Not promoted, deliberately.** PROD-02 and PROD-27 both need a review, and I
wrote the artifacts under review in each case. A maintainer who did not write
them can close either with no external dependency; the implementer must not be
the only judge of its own change.

## Checkpoint 2026-08-21c: what is left, and why

Gates: **2 MET, 22 PARTIAL, 5 NOT_MET, 1 BLOCKED**, from 0/30 with 18 PARTIAL
and 11 NOT_MET at the start of the day. Six criteria moved off NOT_MET
(PROD-01, 07, 15, 16, 20, 27), two were promoted (PROD-08, PROD-12).

Work landed since the previous checkpoint:

- **Fault attribution** (PROD-07). A mixer's receipt already signed context,
  input, output and proof digests together; nothing used it. `AttributeFault`
  names the signer of an unsound round and `VerifyFaultReport` re-derives the
  fault so a third party confirms it rather than trusting the reporter. Three
  of the four fault kinds are deliberately *not* attributable, because
  attributing them would let one mixer frame another.
- **Site recovery drill** (PROD-15), and SITE_IDENTITY promoted to normative
  v1. Writing the drill corrected a wrong expectation: recovery invalidates
  the compromised key's back catalogue by design, which rotation does not, and
  the specification says so.
- **Compatibility matrix** (PROD-01), 58 frozen labels, enforced by a test
  that fails naming any version constant the matrix omits. Writing it settled
  the downgrade rule, which had been implicit in the code.
- **Crash-output control** (PROD-27), after finding the obvious in-process fix
  measurably does nothing.

**The five NOT_MET, and what each actually needs.** PROD-03 needs a second
implementer (EB-5). PROD-30 needs a second release approver and a monitored
beta (EB-6). PROD-28 needs thirty days to pass. PROD-17 and PROD-18 need the
distributed deposit path, which is the one substantial piece of engineering
left in this list; PROD-07's live fault-injection blocker and PROD-18's
multi-publisher capture both sit behind it.

**Two gates are held by a second party rather than an external one.** PROD-02
and PROD-27 each need a review, and in both cases this session wrote the
artifact under review. A maintainer who did not write them can close either
with no external dependency at all. Recording that distinction matters,
because it is the difference between "waiting on the world" and "waiting on a
second pair of eyes in this project".

**30/30 is not reachable from here.** PROD-28 alone puts it at least thirty
days out, and four more gates need people this session cannot be. What is
reachable is that every gate is honestly marked with a specific blocker rather
than a general one, and that is now true of all thirty.

## Checkpoint 2026-08-21d: the deposit path, and the end of achievable NOT_MET

**Publication had no distributed form.** The queue held encrypted fragments,
the uplink could seal work and cover indistinguishably, the airlock could
accept deposits and seal a batch — and nothing called `Queue.Next` or
`Airlock.Deposit`. The sizes had been designed to fit and had never met: a
fragment is 504 bytes, exactly one uplink payload and one mix plaintext; the
uplink's inner layer is 1152 bytes, exactly one airlock deposit.

`live/deposit` joins them. The design point is what the drain does *not* do:
call the queue on the cadence tick. An empty queue costs one directory read
and a non-empty one costs a read, a decrypt, an unlink and a sync, and that
difference is publication timing. A filling goroutine holds a one-slot buffer;
the tick does a non-blocking receive and touches no disk.

**Two instrument defects caught before they became evidence.**

The correlation experiment's first positive control was an unshuffled airlock
batch, and it scored chance — which looked exactly like the unlinkability
measurement this project withdrew earlier, and was in fact the airlock
working: `Seal` orders by deposit ID and randomises placement, destroying
arrival order before any mixer touches the batch. The control was rebuilt with
no defence at all, where the matcher recovers the mapping at 1.00.

The publication campaign's first version synthesised each packet's timestamp
as base plus tick times interval. Every capture was then perfectly regular by
construction and the preregistered rule reported KS p=1.0 on all five pairs —
a fabricated agreement that would have been filed as evidence of timing
indistinguishability.

**A refusal worth recording.** With real timestamps the campaign's own control
fails: two idle publishers differ in mean inter-arrival by 0.003 to 0.520 of
the nominal interval across five runs, against a 0.02 tolerance. The campaign
therefore judges cell count, size and destination — which are exact — and
explicitly declines to judge timing, while still measuring the floor every run
so the refusal stays a finding rather than an assumption.

**Gates: 2 MET, 24 PARTIAL, 3 NOT_MET, 1 BLOCKED.** The three NOT_MET are
PROD-03 (a second implementer), PROD-28 (thirty days) and PROD-30 (a monitored
beta and a second approver); PROD-29 is BLOCKED on an external assessor. No
gate whose remaining work this project could do is still NOT_MET.

That is a statement about NOT_MET, not about readiness. Twenty-four criteria
are PARTIAL and their blockers are now specific rather than general: no
independent review anywhere, no distributed correlation experiment, no
descriptor distribution, no economic analysis, no availability claim under
sustained flood, and no measurement of long-horizon correlation at all.

## Checkpoint: the quietest cause of the loudest event

PROD-14 asked what a node emits at a resource limit. Reading the emission path
to write the test answered it before the test did: `Scheduler.run` returned on
any Sink error, and `node.Run` closed the socket on return, so an exhausted
socket buffer or a full disk under the hop sequence reservation stopped the
node permanently. A node going silent is the most visible thing a passive
observer can see, and every cause was local and ordinary.

Fixed in the fabric (`ErrCellDropped`: count the cell, keep the absolute
deadline, never retry or catch up, only a closed socket is fatal) and in the
node (one classification rule every failure site routes through; a health-file
write can no longer end `maintain`). Then the two-world test PROD-14 actually
asked for: one node's cache rejecting 448 of 449 streams against one storing
449, matching sizes, counts, destination split and burst ceiling.

Three things worth keeping from this one.

**The fix removed an alarm, so the alarm had to be rebuilt.** A node that no
longer stops is a node that can be up, on cadence, and silently dropping every
cell — invisible to a Compose healthcheck that asked `test -s health.json`.
`last_sent_at` and `send_dropped` are published, `nomad-node --check-health`
reads them, and the live e2e asserts on them. Trading a crude alarm for none
would have been a worse change than the bug.

**A test passed for the wrong reason and mutation testing caught it.** The
first closed-socket test called `Send` on a closed socket expecting the fatal
branch; `SetWriteDeadline` fails first, so that branch never ran, and deleting
it left the test green. Reading the test would not have found this. The
classification moved into one function and got a table over the real errno
values.

**What the test does not claim is now asserted rather than omitted.** The two
worlds emit the same size, count and destinations, and a *different* work/cover
mix — readable on the wire, because the operator-to-operator hop header is
authenticated but not encrypted. That was already known and documented; the
test now asserts the mix actually moved, so the limitation is measured rather
than mentioned.

Gate counts unchanged at 2 MET / 24 PARTIAL / 3 NOT_MET / 1 BLOCKED. PROD-14
keeps its status and loses two blockers, gaining narrower ones: no whole-system
load evidence, and a loopback single-host boundary.

## Checkpoint: the evaluator said no, and the reasons were better than the change

The above was reviewed before it was recorded, and came back "do not call this
done". Two Sev1 defects, both in the parts that looked most obviously right.

**The classification had the wrong polarity.** Asking "is this error fatal?"
and answering with a denylist of one meant every error nobody had thought of
became a lost cell -- including hop sequence exhaustion, whose own message says
to rotate the topology epoch. A failed cryptographic precondition downgraded to
a counter, which CLAUDE.md forbids in as many words. The argument against that
shape was already written down in this codebase, about telemetry field names,
and the change had picked the opposite side of it. Now an allowlist of named
transient conditions; EPERM and EINVAL are off it, because on Linux they mean
a firewall verdict and a destination the kernel will never accept.

**A dropped cell burned a cleartext sequence number.** The hop sequence is in
the clear in every header. A number issued to a cell that then failed at the
socket left a gap, and the gap counted local send failures exactly, for the
receiving peer and anyone watching the link. Worse, the evidence note argued
that publishing `send_dropped` conceded nothing *because* an observer reads it
off the wire -- using the channel as the justification without noticing it was
the finding. Numbers are returned now, and a test reads the sequences off the
emitted cells: 27 cells carrying 1..27 across a run with 18 drops.

Three lessons worth keeping.

**The safety argument was the untested part.** The whole case for letting a
node keep running was "the alarm is replaced". That replacement was tested
only against hand-built structs, and two mutations survived the suite --
including storing the liveness timestamp before the write, which makes a node
dropping every cell report itself healthy forever. The part of a change that
carries its justification is the part to attack hardest, and it was the part I
had tested least.

**A fix that removes an alarm has to follow it everywhere.** Compose was
updated; the two operator runbooks and the WAN campaign still checked that the
process was alive, which the change had made permanently true, and the Compose
healthcheck's verdict was recorded in evidence and never read. One surface out
of four.

**A flaky test is not weak evidence, it is none.** The two-world comparison
failed about one run in ten under `-race`, in both directions, reporting a
loaded runner as a count divergence between worlds -- a message that reads like
a privacy finding. Split now: a deterministic structural half that ran 15/15,
and a rate comparison behind the campaign gate with a floor measured from three
worlds that differ by nothing. Chasing sub-second statistics in a per-push
suite was a decision this project had already made correctly once, and I had
quietly unmade it.


## Checkpoint: the embedding service was whoever answered the port

`nomad-semantic-basins` bd3c5cc, 2dc8eb4; vendored into `Nomad-browser`
c06c87b; snapshot repinned in `nomad-testnet` 9fccaba.

PROD-24's blocker named a real defect and named it precisely: the API key
authenticated the client to the service, never the service to the client --
and that service is the one component handed the reader's query in the clear.
The URL checks established that the destination was loopback. They said
nothing about who was listening there. A process that bound the port first
received every query and the credential meant to protect it.

**The first fix was wrong and is worth recording.** I implemented a
challenge-response handshake: prove the service holds the key, then send. It
compiled, it was clean, and it does not establish the property. It proves
somebody holding the key is reachable, not that the party about to receive the
query is that somebody -- an impostor on the configured port can relay the
challenge to the real service on another port and then take the query. It also
leaves the reply unauthenticated, and an impostor's chosen vector chooses the
reader's basin, which is the same "you fetch a different part of the
catalogue" failure `basin/attest.go` exists to catch. Rereading my own design
after it built is what caught this; the tests I had planned would all have
passed.

**What shipped instead.** The query is sealed to the key rather than gated on
it: fresh 32-byte salt per request, HKDF-SHA256 per direction, AES-256-GCM,
256-byte padding blocks. Both directions authenticated, replies bound to their
request, no unauthenticated mode. `loopback.Service` and
`cmd/nomad-embed-service` are the other half of the channel, so this is a
deployment a person can run rather than a client with no counterpart.

**Two failures in my own verification.** The mutation script crashed partway
through one run and left a mutation applied; the next run took that tree as
its baseline, so every result it printed was measured against already-broken
code. It now asserts a green baseline before and after. And two mutations
initially survived because the address tests only checked that an error came
back -- every address in the table also fails to connect. They now assert the
reason. That is the same defect class as the closed-socket test recorded
earlier in this file: a test passing for a reason unrelated to its claim, twice
now, in work whose whole purpose is to be the thing that catches that.

PROD-24 stays PARTIAL. What is left is a sandbox whose escape has been
attempted and an attempted-egress packet capture. The systemd profile is
pinned by directive presence and has never been run.

## Checkpoint: eleven blockers closed by code, and what the closing found

Since the last checkpoint, work in `nomad-testnet`, `nomad-semantic-basins`,
`nomad-anytrust-mix-sim` and `Nomad-browser` closed eleven blockers. Nine
criteria are now down to a single blocker each, and in every one of those nine
the remaining item is a second party, a platform, or elapsed time.

**What was built.** The hop cell is encrypted per link, not merely
authenticated (DEC-016). The topology's canonical encoding is specified rather
than inherited from Go's `encoding/json` (DEC-017). The uplink session is
established in band and one-sided (DEC-018). The relay path allocates per
sender at both layers a flood reaches. Storage non-interference under private
reads is measured. The dependency set is closed and reviewed. The embedding
chain's egress is measured in a namespace with no route off the host. The
release binary's network boundary is observed at runtime by system-call trace.
A committee transcript can be verified by a third party with a tool rather
than a library. Every message the wire corpus publishes, and the renderer's 59
frozen URL decisions, now have a consumer that is not the encoder that wrote
them.

**Eight defects the work found in itself.** These matter more than the
features, because each is a way evidence can look sound and not be.

1. `Node.Run` returned as soon as one of its three goroutines finished,
   leaving the other two cancelled but still writing to the cache, the health
   file and the durable sequence state. Found by a temp-directory cleanup
   failing under `-race` — the kind of complaint that is easy to read as noise.
2. A session-identifier HKDF domain equal to the session-secret domain makes
   the *public* deposit identifier be the session secret. A one-character edit;
   no round-trip test notices. Found as a surviving mutation.
3. `strace` writes `<pid>  syscall(...)` with `-f -o`, not `[pid N] ...`. The
   parser matched only the second form, found nothing, and reported zero
   network syscalls for every binary — including the control that opens one.
   Both "measurements" would have gone into the registry as evidence.
4. Checking captured packets for loopback by substring accepts exactly the
   packets the check exists to catch: `::1` is a substring of `2001:db8::1`.
5. `tcpdump` buffers, and a buffer unwritten when the process is killed leaves
   a truncated file that reads as "nothing was captured" — indistinguishable
   from the result the test reports.
6. The mix wire encoding pads with fresh randomness, so encoding one batch
   twice gives different bytes and a published transcript's chain could not be
   read from the file at all.
7. A transcript missing its last round is a valid shorter transcript. The test
   trimmed its own key list to fit, which is exactly what a dishonest committee
   would want a verifier to do.
8. A write-failure toggle at half the cell cadence resonates: writes land
   entirely in the healthy phase, nothing is dropped, and the test fails with
   "nothing was dropped", which reads like a production defect.

**Two of my own tests passed for the wrong reason** and were caught by
mutation: the upstream-address tests only checked *that* an error came back,
when every address in the table also fails to connect; and three hop tests
were satisfied by metadata failing to validate rather than by the check under
test. Both now assert the reason. That is the third and fourth time this
defect class has appeared in this project.

**A process failure worth recording.** One commit was pushed with two tests
red — the compatibility gate catching a missing label, and a fairness test
losing datagrams to the kernel under `-race`. Both were fixed immediately
after, but the push came first, which is the discipline the
`agent-efficient-ci` skill in this repository states in as many words.

**Where the code ran out.** Nine criteria have exactly one blocker and it is
external in every case: a reviewer who did not write the document (PROD-02), a
second implementer (PROD-03, PROD-19), independent cryptographic review
(PROD-04), a macOS runner (PROD-09, PROD-23), a Windows runner (PROD-16), a
release key (PROD-01), and assessors who cannot be self-appointed (PROD-29).

## 2026-08-28: what a working CI found, and one diagnosis that had to be withdrawn

CI ran for the first time since 2026-08-19. The cause of the outage was the
account spending limit, which the repositories going public removed. Four
things follow from having the gates actually execute.

**A diagnosis of my own had to be withdrawn.** Mid-outage I replaced the
correct explanation with a wrong one -- that `actions/checkout@v7` and
`actions/setup-go@v7` did not exist -- and committed it to nine repositories.
Both tags existed throughout. The evidence against it had been sitting on the
failed check run the whole time, as a single annotation in plain English:
"The job was not started because recent account payments have failed or your
spending limit needs to be increased." I never queried the annotations
endpoint before concluding it could not answer. The failed jobs also recorded
*zero* steps, not even `Set up job`, which an unresolvable action reference
does not produce -- I had written that shape down in EB-8 myself and then
argued against my own observation. The pins stayed, since digest-pinning CI
actions is right for this project, but moved back to v7. EB-8 and the evidence
index carry the correction; the commits are published and referenced, so
nothing was rewritten.

**A cross-implementation check that had never run, and was wrong.** The first
green testnet run failed on operator attestations. The Python second
implementation verified them against `sha256(draft_domain || draft)` while Go
signs a domain-separated message over `{"document", "operator_id"}`: wrong
domain, and no operator identifier at all, so every operator in an epoch would
have signed identical bytes and one cooperating signer's attestation would
have verified under every other name. It had never executed, because
`cryptography` panics in the container and the import guard set
`SIGNATURES_CHECKABLE = False` -- the tool reported a clean pass while checking
nothing. Both halves are fixed: the message is correct, and the fallback now
loads an RFC 8032 transcription instead of disabling verification. Verified by
mutation: restoring either half of the defect fails the test.

**A vulnerability gate that would have passed on a bad day.** `govulncheck`
403'd against vuln.go.dev in one of eight simultaneous jobs. It exits non-zero
both for "found vulnerabilities" and "could not fetch the list", so the
tempting fix softens both. The retry is now scoped to the database fetch
alone; a finding is never re-run; an unreachable database fails the run saying
nothing was scanned. `scripts/test-scan-vulnerabilities.sh` stubs the scanner
and pins all four behaviours in every repository's CI. The tool is also pinned
now: `@latest` meant CI installed whatever the proxy served and ran it over
the source it was gating.

**DEC-020's fix was rejected and replaced (DEC-022).** The recorded shape --
retain the sealed cell and retransmit it verbatim -- cannot be used. The
uplink sequence is eight *cleartext* bytes at the head of every cell, durable
and strictly increasing, and cover is never retransmitted, so a repeat tells
the entry operator that this publisher had work refused. Re-sealing is worse
than DEC-020 said: it is an AES-GCM nonce reuse, not merely a conflict the
airlock refuses. What is implemented instead is prevention: the publisher
computes the public deposit window from the same signed bytes the operator
does and does not take work off its durable queue while the window is shut.
Nothing is retransmitted because nothing was sent, and the dominant loss term
-- 25% of every period at the default schedule -- is zero. Loss from a full
epoch or a dropped datagram remains, is undetectable by design, and is not
claimed as fixed.

**The pattern in three of these four.** A check that cannot run reports the
same thing as a check that passes. The attestation verifier, the vulnerability
scanner on an unreachable database, and CI itself for five days each produced
a clean-looking result while testing nothing. Only the last one was noticed at
the time, and even that was diagnosed twice before it was diagnosed right.

## 2026-08-31: assertions that could not fail, a Linux client, and a fifth
## instance of the same pattern

**Five assertions in nomad-testnet were comparing constants.** `fabric.Cell`
is `[1200]byte` and `Session.Open` returns `[1152]byte`, so `len()` of either
is resolved at compile time. `if len(cell) != fabric.CellSize` cannot fail.
Worse, `TestTheWindowGateIsInvisibleOnTheWire` compared `{sequence, size}`
pairs across the four window/queue combinations with both fields built from
the loop index and the type: the core window-gate invariant was guarded by a
tautology. They now compare the cleartext sequence prefix decoded from the
emitted bytes, and require every inner ciphertext to be non-zero and distinct
-- a property that can fail, and that a constant cover layer would break.

Found by staticcheck, which had been reporting zero findings across nine
repositories **while reading none of them**: it exits 0 when it cannot analyse
a module, and every module's go directive was newer than the release
staticcheck was built with. It now runs in CI everywhere behind
`scripts/run-staticcheck.sh`, which proves the tool is analysing with a
positive control before it trusts a clean run. The control plants SA4000 and
SA4006 and requires both, because the first fixture written for it reported
nothing -- against a one-check control that would have been indistinguishable
from a working one.

**That is the fifth instance of the same pattern**, and the first where the
detector itself was the thing that could not run. The attestation verifier,
the vulnerability scanner on an unreachable database, CI for five days, a
mutation that passed against pre-fix code, and now the static analyser.

**The Linux client exists** (`Nomad-browser/cmd/nomad-browser`). The core was
always portable Go; the shell was what was macOS-only. Three layers now hold
the networkless claim, and the third is new: `egress.Policy` declines, the
client's transitive dependency graph contains no networking package at all,
and the process runs in a namespace with no interface to refuse a connection.
`scripts/verify-networkless.sh` binds a listener, requires a probe to reach it
outside the namespace, and only then requires the same probe to fail inside --
because "no connection was made" is also what a host with no network reports.

The gate failed its first CI run with exit 2, correctly: Ubuntu 24.04
restricts unprivileged user namespaces. It was fixed by obtaining the
namespace a second way, not by softening the gate.

`objectstore` is a second implementation of the object verification boundary
the Swift client implements, checked against the corpus both ship. It found a
real divergence: unknown payload fields are refused here and ignored by
Swift's `JSONDecoder`. Refusing is correct, so **the fix belongs on the Swift
side** and the divergence is a standing test until it lands.

**EB-9 records the language model.** There is none, and none is claimed:
`LexicalHashEmbedder` is a lexical baseline by its own documentation.
Everything up to the boundary is built -- the sealed loopback channel, a
required latency budget, a required provenance on every ranking, and an index
that embeds and tokenizes at materialization so one search costs one embedding
call whatever the corpus size. Attaching a model does not reopen the privacy
invariant: inference latency is private-state-dependent, but the packages
holding query text cannot reach the emission planner and the fabric emits on a
fixed cadence regardless, so a slow model costs a reader a wait and costs the
wire nothing.
