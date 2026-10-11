# Applying the preregistered rule to the shaper architecture

Eight emission series from `agent/operator-shaper-process`'s
`TestShaperProcessTimingBoundary`, run on this project's development container
on 2026-09-02, with the dedicated `nomad-shaper` process built from that
branch. Four idle worlds and four with a private-side producer, in the
balanced order the test already uses (`idle active active idle active idle idle
active`), so no condition sits in a fixed wall-clock position.

## Why these exist

That branch is the structural candidate for the timing finding this project
records as a release blocker, and its own gate measures **median cadence
only**. `grep -c KS live/node/campaign_test.go` on that branch returns 0, and
its `decide()` comment says "Only median cadence is gated." This project has
already established that the median is too weak to see this finding: the
in-process gate reported "no finding" on captures the published rule rejected
at p = 1.5e-06 (E-08). So the fix has never been measured against the statistic
that shows the problem.

The series are written in the rendered tcpdump form `scripts/capture.py` reads,
by a small patch to that branch's test that keeps the timestamps it already
collects instead of reducing them to a median. Nothing else about the
experiment was changed.

## Reproducing

```
git worktree add <dir> origin/agent/operator-shaper-process
# in that worktree, have runShaperWorld write its timestamps as rendered
# tcpdump text: "reading from file <label>, link-type EN10MB (Ethernet)"
# then one "<sec>.<usec> IP 127.0.0.1:40000 > 127.0.0.1:41000: UDP, length 1200"
# per observed packet.
go build -o nomad-shaper ./cmd/nomad-shaper
NOMAD_SHAPER_BIN=$PWD/nomad-shaper NOMAD_SHAPER_SERIES_DIR=<out> \
  go test ./testnet/ -run TestShaperProcessTimingBoundary -count=1
python3 scripts/two-world-analysis.py <out>/run-01-idle.txt <out>/run-02-active.txt 1200 50
```

## What was measured

`KS_ALPHA` is 0.01. Seven pairs, each 78 emissions against 78:

| pair | kind | inter-arrival KS p | verdict |
|---|---|---|---|
| run-01-idle vs run-04-idle | control | 0.283 | PASS |
| run-06-idle vs run-07-idle | control | 0.384 | PASS |
| run-01-idle vs run-06-idle | control | 0.025 | PASS |
| run-01-idle vs run-02-active | treatment | 0.202 | PASS |
| run-04-idle vs run-05-active | treatment | 0.283 | PASS |
| run-07-idle vs run-08-active | treatment | 0.062 | PASS |
| run-06-idle vs run-03-active | treatment | 0.0015 | **FAIL** |

The branch's own median gate passed the same runs: signal 0.0021, control
0.0022, tolerance 0.0200.

## What this is not

**It is not evidence that the shaper fixes the finding**, and it is not
recorded as any part of a claim.

- One experiment, on a shared development container the project's own
  documentation says makes these measurements noisy, against the in-process
  campaign's eight rounds on a dedicated runner.
- The control arm is not clean: one idle-vs-idle pair came in at p = 0.025,
  within 2.5x of the rejection threshold. A control that can approach the
  threshold limits what a single treatment rejection means.
- Seven comparisons at alpha 0.01. One rejection is above the expected 0.07
  but is not a result a single experiment settles.
- Different harness, different host and a different number of rounds from the
  in-process campaign, so the numbers are not directly comparable to it.

What can be said, and only this: the in-process campaign rejects 8 of 8
baseline treatment pairs with 0 of 8 controls rejecting, and this probe of the
separate-process architecture rejects 1 of 4 with a dirtier control. That is a
reason to run the real experiment, not a substitute for it.

## What would settle it

The shaper architecture through the same campaign harness as the in-process
path: same rounds, same stressors, same rule, on a dedicated runner, with the
idle-vs-idle control arm reported alongside. That is now a defined acceptance
test for integrating the shaper, which it did not have before -- its own gate
would have passed it on a statistic that cannot see the finding.
