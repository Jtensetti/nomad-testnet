# Multi-region WAN campaign harness

Runs the preregistered two-world test on real hosts in three countries, rather
than on one machine's loopback. The point is the network path: a fixed-cadence
scheduler that looks flat over loopback is not evidence about a scheduler
crossing three jurisdictions, three providers' backbones and three clocks.

    ./run-campaign.sh OUT_DIR [CAPTURE_SECONDS]

Requires `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` and `SCW_DEFAULT_PROJECT_ID`.

## Shape of a run

1. `reserve-ips.py` takes one public address per zone. The addresses must exist
   before the hosts do, because each host learns its peers from a signed
   topology and cloud-init can only be supplied when a server is created.
2. `nomad-bootstrap` signs a topology naming those addresses.
3. `stage-payload.py` uploads the node binary and config to Object Storage and
   mints per-key presigned URLs.
4. `build-cloud-init.py` renders each operator's payload.
5. `provision.py` creates the hosts, attached to the reserved addresses, and
   fails the run if any host comes up on a different one.
6. `collect.py` polls the bucket for results.
7. `scaleway-teardown.sh` runs from an EXIT trap, so an abort between "create"
   and "measure" does not leave instances billing.

Each host runs both worlds itself, back to back: idle, then the same node with a
published object seeded into its cache. One host rather than a pair, because two
hosts differ in placement, neighbours and clock, and those differences would sit
inside the comparison rather than outside it.

## What the hosts are trusted with

The hosts get presigned URLs, never credentials. Each URL is scoped to one key,
so a host compromised mid-campaign can read the campaign's own inputs and write
its own results, and nothing else in the account; the URLs also expire.

Threshold shares and the authority private key are never staged. The bucket
holds each operator's node secrets under a separate key, and no host holds a URL
for another's.

Key material is generated per run and thrown away with the deployment. Nothing
here is production key material and none of it should be reused as such.

## Reading a result

`scripts/two-world-analysis.py A.pcap B.pcap CELL_SIZE INTERVAL_MS` applies the
preregistered decision rule. Exit 0 is a pass, 1 is a finding, 2 means the rule
could not run -- kept apart because a crash reported as a rejection is a crash
recorded as a verdict.

A pass bounds an attacker at the sample size measured. It is not proof of
indistinguishability, and a single-administrator deployment is not evidence of
independent operation.
