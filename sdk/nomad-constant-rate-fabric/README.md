# Nomad constant-rate fabric

This module emits opaque 1200-byte UDP datagrams at a public, fixed cadence. Private reader state is not represented in its API.

Implemented:

- absolute-deadline scheduling with one cell per interval;
- no catch-up bursts after missed deadlines;
- a bounded queue for public replication and cache-maintenance work;
- automatic random filler when no work cell is available;
- a UDP sink whose peer-slot sequence is fixed at construction;
- a black-box UDP observer that records received size, time and digest;
- race-enabled unit and loopback wire tests.

The scheduler cannot make a general-purpose operating system real-time. A missed deadline fails closed and is reported; it is never hidden by a burst. WAN congestion control, peer discovery, NAT traversal and production packet capture remain testnet or deployment responsibilities.

Run go test -race ./..., go vet ./... and go run ./cmd/fabric-sim.
