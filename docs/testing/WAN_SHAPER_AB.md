# WAN shaper A/B campaign

Purpose: compare the legacy coupled fixed-rate sender with the isolated `nomad-shaper` process on the same corrected Scaleway harness and the same commit.

The experiment variable is only the egress process boundary.

- A (`coupled`): receive/cache/relay and fixed-rate egress in `nomad-node`.
- B (`isolated`): receive/cache/relay in `nomad-node`; fixed-rate egress in `nomad-shaper`; one-way bounded nonblocking Unix datagram handoff.
- Same topology, 1200-byte cells, 50 ms cadence, regions, host type, world schedule, analyzer, and preregistered thresholds.
- Each architecture runs two idle controls plus one active world with rotated position.
- Verdicts are per emitted flow under PREREGISTRATION v2. Received-flow findings are reported separately and attributed using both-end captures.
- No threshold is changed after observing results.

After the A/B run, the winning production boundary is used for the publication end-to-end and traffic-analysis screening campaigns.
