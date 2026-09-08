# Contributing

Keep claims narrower than the evidence.

A unit test can establish that a function behaves as specified. It cannot by itself establish anonymity, unlinkability or resistance to a global adversary. Security-sensitive changes should state:

1. which observable or invariant changes,
2. what adversary capability is assumed,
3. what test would fail if the implementation leaked,
4. which parts remain assumptions rather than tested properties.

Do not introduce bespoke cryptographic constructions into deployable code without external review and a clear security rationale.
