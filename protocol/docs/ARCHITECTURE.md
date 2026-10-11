# Architecture

## Reader-side reference path

The v0.1 reference stack composes this tested direction:

    PUBLIC / NETWORK DOMAIN
    public traffic class
        -> pure emission plan
        -> absolute-deadline scheduler
        -> 1200-byte UDP cells
        -> receiver-side network cache
        -> encrypted batch parsing and verified mix history
        -> 504-byte coded generation packets
        |
        v
    PRIVATE DOMAIN
    local query -> local embedding -> local basin -> local ranking
        -> incremental RLNC reconstruction
        -> signed-manifest length check
        -> SHA-256 commitment
        -> Ed25519 object signature
        -> verified object

Network packages do not import semantic selection or reconstruction packages.
Private selector/cache/adapter packages do not import the planner, scheduler or
mix. The composed testnet is the explicit integration root that can see both
sides while testing the boundary.

## Publication fixture versus publication protocol

The testnet creates, signs, codes and encrypts an object before its wire test.
That is a deterministic publication fixture, not an anonymous deposit:

    publisher fixture
        -> signed manifest
        -> RLNC generation
        -> mix encryption
        -> verified shuffles
        -> fixed-cadence distribution

New information still has a first causal entry point. A production publication
airlock needs a separately specified constant-traffic deposit, threshold mix,
replication delay, failure handling and discovery transition.

## Fixed cell layers

- RLNC clear packet: 504 bytes.
- Mix ciphertext: 18 ElGamal point pairs, 1152 bytes.
- Random wire padding: 48 bytes.
- UDP payload: 1200 bytes.

Every cell in the composed reference batch carries a coded symbol. The fabric
can fall back to random cover only when public network-domain work is
unavailable. Private reading does not enqueue or reprioritize that work.

## Selection boundary

The reader implementation has two capabilities:

- **network capability:** public planning, peer selection, fixed cadence,
  replication/cache work and transport;
- **selection capability:** query embedding, basin calculation, candidate
  ranking, reconstruction and verified-resource rendering.

The public planner fixes cell count, size, interval, cadence index, epoch offset
and peer slot. Its API has no query, basin, selected-object or reconstruction
argument. Browser and OS integrations can still violate non-interference unless
they enforce the same capability split.

## Semantic basins

Basins are coarse similarity hints, not secret labels or object identities.
The first safe client profile computes them locally. Exposing a basin may enable
inversion, membership inference or interest profiling.

## Mixing

The research mix embeds each 504-byte cell in 18 chunks, encrypts them as
ElGamal pairs and uses Kyber's Andrew Neff sequence shuffle so all chunks follow
one hidden permutation. Each round is re-randomized and proof-verified.

The test profile has a single decryption key. Production needs threshold key
generation/decryption, authenticated committee membership, replay/drop/delay
accountability, active-adversary handling and independent review.

## Browser boundary

Nomad-browser defines a signed bundle, immutable verified cache, local resource
adapter and deny-all egress contract. It does not contain a renderer or socket
fallback. Firefox and Chromium must still route every renderer and background
service path through that contract before browser isolation can be claimed.
