"""A second implementation of the publisher uplink frame and its derivations.

Written from docs/PROTOCOL.md and PUBLICATION_INGRESS.md in the nomad-protocol
repository, not from the Go source.

**What this covers and what it does not.** The uplink cell is an 8-byte
cleartext sequence followed by AES-256-GCM over the inner committee ciphertext
and its padding. This file does not reimplement AES-GCM: the Python standard
library has no AES, and hand-rolling one for a conformance tool would be a
worse example than saying plainly that it is not covered.

What it does cover is the part where two implementations actually diverge. An
AEAD either matches or it does not, and when it does not the failure is loud.
The derivations that feed it fail silently: an HKDF info string assembled with
the fields in a different order, a length prefix that one side writes as two
bytes and the other as eight, a nonce over the wrong inputs -- each produces a
correctly formed cell that the other side refuses with no clue why. Those are
reproduced here from the specification, byte for byte, and checked against the
corpus.

FINDINGS while writing this:

1. The session key derivation's info string length-prefixes the network
   identifier with **eight** bytes, not the two the hop tag uses for the same
   field. Two length prefixes for one field in one protocol is a trap, and an
   implementation that assumed consistency would derive a different key and see
   only "authentication failed". Recorded rather than silently matched; the
   specification now states the width.

2. The nonce is derived from the session key itself, not from the shared
   secret, and it is the first 12 bytes of the SHA-256 rather than a truncation
   chosen elsewhere. Both were ambiguous in the earlier text.
"""

from __future__ import annotations

import hashlib
import hmac

SEQUENCE_SIZE = 8
INNER_SIZE = 1152
CELL_SIZE = 1200
TAG_SIZE = 16
PADDING_SIZE = CELL_SIZE - SEQUENCE_SIZE - INNER_SIZE - TAG_SIZE

SESSION_INFO_DOMAIN = b"nomad-uplink-session-v1"
NONCE_DOMAIN = b"nomad-uplink-nonce-v1"
NONCE_SIZE = 12


class UplinkError(Exception):
    """An uplink frame or context this implementation refuses."""


def hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 with SHA-256, which the standard library does not provide."""
    if length > 255 * hashlib.sha256().digest_size:
        raise UplinkError("HKDF output is too long")
    extracted = hmac.new(salt, secret, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(
            extracted, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        out += block
        counter += 1
    return out[:length]


def session_key(
    shared_secret: bytes,
    network_id: str,
    epoch: int,
    entry_operator: int,
    topology_digest: bytes,
) -> bytes:
    """Derive the outer session key.

    HKDF-SHA-256 with the topology digest as the salt and an info string that
    binds the network, epoch and entry operator slot, so a key derived for one
    network, epoch, topology or operator cannot be used in another.
    """
    if not shared_secret:
        raise UplinkError("uplink shared secret is required")
    if not network_id or epoch == 0 or topology_digest == bytes(32):
        raise UplinkError("uplink context is incomplete")
    if len(topology_digest) != 32:
        raise UplinkError("topology digest must be 32 bytes")

    network = network_id.encode()
    info = (
        SESSION_INFO_DOMAIN
        # Eight bytes, not the two the hop tag uses for the same field.
        + len(network).to_bytes(8, "big")
        + network
        + epoch.to_bytes(8, "big")
        + entry_operator.to_bytes(2, "big")
    )
    return hkdf_sha256(shared_secret, topology_digest, info, 32)


def nonce(key: bytes, sequence: int) -> bytes:
    """Derive the AEAD nonce for one sequence under one session key.

    Deterministic from the cleartext sequence, so no random nonce is
    transmitted and a nonce cannot repeat under one key without the sequence
    repeating. That makes the sequence's uniqueness a hard requirement rather
    than a convenience.
    """
    if len(key) != 32:
        raise UplinkError("session key must be 32 bytes")
    if sequence == 0:
        raise UplinkError("uplink sequence must be non-zero")
    digest = hashlib.sha256()
    digest.update(NONCE_DOMAIN)
    digest.update(key)
    digest.update(sequence.to_bytes(8, "big"))
    return digest.digest()[:NONCE_SIZE]


def parse_frame(cell: bytes) -> int:
    """Read the one cleartext field of an uplink cell: its sequence.

    Everything else is inside the AEAD, which is the property the profile
    exists for -- work and cover are the same length and the same shape, and
    the entry operator learns only that a well-formed cell arrived.
    """
    if len(cell) != CELL_SIZE:
        raise UplinkError(f"uplink cell must be exactly {CELL_SIZE} bytes")
    sequence = int.from_bytes(cell[:SEQUENCE_SIZE], "big")
    if sequence == 0:
        raise UplinkError("uplink sequence must be non-zero")
    return sequence


def check_frame_layout(
    cell_size: int, sequence_size: int, inner_size: int, tag_size: int, padding_size: int
) -> None:
    """The lengths must add up, and this implementation computes the padding.

    A corpus that stated all five independently would let one drift; deriving
    the padding here means a disagreement about any of the other four shows up
    as a disagreement about this one.
    """
    if (cell_size, sequence_size, inner_size, tag_size) != (
        CELL_SIZE,
        SEQUENCE_SIZE,
        INNER_SIZE,
        TAG_SIZE,
    ):
        raise UplinkError(
            f"frame sizes disagree: corpus says {cell_size}/{sequence_size}/"
            f"{inner_size}/{tag_size}, this implementation has {CELL_SIZE}/"
            f"{SEQUENCE_SIZE}/{INNER_SIZE}/{TAG_SIZE}"
        )
    if padding_size != PADDING_SIZE:
        raise UplinkError(
            f"padding is {padding_size} in the corpus and {PADDING_SIZE} here"
        )
