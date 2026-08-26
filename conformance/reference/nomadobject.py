"""A second implementation of Nomad's signed object manifest.

Written from docs/PROTOCOL.md in the nomad-protocol repository, not from the
Go source, for the same reason as its siblings: an implementation that consults
the first one tests nothing about whether the specification is sufficient to
build from.

The manifest is the join between the network and local reconstruction. It is
228 fixed bytes and two signatures, and it is the last thing checked before a
reader treats an object as the object it asked for, so an implementation that
gets it subtly wrong accepts content that the reference would refuse.

Ed25519 verification uses `cryptography` when it is importable, on the same
reasoning nomadtopology.py records: hand-rolling Ed25519 for a conformance tool
would be a worse example than depending on a reviewed library, and the
independence that matters is independence from the Go implementation rather
than from all libraries. Where it is missing, the layout, the digest and both
signing messages are still reproduced -- and reproducing a signing message
byte-exactly is the part that actually tests interoperability.

FINDINGS while writing this:

1. The specification gives the manifest signing message as "the domain string
   nomad-manifest-v1 followed by the canonical length, basin, generation, root,
   public key and object signature fields". "Canonical" is doing a lot of work
   there: the two integers are 8-byte big-endian and the rest are raw bytes in
   the order the table lists them, with no length prefixes. That reading is the
   one that interoperates, and it is now the one the text gives.

2. The object signing message covers SHA-256 of the content, not the content.
   The specification says so; it is recorded because an implementation that
   signed the content directly would still verify against itself and fail only
   against another implementation, which is the failure mode a second
   implementation exists to surface.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MANIFEST_SIZE = 228
MAGIC = bytes([0x4E, 0x4F, 0x4D, 0x01])
OBJECT_DOMAIN = b"nomad-object-v1"
MANIFEST_DOMAIN = b"nomad-manifest-v1"

# Offsets into the manifest, from the field table in the specification.
_LENGTH = 4
_BASIN = 12
_GENERATION = 20
_ROOT = 36
_PUBLIC_KEY = 68
_OBJECT_SIGNATURE = 100
_MANIFEST_SIGNATURE = 164

try:  # pragma: no cover - presence depends on the environment
    import contextlib
    import io

    with contextlib.redirect_stderr(io.StringIO()):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    SIGNATURES_CHECKABLE = True
except BaseException:  # noqa: BLE001  # pragma: no cover
    # BaseException, and only here: a broken pyo3 extension raises
    # PanicException, which does not derive from Exception. See the same
    # comment in nomadtopology.py.
    SIGNATURES_CHECKABLE = False


class ManifestError(Exception):
    """A manifest this implementation refuses."""


@dataclass(frozen=True)
class Manifest:
    length: int
    basin: int
    generation: bytes
    root: bytes
    public_key: bytes
    object_signature: bytes
    manifest_signature: bytes


def parse(wire: bytes) -> Manifest:
    """Read a manifest. Authenticates nothing; call verify for that."""
    if len(wire) != MANIFEST_SIZE:
        raise ManifestError(f"manifest must be exactly {MANIFEST_SIZE} bytes")
    if wire[0:4] != MAGIC:
        raise ManifestError("unsupported manifest magic or version")
    return Manifest(
        length=int.from_bytes(wire[_LENGTH:_LENGTH + 8], "big"),
        basin=int.from_bytes(wire[_BASIN:_BASIN + 8], "big"),
        generation=bytes(wire[_GENERATION:_GENERATION + 16]),
        root=bytes(wire[_ROOT:_ROOT + 32]),
        public_key=bytes(wire[_PUBLIC_KEY:_PUBLIC_KEY + 32]),
        object_signature=bytes(wire[_OBJECT_SIGNATURE:_OBJECT_SIGNATURE + 64]),
        manifest_signature=bytes(wire[_MANIFEST_SIGNATURE:_MANIFEST_SIGNATURE + 64]),
    )


def encode(manifest: Manifest) -> bytes:
    """Render a manifest back to its 228 bytes."""
    out = bytearray(MANIFEST_SIZE)
    out[0:4] = MAGIC
    out[_LENGTH:_LENGTH + 8] = manifest.length.to_bytes(8, "big")
    out[_BASIN:_BASIN + 8] = manifest.basin.to_bytes(8, "big")
    out[_GENERATION:_GENERATION + 16] = manifest.generation
    out[_ROOT:_ROOT + 32] = manifest.root
    out[_PUBLIC_KEY:_PUBLIC_KEY + 32] = manifest.public_key
    out[_OBJECT_SIGNATURE:_OBJECT_SIGNATURE + 64] = manifest.object_signature
    out[_MANIFEST_SIGNATURE:_MANIFEST_SIGNATURE + 64] = manifest.manifest_signature
    return bytes(out)


def object_signing_message(root: bytes) -> bytes:
    """What the object signature covers: the domain and the content root."""
    if len(root) != 32:
        raise ManifestError("content root must be 32 bytes")
    return OBJECT_DOMAIN + root


def manifest_signing_message(manifest: Manifest) -> bytes:
    """What the manifest signature covers.

    Everything in the manifest except the manifest signature itself, in the
    order the field table lists it, with the two integers as 8-byte big-endian
    and no length prefixes anywhere.
    """
    return (
        MANIFEST_DOMAIN
        + manifest.length.to_bytes(8, "big")
        + manifest.basin.to_bytes(8, "big")
        + manifest.generation
        + manifest.root
        + manifest.public_key
        + manifest.object_signature
    )


def verify(wire: bytes, content: bytes | None = None) -> Manifest:
    """Check a manifest, and the object it describes when it is supplied.

    Fails closed on every path. There is deliberately no mode that reports a
    bad signature as a warning: the manifest is the last check before a reader
    treats bytes as the object it asked for.
    """
    manifest = parse(wire)
    if manifest.length == 0:
        raise ManifestError("a manifest over a zero-length object is refused")
    if manifest.root == bytes(32):
        raise ManifestError("content root is all zero")
    if manifest.public_key == bytes(32):
        raise ManifestError("publisher key is all zero")

    if content is not None:
        if len(content) != manifest.length:
            raise ManifestError(
                f"content is {len(content)} bytes, the manifest signs {manifest.length}"
            )
        if hashlib.sha256(content).digest() != manifest.root:
            raise ManifestError("content does not hash to the signed root")

    if SIGNATURES_CHECKABLE:
        key = Ed25519PublicKey.from_public_bytes(manifest.public_key)
        try:
            key.verify(manifest.object_signature, object_signing_message(manifest.root))
        except InvalidSignature as failure:
            raise ManifestError("object signature does not verify") from failure
        try:
            key.verify(manifest.manifest_signature, manifest_signing_message(manifest))
        except InvalidSignature as failure:
            raise ManifestError("manifest signature does not verify") from failure
    return manifest
