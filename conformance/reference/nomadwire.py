"""A second implementation of Nomad's public wire protocol.

Written from docs/PROTOCOL.md in the nomad-protocol repository, not from the Go
source. That restriction is the point: PROD-03 asks for two implementations
that interoperate "without sharing protocol code", and an implementation that
consults the first one tests nothing about whether the specification is
sufficient to build from.

It shares no code with the Go implementation, no build system and no
dependencies beyond the Python standard library. Where it needed something the
specification did not say, that is recorded in FINDINGS below rather than
resolved by reading the Go, because a gap found here is a gap a real second
implementer would hit.

FINDINGS while writing this:

1. The specification described bytes 1152..1200 as "random representation
   padding, fresh filler, not application data". They are the hop header. An
   implementation built from that text could not interoperate at all: it would
   emit random bytes where the magic, sender slot, sequence and authentication
   tag belong, and every cell would be rejected. Fixed in the specification
   before this file was written; recorded because the corpus alone would not
   have revealed the intent, only the bytes.

2. The specification did not say the tag region is zeroed before the tag is
   computed. Without that, a verifier cannot recompute the tag over a cell that
   already carries one, and the ambiguity is silent: both readings produce a
   16-byte value, and only one matches. Fixed in the specification.

3. The specification did not say whether the stream ID hash covers the batch
   size. It does. An implementation guessing otherwise would produce stream IDs
   that differ from the Go implementation's for the same batch, which shows up
   only when the two exchange work cells rather than in a corpus check. Fixed
   in the specification.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

CELL_SIZE = 1200
CIPHERTEXT_SIZE = 1152
HEADER_SIZE = 48
TAG_SIZE = 16
MAXIMUM_BATCH = 256
FLAG_WORK = 1

MAGIC = bytes([0x4E, 0x48, 0x43, 0x01])
CELL_DOMAIN = b"nomad-hop-cell-v1"
STREAM_DOMAIN = b"nomad-live-stream-v1"

# Offsets within the header, which starts at CIPHERTEXT_SIZE.
_SENDER = 4
_ORDINAL = 6
_BATCH = 8
_FLAGS = 10
_STREAM = 12
_SEQUENCE = 28
_TAG = 32


class WireError(Exception):
    """A cell, header or context that the protocol does not permit."""


@dataclass(frozen=True)
class Context:
    """What a hop tag is bound to besides the cell itself."""

    topology_digest: bytes
    network_id: str
    epoch: int
    receiver: int

    def validate(self) -> None:
        if len(self.topology_digest) != 32:
            raise WireError("topology digest must be 32 bytes")
        if self.topology_digest == bytes(32):
            raise WireError("authentication context has a zero topology digest")
        if not self.network_id:
            raise WireError("authentication context has an empty network identifier")
        if self.epoch == 0:
            raise WireError("authentication context has a zero epoch")
        if not 0 <= self.receiver < 1 << 16:
            raise WireError("receiver slot is out of range")


@dataclass(frozen=True)
class Metadata:
    """The routing fields of a hop header."""

    sender: int = 0
    ordinal: int = 0
    batch_size: int = 0
    flags: int = 0
    stream: bytes = bytes(16)
    sequence: int = 0

    @property
    def is_work(self) -> bool:
        return bool(self.flags & FLAG_WORK)

    def validate(self) -> None:
        if self.flags & ~FLAG_WORK:
            raise WireError("unsupported hop flags")
        if self.is_work:
            if self.stream == bytes(16):
                raise WireError("work cell has an empty stream ID")
            if not 2 <= self.batch_size <= MAXIMUM_BATCH:
                raise WireError("work cell has an invalid batch size")
            if self.ordinal >= self.batch_size:
                raise WireError("work cell ordinal is not below its batch size")
            return
        if self.stream != bytes(16) or self.ordinal or self.batch_size:
            raise WireError("cover cell carries work metadata")


def cover_metadata() -> Metadata:
    return Metadata()


def work_metadata(stream: bytes, ordinal: int, batch_size: int) -> Metadata:
    metadata = Metadata(
        ordinal=ordinal, batch_size=batch_size, flags=FLAG_WORK, stream=stream
    )
    metadata.validate()
    return metadata


def stream_for(payloads: list[bytes]) -> bytes:
    """The stream ID of a batch: stable across hops because it hashes payloads."""
    if not 2 <= len(payloads) <= MAXIMUM_BATCH:
        raise WireError("stream payload count is outside the supported batch range")
    digest = hashlib.sha256()
    digest.update(STREAM_DOMAIN)
    digest.update(len(payloads).to_bytes(2, "big"))
    for payload in payloads:
        if len(payload) != CIPHERTEXT_SIZE:
            raise WireError("stream payload is not one ciphertext")
        digest.update(payload)
    return digest.digest()[:16]


def encode_header(metadata: Metadata) -> bytes:
    """Render a header with the tag region zeroed, which is what the tag covers."""
    header = bytearray(HEADER_SIZE)
    header[0:4] = MAGIC
    header[_SENDER:_SENDER + 2] = metadata.sender.to_bytes(2, "big")
    header[_ORDINAL:_ORDINAL + 2] = metadata.ordinal.to_bytes(2, "big")
    header[_BATCH:_BATCH + 2] = metadata.batch_size.to_bytes(2, "big")
    header[_FLAGS:_FLAGS + 2] = metadata.flags.to_bytes(2, "big")
    header[_STREAM:_STREAM + 16] = metadata.stream
    header[_SEQUENCE:_SEQUENCE + 4] = metadata.sequence.to_bytes(4, "big")
    return bytes(header)


def decode_header(header: bytes) -> tuple[Metadata, bytes]:
    """Split a header into its routing fields and its tag. Authenticates nothing."""
    if len(header) != HEADER_SIZE:
        raise WireError("hop header is not 48 bytes")
    if header[0:4] != MAGIC:
        raise WireError("unsupported hop header")
    metadata = Metadata(
        sender=int.from_bytes(header[_SENDER:_SENDER + 2], "big"),
        ordinal=int.from_bytes(header[_ORDINAL:_ORDINAL + 2], "big"),
        batch_size=int.from_bytes(header[_BATCH:_BATCH + 2], "big"),
        flags=int.from_bytes(header[_FLAGS:_FLAGS + 2], "big"),
        stream=bytes(header[_STREAM:_STREAM + 16]),
        sequence=int.from_bytes(header[_SEQUENCE:_SEQUENCE + 4], "big"),
    )
    return metadata, bytes(header[_TAG:_TAG + TAG_SIZE])


def authentication_tag(cell: bytes, key: bytes, context: Context) -> bytes:
    if len(key) != 32:
        raise WireError("hop key must be 32 bytes")
    if key == bytes(32):
        raise WireError("all-zero hop key is forbidden")
    context.validate()
    if len(cell) != CELL_SIZE:
        raise WireError("cell is not 1200 bytes")
    network = context.network_id.encode()
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(CELL_DOMAIN)
    mac.update(context.topology_digest)
    mac.update(context.epoch.to_bytes(8, "big"))
    mac.update(context.receiver.to_bytes(2, "big"))
    mac.update(len(network).to_bytes(2, "big"))
    mac.update(network)
    mac.update(cell[: CELL_SIZE - TAG_SIZE])
    return mac.digest()[:TAG_SIZE]


def seal(
    ciphertext: bytes,
    metadata: Metadata,
    sender: int,
    sequence: int,
    key: bytes,
    context: Context,
) -> bytes:
    """Produce a complete cell another implementation must accept."""
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise WireError("ciphertext is not 1152 bytes")
    if sequence == 0:
        raise WireError("hop sequence must be non-zero")
    sealed = Metadata(
        sender=sender,
        ordinal=metadata.ordinal,
        batch_size=metadata.batch_size,
        flags=metadata.flags,
        stream=metadata.stream,
        sequence=sequence,
    )
    sealed.validate()
    cell = bytearray(ciphertext + encode_header(sealed))
    tag = authentication_tag(bytes(cell), key, context)
    cell[CIPHERTEXT_SIZE + _TAG : CIPHERTEXT_SIZE + _TAG + TAG_SIZE] = tag
    return bytes(cell)


def verify(cell: bytes, expected_sender: int, key: bytes, context: Context) -> Metadata:
    """Authenticate a cell and return its routing fields. Raises on any failure."""
    if len(cell) != CELL_SIZE:
        raise WireError("cell is not 1200 bytes")
    metadata, observed = decode_header(cell[CIPHERTEXT_SIZE:])
    if metadata.sender != expected_sender:
        raise WireError("authenticated sender slot mismatch")
    if metadata.sequence == 0:
        raise WireError("hop sequence must be non-zero")
    metadata.validate()
    cleared = bytearray(cell)
    cleared[CIPHERTEXT_SIZE + _TAG : CIPHERTEXT_SIZE + _TAG + TAG_SIZE] = bytes(TAG_SIZE)
    expected = authentication_tag(bytes(cleared), key, context)
    if not hmac.compare_digest(observed, expected):
        raise WireError("hop authentication failed")
    return metadata


class ReplayWindow:
    """One sender, one epoch: accept bounded reordering, refuse duplicates."""

    def __init__(self) -> None:
        self._highest = 0
        self._bitmap = 0
        self._started = False

    def accept(self, sequence: int) -> None:
        if sequence == 0:
            raise WireError("replayed or expired hop sequence")
        if not self._started:
            self._started = True
            self._highest = sequence
            self._bitmap = 1
            return
        if sequence > self._highest:
            shift = sequence - self._highest
            self._bitmap = 1 if shift >= 64 else ((self._bitmap << shift) | 1) & ((1 << 64) - 1)
            self._highest = sequence
            return
        delta = self._highest - sequence
        if delta >= 64 or self._bitmap & (1 << delta):
            raise WireError("replayed or expired hop sequence")
        self._bitmap |= 1 << delta
