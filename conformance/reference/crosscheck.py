#!/usr/bin/env python3
"""Run the published corpus against the second implementation, both ways.

PROD-03 asks that two implementations interoperate for the public wire
protocol without sharing protocol code. One direction is not enough: an
implementation that only *reads* the other's output can be wrong in any way
that happens to be permissive, and one that only writes can be wrong in any way
the reader tolerates. So this does both.

Direction A: the second implementation verifies every authenticated vector the
Go implementation published, and reproduces its stream IDs and its
authentication tags byte for byte.

Direction B: the second implementation produces cells the Go implementation has
never seen, written to a file that a Go test then verifies.

Direction C, which matters as much: negative cases. Two implementations that
both accept everything also "interoperate". Each mutation below must be
refused, and refused for the stated reason.

Usage:
    crosscheck.py <corpus.json> [--emit <path for direction B>]
"""

import argparse
import base64
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import nomadtopology  # noqa: E402
import nomadwire  # noqa: E402


class Failure(Exception):
    pass


def context_of(fields: dict) -> nomadwire.Context:
    return nomadwire.Context(
        topology_digest=bytes.fromhex(fields["topology_digest"]),
        network_id=fields["network_id"],
        epoch=int(fields["epoch"]),
        receiver=int(fields["receiver"]),
    )


def direction_a(vectors: list[dict]) -> int:
    """Verify what the first implementation published."""
    checked = 0
    for vector in vectors:
        if vector["message"] != "hop-cell-v2":
            continue
        fields = vector["fields"]
        cell = bytes.fromhex(vector["bytes_hex"])

        if len(cell) != vector["length"]:
            raise Failure(f"{vector['name']}: length field disagrees with the bytes")
        if hashlib.sha256(cell).hexdigest() != vector["sha256"]:
            raise Failure(f"{vector['name']}: sha256 field disagrees with the bytes")

        key = bytes.fromhex(fields["conformance_hop_key"])
        context = context_of(fields)
        sender = int(fields["sender"])

        metadata, payload = nomadwire.open_cell(cell, sender, key, context)

        for name, actual, expected in (
            ("sequence", metadata.sequence, int(fields["sequence"])),
            ("flags", metadata.flags, int(fields["flags"])),
            ("ordinal", metadata.ordinal, int(fields["ordinal"])),
            ("batch_size", metadata.batch_size, int(fields["batch_size"])),
            ("stream", metadata.stream.hex(), fields["stream"]),
        ):
            if actual != expected:
                raise Failure(
                    f"{vector['name']}: decoded {name} {actual!r}, corpus says {expected!r}"
                )
        if int(fields["header_at"]) != nomadwire.CIPHERTEXT_SIZE:
            raise Failure(f"{vector['name']}: header offset disagrees")
        if int(fields["tag_at"]) != nomadwire.CELL_SIZE - nomadwire.TAG_SIZE:
            raise Failure(f"{vector['name']}: tag offset disagrees")

        # Reproduce the cell rather than only accepting it: an implementation
        # that verifies but cannot produce has not shown it agrees on the
        # construction, only that it can be convinced. Under version 2 this is
        # a stronger statement than it was, because reproducing the bytes now
        # requires agreeing on the keystream as well as the tag -- and the
        # payload fed back in is the decrypted one, not what is on the wire.
        reproduced = nomadwire.seal(
            payload,
            metadata,
            sender,
            metadata.sequence,
            key,
            context,
        )
        if reproduced != cell:
            raise Failure(
                f"{vector['name']}: re-sealed cell differs from the published bytes"
            )
        checked += 1
    if checked == 0:
        raise Failure("the corpus contained no hop-cell-v2 vectors; nothing was checked")
    return checked


def direction_b(vectors: list[dict], out: pathlib.Path) -> int:
    """Produce cells the first implementation has never seen."""
    template = next(v for v in vectors if v["message"] == "hop-cell-v2")
    fields = template["fields"]
    key = bytes.fromhex(fields["conformance_hop_key"])
    context = context_of(fields)
    sender = int(fields["sender"])

    payloads = [
        bytes((index * 7 + position) % 256 for position in range(nomadwire.CIPHERTEXT_SIZE))
        for index in range(4)
    ]
    stream = nomadwire.stream_for(payloads)

    produced = []
    for ordinal, payload in enumerate(payloads):
        metadata = nomadwire.work_metadata(stream, ordinal, len(payloads))
        cell = nomadwire.seal(payload, metadata, sender, 1000 + ordinal, key, context)
        produced.append(
            {
                "name": f"python-work-{ordinal}",
                "bytes_hex": cell.hex(),
                "sender": sender,
                "sequence": 1000 + ordinal,
                "flags": nomadwire.FLAG_WORK,
                "ordinal": ordinal,
                "batch_size": len(payloads),
                "stream": stream.hex(),
            }
        )

    cover = nomadwire.seal(
        bytes((position * 3) % 256 for position in range(nomadwire.CIPHERTEXT_SIZE)),
        nomadwire.cover_metadata(),
        sender,
        2000,
        key,
        context,
    )
    produced.append(
        {
            "name": "python-cover",
            "bytes_hex": cover.hex(),
            "sender": sender,
            "sequence": 2000,
            "flags": 0,
            "ordinal": 0,
            "batch_size": 0,
            "stream": bytes(16).hex(),
        }
    )

    out.write_text(
        json.dumps(
            {
                "produced_by": "conformance/reference/nomadwire.py",
                "conformance_hop_key": key.hex(),
                "topology_digest": context.topology_digest.hex(),
                "network_id": context.network_id,
                "epoch": context.epoch,
                "receiver": context.receiver,
                "cells": produced,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    return len(produced)


def direction_c(vectors: list[dict]) -> int:
    """Every one of these must be refused. Two permissive implementations agree."""
    template = next(v for v in vectors if v["message"] == "hop-cell-v2")
    fields = template["fields"]
    key = bytes.fromhex(fields["conformance_hop_key"])
    context = context_of(fields)
    sender = int(fields["sender"])
    cell = bytes.fromhex(template["bytes_hex"])
    header = nomadwire.CIPHERTEXT_SIZE

    def flipped(offset: int, value: bytes) -> bytes:
        mutated = bytearray(cell)
        mutated[offset : offset + len(value)] = value
        return bytes(mutated)

    cases = [
        ("a flipped ciphertext byte", lambda: flipped(0, bytes([cell[0] ^ 0x01]))),
        ("a flipped tag byte", lambda: flipped(1184, bytes([cell[1184] ^ 0x01]))),
        ("a changed sequence", lambda: flipped(header + 4, (99).to_bytes(4, "big"))),
        ("a zero sequence", lambda: flipped(header + 4, bytes(4))),
        ("a corrupted magic", lambda: flipped(0 + header, b"XXXX")),
        ("a downgraded version", lambda: flipped(header + 3, bytes([1]))),
        # Version 2 encrypts the routing metadata, so there is no sender slot
        # or flag field to change: those mutations become flips in the sealed
        # region, which the tag catches before anything is decrypted.
        ("a flipped metadata byte", lambda: flipped(header + 8, bytes([cell[header + 8] ^ 0x01]))),
        ("a flipped metadata byte at the end",
         lambda: flipped(header + 31, bytes([cell[header + 31] ^ 0x01]))),
        ("a truncated cell", lambda: cell[:-1]),
        ("an over-long cell", lambda: cell + b"\x00"),
    ]

    refused = 0
    for name, build in cases:
        try:
            nomadwire.verify(build(), sender, key, context)
        except nomadwire.WireError:
            refused += 1
            continue
        raise Failure(f"the second implementation accepted {name}")

    # Wrong key, wrong epoch, wrong receiver, wrong network: each is a distinct
    # binding in the tag, and losing any one of them is a cross-context replay.
    bindings = [
        ("a different pairwise key", bytes([key[0] ^ 0x01]) + key[1:], context),
        (
            "a different epoch",
            key,
            nomadwire.Context(context.topology_digest, context.network_id,
                              context.epoch + 1, context.receiver),
        ),
        (
            "a different receiver",
            key,
            nomadwire.Context(context.topology_digest, context.network_id,
                              context.epoch, context.receiver + 1),
        ),
        (
            "a different network",
            key,
            nomadwire.Context(context.topology_digest, context.network_id + "-other",
                              context.epoch, context.receiver),
        ),
        (
            "a different topology digest",
            key,
            nomadwire.Context(bytes([context.topology_digest[0] ^ 0x01])
                              + context.topology_digest[1:],
                              context.network_id, context.epoch, context.receiver),
        ),
    ]
    for name, other_key, other_context in bindings:
        try:
            nomadwire.verify(cell, sender, other_key, other_context)
        except nomadwire.WireError:
            refused += 1
            continue
        raise Failure(f"the second implementation accepted the cell under {name}")

    # A replay window that accepts a duplicate is a replay window in name only.
    window = nomadwire.ReplayWindow()
    window.accept(10)
    window.accept(11)
    try:
        window.accept(10)
    except nomadwire.WireError:
        refused += 1
    else:
        raise Failure("the replay window accepted a duplicate")
    try:
        window.accept(11 - 64)
    except nomadwire.WireError:
        refused += 1
    else:
        raise Failure("the replay window accepted a sequence beyond its span")
    window.accept(12)
    return refused


def direction_d(path: pathlib.Path) -> int:
    """Verify cells the first implementation sealed just now, not months ago.

    Direction A checks a committed corpus, which is a snapshot: an encoder that
    drifts after the corpus was written stays undetected there. Mutating the
    header layout in the first implementation's encoder was, in fact, invisible
    to every check in its conformance package, because nothing re-derived the
    vectors and handed them to an independent decoder. This does.
    """
    produced = json.loads(path.read_text())
    key = bytes.fromhex(produced["conformance_hop_key"])
    context = nomadwire.Context(
        topology_digest=bytes.fromhex(produced["topology_digest"]),
        network_id=produced["network_id"],
        epoch=int(produced["epoch"]),
        receiver=int(produced["receiver"]),
    )
    cells = produced["cells"]
    if len(cells) < 2:
        raise Failure(f"the first implementation emitted {len(cells)} cells; nothing is checked")
    work: dict[str, list[bytes]] = {}
    for entry in cells:
        cell = bytes.fromhex(entry["bytes_hex"])
        metadata, payload = nomadwire.open_cell(cell, int(entry["sender"]), key, context)
        for name, actual, expected in (
            ("sequence", metadata.sequence, int(entry["sequence"])),
            ("flags", metadata.flags, int(entry["flags"])),
            ("ordinal", metadata.ordinal, int(entry["ordinal"])),
            ("batch_size", metadata.batch_size, int(entry["batch_size"])),
            ("stream", metadata.stream.hex(), entry["stream"]),
        ):
            if actual != expected:
                raise Failure(
                    f"{entry['name']}: decoded {name} {actual!r}, the first "
                    f"implementation declared {expected!r}"
                )
        if metadata.is_work:
            # The stream ID is a hash of the plaintext payloads. Under version
            # 2 that is not what is on the wire, so the decrypted payload is
            # what goes into the recomputation.
            work.setdefault(metadata.stream.hex(), []).append(payload)
    # The stream ID is a hash both sides must derive identically, and a wrong
    # one still carries a valid tag over itself. Recompute it here.
    for declared, payloads in work.items():
        if len(payloads) < 2:
            continue
        recomputed = nomadwire.stream_for(payloads).hex()
        if recomputed != declared:
            raise Failure(
                f"stream ID disagreement: this implementation computes {recomputed}, "
                f"the first declared {declared}"
            )
    return len(cells)


def direction_e(vectors: list[dict]) -> int:
    """Verify the signed topology, which is the root of trust for everything.

    The digest is the check that matters. It is a SHA-256 over the canonical
    encoding, so reproducing it means having reproduced those bytes exactly --
    Go's member order, Go's habit of escaping <, > and &, Go's null for an
    absent array. A second implementation that got any of that wrong would
    verify signatures it computed itself and disagree with everyone.
    """
    checked = 0
    for vector in vectors:
        if vector["message"] != "topology-document-v3":
            continue
        encoded = bytes.fromhex(vector["bytes_hex"])
        authority = base64.b64decode(vector["fields"]["conformance_authority_key"])
        document = nomadtopology.verify(encoded, authority)

        computed = nomadtopology.topology_digest(document).hex()
        if computed != vector["fields"]["topology_digest"]:
            raise Failure(
                f"{vector['name']}: this implementation computes topology digest "
                f"{computed[:16]}, the corpus says "
                f"{vector['fields']['topology_digest'][:16]} -- the canonical "
                "encoding was not reproduced"
            )
        for name, actual, expected in (
            ("network_id", document["network_id"], vector["fields"]["network_id"]),
            ("epoch", str(document["epoch"]), vector["fields"]["epoch"]),
            ("operators", str(len(document["operators"])), vector["fields"]["operators"]),
            ("cell_size", str(document["traffic"]["cell_size"]), vector["fields"]["cell_size"]),
        ):
            if actual != expected:
                raise Failure(f"{vector['name']}: decoded {name} {actual!r}, corpus says {expected!r}")

        # Negative cases. A verifier that accepts everything also "agrees".
        #
        # They are built by re-serialising the parsed document rather than by
        # editing its text: the file is pretty-printed and a string replace
        # aimed at compact JSON silently matches nothing, which is how an
        # earlier version of this reported that an unknown member was
        # accepted when the mutation had never been applied.
        outer = json.loads(encoded.decode())

        # Structural mutations are refused by the parser, with or without an
        # ed25519 library present.
        refused = {
            "an unknown document member":
                json.dumps({**outer, "document": {**outer["document"], "surprise": 1}}),
            "an unknown outer member": json.dumps({**outer, "surprise": 1}),
            "an unrecognised version":
                json.dumps({**outer,
                            "document": {**outer["document"],
                                         "version": "nomad-live-topology-v9"}}),
            "trailing data": encoded.decode() + "{}",
            "a duplicate member": encoded.decode().replace(
                '"network_id"', '"network_id": "elsewhere",\n    "network_id"', 1),
        }
        for name, mutated in refused.items():
            try:
                nomadtopology.verify(mutated.encode(), authority)
            except (nomadtopology.TopologyError, ValueError):
                continue
            raise Failure(f"{vector['name']}: accepted {name}")

        # Tampering with a *value* is caught by the signature, which needs a
        # library that may not be here. It is also caught by the digest, which
        # needs only hashlib -- and the digest is the property that carries:
        # the hop authentication tag binds it, so a document whose digest
        # moved is one every authenticated cell in the epoch rejects.
        for name, changed in {
            "a changed epoch": {**document, "epoch": 9999},
            "a changed network": {**document, "network_id": "elsewhere"},
            "a changed cell interval": {
                **document,
                "traffic": {**document["traffic"], "cell_interval_ms": 999},
            },
            "a moved validity window": {**document, "not_after": "2099-01-01T00:00:00Z"},
        }.items():
            if nomadtopology.topology_digest(changed).hex() == computed:
                raise Failure(
                    f"{vector['name']}: {name} left the topology digest unchanged, so "
                    "nothing binding that digest would notice"
                )

        # And the digest must move when the document does, or it is pinning
        # nothing. Blanking one attestation is the subtlest such change.
        tampered = json.loads(json.dumps(document))
        tampered["operators"][0]["attestation"] = ""
        if nomadtopology.topology_digest(tampered).hex() == computed:
            raise Failure(f"{vector['name']}: the digest did not change when the document did")
        checked += 1
    if checked == 0:
        raise Failure("the corpus contained no topology vectors; nothing was checked")
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("--emit", help="write cells for the first implementation to verify")
    parser.add_argument("--verify", help="verify cells the first implementation just sealed")
    arguments = parser.parse_args()

    corpus = json.loads(pathlib.Path(arguments.corpus).read_text())
    vectors = corpus["vectors"]

    try:
        verified = direction_a(vectors)
        print(f"A: verified and reproduced {verified} authenticated cells from the corpus")
        refused = direction_c(vectors)
        print(f"C: refused {refused} mutations and cross-context replays")
        topologies = direction_e(vectors)
        signatures = "with signatures" if nomadtopology.SIGNATURES_CHECKABLE \
            else "canonical encoding and digest only; no ed25519 library here"
        print(f"E: verified {topologies} signed topologies ({signatures})")
        if arguments.emit:
            emitted = direction_b(vectors, pathlib.Path(arguments.emit))
            print(f"B: produced {emitted} cells for the first implementation at {arguments.emit}")
        if arguments.verify:
            fresh = direction_d(pathlib.Path(arguments.verify))
            print(f"D: verified {fresh} cells the first implementation sealed just now")
    except Failure as failure:
        print(f"CROSS-IMPLEMENTATION FAILURE: {failure}", file=sys.stderr)
        return 1
    except nomadwire.WireError as error:
        print(f"CROSS-IMPLEMENTATION FAILURE: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
