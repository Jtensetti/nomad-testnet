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

Direction E covers the signed topology, F the object manifest, and G the
publisher uplink frame and its derivations. Between them every message the
corpus publishes now has a consumer that is not the encoder that produced it,
which is what PROD-19 asks for and what a corpus checked only by its own
encoder cannot give.

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

import nomadobject  # noqa: E402
import nomadtopology  # noqa: E402
import nomaduplink  # noqa: E402
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


def direction_e(vectors: list[dict]) -> tuple[int, int]:
    """Verify the signed topology, which is the root of trust for everything.

    The digest is the check that matters. It is a SHA-256 over the canonical
    encoding, so reproducing it means having reproduced those bytes exactly --
    Go's member order, Go's habit of escaping <, > and &, Go's null for an
    absent array. A second implementation that got any of that wrong would
    verify signatures it computed itself and disagree with everyone.
    """
    checked = 0
    # Counted and reported for the same reason the cell mutations are: a list
    # that quietly shrinks is a check that quietly stops checking.
    structurally_refused = 0
    for vector in vectors:
        if vector["message"] != "topology-document-v3":
            continue
        encoded = bytes.fromhex(vector["bytes_hex"])
        authority = base64.b64decode(vector["fields"]["conformance_authority_key"], validate=True)
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
            # A base64 field with a newline in it. Go's decoder ignores CR and
            # LF wherever they appear and Strict() does not change that, so
            # this verified in Go while validate=True refused it here: one
            # signed topology, two answers. The signature cannot object,
            # because the signature field is not covered by the signature.
            # The Go mirror is TestAmbiguousJSONRepresentationsAreRefusedOrCanonical.
            "a newline inside a base64 field": json.dumps(
                {**outer, "signature": outer["signature"][:8] + "\n"
                 + outer["signature"][8:]}),
        }
        for name, mutated in refused.items():
            try:
                nomadtopology.verify(mutated.encode(), authority)
            except (nomadtopology.TopologyError, ValueError):
                structurally_refused += 1
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
    return checked, structurally_refused


def direction_f(vectors: list[dict]) -> int:
    """The object manifest: the last check before bytes become an object.

    Verifying is not enough on its own -- an implementation that verifies but
    cannot reproduce the signing messages has only shown it can be convinced.
    So both signing messages are rebuilt from the parsed fields and the
    manifest is re-encoded to its 228 bytes.
    """
    checked = 0
    for vector in vectors:
        if vector["message"] != "object-manifest-v1":
            continue
        wire = bytes.fromhex(vector["bytes_hex"])
        if len(wire) != vector["length"]:
            raise Failure(f"{vector['name']}: length field disagrees with the bytes")
        if hashlib.sha256(wire).hexdigest() != vector["sha256"]:
            raise Failure(f"{vector['name']}: sha256 field disagrees with the bytes")

        manifest = nomadobject.verify(wire)
        fields = vector["fields"]
        if manifest.length != int(fields["object_length"]):
            raise Failure(
                f"{vector['name']}: decoded length {manifest.length}, corpus says "
                f"{fields['object_length']}"
            )
        if manifest.basin != int(fields["basin"]):
            raise Failure(
                f"{vector['name']}: decoded basin {manifest.basin}, corpus says "
                f"{fields['basin']}"
            )
        if int(fields["manifest_size"]) != nomadobject.MANIFEST_SIZE:
            raise Failure(f"{vector['name']}: manifest size disagrees")
        if base64.b64encode(manifest.public_key).decode() != fields["publisher_key"]:
            raise Failure(f"{vector['name']}: publisher key disagrees")

        if nomadobject.encode(manifest) != wire:
            raise Failure(f"{vector['name']}: re-encoding does not reproduce the bytes")

        # The signing messages are the interoperability surface: a manifest
        # whose message is assembled differently verifies against itself and
        # against nothing else.
        object_message = nomadobject.object_signing_message(manifest.root)
        if not object_message.startswith(nomadobject.OBJECT_DOMAIN):
            raise Failure(f"{vector['name']}: object signing message lost its domain")
        manifest_message = nomadobject.manifest_signing_message(manifest)
        expected_length = (
            len(nomadobject.MANIFEST_DOMAIN) + 8 + 8 + 16 + 32 + 32 + 64
        )
        if len(manifest_message) != expected_length:
            raise Failure(
                f"{vector['name']}: manifest signing message is "
                f"{len(manifest_message)} bytes, expected {expected_length}"
            )
        checked += 1

    if checked == 0:
        raise Failure("the corpus contained no object-manifest-v1 vectors")

    # Negative cases, on the same reasoning as direction C.
    subject = next(v for v in vectors if v["message"] == "object-manifest-v1")
    wire = bytes.fromhex(subject["bytes_hex"])

    def flipped(offset: int, value: bytes) -> bytes:
        mutated = bytearray(wire)
        mutated[offset:offset + len(value)] = value
        return bytes(mutated)

    # Two groups, because they are refused by different things. The first is
    # refused by the layout and the explicit checks, whatever the environment.
    # The second is refused only by a signature, so it is skipped -- and
    # reported as skipped -- where no Ed25519 library is importable. A
    # conformance tool that counted those as passes would be reporting on the
    # environment rather than on the protocol.
    structural = [
        ("a corrupted magic", lambda: flipped(0, b"XXXX")),
        ("a downgraded version", lambda: flipped(3, bytes([0]))),
        ("a truncated manifest", lambda: wire[:-1]),
        ("an over-long manifest", lambda: wire + b"\x00"),
        ("a zero object length", lambda: flipped(4, bytes(8))),
        ("an all-zero publisher key", lambda: flipped(68, bytes(32))),
        ("an all-zero content root", lambda: flipped(36, bytes(32))),
    ]
    signature_only = [
        ("a flipped root byte", lambda: flipped(36, bytes([wire[36] ^ 0x01]))),
        ("a flipped object signature byte", lambda: flipped(100, bytes([wire[100] ^ 0x01]))),
        ("a flipped manifest signature byte", lambda: flipped(164, bytes([wire[164] ^ 0x01]))),
        ("a swapped publisher key", lambda: flipped(68, bytes([wire[68] ^ 0x01]) + wire[69:100])),
    ]
    refused = 0
    for name, build in structural:
        try:
            nomadobject.verify(build())
        except nomadobject.ManifestError:
            refused += 1
            continue
        except Exception as error:  # noqa: BLE001
            raise Failure(f"{name} raised {error!r} rather than being refused") from error
        raise Failure(f"the second implementation accepted {name}")

    if nomadobject.SIGNATURES_CHECKABLE:
        for name, build in signature_only:
            try:
                nomadobject.verify(build())
            except nomadobject.ManifestError:
                refused += 1
                continue
            except Exception as error:  # noqa: BLE001
                raise Failure(f"{name} raised {error!r} rather than being refused") from error
            raise Failure(f"the second implementation accepted {name}")

    # The content check, which the corpus cannot carry because the object is
    # 4096 bytes of test data rather than a published vector: a manifest must
    # refuse content that does not hash to its signed root.
    manifest = nomadobject.parse(wire)
    try:
        nomadobject.verify(wire, content=b"x" * manifest.length)
    except nomadobject.ManifestError:
        refused += 1
    else:
        raise Failure("content that does not hash to the signed root was accepted")

    return checked * 100 + refused


def direction_g(vectors: list[dict]) -> int:
    """The publisher uplink: the frame and the two derivations that feed it.

    AES-GCM is not reimplemented here -- the Python standard library has no
    AES, and hand-rolling one for a conformance tool would be a worse example
    than saying so. What is reproduced is where implementations actually
    diverge: the HKDF info string and the nonce. An AEAD either matches or
    fails loudly; a derivation assembled differently produces a well-formed
    cell that the other side refuses with no clue why.
    """
    checked = 0
    for vector in vectors:
        if vector["message"] != "uplink-cell-frame-v1":
            continue
        fields = vector["fields"]
        nomaduplink.check_frame_layout(
            cell_size=int(fields["cell_size"]),
            sequence_size=int(fields["sequence_size"]),
            inner_size=int(fields["inner_size"]),
            tag_size=int(fields["tag_size"]),
            padding_size=int(fields["padding_size"]),
        )

        prefix = bytes.fromhex(vector["bytes_hex"])
        if len(prefix) != nomaduplink.SEQUENCE_SIZE:
            raise Failure(f"{vector['name']}: the sequence prefix is not 8 bytes")
        if int.from_bytes(prefix, "big") != int(fields["sequence"]):
            raise Failure(f"{vector['name']}: the prefix does not encode the stated sequence")

        derived = nomaduplink.session_key(
            shared_secret=bytes.fromhex(fields["conformance_shared_secret"]),
            network_id=fields["network_id"],
            epoch=int(fields["epoch"]),
            entry_operator=int(fields["entry_operator"]),
            topology_digest=bytes.fromhex(fields["topology_digest"]),
        )
        if derived.hex() != fields["session_key"]:
            raise Failure(
                f"{vector['name']}: derived session key {derived.hex()}, the first "
                f"implementation derived {fields['session_key']}"
            )
        derived_nonce = nomaduplink.nonce(derived, int(fields["sequence"]))
        if derived_nonce.hex() != fields["nonce"]:
            raise Failure(
                f"{vector['name']}: derived nonce {derived_nonce.hex()}, the first "
                f"implementation derived {fields['nonce']}"
            )
        checked += 1

    if checked == 0:
        raise Failure("the corpus contained no uplink-cell-frame-v1 vectors")

    # Negative cases. Each binding in the derivation is a distinct
    # cross-context replay if it is not really bound.
    subject = next(v for v in vectors if v["message"] == "uplink-cell-frame-v1")
    fields = subject["fields"]
    base = dict(
        shared_secret=bytes.fromhex(fields["conformance_shared_secret"]),
        network_id=fields["network_id"],
        epoch=int(fields["epoch"]),
        entry_operator=int(fields["entry_operator"]),
        topology_digest=bytes.fromhex(fields["topology_digest"]),
    )
    expected = fields["session_key"]
    separated = 0
    for name, change in (
        ("another network", {"network_id": "other-network"}),
        ("another epoch", {"epoch": base["epoch"] + 1}),
        ("another entry operator", {"entry_operator": base["entry_operator"] + 1}),
        ("another topology", {"topology_digest": bytes(31) + b"\x01"}),
        ("another secret", {"shared_secret": bytes(32)[:-1] + b"\x01"}),
    ):
        altered = dict(base)
        altered.update(change)
        if nomaduplink.session_key(**altered).hex() == expected:
            raise Failure(f"the session key is not bound to the context: {name} derived the same key")
        separated += 1

    for name, arguments in (
        ("an empty secret", dict(base, shared_secret=b"")),
        ("an empty network", dict(base, network_id="")),
        ("a zero epoch", dict(base, epoch=0)),
        ("a zero topology digest", dict(base, topology_digest=bytes(32))),
        ("a short topology digest", dict(base, topology_digest=bytes(31))),
    ):
        try:
            nomaduplink.session_key(**arguments)
        except nomaduplink.UplinkError:
            separated += 1
            continue
        raise Failure(f"the second implementation derived a key from {name}")

    key = bytes.fromhex(expected)
    if nomaduplink.nonce(key, 1) == nomaduplink.nonce(key, 2):
        raise Failure("the nonce does not depend on the sequence")
    try:
        nomaduplink.nonce(key, 0)
    except nomaduplink.UplinkError:
        separated += 1
    else:
        raise Failure("a zero sequence was given a nonce")

    for name, cell in (
        ("a short cell", bytes(nomaduplink.CELL_SIZE - 1)),
        ("a long cell", bytes(nomaduplink.CELL_SIZE + 1)),
        ("a zero sequence", bytes(nomaduplink.CELL_SIZE)),
    ):
        try:
            nomaduplink.parse_frame(cell)
        except nomaduplink.UplinkError:
            separated += 1
            continue
        raise Failure(f"the second implementation accepted {name}")

    return checked * 100 + separated


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
        topologies, topology_refusals = direction_e(vectors)
        signatures = "with signatures" if nomadtopology.SIGNATURES_CHECKABLE \
            else "canonical encoding and digest only; no ed25519 library here"
        print(f"E: verified {topologies} signed topologies and refused "
              f"{topology_refusals} ambiguous or malformed ones ({signatures})")
        manifests = direction_f(vectors)
        manifest_signatures = "with signatures" if nomadobject.SIGNATURES_CHECKABLE \
            else "layout and signing messages only; no ed25519 library here"
        print(f"F: verified {manifests // 100} object manifest(s) and refused "
              f"{manifests % 100} malformed ones ({manifest_signatures})")
        uplinks = direction_g(vectors)
        print(f"G: reproduced {uplinks // 100} uplink frame derivation(s) and refused "
              f"{uplinks % 100} unbound or malformed ones")
        if arguments.emit:
            emitted = direction_b(vectors, pathlib.Path(arguments.emit))
            print(f"B: produced {emitted} cells for the first implementation at {arguments.emit}")
        if arguments.verify:
            fresh = direction_d(pathlib.Path(arguments.verify))
            print(f"D: verified {fresh} cells the first implementation sealed just now")
    except Failure as failure:
        print(f"CROSS-IMPLEMENTATION FAILURE: {failure}", file=sys.stderr)
        return 1
    except (nomadwire.WireError, nomadobject.ManifestError,
            nomaduplink.UplinkError, nomadtopology.TopologyError) as error:
        print(f"CROSS-IMPLEMENTATION FAILURE: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
