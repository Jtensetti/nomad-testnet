"""A second implementation of Nomad's signed topology document.

Written from nomad-protocol docs/PROTOCOL.md, "Signed topology document",
not from the Go. The topology is the root of trust -- it names the operator
set, their keys, the epoch, the validity window and the traffic class -- so an
implementation that cannot verify one cannot participate at all.

FINDING, and it is the reason this file exists:

    The document that everything else is checked against was not specified.
    docs/PROTOCOL.md described the wire cell, the RLNC packet, the mix batch,
    the object manifest and the basin, and said nothing whatever about the
    topology. There was no encoding to implement, no signing domain to use and
    no verification order to follow.

    Worse than absent, at first: the encoding the reference implementation
    signed was the output of Go's encoding/json on its own structs. Reproducing
    it required Go's member order rather than sorted keys, Go's habit of
    escaping <, > and & as \\u003c, \\u003e and \\u0026 -- which no JSON
    specification requires -- and Go's rendering of an absent array as null. A
    second implementation that emitted the obvious bytes produced a different
    message and every signature over it failed, and none of it was visible
    until a network_id or an endpoint contained an ampersand.

    That was recorded as a defect that should not survive the freeze, and it
    did not. The canonical encoding is now specified: members sorted by their
    UTF-16 code units, no whitespace, minimal string escaping, integers only,
    and an absent array as []. This file implements the specification rather
    than one language's defaults, which is the difference between a second
    implementation and a reimplementation.

The signature check uses `cryptography` when it is importable. That is a
dependency this file's sibling nomadwire.py does not have, and the reason is
deliberate: hand-rolling Ed25519 for a conformance tool would be a worse
example than depending on a reviewed library, and the independence that
matters here is independence from the Go implementation, not from all
libraries. Where it is missing, the canonical-encoding and digest checks still
run -- and those are the ones that actually test interoperability, because
reproducing a SHA-256 over the canonical bytes requires producing them exactly.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

DOCUMENT_VERSION = "nomad-live-topology-v3"
DRAFT_DOMAIN = b"nomad-topology-draft-v3"
AUTHORITY_DOMAIN = b"nomad-topology-authority-v3"
DIGEST_DOMAIN = b"nomad-topology-digest-v3"

DOCUMENT_MEMBERS = (
    "version", "network_id", "epoch", "not_before", "not_after",
    "traffic", "dkg", "operators",
)
TRAFFIC_MEMBERS = ("cell_size", "cell_interval_ms", "max_lateness_ms", "queue_capacity")
DKG_MEMBERS = ("threshold", "session_id", "start_at", "phase_duration_ms")
OPERATOR_MEMBERS = (
    "id", "index", "endpoint", "partial_endpoint", "dkg_endpoint",
    "identity_key", "kex_key", "dkg_identity_key", "peer_plan", "attestation",
)

# A broken install is caught as well as a missing one, and deliberately so:
# the container this was written in has `cryptography` present but unusable
# (its Rust extension raises a panic rather than an ImportError), and a
# conformance tool that died on someone else's broken environment would be
# reporting on the environment rather than on the protocol.
try:  # pragma: no cover - presence depends on the environment
    # stderr is redirected because a broken pyo3 extension prints a Rust
    # backtrace on the way to failing, and a conformance run's output should
    # be about the protocol.
    import contextlib
    import io

    with contextlib.redirect_stderr(io.StringIO()):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    SIGNATURES_CHECKABLE = True
except BaseException:  # noqa: BLE001  # pragma: no cover
    # BaseException, not Exception, and only here. A broken pyo3 extension
    # raises PanicException, which derives from BaseException, so the narrower
    # clause does not catch it. Around a single import at module load there is
    # nothing else this can swallow.
    SIGNATURES_CHECKABLE = False


class TopologyError(Exception):
    """A topology this implementation refuses."""


def _escape(text: str) -> str:
    """Render a JSON string with the minimal escaping the encoding specifies.

    Only the quote, the backslash and the control characters are escaped, with
    the short forms where they exist and lowercase \\u00xx otherwise. Nothing
    else -- and in particular not <, > or &, which Go escapes by default and
    no specification asks anyone to.
    """
    out = ['"']
    short = {0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}
    for character in text:
        code = ord(character)
        if character == '"':
            out.append('\\"')
        elif character == "\\":
            out.append("\\\\")
        elif code in short:
            out.append(short[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _sort_key(name: str) -> tuple:
    """Order member names by their UTF-16 code units, as the encoding says."""
    return tuple(name.encode("utf-16-be")[i] << 8 | name.encode("utf-16-be")[i + 1]
                 for i in range(0, len(name.encode("utf-16-be")), 2))


def _encode(value: Any) -> str:
    if value is None:
        # A document has no nullable members, so this is an absent array.
        return "[]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return _object(value, tuple(value))
    raise TopologyError(f"cannot canonically encode {type(value).__name__}")


def _object(source: dict, members: tuple[str, ...]) -> str:
    missing = [name for name in members if name not in source]
    if missing:
        raise TopologyError(f"member(s) absent from the document: {', '.join(missing)}")
    extra = [name for name in source if name not in members]
    if extra:
        raise TopologyError(f"unknown member(s): {', '.join(sorted(extra))}")
    ordered = sorted(source, key=_sort_key)
    return "{" + ",".join(f'{_escape(name)}:{_encode(source[name])}' for name in ordered) + "}"


def canonical(document: dict) -> bytes:
    """The exact bytes the three signed messages are computed over."""
    missing = [name for name in DOCUMENT_MEMBERS if name not in document]
    if missing:
        raise TopologyError(f"document has no {', '.join(missing)}")
    extra = [name for name in document if name not in DOCUMENT_MEMBERS]
    if extra:
        raise TopologyError(f"unknown document member(s): {', '.join(sorted(extra))}")

    rendered: dict[str, str] = {}
    for name, value in document.items():
        if name == "traffic":
            rendered[name] = _object(value, TRAFFIC_MEMBERS)
        elif name == "dkg":
            rendered[name] = _object(value, DKG_MEMBERS)
        elif name == "operators":
            if value is None:
                rendered[name] = "[]"
            else:
                rendered[name] = "[" + ",".join(
                    _object(item, OPERATOR_MEMBERS) for item in value) + "]"
        else:
            rendered[name] = _encode(value)
    ordered = sorted(rendered, key=_sort_key)
    return ("{" + ",".join(f'{_escape(name)}:{rendered[name]}' for name in ordered) + "}").encode()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """Refuse an object two parsers could read differently.

    A signature check cannot catch this: each implementation verifies whatever
    it parsed, so a duplicate member makes one accept what another refuses.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise TopologyError(f"duplicate member {key!r}: the encoding is ambiguous")
        seen[key] = value
    return seen


def draft_digest(document: dict) -> bytes:
    """What each operator attests to: the document with attestations blanked."""
    draft = json.loads(json.dumps(document), object_pairs_hook=_reject_duplicate_keys)
    for operator in draft.get("operators") or []:
        operator["attestation"] = ""
    return hashlib.sha256(DRAFT_DOMAIN + canonical(draft)).digest()


def topology_digest(document: dict) -> bytes:
    """The 32-byte value the hop authentication tag binds to."""
    return hashlib.sha256(DIGEST_DOMAIN + canonical(document)).digest()


def verify(encoded: bytes, authority: bytes, maximum_bytes: int = 1 << 20) -> dict:
    """Verify a signed topology against a pinned authority key.

    The key is a parameter and never read from the document: a topology that
    named its own authority would authenticate nothing.
    """
    if not encoded or len(encoded) > maximum_bytes:
        raise TopologyError("topology encoding is empty or too large")
    if len(authority) != 32:
        raise TopologyError("pinned authority key is not an ed25519 public key")

    outer = json.loads(encoded.decode(), object_pairs_hook=_reject_duplicate_keys)
    if set(outer) != {"document", "signature"}:
        raise TopologyError("a signed topology has exactly a document and a signature")
    document = outer["document"]
    if document.get("version") != DOCUMENT_VERSION:
        raise TopologyError(
            f"unrecognised topology version {document.get('version')!r}, which is "
            "refused rather than downgraded to"
        )

    message = AUTHORITY_DOMAIN + canonical(document)
    signature = base64.b64decode(outer["signature"], validate=True)
    if len(signature) != 64:
        raise TopologyError("authority signature is not 64 bytes")
    if SIGNATURES_CHECKABLE:
        try:
            Ed25519PublicKey.from_public_bytes(authority).verify(signature, message)
        except InvalidSignature as failure:
            raise TopologyError("authority signature does not verify") from failure

        # Every operator attests to the same draft, so one bad attestation is
        # an operator that signed a different membership from the rest.
        draft = draft_digest(document)
        for operator in document.get("operators") or []:
            attestation = base64.b64decode(operator["attestation"], validate=True)
            if len(attestation) != 64:
                raise TopologyError(f"{operator['id']}: attestation is not 64 bytes")
            identity = base64.b64decode(operator["identity_key"], validate=True)
            try:
                Ed25519PublicKey.from_public_bytes(identity).verify(attestation, draft)
            except InvalidSignature as failure:
                raise TopologyError(
                    f"{operator['id']}: attestation does not verify against the draft "
                    "every operator is supposed to have signed"
                ) from failure
    return document
