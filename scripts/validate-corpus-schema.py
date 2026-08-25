#!/usr/bin/env python3
"""Validate the conformance corpus against its published JSON Schema.

PROD-01 recorded that the corpus was "a JSON file with a fixed shape enforced by
its own encoder, not a published schema a second implementation could validate
against". conformance/wire-vectors.schema.json is that schema. This validates
our corpus against it, so the schema cannot drift away from the file it
describes.

Scope, stated rather than implied: this is NOT a general JSON Schema
implementation. It implements exactly the keywords the schema uses -- type,
const, enum, required, properties, additionalProperties, $ref to $defs, pattern,
minLength, minimum, items, minItems -- and refuses any keyword it does not know,
so the schema cannot quietly grow a constraint this does not check. A second
implementation should use a real validator; the schema is the deliverable, this
is only our own conformance to it.

Beyond the schema it checks the two cross-field invariants a schema cannot
express: length must equal half the hex length, and names must be unique.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWN = {
    "$schema", "$id", "title", "description", "type", "const", "enum",
    "required", "properties", "additionalProperties", "$ref", "$defs",
    "pattern", "minLength", "minimum", "items", "minItems",
}


def validate(value, schema, root, path, errors):
    unknown = set(schema) - KNOWN
    if unknown:
        errors.append(f"{path}: schema uses keywords this validator does not "
                      f"implement: {sorted(unknown)}")
        return
    if "$ref" in schema:
        target = schema["$ref"]
        if not target.startswith("#/$defs/"):
            errors.append(f"{path}: only #/$defs/ references are supported, got {target}")
            return
        validate(value, root["$defs"][target[len("#/$defs/"):]], root, path, errors)
        return

    expected = schema.get("type")
    if expected:
        kinds = {
            "object": dict, "array": list, "string": str,
            "integer": int, "number": (int, float), "boolean": bool,
        }[expected]
        if expected == "integer" and isinstance(value, bool):
            errors.append(f"{path}: expected integer, got boolean")
            return
        if not isinstance(value, kinds):
            errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
            return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected the constant {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} is below {schema['minimum']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: has {len(value)} items, needs {schema['minItems']}")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], root, f"{path}[{index}]", errors)
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                validate(item, properties[name], root, f"{path}.{name}", errors)
                continue
            extra = schema.get("additionalProperties", True)
            if extra is False:
                errors.append(f"{path}: unexpected property {name!r}")
            elif isinstance(extra, dict):
                validate(item, extra, root, f"{path}.{name}", errors)


def main() -> int:
    schema = json.loads((ROOT / "conformance/wire-vectors.schema.json").read_text())
    corpus = json.loads((ROOT / "conformance/wire-vectors.json").read_text())

    errors = []
    validate(corpus, schema, schema, "corpus", errors)

    # Cross-field invariants a schema cannot express.
    seen = set()
    for index, vector in enumerate(corpus.get("vectors", [])):
        where = f"vectors[{index}]"
        name = vector.get("name")
        if name in seen:
            errors.append(f"{where}: duplicate vector name {name!r}")
        seen.add(name)
        hex_bytes = vector.get("bytes_hex", "")
        if isinstance(hex_bytes, str) and isinstance(vector.get("length"), int):
            if vector["length"] != len(hex_bytes) // 2:
                errors.append(f"{where}: length {vector['length']} but bytes_hex holds "
                              f"{len(hex_bytes) // 2} bytes")
        if isinstance(hex_bytes, str) and isinstance(vector.get("sha256"), str):
            try:
                actual = hashlib.sha256(bytes.fromhex(hex_bytes)).hexdigest()
            except ValueError:
                actual = None
            if actual and actual != vector["sha256"]:
                errors.append(f"{where}: sha256 does not match its own bytes")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"corpus validates against the published schema: "
          f"{len(corpus['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
