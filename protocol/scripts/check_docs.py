#!/usr/bin/env python3
from pathlib import Path
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md",
    "docs/DEFINITION_OF_DONE.md",
    "docs/PRODUCTION_DEFINITION_OF_DONE.md",
    "docs/IMPLEMENTATION_STATUS.md",
    "docs/ARCHITECTURE.md",
    "docs/PROTOCOL.md",
    "docs/SECURITY_PROPERTIES.md",
    "docs/THREAT_MODEL.md",
    "PRODUCTION_STATUS.md",
]
FORBIDDEN_STALE = [
    "Payload-preserving mix crypto | none | missing",
    "Real UDP transport | \u0060nomad-testnet\u0060 | missing",
    "Reader packet-trace indistinguishability | none | missing",
    "currently only a model",
    "current mix repository does not carry application payload",
    "BROWSER_RC_COMMIT",
]

errors = []
documents = {}
for relative in REQUIRED:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"missing required document: {relative}")
        continue
    text = path.read_text(encoding="utf-8")
    documents[relative] = text
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.rstrip() != line:
            errors.append(f"{relative}:{line_number}: trailing whitespace")

joined = "\n".join(documents.values())
for stale in FORBIDDEN_STALE:
    if stale in joined:
        errors.append(f"stale or placeholder claim remains: {stale!r}")

dod = documents.get("docs/DEFINITION_OF_DONE.md", "")
for number in range(1, 13):
    criterion = f"DOD-{number:02d}"
    if dod.count(criterion) != 1:
        errors.append(f"{criterion} must appear exactly once")
if dod.count("| MET |") != 12:
    errors.append("all twelve v0.1 DoD criteria must have explicit MET status")

registry_path = ROOT / "production/readiness.json"
if not registry_path.is_file():
    errors.append("missing production readiness registry: production/readiness.json")
    registry = {"criteria": []}
else:
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        errors.append(f"invalid production readiness registry: {exc}")
        registry = {"criteria": []}

production_dod = documents.get("docs/PRODUCTION_DEFINITION_OF_DONE.md", "")
allowed_statuses = {"NOT_MET", "PARTIAL", "BLOCKED", "MET"}
criteria = registry.get("criteria", [])
registry_ids = [item.get("id") for item in criteria if isinstance(item, dict)]
expected_ids = [f"PROD-{number:02d}" for number in range(1, 31)]
if registry_ids != expected_ids:
    errors.append("production registry must contain PROD-01 through PROD-30 in order")

table_statuses = {}
for match in re.finditer(
    r"^\| (PROD-\d{2}) \|.*\| (NOT_MET|PARTIAL|BLOCKED|MET) \|$",
    production_dod,
    re.MULTILINE,
):
    table_statuses[match.group(1)] = match.group(2)

if list(table_statuses) != expected_ids:
    errors.append("production DoD table must contain PROD-01 through PROD-30 in order")

met_count = 0
for item in criteria:
    if not isinstance(item, dict):
        errors.append("every production criterion must be an object")
        continue
    criterion = item.get("id")
    status = item.get("status")
    if status not in allowed_statuses:
        errors.append(f"{criterion}: unknown production status {status!r}")
    if table_statuses.get(criterion) != status:
        errors.append(f"{criterion}: document and registry status differ")
    evidence = item.get("evidence")
    blockers = item.get("blockers")
    if not isinstance(evidence, list) or not isinstance(blockers, list):
        errors.append(f"{criterion}: evidence and blockers must be lists")
        continue
    if status == "MET":
        met_count += 1
        if not evidence:
            errors.append(f"{criterion}: MET requires immutable evidence")
        if blockers:
            errors.append(f"{criterion}: MET cannot retain blockers")
    elif not blockers:
        # A criterion that is not MET and names nothing missing has either
        # been promoted without saying so or never examined. Both should be
        # visible rather than inferred from an empty list.
        errors.append(f"{criterion}: {status} must record at least one blocker "
                      "saying what is missing")

score = re.search(r"Current score: \*\*(\d+)/30 production gates MET\.\*\*", production_dod)
if not score:
    errors.append("production DoD must contain the machine-checkable score")
elif int(score.group(1)) != met_count:
    errors.append("production DoD score does not match readiness registry")

# PRODUCTION_STATUS.md is the prose deliverable people read instead of the
# registry, so it is the one most likely to keep saying something the registry
# stopped meaning. It drifted to a stale "0 of 30" once; this makes that a
# build failure rather than a discovery.
production_status = documents.get("PRODUCTION_STATUS.md", "")
if not production_status:
    errors.append("PRODUCTION_STATUS.md is missing")
else:
    headline = re.search(r"\*\*Nomad is not production ready\.\*\* (\d+) of 30 "
                         r"production gates are MET\.", production_status)
    if met_count == 30:
        if "not production ready" in production_status:
            errors.append("PRODUCTION_STATUS.md still says not production ready at 30/30")
    elif not headline:
        errors.append("PRODUCTION_STATUS.md must carry the machine-checkable headline")
    elif int(headline.group(1)) != met_count:
        errors.append(f"PRODUCTION_STATUS.md says {headline.group(1)} of 30 MET, "
                      f"registry says {met_count}")
    counts = {status: 0 for status in allowed_statuses}
    for item in criteria:
        counts[item.get("status")] = counts.get(item.get("status"), 0) + 1
    # Mandatory, not best-effort. This used to run only if the sentence
    # matched, so rewording it -- or deleting it -- turned the check off
    # silently, which is the failure mode the check exists to prevent.
    breakdown = re.search(r"registry holds (\d+) PARTIAL, (\d+) NOT_MET\s+and (\d+)\s+BLOCKED",
                          production_status)
    if not breakdown:
        errors.append("PRODUCTION_STATUS.md must carry the machine-checkable breakdown "
                      "sentence (\"registry holds N PARTIAL, N NOT_MET and N BLOCKED\")")
    else:
        stated = tuple(int(value) for value in breakdown.groups())
        actual = (counts["PARTIAL"], counts["NOT_MET"], counts["BLOCKED"])
        if stated != actual:
            errors.append(f"PRODUCTION_STATUS.md breakdown {stated} does not match "
                          f"registry {actual}")

# The execution artifacts CLAUDE.md requires. They are the record of what was
# done and what is still missing, and nothing checked they existed: a deleted
# or renamed one would simply stop being maintained.
EXECUTION_ARTIFACTS = [
    "production/workstreams.json",
    "production/EXECUTION_PLAN.md",
    "production/claude-progress.md",
    "production/CLAIM_TEST_MATRIX.md",
    "production/EVIDENCE_INDEX.md",
    "production/DECISIONS.md",
    "production/EXTERNAL_BLOCKERS.md",
    "production/GOAL.md",
]
artifacts = {}
for relative in EXECUTION_ARTIFACTS:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"missing execution artifact: {relative}")
        continue
    artifacts[relative] = path.read_text(encoding="utf-8")

# workstreams.json drives the same claims as the registry and had no schema
# check at all, so a typo in a status or a requirement that lost its note went
# unnoticed.
workstream_statuses = {"NOT_STARTED", "PARTIAL", "BLOCKED", "MET", "DONE", "VERIFIED"}
workstreams_text = artifacts.get("production/workstreams.json")
if workstreams_text is not None:
    try:
        workstreams = json.loads(workstreams_text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        errors.append(f"invalid workstreams file: {exc}")
        workstreams = {}
    streams = workstreams.get("workstreams", {})
    if not isinstance(streams, dict) or not streams:
        errors.append("workstreams.json must carry a non-empty workstreams object")
        streams = {}
    for letter, stream in sorted(streams.items()):
        if not isinstance(stream, dict):
            errors.append(f"workstream {letter}: must be an object")
            continue
        for field in ("title", "phase", "repos", "requirements"):
            if field not in stream:
                errors.append(f"workstream {letter}: missing {field}")
        seen_ids = set()
        for requirement in stream.get("requirements", []):
            if not isinstance(requirement, dict):
                errors.append(f"workstream {letter}: every requirement must be an object")
                continue
            identifier = requirement.get("id", "")
            if not re.fullmatch(rf"{re.escape(letter)}-\d{{2}}", identifier):
                errors.append(f"workstream {letter}: requirement id {identifier!r} is not "
                              f"{letter}-NN")
            if identifier in seen_ids:
                errors.append(f"workstream {letter}: duplicate requirement id {identifier}")
            seen_ids.add(identifier)
            if not requirement.get("summary"):
                errors.append(f"{identifier}: missing summary")
            status = requirement.get("status")
            if status not in workstream_statuses:
                errors.append(f"{identifier}: unknown workstream status {status!r}")
            # A requirement that is neither untouched nor finished must say
            # where it stands, or "PARTIAL" carries no information.
            if status in {"PARTIAL", "BLOCKED"} and not requirement.get("note"):
                errors.append(f"{identifier}: {status} must carry a note saying what is done "
                              "and what is not")

# Every external blocker cited anywhere must be defined, or a criterion can
# point at a handoff that does not exist.
blockers_text = artifacts.get("production/EXTERNAL_BLOCKERS.md", "")
defined_blockers = set(re.findall(r"^#+ *(EB-\d+)", blockers_text, re.MULTILINE))
defined_blockers |= set(re.findall(r"^\| *(EB-\d+) *\|", blockers_text, re.MULTILINE))
cited = set()
for text in list(documents.values()) + list(artifacts.values()):
    cited |= set(re.findall(r"\bEB-\d+\b", text))
cited |= set(re.findall(r"\bEB-\d+\b", json.dumps(registry)))
if not defined_blockers:
    errors.append("EXTERNAL_BLOCKERS.md defines no EB-N entries, so nothing citing one "
                  "can be checked")
for reference in sorted(cited - defined_blockers):
    errors.append(f"{reference} is cited but not defined in EXTERNAL_BLOCKERS.md")

# A BLOCKED criterion must name the external dependency it waits on.
for item in criteria:
    if isinstance(item, dict) and item.get("status") == "BLOCKED":
        text = json.dumps(item)
        if not re.search(r"\bEB-\d+\b", text):
            errors.append(f"{item.get('id')}: BLOCKED must cite the EB-N it waits on")

for relative, text in documents.items():
    base = (ROOT / relative).parent
    for target in re.findall(r"\[[^\]]+\]\(([^)]+\.md)\)", text):
        if "://" in target:
            continue
        if not (base / target).resolve().is_file():
            errors.append(f"{relative}: broken Markdown link: {target}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
# The evidence index's contents block is generated, so it can go stale in a
# way nothing else here would notice: a section added without regenerating it
# is simply absent from the list, and an absent entry looks like no entry.
if subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "toc.py"), "--check"]
).returncode != 0:
    raise SystemExit(1)
print("Nomad protocol documentation checks passed")
