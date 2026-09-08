#!/usr/bin/env bash
# Generates a CycloneDX-shaped SBOM for the browser core from the Go module
# graph and the pinned component snapshot. It uses only the toolchain and
# files already in the repository, so it produces the same output for the
# same commit on any builder, which is what makes it comparable across the
# two independent builds required for reproducibility.
set -euo pipefail

commit="$(git rev-parse HEAD)"
output="${1:-sbom.cdx.json}"

# go list gives the exact module graph the build actually uses, including
# versions and, where the module cache has them, upstream hashes.
modules="$(go list -deps -json ./... | python3 -c '
import json, sys
seen = {}
decoder = json.JSONDecoder()
data = sys.stdin.read()
index = 0
while index < len(data):
    while index < len(data) and data[index].isspace():
        index += 1
    if index >= len(data):
        break
    obj, offset = decoder.raw_decode(data, index)
    index = offset
    module = obj.get("Module")
    if not module or module.get("Main"):
        continue
    path = module.get("Path")
    if path in seen:
        continue
    seen[path] = {
        "type": "library",
        "name": path,
        "version": module.get("Version") or "(local replace)",
        "purl": "pkg:golang/%s@%s" % (path, module.get("Version") or "local"),
    }
    if module.get("Sum"):
        seen[path]["hashes"] = [{"alg": "SHA-256", "content": module["Sum"]}]
    if module.get("Replace"):
        seen[path]["properties"] = [
            {"name": "nomad:replaced-by", "value": module["Replace"].get("Path", "")}
        ]
print(json.dumps(sorted(seen.values(), key=lambda item: item["name"]), indent=2))
')"

# The vendored Nomad components are pinned by commit in COMPONENTS.lock and
# by content in COMPONENTS.sha256; both belong in the bill of materials.
components="$(python3 - <<'PY'
import json, os
entries = []
if os.path.exists("COMPONENTS.lock"):
    for line in open("COMPONENTS.lock"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entries.append({
            "type": "library",
            "name": parts[0],
            "version": parts[1],
            "purl": "pkg:github/%s@%s" % (parts[0].replace("github.com/", ""), parts[1]),
            "properties": [{"name": "nomad:pinned-branch", "value": parts[2] if len(parts) > 2 else ""}],
        })
print(json.dumps(entries, indent=2))
PY
)"

python3 - "$commit" "$output" <<PY
import json, subprocess, sys
commit, output = sys.argv[1], sys.argv[2]
modules = json.loads('''$modules''')
components = json.loads('''$components''')
document = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "nomad-browser",
            "version": commit,
            "purl": "pkg:github/Jtensetti/Nomad-browser@" + commit,
        },
        "properties": [
            {"name": "nomad:go-version", "value": subprocess.check_output(["go", "version"]).decode().strip()},
        ],
    },
    "components": components + modules,
}
with open(output, "w") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("wrote %s with %d components" % (output, len(document["components"])))
PY
