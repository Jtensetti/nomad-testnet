#!/usr/bin/env bash
# Emits SLSA-shaped in-toto provenance binding the built artifact to the
# exact commit, builder, toolchain and dependency state that produced it.
#
# This attests; it does not sign. Signing requires a key this repository
# must never hold. In CI the document is signed by the release workflow's
# protected identity; locally it is unsigned and says so, so an unsigned
# provenance can never be mistaken for a signed one.
set -euo pipefail

artifact="${1:?usage: generate-provenance.sh <artifact> [output]}"
output="${2:-provenance.intoto.jsonl}"

commit="$(git rev-parse HEAD)"
digest="$(sha256sum "$artifact" | cut -d' ' -f1)"
sbom_digest=""
if [ -f sbom.cdx.json ]; then
  sbom_digest="$(sha256sum sbom.cdx.json | cut -d' ' -f1)"
fi

python3 - "$artifact" "$digest" "$commit" "$sbom_digest" "$output" <<'PY'
import json, os, subprocess, sys

artifact, digest, commit, sbom_digest, output = sys.argv[1:6]
in_ci = os.environ.get("GITHUB_ACTIONS") == "true"

statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": os.path.basename(artifact), "digest": {"sha256": digest}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://nomad.invalid/buildtypes/go-release/v1",
            "externalParameters": {
                "repository": "https://github.com/Jtensetti/Nomad-browser",
                "ref": os.environ.get("GITHUB_REF", subprocess.check_output(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"]).decode().strip()),
            },
            "resolvedDependencies": [
                {
                    "uri": "git+https://github.com/Jtensetti/Nomad-browser",
                    "digest": {"gitCommit": commit},
                }
            ],
            "internalParameters": {
                "goVersion": subprocess.check_output(["go", "version"]).decode().strip(),
                "GOOS": subprocess.check_output(["go", "env", "GOOS"]).decode().strip(),
                "GOARCH": subprocess.check_output(["go", "env", "GOARCH"]).decode().strip(),
                "CGO_ENABLED": subprocess.check_output(["go", "env", "CGO_ENABLED"]).decode().strip(),
            },
        },
        "runDetails": {
            "builder": {
                "id": os.environ.get(
                    "GITHUB_WORKFLOW_REF",
                    "https://nomad.invalid/builders/local-unsigned",
                ),
            },
            "metadata": {
                "invocationId": os.environ.get("GITHUB_RUN_ID", "local"),
            },
        },
    },
}
if sbom_digest:
    statement["predicate"]["buildDefinition"]["resolvedDependencies"].append(
        {"name": "sbom.cdx.json", "digest": {"sha256": sbom_digest}}
    )
if not in_ci:
    statement["predicate"]["runDetails"]["metadata"]["nomadUnsigned"] = (
        "Generated outside CI. This provenance is NOT signed and must not be "
        "published as release evidence."
    )

with open(output, "w") as handle:
    handle.write(json.dumps(statement, sort_keys=True) + "\n")
print("wrote %s for %s (sha256:%s)" % (output, artifact, digest[:16]))
PY
