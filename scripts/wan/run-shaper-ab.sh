#!/usr/bin/env bash
# Run both egress architectures as separate disposable three-region campaigns.
# Diagnostic only: default 60s worlds are shorter than the preregistered 5m
# screening sample. The same v2 decision rule is used, but no screening claim
# is made from this run.
set -uo pipefail

out=${1:?usage: run-shaper-ab.sh OUT_DIR [CAPTURE_SECONDS]}
seconds=${2:-60}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out/coupled" "$out/isolated"

run_mode() {
  local mode=$1 root="$out/$1" run_status=0 verdict_status=0
  echo "=== real WAN diagnostic: $mode ===" >&2
  "$here/run-campaign.sh" "$root" "$seconds" "$mode" || run_status=$?
  if [ "$run_status" -ne 0 ]; then
    echo "$mode infrastructure/capture failed with $run_status" >&2
    return "$run_status"
  fi
  local work
  work=$(cat "$root/last_run")
  echo "$work" > "$root/work_path"
  python3 "$here/wan-verdict.py" "$work/results" 1200 50 \
    > "$root/verdict.json" 2> "$root/verdict.txt" || verdict_status=$?
  cat "$root/verdict.txt" >&2
  echo "$verdict_status" > "$root/verdict_exit"
  # A finding/inconclusive result is valid experimental output, not a broken
  # campaign. Infrastructure errors above still stop the wrapper.
  return 0
}

run_mode coupled || exit $?
run_mode isolated || exit $?

python3 - "$out" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
summary = {"kind": "diagnostic-short-run", "screening": False, "architectures": {}}
for mode in ("coupled", "isolated"):
    verdict = json.loads((root / mode / "verdict.json").read_text())
    summary["architectures"][mode] = verdict
(root / "AB_RESULT.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
