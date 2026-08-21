#!/usr/bin/env bash
# Preregistered baseline screening: 30 independent captures per world, 5 min.
# Each disposable campaign yields idle1, idle2 and active on each of the three
# regions. A FINDING stops immediately for investigation; INCONCLUSIVE is kept
# as data and the next independent campaign may run, but never converted to a
# pass. Existing completed iterations are not rerun on resume.
set -uo pipefail

root=${1:?usage: run-screening.sh OUT_DIR EGRESS_MODE [START_INDEX]}
mode=${2:?egress mode required}
start=${3:-1}
case "$mode" in coupled|isolated) ;; *) echo "mode must be coupled or isolated" >&2; exit 2;; esac
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$root/runs"
manifest="$root/SCREENING_MANIFEST.jsonl"

for index in $(seq "$start" 30); do
  runroot="$root/runs/$(printf '%02d' "$index")"
  if [ -s "$runroot/verdict.json" ]; then
    echo "screening $index/30 already complete; preserving immutable sample" >&2
    continue
  fi
  mkdir -p "$runroot"
  echo "=== screening sample $index/30, mode=$mode, 300s/world ===" >&2
  status=0
  "$here/run-campaign.sh" "$runroot" 300 "$mode" || status=$?
  if [ "$status" -ne 0 ]; then
    printf '{"sample":%d,"mode":"%s","campaign_status":"BROKEN","exit":%d}\n' "$index" "$mode" "$status" >> "$manifest"
    echo "campaign infrastructure/capture failed; screening stops" >&2
    exit "$status"
  fi
  work=$(cat "$runroot/last_run")
  verdict_status=0
  python3 "$here/wan-verdict.py" "$work/results" 1200 50 > "$runroot/verdict.json" 2> "$runroot/verdict.txt" || verdict_status=$?
  sha256sum "$work"/results/*.pcap > "$runroot/PCAP_SHA256SUMS"
  printf '{"sample":%d,"mode":"%s","campaign_status":"COMPLETE","verdict_exit":%d,"work":"%s"}\n' "$index" "$mode" "$verdict_status" "$work" >> "$manifest"
  cat "$runroot/verdict.txt" >&2
  case "$verdict_status" in
    0)
      ;;
    1)
      echo "FINDING at sample $index: stop, explain, fix, then preregister any new experiment before rerun" >&2
      exit 1
      ;;
    2)
      echo "sample $index is INCONCLUSIVE; preserving it and continuing with the next independent sample" >&2
      ;;
    *)
      echo "unexpected verdict exit $verdict_status; screening instrument is broken" >&2
      exit 2
      ;;
  esac
done

python3 - "$root" "$mode" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]); mode = sys.argv[2]
records=[]
for p in sorted((root/'runs').glob('*/verdict.json')):
    records.append({'sample': int(p.parent.name), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'verdict': json.loads(p.read_text())})
summary={'kind':'preregistered-screening-v2','mode':mode,'required_samples_per_world':30,'capture_seconds':300,'completed_campaigns':len(records),'records':records}
(root/'SCREENING_RESULT.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps({'completed_campaigns':len(records),'mode':mode},sort_keys=True))
if len(records) != 30:
    raise SystemExit(2)
PY
