#!/usr/bin/env bash
set -euo pipefail

uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

if [[ -n "${SCW_PROJECT_ID:-}" ]]; then
  [[ "$SCW_PROJECT_ID" =~ $uuid_re ]] || {
    echo 'SCW_PROJECT_ID is present but is not a UUID' >&2
    exit 1
  }
  printf '%s\n' "$SCW_PROJECT_ID"
  exit 0
fi

: "${SCW_SECRET_KEY:?SCW_SECRET_KEY is required}"

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
candidates="$work_dir/candidates"
: > "$candidates"

# IAM self-inspection is useful when permitted, but a narrowly scoped Instance
# key may correctly receive 401/403 here. That must not turn into a credential
# failure: the same key can still be valid for the WAN resources we need.
if [[ -n "${SCW_ACCESS_KEY:-}" ]]; then
  key_json="$work_dir/api-key.json"
  if curl --fail --silent --show-error --max-time 15 \
    -H "X-Auth-Token: $SCW_SECRET_KEY" \
    -H 'Accept: application/json' \
    "https://api.scaleway.com/iam/v1alpha1/api-keys/$SCW_ACCESS_KEY" \
    -o "$key_json" 2>/dev/null; then
    python3 - "$key_json" >> "$candidates" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    value = json.load(handle).get('default_project_id') or ''
if value:
    print(value)
PY
  fi
fi

# Fallback for Instance-scoped API keys: inspect only top-level project fields
# on resources visible in the three intended zones. We deliberately do not
# recurse into public image/snapshot metadata, because those belong to Scaleway
# projects and are not an account-scope signal.
for zone in fr-par-1 nl-ams-1 pl-waw-2; do
  for resource in servers ips security_groups; do
    json="$work_dir/${zone}-${resource}.json"
    if ! curl --fail --silent --show-error --max-time 15 \
      -H "X-Auth-Token: $SCW_SECRET_KEY" \
      -H 'Accept: application/json' \
      "https://api.scaleway.com/instance/v1/zones/$zone/$resource" \
      -o "$json" 2>/dev/null; then
      continue
    fi
    python3 - "$json" "$resource" >> "$candidates" <<'PY'
import json, sys
path, collection = sys.argv[1:]
with open(path, encoding='utf-8') as handle:
    data = json.load(handle)
items = data.get(collection) or []
if not isinstance(items, list):
    raise SystemExit(0)
for item in items:
    if not isinstance(item, dict):
        continue
    value = item.get('project') or item.get('project_id') or ''
    if isinstance(value, str) and value:
        print(value)
PY
  done
done

mapfile -t unique < <(grep -E "$uuid_re" "$candidates" | sort -u)
case ${#unique[@]} in
  1)
    printf '%s\n' "${unique[0]}"
    ;;
  0)
    echo 'No Project ID could be resolved with this API key. The account may be empty or the key may not have project-metadata visibility. Add SCW_PROJECT_ID as a GitHub Actions repository secret and rerun.' >&2
    exit 3
    ;;
  *)
    echo "Multiple Project IDs are visible to this key (${#unique[@]}). Refusing to guess which Project should own the WAN lab; add SCW_PROJECT_ID as a repository secret." >&2
    exit 4
    ;;
esac
