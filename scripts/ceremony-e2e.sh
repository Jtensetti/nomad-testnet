#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ceremony_root=$(mktemp -d "${TMPDIR:-/tmp}/nomad-ceremony.XXXXXX")

cleanup() {
    if [ -n "${ceremony_root:-}" ] && [ -d "$ceremony_root" ]; then
        rm -rf -- "$ceremony_root"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$ceremony_root/bin" "$ceremony_root/authority" "$ceremony_root/public"
for operator in a b c; do
    mkdir -p "$ceremony_root/operator-$operator"
done

cd "$repo_root"
go build -trimpath -o "$ceremony_root/bin/nomad-operator" ./cmd/nomad-operator
go build -trimpath -o "$ceremony_root/bin/nomad-topology" ./cmd/nomad-topology

for operator in a b c; do
    index=$(printf '%s' "$operator" | tr abc 123)
    "$ceremony_root/bin/nomad-operator" init \
        --id="operator-$operator" \
        --endpoint="127.0.0.1:420$index" \
        --partial-endpoint="http://127.0.0.1:430$index" \
        --secret="$ceremony_root/operator-$operator/node-secrets.json" \
        --enrollment="$ceremony_root/operator-$operator/enrollment.json" \
        >"$ceremony_root/operator-$operator/init.json"
    if grep -Eq 'outbound_keys|inbound_keys' "$ceremony_root/operator-$operator/node-secrets.json"; then
        echo "operator secret contains centrally distributed hop keys" >&2
        exit 1
    fi
done

"$ceremony_root/bin/nomad-topology" authority-init \
    --private="$ceremony_root/authority/authority.key" \
    --public="$ceremony_root/public/authority.pub" \
    >"$ceremony_root/authority/result.json"

"$ceremony_root/bin/nomad-topology" draft \
    --network-id=nomad-ceremony-e2e \
    --epoch=7 \
    --cell-interval-ms=50 \
    --enrollments="$ceremony_root/operator-c/enrollment.json,$ceremony_root/operator-a/enrollment.json,$ceremony_root/operator-b/enrollment.json" \
    --out="$ceremony_root/public/topology-draft.json" \
    >"$ceremony_root/public/draft-result.json"

for operator in a b c; do
    "$ceremony_root/bin/nomad-operator" attest \
        --secret="$ceremony_root/operator-$operator/node-secrets.json" \
        --draft="$ceremony_root/public/topology-draft.json" \
        --out="$ceremony_root/operator-$operator/attestation.json" \
        >"$ceremony_root/operator-$operator/attest-result.json"
done

"$ceremony_root/bin/nomad-topology" finalize \
    --draft="$ceremony_root/public/topology-draft.json" \
    --attestations="$ceremony_root/operator-a/attestation.json,$ceremony_root/operator-b/attestation.json,$ceremony_root/operator-c/attestation.json" \
    --authority-private="$ceremony_root/authority/authority.key" \
    --out="$ceremony_root/public/topology.json" \
    >"$ceremony_root/public/finalize-result.json"

for operator in a b c; do
    "$ceremony_root/bin/nomad-operator" verify \
        --secret="$ceremony_root/operator-$operator/node-secrets.json" \
        --topology="$ceremony_root/public/topology.json" \
        --authority-key="$ceremony_root/public/authority.pub" \
        >"$ceremony_root/operator-$operator/verify-result.json"
done

echo "independent operator topology ceremony passed"
