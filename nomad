#!/usr/bin/env bash
# Local entry point for the Nomad evaluation kit. No services are provisioned.
set -euo pipefail
NOMAD_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$NOMAD_ROOT"

need_go() {
  command -v go >/dev/null || {
    echo 'Install Go 1.25 or newer, then run this command again: https://go.dev/dl/' >&2
    exit 2
  }
  # Keep this checkout isolated from a caller's workspace and prevent an
  # implicit toolchain download. Demo modules have no remote dependencies.
  export GOWORK=off GOTOOLCHAIN=local
}

case "${1:-help}" in
  status)
    python3 scripts/check-package.py --status
    ;;
  check)
    python3 scripts/check-package.py
    ;;
  demo)
    need_go
    export GOPROXY=off GOSUMDB=off
    echo 'Nomad Verify — local verification demonstration'
    echo 'Exercises the real library: valid history, tampering, stale views and conflicting signed histories.'
    echo 'No account, API key, cloud service or external connection is used by this demonstration.'
    cd sdk/nomad-local-reconstruction
    go test -count=1 -v ./site/transparency -run '^(TestRootsMatchRFC6962|TestADescriptorOutsideTheLogCannotBeAccepted|TestAPartitionedReaderGoesStaleAndStopsAccepting|TestAForkedLogIsCaughtAndTheEvidenceIsTransferable|TestEquivocationEndsTheReadersRelationshipWithTheLog|TestALogCannotServeTwoReadersTwoHistoriesOnceWitnessesCosign|TestAForgedCosignatureFromATrustedWitnessIsAHardFailure)$'
    ;;
  reader-demo)
    need_go
    export GOPROXY=off GOSUMDB=off
    NOMAD_DEMO_DIR="$(mktemp -d)"
    trap 'rm -rf -- "$NOMAD_DEMO_DIR"' EXIT
    cp deploy/fixture/demo.nomadobject "$NOMAD_DEMO_DIR/demo.nomadobject"
    echo 'Nomad Reader — signed local content and local search'
    echo 'The publisher key below is pinned for this public fixture only.'
    cd browser
    printf 'list\nsearch nomad\nquit\n' | go run ./cmd/nomad-browser \
      -objects "$NOMAD_DEMO_DIR" -reload=0 \
      -trust 'SsX0q+oi8C1+v0yTSrltfxYkztmjrdJNE/gN7XN0jEk='
    ;;
  test)
    need_go
    case "${2:-verify}" in
      verify)
        export GOPROXY=off GOSUMDB=off
        cd sdk/nomad-local-reconstruction
        go test -race -count=1 ./...
        go vet ./...
        ;;
      all)
        python3 scripts/check-package.py
        # This broader check may download the runtime's declared Go modules.
        # It uses local compute; it does not deploy a network or buy services.
        for NOMAD_MODULE in . browser sdk/* components/* browser/components/*; do
          test -f "$NOMAD_MODULE/go.mod" || continue
          echo "Checking $NOMAD_MODULE"
          (cd "$NOMAD_MODULE" && go build ./... && go vet ./... && go test -race -count=1 ./...)
        done
        python3 protocol/scripts/check_docs.py
        ;;
      *) echo 'Usage: ./nomad test [verify|all]' >&2; exit 2 ;;
    esac
    ;;
  package)
    python3 scripts/package-evaluation.py
    ;;
  help|-h|--help)
    cat <<'HELP'
Nomad evaluation kit

  ./nomad status        Read the actual production readiness registry
  ./nomad demo          Exercise the verification library locally (Go 1.25+)
  ./nomad reader-demo   Open and search a signed local fixture (Go 1.25+)
  ./nomad check         Verify the pinned source snapshots (Python 3)
  ./nomad test          Run the verification module's tests and vet
  ./nomad test all      Build, vet and test every included Go module
  ./nomad package       Produce a source handover ZIP from a clean git commit

Start: README.md     Buyer brief: product/BUYER_BRIEF.md
Scope: product/STATUS.md     Terms: COMPONENT_LICENSES.md
HELP
    ;;
  *) echo "Unknown command: $1. Run ./nomad help." >&2; exit 2 ;;
esac
