#!/usr/bin/env bash
# Scan the given module directories for reachable vulnerabilities.
#
# Two things this deliberately does not do.
#
# It does not install govulncheck at @latest. CI runs this tool over the source
# it is gating, so the tool is part of the trusted set, and @latest is whichever
# build the proxy served that minute with nothing recording what ran. Pinning
# does not stale the findings: only the fetching code is fixed, not the data.
#
# It does not treat an unreachable database as a pass. govulncheck exits
# non-zero both for "found vulnerabilities" and "could not fetch the list to
# compare against", and collapsing those would let the gate report success on
# the one day it is worth having. A fetch failure is retried; if it still
# cannot read the database the run fails saying no scan happened.

set -euo pipefail

VERSION="${GOVULNCHECK_VERSION:-v1.7.0}"
ATTEMPTS="${GOVULNCHECK_ATTEMPTS:-4}"
# Overridden to zero by the test, which has no reason to wait for a stub.
DELAY="${GOVULNCHECK_DELAY:-5}"

install_tool() {
  local attempt=1 delay="$DELAY"
  while :; do
    if go install "golang.org/x/vuln/cmd/govulncheck@${VERSION}"; then
      return 0
    fi
    if test "$attempt" -ge "$ATTEMPTS"; then
      echo "could not install govulncheck ${VERSION} after ${ATTEMPTS} attempts" >&2
      return 1
    fi
    echo "install failed, retrying in ${delay}s (attempt ${attempt}/${ATTEMPTS})" >&2
    if test "$delay" -gt 0; then sleep "$delay"; fi
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

scan() {
  local directory="$1"
  local attempt=1 delay="$DELAY"
  local output status
  while :; do
    set +e
    output="$(cd "$directory" && "$GOVULNCHECK" ./... 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$output"
    if test "$status" -eq 0; then
      return 0
    fi
    # Anchored on govulncheck's own error prefix rather than the phrase alone:
    # stdout and stderr are merged here, so a finding whose text happened to
    # contain those words would otherwise be retried and then reported as an
    # unreachable database -- a failure either way, but the wrong one.
    #
    # Anything that is not that error is a finding, or a build that does not
    # compile, and is never retried: re-running a scan because it found
    # something is how a finding gets lost.
    if ! printf '%s' "$output" | grep -q '^govulncheck: fetching vulnerabilities'; then
      return "$status"
    fi
    if test "$attempt" -ge "$ATTEMPTS"; then
      echo "the vulnerability database was unreachable after ${ATTEMPTS} attempts" >&2
      echo "nothing was scanned; this run fails for that, not for a finding" >&2
      return 1
    fi
    echo "vulnerability database unreachable, retrying in ${delay}s (attempt ${attempt}/${ATTEMPTS})" >&2
    if test "$delay" -gt 0; then sleep "$delay"; fi
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

install_tool
GOVULNCHECK="${GOVULNCHECK_BINARY:-$(go env GOPATH)/bin/govulncheck}"

if test "$#" -eq 0; then
  set -- .
fi
for directory in "$@"; do
  echo "== ${directory} =="
  scan "$directory"
done
