#!/usr/bin/env bash
# Builds the Go release binaries twice, from two different source paths, and
# requires the results to be byte-identical.
#
# This is the half of reproducibility one builder can establish alone:
# determinism. It cannot establish the other half -- that a *second, independent*
# builder gets the same bytes -- and does not claim to. See H-03 and EB-2.
#
# The two-path part is the point. Building twice in one directory proves almost
# nothing; building from two paths is what shows the source path does not reach
# the binary, which -trimpath is supposed to guarantee and which nothing here
# had checked.
#
# -buildvcs=false is deliberate and is the trap this script exists to document.
# By default Go stamps the commit hash and dirty flag into the binary, so a
# builder working from a git checkout and one working from an exported tarball
# get different bytes from the same source. That is a difference in provenance
# metadata, not in the program, but a second builder who hits it and does not
# know why will reasonably conclude the build is not reproducible. Release
# builds should stamp; comparisons between builders must either both stamp from
# the same commit or both omit it.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

# Refuse to run against anything that is not this repository. The root is
# derived from the script's own location, so a copy of this script placed
# elsewhere resolves it somewhere else -- and since the next thing that happens
# is `tar -cf - .` over that root, "somewhere else" can be the filesystem. That
# is not hypothetical: copying this script to /tmp to mutation-test it did
# exactly that and filled the disk.
if ! grep -qx 'module github.com/Jtensetti/nomad-browser' "$repo_root/go.mod" 2>/dev/null; then
    echo "refusing to run: $repo_root is not the nomad-browser repository" >&2
    exit 2
fi
targets="${NOMAD_REPRO_TARGETS:-darwin/arm64 darwin/amd64 linux/amd64}"
commands="${NOMAD_REPRO_COMMANDS:-nomad-browser-verify}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Two copies at deliberately different path lengths: a path that leaked would
# most likely leak as an embedded string, and equal-length paths could mask it.
left="$work/a"
right="$work/bbbbbbbbbbbbbbbbbbbb"
for copy in "$left" "$right"; do
    mkdir -p "$copy"
    tar -C "$repo_root" --exclude=.git -cf - . | tar -C "$copy" -xf -
done

status=0
for target in $targets; do
    for command in $commands; do
        for copy in "$left" "$right"; do
            (cd "$copy" && CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" \
                go build -trimpath -buildvcs=false -ldflags='-s -w' \
                -o "$copy/out-$command" "./cmd/$command")
        done
        if cmp -s "$left/out-$command" "$right/out-$command"; then
            printf 'IDENTICAL %-14s %-24s %s\n' "$target" "$command" \
                "$(sha256sum "$left/out-$command" | cut -c1-16)"
        else
            printf 'DIFFERS   %-14s %-24s %s vs %s\n' "$target" "$command" \
                "$(sha256sum "$left/out-$command" | cut -c1-16)" \
                "$(sha256sum "$right/out-$command" | cut -c1-16)"
            status=1
        fi
    done
done

if [ "$status" -ne 0 ]; then
    echo "the build is not deterministic: the source path reaches the binary" >&2
fi
exit "$status"
