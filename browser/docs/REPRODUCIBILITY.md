# Reproducing a Nomad Browser release build

Reproducibility has two halves and they need different things.

**Determinism** — the same source produces the same bytes — is something one
builder can establish alone, and `scripts/check-reproducible.sh` establishes it
on every push. It builds the Go release binaries twice from two copies of the
source at deliberately different path lengths and requires the results to be
byte-identical. Building twice in one directory would prove almost nothing; two
paths is what shows the source path does not reach the binary, which `-trimpath`
is supposed to guarantee and which nothing had checked. Removing `-trimpath`
makes the check fail, so it is not passing vacuously.

**Independence** — a second builder, on their own machine, gets the same bytes —
is not something this project can establish about itself. It needs someone else.
See H-03 and EB-2.

## The trap a second builder will hit first

By default Go stamps VCS information into the binary: the commit hash, and
whether the tree was dirty. So a builder working from a git checkout and a
builder working from an exported tarball produce **different bytes from
identical source**.

That is a difference in provenance metadata rather than in the program, but a
second builder who hits it without knowing why will reasonably conclude the
build is not reproducible. It cost an afternoon here before being recognised.

Either both builders stamp, from the same commit with a clean tree, or neither
does. `check-reproducible.sh` passes `-buildvcs=false` because it is comparing
two copies that have no `.git` at all; release builds should stamp, because the
stamp is useful provenance.

## The procedure

To reproduce a release binary and compare it against a published digest:

```
git clone <repo> nomad-browser && cd nomad-browser
git checkout <the release commit>
git status --porcelain      # must be empty: a dirty tree changes the stamp
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> \
  go build -trimpath -ldflags='-s -w' -o nomad-browser-verify ./cmd/nomad-browser-verify
sha256sum nomad-browser-verify
```

Use the same Go minor version as the release. The toolchain is part of the
input: a different Go version legitimately produces different bytes, and the CI
pin (`1.25.x`) is what the published digest was built with.

If your digest differs, `scripts/compare-builds.sh <dir-a> <dir-b>` reports
*which* artifacts differ rather than only that they do.

## What is not covered

The macOS `.dmg` is not covered by the determinism check. It is produced by
`macos/scripts/build_dmg.sh`, which invokes `codesign` and `hdiutil`; both embed
timestamps, and an ad-hoc or Developer ID signature is not reproducible by
construction. Reproducibility for the shipped installer would have to compare
the unsigned payload rather than the image, and that is not implemented.
