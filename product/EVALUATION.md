# Evaluate Nomad locally

Use Linux or macOS with Bash, Git, Python 3 and Go 1.25 or newer from
[go.dev](https://go.dev/dl/). No account or API key is required. Windows users
can use WSL; a native Windows launcher or GUI is not included.

```bash
./nomad check
./nomad status
./nomad demo
./nomad reader-demo
```

The demonstrations set `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off` and
`GOSUMDB=off`. Their modules have no external dependencies. The first compilation
can take longer than later runs. Nothing is installed or provisioned by the scripts.

## Verification demonstration

`./nomad demo` runs seven named scenarios from the pinned transparency library:
RFC 6962 roots, valid versus unlogged content, stale-view refusal, transferable
split-view evidence, refusal to resume trust after equivocation, witness agreement
and forged cosignatures. Expected result: seven tests PASS and exit status zero.
Inputs are synthetic; a live third-party release registry is not integrated.

`./nomad test` runs the entire verification module, including signatures,
manifests, identity state and adversarial checks, with the race detector and vet.
The race detector requires a working C compiler on supported Go platforms.

## Reader demonstration

`./nomad reader-demo` copies the committed signed fixture to a temporary cache,
pins its known publisher key, lists the verified document, searches for `nomad`
and exits. The cache is removed on exit. The fixture's embedded publisher key is
not read as a new source of trust: the launcher supplies the pinned key.

The document is titled **Välkommen till Nomad** and ranking is labelled lexical.
This does not exercise a live network, install a model or prove a kernel sandbox.
Linux namespace/trace gates and macOS release instructions remain under `browser/`.

## Broader checks and export

`./nomad test all` builds, vets and race-tests every included Go module, including
both sets of integration components, and checks protocol docs. The runtime may
download declared Go dependencies. Some upstream tests require system tools and
privileges; existing workflows declare those requirements. A skipped local
capability test is not a passed capability gate.

For Docker/network work, follow [the original runtime guide](../LEGACY_README.md).
No cloud provisioning command is part of the new `./nomad` entry point.

`./nomad package` requires a clean commit and writes a source ZIP and SHA-256
sidecar under `dist/`. It includes tracked source, licences and pins, excluding
the Git database, generated caches and toolchain. It is not a signed binary release.
