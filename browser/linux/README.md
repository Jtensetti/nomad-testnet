# Nomad browser on Linux

The Nomad browser core is portable Go and has always built here; what this
directory adds is a client and the enforcement that makes its central claim
checkable.

## What the client is

`cmd/nomad-browser` reads and ranks cryptographically verified local objects.
It has no address field, no web engine, no resolver and no socket. Commands
are read from standard input, so the same code path serves a person typing and
a test piping.

```
nomad-browser -objects ~/.local/share/nomad/objects -trust <base64 publisher key>
```

`-trust` is required. A client with nothing anchored would have to choose
between rendering everything in the directory and rendering nothing, and both
are worse than saying which key is missing.

## Why Linux is the stronger platform for the claim

The macOS client is denied the network by App Sandbox entitlement: the system
refuses the operation. On Linux the client runs in a network namespace that
contains no interface to refuse, so there is nothing to reach and nothing to
enforce against.

Three layers, weakest to strongest:

1. `egress.Policy` refuses every network capability by construction. This is
   the program declining to act.
2. The client's dependency graph contains no networking package at all --
   `TestTheLinuxClientLinksNoNetworkingPackage` asserts it over the full
   transitive graph. There is no socket API linked into the binary.
3. `PrivateNetwork=yes` (systemd) or `--unshare-net` (bubblewrap) gives the
   process an empty network namespace. This is the kernel, and it holds
   regardless of what the binary contains.

## Verifying it

`scripts/verify-networkless.sh` is the gate, and it runs in CI.

It does not merely check that no connection was made -- a host with no network
says that too, and a gate that passes for that reason reports the same thing
whether the sandbox works or not. Instead it binds a listener on the host,
requires a probe to reach it from outside the namespace, and only then requires
the same probe to fail inside. Then it runs the client in that namespace and
requires it to load and rank the corpus.

The namespace is obtained one of two ways: an unprivileged user namespace, or
`sudo unshare --net` where that is restricted, as it is on Ubuntu 24.04 and so
on GitHub's runners. The two differ only in how the namespace is obtained, not
in what it proves. Under the second, the probe inside the namespace runs as
root while the control ran as an ordinary user, which strengthens the result
rather than weakening it: the more privileged process is the one that cannot
reach the listener.

If neither mechanism is available the gate exits 2, distinctly from both pass
and fail. A check that cannot run must not report what a check that passed
reports.

## Running it

With systemd, install `nomad-browser.service` to `~/.config/systemd/user/`,
set `NOMAD_TRUST`, and `systemctl --user start nomad-browser`.

Without systemd, use `run-sandboxed.sh`, which prefers bubblewrap and falls
back to `unshare`. If neither is available it refuses to run rather than
starting outside the sandbox: running anyway would leave the claim resting on
the program alone, which is not what the script promises.

## Removing it

The client writes nothing. It reads the object directory, holds its index in
memory, and creates no file, directory or temporary anywhere -- asserted by
`TestTheLinuxClientWritesNothingToDisk`, which walks the call graph of every
package the client links and fails on any standard-library call that creates
or modifies a path. That test carries its own control: the detector is pointed
at a package that does write and must find it, so a detector that listed
nothing could not pass by finding nothing.

So removing the client is removing the binary and, if you installed it, the
unit file:

    rm -f "$(command -v nomad-browser)" ~/.config/systemd/user/nomad-browser.service

The object directory is yours: it holds the verified objects a materializer
put there, not anything this client produced, and nothing here deletes it for
you.

What that leaves is what the operating system keeps regardless -- shell
history naming your `-trust` key, a core dump if the process crashed with
`kernel.core_pattern` set, and the systemd journal's record that the unit ran.
None of those is the client writing; all of them are outside anything it
controls. The macOS side documents the equivalent in `docs/DATA_RETENTION.md`,
and the same reasoning applies: what an operating system retains is answered
honestly rather than claimed away.

If a future build persists an index -- which would be a reasonable thing to
want -- this section, that test and `run-sandboxed.sh`'s read-only bind of the
object directory all change together. The test exists so that is a decision
rather than a discovery.
