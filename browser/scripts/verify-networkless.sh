#!/usr/bin/env bash
#
# Proves the Linux client's networkless claim in the strongest form available:
# it runs in a network namespace that has no route anywhere, and the namespace
# is shown to be empty by a probe that succeeds outside it and fails inside.
#
# The control matters more than the assertion. "No connection was made" is what
# a host with no network says too, and a gate that passes for that reason
# reports the same thing whether the sandbox works or not. So this binds a
# listener on the host, proves the probe reaches it from outside the namespace,
# and only then requires the probe to fail inside.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Two ways to get an empty network namespace. They differ only in how it is
# obtained, never in what it proves: either way the process lands in a
# namespace whose only interface is a down loopback.
#
# Unprivileged user namespaces are restricted on Ubuntu 24.04 by an AppArmor
# rule, which is why GitHub's runners need the second one.
kind="${NOMAD_NETNS_KIND:-}"
if [ -z "$kind" ]; then
  if unshare --user --map-root-user --net true 2>/dev/null; then
    kind=userns
  elif sudo -n unshare --net true 2>/dev/null; then
    kind=sudo
  fi
fi

in_namespace() {
  case "$kind" in
    userns) unshare --user --map-root-user --net "$@" ;;
    sudo) sudo -n unshare --net "$@" ;;
    *) echo "verify-networkless: no namespace mechanism selected" >&2; return 2 ;;
  esac
}

case "$kind" in
  userns|sudo) echo "verify-networkless: using the $kind network namespace mechanism" ;;
  *)
    echo "verify-networkless: no way to obtain an empty network namespace here:" >&2
    echo "verify-networkless: unprivileged user namespaces are unavailable and" >&2
    echo "verify-networkless: passwordless sudo is not available either." >&2
    echo "verify-networkless: this gate cannot run, which is not the same as passing" >&2
    exit 2 ;;
esac

echo "== building the client =="
go build -o "$work/nomad-browser" "$root/cmd/nomad-browser"

echo "== materializing the shared corpus =="
mkdir -p "$work/objects"
python3 - "$root" "$work/objects" <<'PY'
import json, pathlib, sys
root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
catalog = json.loads((root / "macos/Sources/NomadBrowser/Resources/demo-catalog.json").read_text())
for index, envelope in enumerate(catalog):
    (out / f"object-{index}.nomadobject").write_text(json.dumps(envelope))
print(f"wrote {len(catalog)} objects")
PY

# A listener on the host, so the probe has something real to reach.
python3 - "$work" <<'PY' &
import pathlib, socket, sys, time
work = pathlib.Path(sys.argv[1])
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(8)
(work / "port").write_text(str(listener.getsockname()[1]))
deadline = time.time() + 60
while time.time() < deadline:
    listener.settimeout(1)
    try:
        connection, _ = listener.accept()
        connection.close()
    except socket.timeout:
        continue
PY
listener_pid=$!
trap 'kill "$listener_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

for _ in $(seq 1 50); do
  [ -s "$work/port" ] && break
  sleep 0.1
done
port="$(cat "$work/port")"
echo "== host listener on 127.0.0.1:$port =="

probe='
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
    s.close()
    print("REACHED")
except OSError as error:
    print("UNREACHABLE", type(error).__name__, error)
'

echo "== control: the probe must reach the listener outside the namespace =="
outside="$(python3 -c "$probe" "$port")"
echo "  $outside"
case "$outside" in
  REACHED*) ;;
  *) echo "verify-networkless: the probe cannot reach a listener on this host, so a
failure inside the namespace would prove nothing about the namespace" >&2
     exit 1 ;;
esac

# Under the sudo mechanism the inside probe runs as root while the control ran
# as an ordinary user. That asymmetry only strengthens the result: the more
# privileged process is the one that cannot reach the listener.
echo "== the same probe must fail inside the namespace =="
inside="$(in_namespace python3 -c "$probe" "$port")"
echo "  $inside"
case "$inside" in
  UNREACHABLE*) ;;
  *) echo "verify-networkless: the sandbox namespace can reach the host network" >&2
     exit 1 ;;
esac

echo "== the client must still work inside that namespace =="
output="$(printf 'list\nsearch nomad\nquit\n' | in_namespace \
  "$work/nomad-browser" -objects "$work/objects" \
  -trust 'SsX0q+oi8C1+v0yTSrltfxYkztmjrdJNE/gN7XN0jEk=')"
echo "$output" | sed 's/^/  /'

case "$output" in
  *"3 verified objects, 3 searchable"*) ;;
  *) echo "verify-networkless: the client did not load the corpus in the sandbox" >&2
     exit 1 ;;
esac
case "$output" in
  *"lexical ranking"*) ;;
  *) echo "verify-networkless: the ranking did not name its provenance" >&2
     exit 1 ;;
esac

echo "verify-networkless: OK -- the client reads and ranks verified objects in a"
echo "namespace where a probe that works on this host cannot reach anything."
