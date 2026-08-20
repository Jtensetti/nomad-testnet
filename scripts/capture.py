"""Shared, fail-closed reader for tcpdump captures.

Both the cadence gate and the two-world analysis depend on counting every
packet in a capture. A parser that skips lines it does not recognise is not
merely incomplete: the packets an unfamiliar link-layer prefix hides are
exactly the ones a difference between two worlds would appear in, so quiet
skipping makes captures converge and reports a pass. Anything unparsed is
therefore an error, never a skip.
"""

import re
import subprocess

# The link-layer prefix between the timestamp and the IP token varies with the
# capture interface: absent on a raw IP link, "vlan 7, p 0," on a tagged one,
# an Ethertype on some others. It is matched permissively and the packet body
# strictly, so a new prefix does not drop packets and a malformed body does
# not parse as one.
LINE = re.compile(
    r"^(?P<time>\d+\.\d+)\s+.*?\bIP6?\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s+UDP, length (?P<size>\d+)$"
)
PREAMBLE = re.compile(r"^(reading from file|tcpdump:|listening on|\d+ packets? )")


class CaptureError(Exception):
    """A capture could not be read in full."""


def parse_tcpdump(text):
    """Return (timestamps, sizes, destinations, sources) for every packet line."""
    times, sizes, destinations, sources = [], [], [], []
    unparsed = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or PREAMBLE.match(line):
            continue
        match = LINE.match(line)
        if not match:
            unparsed.append(line)
            continue
        times.append(float(match.group("time")))
        sizes.append(int(match.group("size")))
        destinations.append(match.group("dst"))
        sources.append(match.group("src"))
    if unparsed:
        sample = "\n".join(unparsed[:5])
        raise CaptureError(
            f"{len(unparsed)} capture line(s) did not parse; first:\n{sample}"
        )
    return times, sizes, destinations, sources


def read_capture(path, expression="udp"):
    """Run tcpdump over a capture file and parse all of its output."""
    result = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", path] + expression.split(),
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return parse_tcpdump(result.stdout)
