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


# The first four bytes of a libpcap or pcapng file, in both byte orders and
# in the nanosecond variants.
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",   # libpcap, microsecond
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",   # libpcap, nanosecond
    b"\x0a\x0d\x0d\x0a",                           # pcapng
}


def is_pcap(path):
    """Report whether a path holds a binary capture rather than rendered text."""
    with open(path, "rb") as handle:
        return handle.read(4) in PCAP_MAGICS


def read_capture(path, expression="udp"):
    """Parse a capture, whether it is a pcap file or already-rendered text.

    Captures reach this function two ways: as pcap files from tcpdump on a
    real interface, and as text already in tcpdump's format, which is how the
    in-process wire campaign records what it observed. Running tcpdump over
    the second kind fails, and the failure previously surfaced as a rejection
    -- the rule reported that two worlds differed when in fact it had never
    read them. The format identifies itself in its first four bytes, so the
    decision is made on the file rather than on its name.
    """
    if not is_pcap(path):
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            return parse_tcpdump(handle.read())
    result = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", path] + expression.split(),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise CaptureError(
            f"tcpdump could not read {path}: exit {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return parse_tcpdump(result.stdout)
