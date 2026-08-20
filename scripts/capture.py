"""Shared, fail-closed reader for tcpdump captures.

Both the cadence gate and the two-world analysis depend on counting every
packet in a capture. A parser that skips lines it does not recognise is not
merely incomplete: the packets an unfamiliar link-layer prefix hides are
exactly the ones a difference between two worlds would appear in, so quiet
skipping makes captures converge and reports a pass. Anything unparsed is
therefore an error, never a skip.

Two evidence forms are accepted deliberately:

* binary pcap/pcapng from a real capture interface, decoded by ``tcpdump -r``;
* UTF-8 tcpdump text emitted by ``live/wire.Capture.WriteTcpdump`` in the Go
  campaign. That writer exists specifically so the same decision rule can
  judge the in-process campaign and later real pcaps.

The format is detected from the capture bytes, never from the filename.
"""

from pathlib import Path
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

# Classic pcap has four byte-order/timestamp-resolution magic values. Pcapng
# starts with the section-header block magic. Inspecting magic rather than the
# extension prevents a text fixture called .pcap (or a binary file called
# .txt) from silently taking the wrong parser path.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


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


def _is_binary_capture(prefix):
    return len(prefix) >= 4 and prefix[:4] in PCAP_MAGICS


def read_capture(path, expression="udp"):
    """Read every packet from a binary pcap/pcapng or Go-rendered tcpdump text."""
    capture_path = Path(path)
    try:
        encoded = capture_path.read_bytes()
    except OSError as error:
        raise CaptureError(f"capture could not be opened: {error}") from error

    if _is_binary_capture(encoded[:4]):
        try:
            result = subprocess.run(
                ["tcpdump", "-tt", "-nn", "-r", str(capture_path)] + expression.split(),
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise CaptureError(f"tcpdump could not read binary capture: {error}") from error
        return parse_tcpdump(result.stdout)

    # Go's wire campaign writes already-filtered UDP observations in tcpdump's
    # text form. Applying an arbitrary BPF expression to text would require a
    # second, subtly different filter implementation, so fail closed if a
    # caller asks for anything beyond the campaign's only supported filter.
    if expression.strip() != "udp":
        raise CaptureError(
            "rendered text captures support only the default 'udp' expression"
        )
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaptureError(
            "capture is neither recognized pcap/pcapng nor UTF-8 tcpdump text"
        ) from error
    return parse_tcpdump(text)
