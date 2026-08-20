package wire

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The rendered format is the seam between this campaign and the preregistered
// analysis harness, which parses it with scripts/capture.py. A change here
// that the parser does not follow would not fail loudly: the parser rejects
// unparsed lines, but only once someone runs it. Asserting the exact bytes
// makes the coupling visible at the point of change, and the committed sample
// below is parsed by the harness's own self-tests.
func TestWriteTcpdumpRendersTheParsedFormat(t *testing.T) {
	base := time.Unix(1712345678, 0).UTC()
	capture := &Capture{Label: "sample"}
	capture.Add(Packet{At: base.Add(50 * time.Millisecond), Size: 1200,
		Source: "10.0.0.2.4200", Destination: "10.0.0.3.4200"})
	// Out of order on purpose: the renderer sorts, because a capture is a
	// record of what an observer saw, not of when the code recorded it.
	capture.Add(Packet{At: base, Size: 1200,
		Source: "10.0.0.2.4200", Destination: "10.0.0.3.4200"})

	var rendered bytes.Buffer
	if err := capture.WriteTcpdump(&rendered); err != nil {
		t.Fatal(err)
	}
	want := "reading from file sample, link-type EN10MB (Ethernet)\n" +
		"1712345678.000000 IP 10.0.0.2.4200 > 10.0.0.3.4200: UDP, length 1200\n" +
		"1712345678.050000 IP 10.0.0.2.4200 > 10.0.0.3.4200: UDP, length 1200\n"
	if rendered.String() != want {
		t.Errorf("rendered capture does not match the parsed format.\ngot:\n%s\nwant:\n%s",
			rendered.String(), want)
	}
}

func TestCaptureStatistics(t *testing.T) {
	base := time.Unix(1712345678, 0).UTC()
	capture := &Capture{Label: "stats"}
	for index, offset := range []time.Duration{0, 20, 40, 60, 2000, 2020} {
		destination := "10.0.0.3.4200"
		if index%2 == 1 {
			destination = "10.0.0.4.4200"
		}
		capture.Add(Packet{At: base.Add(offset * time.Millisecond), Size: 1200,
			Source: "10.0.0.2.4200", Destination: destination})
	}
	gaps := capture.Interarrivals()
	if len(gaps) != 5 || gaps[0] != 20*time.Millisecond || gaps[3] != 1940*time.Millisecond {
		t.Errorf("inter-arrivals are %v", gaps)
	}
	if burst := capture.MaxBurst(time.Second); burst != 4 {
		t.Errorf("max burst in one second is %d, want 4", burst)
	}
	if sizes := capture.Sizes(); len(sizes) != 1 || sizes[0] != 1200 {
		t.Errorf("sizes are %v", sizes)
	}
	if destinations := capture.Destinations(); len(destinations) != 2 {
		t.Errorf("destinations are %v", destinations)
	}
}

// TestSampleIsParsedByTheHarness keeps the committed sample the analysis
// self-tests read in step with what this package actually emits.
func TestSampleIsParsedByTheHarness(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "testdata", "go-rendered-capture.txt")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed sample: %v", err)
	}
	base := time.Unix(1712345678, 0).UTC()
	capture := &Capture{Label: "go-rendered-capture.pcap"}
	for index := 0; index < 8; index++ {
		destination := "10.0.0.3.4200"
		if index%2 == 1 {
			destination = "fd00::3.4200"
		}
		capture.Add(Packet{At: base.Add(time.Duration(index) * 20 * time.Millisecond),
			Size: 1200, Source: "10.0.0.2.4200", Destination: destination})
	}
	var rendered bytes.Buffer
	if err := capture.WriteTcpdump(&rendered); err != nil {
		t.Fatal(err)
	}
	if rendered.String() != string(committed) {
		t.Errorf("%s is stale; regenerate it so the analysis self-tests parse what this "+
			"package emits.\ngot:\n%s\nhave:\n%s", path, rendered.String(), string(committed))
	}
}
