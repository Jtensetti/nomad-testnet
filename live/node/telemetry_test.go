package node

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
)

// PROD-27 asks that operational output cannot contain queries, basins, object
// choices, plaintext, stable cross-epoch identifiers or secret keys.
//
// A schema assertion alone would not establish that. This runs the production
// node with secrets whose exact bytes are known, then scans everything the
// process wrote -- every file under its state directory, not just the health
// file it meant to write -- for those bytes in every encoding a process might
// render them in. It is a direct test rather than a heuristic about what looks
// sensitive.
func TestTheNodeWritesNoSecretAnywhereUnderItsStateDirectory(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)

	scanner := telemetry.NewScanner()
	// The operator's own signing key: the single most damaging thing that
	// could reach a log.
	self := network.Document.Operators[0]
	scanner.Register("operator identity private key", identities[self.ID])
	// The pairwise hop keys the node holds.
	scanner.Register("outbound hop key", []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	// A publication fragment travelling through the relay queue, standing in
	// for any object content.
	var fragment [hop.CiphertextSize]byte
	if _, err := rand.Read(fragment[:]); err != nil {
		t.Fatal(err)
	}
	scanner.Register("relayed fragment", fragment[:])
	// A reader's query and basin, which never legitimately reach this process
	// at all and must certainly not reach its output.
	scanner.RegisterString("reader query", "how-do-i-contact-a-journalist-safely")
	scanner.RegisterString("semantic basin", "basin-0xdeadbeefcafe")

	// Self-check the instrument before trusting a clean result: a scan that
	// finds nothing means nothing unless it can find these exact secrets when
	// they are present. Asserting a pattern count would be arbitrary; this
	// asserts coverage of every labelled secret this test cares about.
	rehearsal := strings.Join([]string{
		toHexForTest(identities[self.ID]),
		toHexForTest(fragment[:]),
		"how-do-i-contact-a-journalist-safely",
		"basin-0xdeadbeefcafe",
		toHexForTest([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
	}, "|")
	found := map[string]struct{}{}
	for _, finding := range scanner.Scan([]byte(rehearsal)) {
		found[finding.Label] = struct{}{}
	}
	if len(found) != 5 {
		t.Fatalf("the scanner located only %d of 5 secrets in a rehearsal blob (%v); "+
			"a clean scan of the real output would prove nothing", len(found), found)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(1200*time.Millisecond, cancel)
	defer stop.Stop()

	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		if err := worker.Run(ctx); err != nil {
			t.Logf("node stopped: %v", err)
		}
	}()
	// Push the fragment through the relay path so it is genuinely handled,
	// not merely declared.
	group.Add(1)
	go func() {
		defer group.Done()
		var stream hop.StreamID
		stream[15] = 1
		counter := 0
		for ctx.Err() == nil {
			counter++
			stream[0] = byte(counter)
			metadata, err := hop.WorkMetadata(stream, 0, 2)
			if err != nil {
				return
			}
			cell, err := hop.FromCiphertext(fragment, metadata)
			if err != nil {
				return
			}
			worker.queue.Enqueue(cell)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	group.Wait()

	// Everything the process left behind, not just the file it intended.
	inspected := 0
	err := filepath.Walk(scratch, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		inspected++
		if findings := scanner.Scan(data); len(findings) > 0 {
			relative, _ := filepath.Rel(scratch, path)
			for _, finding := range findings {
				t.Errorf("%s contains %s", relative, finding)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspected == 0 {
		t.Fatal("the node wrote no files at all; the scan proved nothing")
	}
	t.Logf("scanned %d files for %d secret patterns", inspected, scanner.Registered())
}

// The health file is the node's deliberate emission, so it must also satisfy
// the field allowlist: a field that is clean today can carry private state
// tomorrow, and adding one should require saying why it is public.
func TestHealthEmissionSatisfiesTheTelemetryAllowlist(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)
	defer func() { _ = worker.conn.Close() }()

	if err := worker.writeHealth(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(scratch, "health.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := telemetry.ValidateEmission(encoded); err != nil {
		t.Errorf("the node's health emission is not allowlisted: %v", err)
	}

	// The allowlist must actually cover this emission rather than happening
	// to be a superset of something smaller.
	if !strings.Contains(string(encoded), "cover_sent") {
		t.Errorf("health emission did not contain the fields the allowlist describes: %s", encoded)
	}
}

// A positive control. If the node ever did write a secret, the test above has
// to fail -- otherwise a clean run says nothing.
func TestTheSecretScanWouldCatchALeak(t *testing.T) {
	scratch := t.TempDir()
	secret := []byte("operator-signing-key-material-42")
	scanner := telemetry.NewScanner()
	scanner.Register("operator key", secret)

	leak := filepath.Join(scratch, "health.json")
	if err := os.WriteFile(leak, []byte(`{"sent":1,"note":"`+toHexForTest(secret)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(leak)
	if err != nil {
		t.Fatal(err)
	}
	findings := scanner.Scan(data)
	if len(findings) == 0 {
		t.Fatal("the scanner missed a hex-encoded key in a health file; a clean scan " +
			"elsewhere would therefore mean nothing")
	}
	// And the allowlist independently rejects the field carrying it.
	if err := telemetry.ValidateEmission(data); err == nil {
		t.Error("the allowlist accepted an emission with an unlisted field")
	}
}

func toHexForTest(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// PROD-27 also asks for retention controls. The node's operational output is
// bounded by construction rather than by a policy someone has to remember: the
// health file is rewritten in place each tick and the sequence file is four
// bytes. An append-only operational log would accumulate a history of a node's
// behaviour, and history is what correlation attacks are made of.
func TestOperationalOutputIsBoundedRatherThanAccumulating(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)
	defer func() { _ = worker.conn.Close() }()

	sizes := make([]int64, 0, 8)
	for tick := 0; tick < 8; tick++ {
		if err := worker.writeHealth(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(scratch, "health.json"))
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, info.Size())
	}
	for index := 1; index < len(sizes); index++ {
		// Counters can widen by a digit; a file that accumulates grows without
		// bound. A generous ceiling separates the two unambiguously.
		if sizes[index] > sizes[0]+64 {
			t.Errorf("health file grew from %d to %d bytes over %d writes; operational "+
				"output is accumulating rather than being rewritten",
				sizes[0], sizes[index], index+1)
		}
	}

	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".log") || strings.Contains(name, ".jsonl") {
			t.Errorf("the node wrote %q, which is an accumulating operational log", name)
		}
	}
}
