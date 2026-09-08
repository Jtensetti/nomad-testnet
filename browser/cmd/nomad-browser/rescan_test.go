package main

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-browser/internal/demotrust"
	"github.com/Jtensetti/nomad-browser/objectstore"
	"github.com/Jtensetti/nomad-semantic-basins/basin"

	"github.com/Jtensetti/nomad-browser/search"
)

// newRescanSession builds a session over directory with an index of its own,
// without going through run: these tests drive the rescan loop directly and
// have no use for the command loop's stdin.
func newRescanSession(t *testing.T, directory string, output io.Writer) *session {
	t.Helper()
	trusted, err := objectstore.ParseTrustSet(demotrust.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	index, err := search.New(search.Config{
		Embedder:    basin.LexicalHashEmbedder{Dims: 256},
		Quantizer:   basin.Quantizer{Seed: localRankingSeed()},
		Provenance:  search.ProvenanceLexical,
		Fingerprint: search.LexicalFingerprint(256),
		Budget:      2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	scan, err := objectstore.Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	index.AddAll(context.Background(), scan.Objects)
	return &session{
		output: output, directory: directory, trusted: trusted,
		index: index, objects: scan.Objects,
	}
}

// halfCorpus writes half of the shipped catalog into a fresh directory and
// returns the directory and the envelopes it held back.
func halfCorpus(t *testing.T) (string, []objectstore.Envelope) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "macos", "Sources",
		"NomadBrowser", "Resources", "demo-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []objectstore.Envelope
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatal(err)
	}
	if len(envelopes) < 2 {
		t.Fatalf("the shipped corpus has %d objects, too few to split", len(envelopes))
	}
	directory := t.TempDir()
	half := len(envelopes) / 2
	for index, envelope := range envelopes[:half] {
		writeEnvelope(t, directory, index, envelope)
	}
	return directory, envelopes[half:]
}

func writeEnvelope(t *testing.T, directory string, index int, envelope objectstore.Envelope) {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "object-"+string(rune('a'+index))+".nomadobject")
	if err := os.WriteFile(name, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An object the materializer writes becomes visible without the reader doing
// anything. Nothing tells this client that a directory changed, so a rescan is
// the only way, and a rescan that did not pick up a new file would leave a
// reader looking at a corpus that stopped growing.
func TestAnObjectWrittenAfterStartupBecomesSearchable(t *testing.T) {
	directory, held := halfCorpus(t)
	output := &strings.Builder{}
	s := newRescanSession(t, directory, output)

	before := len(s.snapshot())
	beforeIndexed := s.index.Len()

	for index, envelope := range held {
		writeEnvelope(t, directory, 100+index, envelope)
	}
	s.rescan(context.Background())

	if after := len(s.snapshot()); after <= before {
		t.Fatalf("the rescan found %d objects, up from %d, with %d written in between",
			after, before, len(held))
	}
	if s.index.Len() <= beforeIndexed {
		t.Fatalf("the index holds %d objects after the rescan, up from %d, "+
			"so the new objects are not searchable", s.index.Len(), beforeIndexed)
	}
}

// A file the materializer removes stops being returned. An index that only
// ever grew would keep serving an object whose bytes are gone.
func TestAnObjectRemovedFromTheDirectoryStopsBeingSearchable(t *testing.T) {
	directory, _ := halfCorpus(t)
	s := newRescanSession(t, directory, &strings.Builder{})
	before := s.index.Len()
	if before == 0 {
		t.Fatal("the fixture indexed nothing, so removal proves nothing")
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, entries[0].Name())); err != nil {
		t.Fatal(err)
	}
	s.rescan(context.Background())

	if s.index.Len() != before-1 {
		t.Fatalf("the index holds %d objects after one of %d was removed",
			s.index.Len(), before)
	}
	if got := len(s.snapshot()); got != before-1 {
		t.Fatalf("the scan reports %d objects after one of %d was removed", got, before)
	}
}

// The property under test. Rescans must happen on their own schedule: the
// instants must be the same whether the reader is searching continuously or
// doing nothing at all. A client that rescanned on a query, or sooner after an
// empty result, would make cache discovery a function of what was searched
// for.
func TestRescanTimingDoesNotDependOnQueryActivity(t *testing.T) {
	const interval = 20 * time.Millisecond
	const window = 700 * time.Millisecond

	run := func(directory string, busy bool) []time.Duration {
		s := newRescanSession(t, directory, io.Discard)
		var mutex sync.Mutex
		var instants []time.Time
		s.observed = func(at time.Time) {
			mutex.Lock()
			instants = append(instants, at)
			mutex.Unlock()
		}
		ctx, stop := context.WithCancel(context.Background())
		go s.rescanUntil(ctx, interval)
		if busy {
			go func() {
				for ctx.Err() == nil {
					_ = s.search(ctx, "verified local information")
					_ = s.snapshot()
				}
			}()
		}
		time.Sleep(window)
		stop()
		mutex.Lock()
		defer mutex.Unlock()
		gaps := make([]time.Duration, 0, len(instants))
		for i := 1; i < len(instants); i++ {
			gaps = append(gaps, instants[i].Sub(instants[i-1]))
		}
		return gaps
	}

	populated, _ := halfCorpus(t)
	// Three worlds, because two would leave the corpus untested. The cadence
	// must be the same whether the reader is searching, sitting idle, or
	// holding nothing at all: an interval derived from how much the last scan
	// found would be a cadence set by this reader's own materialized objects,
	// which is exactly the private state a public periodic process must not
	// consult.
	worlds := map[string][]time.Duration{
		"searching continuously": run(populated, true),
		"idle":                   run(populated, false),
		"idle with no objects":   run(t.TempDir(), false),
	}
	for name, gaps := range worlds {
		if len(gaps) < 5 {
			t.Fatalf("%s produced only %d rescans, too few to compare", name, len(gaps))
		}
	}
	reference := worlds["idle"]
	for name, gaps := range worlds {
		// A client that rescanned on a query, or faster once it had objects,
		// shows up here first as a different number of rescans in the window.
		if ratio := float64(len(gaps)) / float64(len(reference)); ratio < 0.8 || ratio > 1.25 {
			t.Fatalf("%d rescans %s against %d while idle over the same window",
				len(gaps), name, len(reference))
		}
		drift := math.Abs(mean(gaps)-mean(reference)) / float64(interval)
		if drift > 0.25 {
			t.Fatalf("mean rescan gap is %v %s and %v while idle, "+
				"a drift of %.3f of the interval", time.Duration(mean(gaps)), name,
				time.Duration(mean(reference)), drift)
		}
	}
}

func mean(values []time.Duration) float64 {
	total := 0.0
	for _, value := range values {
		total += float64(value)
	}
	return total / float64(len(values))
}

// status is how a failed rescan becomes visible: rescans are not announced
// when they happen, because a line arriving mid-typing is noise, so a rescan
// that failed silently would leave a reader on a stale corpus with no way to
// tell. That makes status the only place the failure surfaces.
func TestStatusReportsWhatTheLastRescanFound(t *testing.T) {
	directory, held := halfCorpus(t)
	output := &strings.Builder{}
	s := newRescanSession(t, directory, output)

	s.status()
	if before := output.String(); !strings.Contains(before, "no rescan yet") {
		t.Fatalf("status before any rescan said %q", before)
	}

	output.Reset()
	for index, envelope := range held {
		writeEnvelope(t, directory, 100+index, envelope)
	}
	s.rescan(context.Background())
	s.status()
	report := output.String()
	for _, expected := range []string{"last rescan at", "verified", "added"} {
		if !strings.Contains(report, expected) {
			t.Fatalf("status does not mention %q: %q", expected, report)
		}
	}

	// A rescan that failed must say so rather than leaving the previous
	// counts standing, which would read as a corpus that simply stopped
	// changing.
	output.Reset()
	s.directory = filepath.Join(t.TempDir(), "gone")
	s.rescan(context.Background())
	s.status()
	if failure := output.String(); !strings.Contains(failure, "failed") {
		t.Fatalf("status after a failed rescan said %q", failure)
	}
}
