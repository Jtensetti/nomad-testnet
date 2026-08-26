package rawcache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// PROD-13 asks that replication, eviction, repair and cache warming stay
// independent of private reads. Three of those four are architectural here:
// there is no eviction (a full cache refuses a new stream rather than choosing
// a victim), replication is driven by what signed peers send, and warming comes
// from a public seed bundle. None of them has a read as an input.
//
// The fourth is the one worth measuring, because it is the one a future change
// would break without anyone noticing. Reading is where an LRU touch, an access
// counter, a "recently materialized" index or a hot-set marker gets added, and
// each of those turns "which objects this reader wanted" into state on disk
// that outlives the read.
//
// So this compares two worlds that receive byte-identical public input and
// differ only in whether anything reads the cache, and requires the resulting
// store to be identical byte for byte. It is not an argument that no such state
// exists today; it is a test that fails on the day someone adds it.

// storeTranscript is every file the cache holds, with its content digest. Names
// and sizes are not enough: a marker written into an existing file, or a
// counter incremented in place, keeps both.
func storeTranscript(t *testing.T, root string) []string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative != "." {
				lines = append(lines, "dir  "+filepath.ToSlash(relative))
			}
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		lines = append(lines, fmt.Sprintf("file %s %d %x",
			filepath.ToSlash(relative), len(content), digest[:8]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return lines
}

type publicCell struct {
	metadata hop.Metadata
	payload  [hop.CiphertextSize]byte
}

// publicInput is the sequence of cells both worlds receive, in the same order.
// It is fixed and derived from nothing private.
func publicInput(t *testing.T, streams, batchSize int) []publicCell {
	t.Helper()
	var input []publicCell
	for index := 0; index < streams; index++ {
		payloads := make([][hop.CiphertextSize]byte, batchSize)
		for ordinal := range payloads {
			for offset := range payloads[ordinal] {
				payloads[ordinal][offset] = byte(index*7 + ordinal*13 + offset)
			}
		}
		stream, err := hop.StreamFor(payloads)
		if err != nil {
			t.Fatal(err)
		}
		for ordinal, payload := range payloads {
			metadata, err := hop.WorkMetadata(stream, uint16(ordinal), uint16(batchSize))
			if err != nil {
				t.Fatal(err)
			}
			metadata.Sender = uint16(1 + index%2)
			input = append(input, publicCell{metadata: metadata, payload: payload})
		}
	}
	return input
}

func TestReadingTheCacheChangesNothingItStores(t *testing.T) {
	const (
		streams   = 6
		batchSize = 2
		limit     = 16
	)
	input := publicInput(t, streams, batchSize)

	// Both worlds take the same public input in the same order. Only one of
	// them is read from, and it is read from hard: every complete stream,
	// repeatedly, plus one stream far more often than the rest, which is what
	// a hot object would look like to any access-derived state.
	run := func(withReads bool) []string {
		root := t.TempDir()
		store, err := OpenShared(root, limit, []uint16{1, 2})
		if err != nil {
			t.Fatal(err)
		}
		var hot hop.StreamID
		for step, cell := range input {
			if _, err := store.Put(cell.metadata, cell.payload); err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			if hot == (hop.StreamID{}) {
				hot = cell.metadata.Stream
			}
			if !withReads {
				continue
			}
			complete, err := store.CompleteStreams()
			if err != nil {
				t.Fatal(err)
			}
			for _, stream := range complete {
				if _, _, err := store.Load(stream); err != nil {
					t.Fatal(err)
				}
			}
			for repeat := 0; repeat < 8; repeat++ {
				if _, _, err := store.Load(hot); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Complete(hot); err != nil {
					t.Fatal(err)
				}
			}
			// A stream that was never received: asking for it must not
			// create anything either, which is how a probe for an object
			// nobody has would otherwise leave a trace.
			var absent hop.StreamID
			absent[0] = 0xFF
			if _, _, err := store.Load(absent); err != nil {
				t.Fatal(err)
			}
		}
		return storeTranscript(t, root)
	}

	read := run(true)
	quiet := run(false)

	if len(read) == 0 {
		t.Fatal("both worlds stored nothing; the comparison is vacuous")
	}
	if strings.Join(read, "\n") != strings.Join(quiet, "\n") {
		t.Fatalf("reading the cache changed what it stores.\nwith reads:\n%s\n\nwithout:\n%s",
			strings.Join(read, "\n"), strings.Join(quiet, "\n"))
	}
	t.Logf("MEASURED: %d stored files identical across a world read %d times per step and "+
		"a world never read", len(read), 8+streams)
}

// The comparison above is only worth having if it would notice. This is the
// positive control: a world that writes one extra byte of read-derived state
// must produce a different transcript.
func TestTheStorageComparisonNoticesReadDerivedState(t *testing.T) {
	root := t.TempDir()
	store, err := OpenShared(root, 8, []uint16{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range publicInput(t, 1, 2) {
		if _, err := store.Put(cell.metadata, cell.payload); err != nil {
			t.Fatal(err)
		}
	}
	before := storeTranscript(t, root)

	// Exactly what an access counter or an LRU touch would look like: one
	// small file, inside the stream directory, written on read.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var streamDir string
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) == 32 {
			streamDir = filepath.Join(root, entry.Name())
			break
		}
	}
	if streamDir == "" {
		t.Fatal("no stream directory was created; the control has nothing to mark")
	}
	if err := os.WriteFile(filepath.Join(streamDir, "last-read"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := storeTranscript(t, root)

	if strings.Join(before, "\n") == strings.Join(after, "\n") {
		t.Fatal("the transcript did not change when read-derived state was added, so the " +
			"comparison above proves nothing")
	}
}

// A read must not be able to make a stream that was never received exist, nor
// to change one that was. Load recomputes the stream ID from the cells it finds
// and refuses a mismatch, so this also pins that a reader cannot use a read to
// have a forged stream accepted.
func TestReadingCannotCreateOrAlterAStream(t *testing.T) {
	root := t.TempDir()
	store, err := OpenShared(root, 8, []uint16{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range publicInput(t, 2, 2) {
		if _, err := store.Put(cell.metadata, cell.payload); err != nil {
			t.Fatal(err)
		}
	}
	before := storeTranscript(t, root)

	for probe := 0; probe < 32; probe++ {
		var stream hop.StreamID
		stream[0], stream[1] = 0xAB, byte(probe)
		payloads, complete, err := store.Load(stream)
		if err != nil {
			t.Fatalf("probe %d: %v", probe, err)
		}
		if complete || payloads != nil {
			t.Fatalf("probe %d returned content for a stream that was never received", probe)
		}
		if _, err := store.Complete(stream); err != nil {
			t.Fatalf("probe %d: %v", probe, err)
		}
	}

	after := storeTranscript(t, root)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("probing for 32 absent streams changed the store:\nbefore:\n%s\n\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}

	// And the directory holds no trace of the probes under any name.
	for _, line := range after {
		if strings.Contains(line, hex.EncodeToString([]byte{0xAB})) &&
			!strings.Contains(strings.Join(before, "\n"), line) {
			t.Fatalf("a probe left %s behind", line)
		}
	}
}
