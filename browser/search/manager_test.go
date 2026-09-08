package search

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

func managerConfig(fingerprint string, provenance Provenance) Config {
	return Config{
		Embedder:    basin.LexicalHashEmbedder{Dims: 128},
		Quantizer:   basin.Quantizer{Seed: [32]byte{3}},
		Provenance:  provenance,
		Fingerprint: fingerprint,
		Budget:      time.Second,
	}
}

// Vectors from two models cannot be compared, so they never share a store.
func TestTwoModelsNeverShareAnIndex(t *testing.T) {
	manager := NewManager(t.TempDir())
	first := LexicalFingerprint(128)
	second := LexicalFingerprint(256)
	if first == second {
		t.Fatal("two widths produced one fingerprint, so this proves nothing")
	}

	a, err := manager.Open(managerConfig(first, "lexical-128"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := manager.Open(managerConfig(second, "lexical-256"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two fingerprints returned one index")
	}

	firstDir, err := manager.Directory(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDir, err := manager.Directory(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDir == secondDir {
		t.Fatal("two fingerprints resolve to one directory")
	}
}

// The same fingerprint is the same index. That is what a fingerprint means.
func TestOneFingerprintIsOneIndex(t *testing.T) {
	manager := NewManager(t.TempDir())
	fingerprint := LexicalFingerprint(128)

	first, err := manager.Open(managerConfig(fingerprint, ProvenanceLexical))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Open(managerConfig(fingerprint, ProvenanceLexical))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("one fingerprint opened two indexes, so an object indexed through one " +
			"would be invisible to a search through the other")
	}
	if got := first.Fingerprint(); got != fingerprint {
		t.Fatalf("the index reports fingerprint %q", got)
	}
}

// One fingerprint under two provenances means something that changes a vector
// is missing from the fingerprint, which is the failure it exists to prevent.
func TestOneFingerprintUnderTwoProvenancesIsRefused(t *testing.T) {
	manager := NewManager(t.TempDir())
	fingerprint := LexicalFingerprint(128)

	if _, err := manager.Open(managerConfig(fingerprint, "lexical")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Open(managerConfig(fingerprint, "some-real-model")); err == nil {
		t.Fatal("one fingerprint was opened under two different provenances")
	}
}

// A fingerprint names a directory, so anything that could escape the root is
// refused before it is joined to a path.
func TestAFingerprintThatIsNotAFingerprintIsRefused(t *testing.T) {
	manager := NewManager("/var/lib/nomad")
	for _, hostile := range []string{
		"",
		"../../etc/passwd",
		"..",
		"/etc/passwd",
		strings.Repeat("a", FingerprintLength-1),
		strings.Repeat("a", FingerprintLength+1),
		strings.ToUpper(LexicalFingerprint(128)),
		strings.Repeat("g", FingerprintLength),
		LexicalFingerprint(128)[:32] + "/" + LexicalFingerprint(128)[33:],
	} {
		t.Run(hostile, func(t *testing.T) {
			directory, err := manager.Directory(hostile)
			if err == nil {
				t.Fatalf("%q resolved to %q", hostile, directory)
			}
			if _, err := manager.Open(managerConfig(hostile, ProvenanceLexical)); err == nil {
				t.Fatalf("%q opened an index", hostile)
			}
		})
	}
}

// The control for the case above: a real fingerprint does resolve, and lands
// inside the root rather than beside it.
func TestARealFingerprintResolvesInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	manager := NewManager(root)
	fingerprint := LexicalFingerprint(128)

	directory, err := manager.Directory(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, IndexRoot, fingerprint)
	if directory != want {
		t.Fatalf("directory is %q, want %q", directory, want)
	}
	if !strings.HasPrefix(filepath.Clean(directory), filepath.Clean(root)+string(filepath.Separator)) {
		t.Fatalf("%q is not inside %q", directory, root)
	}
}

// Uppercase hex is a second spelling of one identity, and two spellings is how
// two directories end up holding one model's vectors.
func TestAFingerprintHasOneSpelling(t *testing.T) {
	fingerprint := LexicalFingerprint(128)
	if err := ValidFingerprint(fingerprint); err != nil {
		t.Fatalf("a real fingerprint was refused: %v", err)
	}
	if err := ValidFingerprint(strings.ToUpper(fingerprint)); err == nil {
		t.Fatal("the uppercase spelling of a fingerprint was accepted as well as the " +
			"lowercase one, so one model can occupy two index directories")
	}
}

// The baseline's fingerprint depends on its width, because the same baseline
// at two widths does not produce comparable vectors either.
func TestTheLexicalBaselineFingerprintTracksItsWidth(t *testing.T) {
	seen := map[string]int{}
	for _, width := range []int{128, 256, 384, 768} {
		fingerprint := LexicalFingerprint(width)
		if err := ValidFingerprint(fingerprint); err != nil {
			t.Fatalf("width %d: %v", width, err)
		}
		if earlier, repeat := seen[fingerprint]; repeat {
			t.Fatalf("widths %d and %d share a fingerprint", earlier, width)
		}
		seen[fingerprint] = width
	}
	// Re-derived rather than compared with itself in one expression, so a
	// derivation that carried state between calls would show up as drift.
	want := LexicalFingerprint(128)
	for repeat := 0; repeat < 8; repeat++ {
		if got := LexicalFingerprint(128); got != want {
			t.Fatalf("derivation %d returned %s, the first returned %s", repeat, got, want)
		}
	}
}
