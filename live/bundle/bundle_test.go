package bundle

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// A seed bundle names a stream and carries the cells that stream consists of.
// The stream ID is a commitment over those cells, and that binding is the
// only thing stopping a bundle from claiming one stream while carrying
// another's payloads. Nothing in this package had a test: Load, Verify,
// Encode and Cells were all at zero coverage across the repository.

func payloads(t *testing.T, count int) [][hop.CiphertextSize]byte {
	t.Helper()
	out := make([][hop.CiphertextSize]byte, count)
	for index := range out {
		if _, err := rand.Read(out[index][:]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func newBundle(t *testing.T, count int) (File, [][hop.CiphertextSize]byte) {
	t.Helper()
	cells := payloads(t, count)
	file, err := New(cells)
	if err != nil {
		t.Fatal(err)
	}
	return file, cells
}

func verifyFile(t *testing.T, file File) error {
	t.Helper()
	encoded, err := Encode(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(encoded)
	return err
}

func TestABundleRoundTripsAndYieldsItsCells(t *testing.T) {
	file, cells := newBundle(t, 4)
	encoded, err := Encode(file)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(encoded)
	if err != nil {
		t.Fatalf("a bundle this package built did not verify: %v", err)
	}
	if len(verified.Payloads) != len(cells) {
		t.Fatalf("verified %d payloads from a bundle of %d", len(verified.Payloads), len(cells))
	}
	for index := range cells {
		if verified.Payloads[index] != cells[index] {
			t.Fatalf("payload %d changed across the round trip", index)
		}
	}
	fabricCells, err := verified.Cells()
	if err != nil {
		t.Fatal(err)
	}
	if len(fabricCells) != len(cells) {
		t.Fatalf("%d cells from %d payloads", len(fabricCells), len(cells))
	}
}

// The commitment is what binds the name to the contents. Without it a bundle
// could carry one stream's payloads under another stream's identifier, which
// is what the identifier is used to look up.
func TestABundleCannotClaimAStreamItDoesNotCarry(t *testing.T) {
	file, _ := newBundle(t, 4)
	other, _ := newBundle(t, 4)

	relabelled := file
	relabelled.StreamID = other.StreamID
	err := verifyFile(t, relabelled)
	if err == nil {
		t.Fatal("a bundle relabelled with another stream's identifier verified")
	}
	if !strings.Contains(err.Error(), "commitment mismatch") {
		t.Fatalf("refused for %q rather than the commitment", err)
	}

	// The same property from the other side: keep the identifier and change a
	// payload.
	tampered := file
	tampered.Cells = append([]string{}, file.Cells...)
	tampered.Cells[1] = other.Cells[1]
	err = verifyFile(t, tampered)
	if err == nil {
		t.Fatal("a bundle with a substituted cell verified under its old identifier")
	}
	if !strings.Contains(err.Error(), "commitment mismatch") {
		t.Fatalf("refused for %q rather than the commitment", err)
	}

	// And reordering, which preserves the multiset and not the commitment.
	reordered := file
	reordered.Cells = append([]string{}, file.Cells...)
	reordered.Cells[0], reordered.Cells[1] = reordered.Cells[1], reordered.Cells[0]
	if err := verifyFile(t, reordered); err == nil {
		t.Fatal("a bundle whose cells were reordered verified")
	}
}

func TestABundleOutsideTheSupportedProfileIsRefused(t *testing.T) {
	file, _ := newBundle(t, 4)
	for name, mutate := range map[string]func(*File){
		"a wrong version": func(f *File) { f.Version = "nomad-seed-bundle-v2" },
		"one cell":        func(f *File) { f.Cells = f.Cells[:1] },
		"no cells":        func(f *File) { f.Cells = nil },
	} {
		broken := file
		mutate(&broken)
		err := verifyFile(t, broken)
		if err == nil {
			t.Fatalf("a bundle with %s verified", name)
		}
		if !strings.Contains(err.Error(), "profile") {
			t.Fatalf("a bundle with %s was refused for %q rather than its profile", name, err)
		}
	}
}

func TestMalformedCellsAndStreamIDsAreRefused(t *testing.T) {
	file, _ := newBundle(t, 4)

	shortStream := file
	shortStream.StreamID = hex.EncodeToString(make([]byte, 8))
	if err := verifyFile(t, shortStream); err == nil {
		t.Fatal("a bundle with a short stream ID verified")
	} else if !strings.Contains(err.Error(), "stream ID") {
		t.Fatalf("refused for %q rather than the stream ID", err)
	}

	shortCell := file
	shortCell.Cells = append([]string{}, file.Cells...)
	shortCell.Cells[0] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	if err := verifyFile(t, shortCell); err == nil {
		t.Fatal("a bundle with an undersized cell verified")
	}

	// A cell is CiphertextSize bytes and that size is divisible by three, so
	// its base64 encoding carries no padding and there are no trailing bits
	// for Strict() to reject. Dropping padding is therefore not a case here --
	// the first version of this test tried it, and trimming "=" from a string
	// with none left it unchanged and passing for that reason. What is a case
	// is a second alphabet or embedded whitespace, either of which decodes to
	// the same bytes under a lenient decoder.
	for name, mutate := range map[string]func(string) string{
		"the URL-safe alphabet": func(cell string) string {
			return strings.NewReplacer("+", "-", "/", "_").Replace(cell)
		},
		"an embedded newline": func(cell string) string {
			return cell[:16] + "\n" + cell[16:]
		},
	} {
		alternate := file
		alternate.Cells = append([]string{}, file.Cells...)
		alternate.Cells[0] = mutate(alternate.Cells[0])
		if alternate.Cells[0] == file.Cells[0] {
			t.Fatalf("%s did not change the cell, so this case tests nothing", name)
		}
		if err := verifyFile(t, alternate); err == nil {
			t.Fatalf("a cell encoded with %s was accepted", name)
		}
	}
}

func TestNonCanonicalBundleDocumentsAreRefused(t *testing.T) {
	file, _ := newBundle(t, 4)
	encoded, err := Encode(file)
	if err != nil {
		t.Fatal(err)
	}
	for name, document := range map[string][]byte{
		"an unknown member": append([]byte(`{"surprise":1,`), encoded[1:]...),
		"trailing data":     append(append([]byte{}, encoded...), []byte("{}")...),
		"empty":             {},
	} {
		if _, err := Verify(document); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestLoadRequiresABoundedRegularFile(t *testing.T) {
	file, _ := newBundle(t, 4)
	encoded, err := Encode(file)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("a written bundle did not load: %v", err)
	}

	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("a directory was accepted as a seed bundle")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a directory was refused for %q rather than for not being a regular file", err)
	}

	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("a missing bundle was accepted")
	}
}
