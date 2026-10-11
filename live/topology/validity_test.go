package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The three fields that decide when a signed topology is a topology at all:
// its epoch, and the two ends of its validity window.
//
// A signature says the authority meant to publish this document. It says
// nothing about whether the document's own numbers make sense, and each of
// these three is checked because something downstream reads the field and
// cannot tell a nonsense value from a deliberate one. Every case here is signed
// by a genuine authority key, so the only thing wrong with it is the field
// under test.
func TestVerifyRefusesDocumentsWhoseValidityFieldsAreNotUsable(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := attestedDocument(t)
	sign := func(mutate func(*Document)) []byte {
		t.Helper()
		document := cloneDocument(base)
		mutate(&document)
		canonical, err := canonicalDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Encode(Signed{
			Document: document,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivate,
				signingMessage("nomad-topology-authority-v3", canonical))),
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	now := time.Now().UTC()
	for _, testCase := range []struct {
		name    string
		mutate  func(*Document)
		at      time.Time
		wantSub string
	}{
		{
			// Epoch 0 is the value the watermark file uses to mean "there is
			// nothing here". A node that accepted an epoch-0 topology would
			// write a watermark it cannot read back, and rollback protection
			// would refuse to start rather than protect anything. The second
			// half of this file shows that happening.
			name:    "epoch zero, which the watermark cannot represent",
			mutate:  func(d *Document) { d.Epoch = 0 },
			at:      now,
			wantSub: "epoch",
		},
		{
			// An unparseable not-before parses as the zero time, which is a
			// validity window with no lower edge. Nothing downstream catches
			// it: an epoch descriptor checks its activation against exactly
			// this field, and every instant is after the zero time.
			name:    "an unparseable not-before, which is no lower edge at all",
			mutate:  func(d *Document) { d.NotBefore = "whenever" },
			at:      now,
			wantSub: "not-before",
		},
		{
			// The upper edge is checked twice when a caller passes a real
			// clock -- once here and once by the window comparison below it --
			// so this case passes the zero time, which is the clock an epoch
			// descriptor verifies an embedded topology with. There the window
			// comparison is skipped and this is the only check there is.
			name:    "an unparseable not-after, verified as an epoch descriptor verifies it",
			mutate:  func(d *Document) { d.NotAfter = "whenever" },
			at:      time.Time{},
			wantSub: "not-after",
		},
		{
			name: "a window that ends before it begins",
			mutate: func(d *Document) {
				d.NotBefore = now.Add(time.Hour).Format(time.RFC3339)
				d.NotAfter = now.Add(-time.Hour).Format(time.RFC3339)
			},
			at:      time.Time{},
			wantSub: "not-after",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Verify(sign(testCase.mutate), authorityPublic, testCase.at)
			if err == nil {
				t.Fatal("a signed topology with an unusable validity field was accepted")
			}
			if !strings.Contains(err.Error(), testCase.wantSub) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}

	// Vacuity: the same signing path with none of the fields touched produces a
	// document that verifies under both clocks, so what refused the cases above
	// was the field under test and not the fixture.
	unchanged := sign(func(*Document) {})
	for _, at := range []time.Time{now, {}} {
		if _, err := Verify(unchanged, authorityPublic, at); err != nil {
			t.Fatalf("vacuity arm: an untouched document was refused at %v: %v", at, err)
		}
	}
}

// Why the epoch check is load-bearing rather than tidy.
//
// The watermark is what makes "newer than what I have already served" a
// checkable property. It reads back an epoch of 0 as an unusable file, and an
// unusable watermark is an error rather than permission to proceed -- so a
// single epoch-0 topology, if one could be accepted, would leave a node unable
// to start until someone deleted the file by hand.
func TestAnEpochZeroWatermarkIsUnreadableRatherThanEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watermark.json")
	stored := `{"version":"` + WatermarkVersion + `","network_id":"downgrade-net","epoch":0,` +
		`"digest":"` + strings.Repeat("ab", 32) + `"}`
	if err := os.WriteFile(path, []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWatermark(path); err == nil {
		t.Fatal("an epoch-zero watermark was read back as usable state")
	}

	// Vacuity: the same record with a non-zero epoch reads back, so what made
	// the file unusable was the epoch and not the rest of its contents.
	usable := strings.Replace(stored, `"epoch":0`, `"epoch":1`, 1)
	if err := os.WriteFile(path, []byte(usable), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWatermark(path); err != nil {
		t.Fatalf("vacuity arm: a non-zero watermark was rejected too: %v", err)
	}
}

// Load's file boundary. Verify is where a topology is judged; Load is where a
// path becomes bytes, and it refuses three things before Verify sees anything:
// what is not a regular file, what is too large to be a topology, and what is
// not there.
//
// The size bound matters most. Without it a path that happens to name a very
// large file is read into memory in full before the encoding check that would
// have refused it, which turns "point the node at the wrong file" into an
// out-of-memory rather than an error message.
func TestLoadRefusesWhatIsNotABoundedRegularFile(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := attestedDocument(t)
	canonical, err := canonicalDocument(base)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(Signed{
		Document: base,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivate,
			signingMessage("nomad-topology-authority-v3", canonical))),
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	now := time.Now().UTC()

	good := filepath.Join(directory, "topology.json")
	if err := os.WriteFile(good, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	// Vacuity first: the fixture loads, so every refusal below is about the
	// path and not about the document at the end of it.
	if _, err := Load(good, authorityPublic, now); err != nil {
		t.Fatalf("vacuity arm: a well-formed topology file was refused: %v", err)
	}

	if _, err := Load(directory, authorityPublic, now); err == nil {
		t.Fatal("a directory was loaded as a topology")
	}
	if _, err := Load(filepath.Join(directory, "absent.json"), authorityPublic, now); err == nil {
		t.Fatal("a path with no file was loaded as a topology")
	}

	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, MaximumFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversized, authorityPublic, now); err == nil {
		t.Fatal("a file past the size bound was read as a topology")
	} else if !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// A FIFO is a path that opens and then never ends. Refusing on the file
	// mode rather than on what reading it produces is what keeps Load from
	// blocking on one.
	fifo := filepath.Join(directory, "topology.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("this platform has no FIFOs: %v", err)
	}
	if _, err := Load(fifo, authorityPublic, now); err == nil {
		t.Fatal("a FIFO was loaded as a topology")
	}
}
