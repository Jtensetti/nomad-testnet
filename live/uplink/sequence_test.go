package uplink

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The sequence is the AEAD nonce, so "never returned twice" is not a
// convenience property. These are the ways a publisher would otherwise reuse
// one, and the first of them is the one that matters: a restart.
func TestASequenceIsNeverHandedOutTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "uplink-sequence")

	first, err := OpenFileSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	var highest uint64
	for index := 0; index < 64; index++ {
		value, err := first.Next()
		if err != nil {
			t.Fatal(err)
		}
		if value == 0 {
			t.Fatal("zero is not a usable sequence: seal refuses it")
		}
		if seen[value] {
			t.Fatalf("sequence %d was handed out twice within one process", value)
		}
		seen[value] = true
		highest = value
	}

	// The restart. A publisher that counted from one again here would re-seal
	// under nonces it had already used.
	second, err := OpenFileSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 64; index++ {
		value, err := second.Next()
		if err != nil {
			t.Fatal(err)
		}
		if seen[value] {
			t.Fatalf("sequence %d was handed out again after a restart: the publisher "+
				"would seal a new fragment under a nonce it has already used", value)
		}
		if value <= highest {
			t.Errorf("sequence went backwards across a restart: %d after %d", value, highest)
		}
		seen[value] = true
	}

	// And a third open, because a reservation that only advanced on the first
	// restart would pass the check above.
	third, err := OpenFileSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := third.Next()
	if err != nil {
		t.Fatal(err)
	}
	if seen[value] {
		t.Fatalf("sequence %d repeated on a second restart", value)
	}
}

// Concurrent callers are the in-process version of the same hazard.
func TestConcurrentCallersNeverShareASequence(t *testing.T) {
	sequence, err := OpenFileSequence(filepath.Join(t.TempDir(), "uplink-sequence"))
	if err != nil {
		t.Fatal(err)
	}
	const workers, each = 8, 200
	results := make(chan uint64, workers*each)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := 0; index < each; index++ {
				value, err := sequence.Next()
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				results <- value
			}
		}()
	}
	group.Wait()
	close(results)

	seen := map[uint64]bool{}
	for value := range results {
		if seen[value] {
			t.Fatalf("sequence %d was handed to two callers at once", value)
		}
		seen[value] = true
	}
	if len(seen) != workers*each {
		t.Errorf("got %d distinct sequences from %d calls", len(seen), workers*each)
	}
}

// An unreadable or corrupt reservation means the nonce space cannot be
// guaranteed unique. It must fail closed rather than start from zero, which
// is the failure mode that would look like a fresh publisher and behave like
// a replay.
func TestUnusableSequenceStateFailsClosed(t *testing.T) {
	directory := t.TempDir()

	for name, prepare := range map[string]func(string) error{
		"truncated": func(path string) error {
			return os.WriteFile(path, []byte{1, 2, 3}, 0o600)
		},
		"oversize": func(path string) error {
			return os.WriteFile(path, make([]byte, 16), 0o600)
		},
		"a directory where the state belongs": func(path string) error {
			return os.Mkdir(path, 0o700)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, "state-"+name[:4])
			if err := prepare(path); err != nil {
				t.Fatal(err)
			}
			_, err := OpenFileSequence(path)
			if err == nil {
				t.Fatal("a publisher opened an unusable nonce state and would have " +
					"started from zero")
			}
			if !errors.Is(err, ErrSequenceStateInvalid) {
				t.Errorf("refused with %v, which does not name the invalid state", err)
			}
		})
	}
}

// The reservation is written before any number is used, so a disk that will
// not take it must stop the publisher rather than let it seal.
func TestAFailedReservationRefusesToHandOutASequence(t *testing.T) {
	directory := t.TempDir()
	blocked := filepath.Join(directory, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenFileSequence(filepath.Join(blocked, "uplink-sequence"))
	if err == nil {
		t.Fatal("a publisher whose reservation could not be written was allowed to seal")
	}
}
