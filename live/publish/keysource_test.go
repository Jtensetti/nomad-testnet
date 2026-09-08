package publish

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func submitOne(t *testing.T, queue *Queue, object string) {
	t.Helper()
	publisher, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Submit([]byte(object), publisher); err != nil {
		t.Fatal(err)
	}
}

func TestAQueueWithoutAKeySourceIsRefused(t *testing.T) {
	_, err := Open(t.TempDir(), Options{MaximumFragments: 8})
	if err == nil {
		t.Fatal("a queue opened with no key source, so one of the two was the silent default")
	}
	if !strings.Contains(err.Error(), "key source") {
		t.Fatalf("refused for %q rather than the missing key source", err)
	}
}

// The property that separates the two sources. Under a passphrase the disk
// carries the sealed fragments, a salt and a verifier, and none of those is
// the key: an attacker holding the whole directory cannot open a fragment.
func TestAPassphraseQueueKeepsNothingOnDiskThatOpensIt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	queue, err := Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err != nil {
		t.Fatal(err)
	}
	submitOne(t, queue, "the thing being published")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, keyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists in a passphrase queue, so the key is on the disk after all",
			keyFileName)
	}

	// Every file on the disk, tried as if it were the key. A stolen disk is
	// exactly this: the bytes, and no passphrase.
	for _, entry := range entries {
		contents, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(contents) != 32 {
			continue
		}
		var candidate [32]byte
		copy(candidate[:], contents)
		attacker := &Queue{root: root, maxFragments: 8, key: candidate}
		if _, err := attacker.Next(); err == nil {
			t.Fatalf("%s opened a fragment, so it is the key", entry.Name())
		}
	}
}

// The other side of the same property, asserted rather than assumed: the
// unprotected source writes a key that does open the queue. This is what
// UnprotectedKeyFile is documented to be, and a reader should be able to see
// the difference measured rather than described.
func TestTheUnprotectedKeyFileOpensItsOwnQueue(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	queue, err := Open(root, Options{MaximumFragments: 8, Key: UnprotectedKeyFile()})
	if err != nil {
		t.Fatal(err)
	}
	submitOne(t, queue, "the thing being published")

	contents, err := os.ReadFile(filepath.Join(root, keyFileName))
	if err != nil {
		t.Fatalf("the unprotected source wrote no key file: %v", err)
	}
	var candidate [32]byte
	copy(candidate[:], contents)
	attacker := &Queue{root: root, maxFragments: 8, key: candidate}
	if _, err := attacker.Next(); err != nil {
		t.Fatalf("the key file beside the fragments did not open one: %v", err)
	}
}

func TestTheRightPassphraseReopensTheQueueAndAWrongOneIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	const object = "the thing being published"
	queue, err := Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err != nil {
		t.Fatal(err)
	}
	submitOne(t, queue, object)

	reopened, err := Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := reopened.Next()
	if err != nil {
		t.Fatalf("the right passphrase did not reopen the queue: %v", err)
	}
	if !bytes.Contains(fragment.Payload[:], []byte(object)) {
		t.Fatal("the reopened fragment does not carry the object")
	}
}

// A wrong passphrase must fail at Open. Left to surface later it would look
// exactly like an empty queue: Drain treats every Next error as "no work" by
// design, so the publisher would emit cover forever while its queue filled.
func TestAWrongPassphraseIsRefusedAtOpen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	queue, err := Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err != nil {
		t.Fatal(err)
	}
	submitOne(t, queue, "the thing being published")

	_, err = Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("wrong horse"))})
	if !errors.Is(err, ErrPassphraseRejected) {
		t.Fatalf("a wrong passphrase was refused with %v, want ErrPassphraseRejected", err)
	}
}

func TestAnEmptyPassphraseIsRefused(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "queue"),
		Options{MaximumFragments: 8, Key: Passphrase(nil)})
	if err == nil {
		t.Fatal("an empty passphrase opened a queue")
	}
}

// The salt fixes the key. A truncated or replaced salt would derive a
// different key and leave every stored fragment unopenable, so it is refused
// rather than regenerated over the top of a queue that still has work in it.
func TestATruncatedSaltIsRefusedRatherThanRegenerated(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	queue, err := Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err != nil {
		t.Fatal(err)
	}
	submitOne(t, queue, "the thing being published")

	saltPath := filepath.Join(root, saltFileName)
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saltPath, salt[:saltSize-1], 0o600); err != nil {
		t.Fatal(err)
	}
	// The message has to name the salt. A damaged salt and a wrong passphrase
	// both end in a key that opens nothing, and the verifier refuses either --
	// but they are different problems for whoever has to fix one, and reporting
	// a damaged disk as a wrong passphrase sends them the wrong way.
	_, err = Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err == nil {
		t.Fatal("a truncated salt was accepted, so the queue derived a key that opens nothing")
	}
	if errors.Is(err, ErrPassphraseRejected) || !strings.Contains(err.Error(), "salt") {
		t.Fatalf("a truncated salt was reported as %q rather than as a damaged salt", err)
	}
}

// Two queues under the same passphrase must not share a key: the salt is what
// stops one derivation covering both, and a fixed salt would also make a
// precomputed table useful against every Nomad queue at once.
func TestTwoQueuesUnderOnePassphraseDeriveDifferentKeys(t *testing.T) {
	passphrase := []byte("correct horse")
	first, err := Open(filepath.Join(t.TempDir(), "one"),
		Options{MaximumFragments: 8, Key: Passphrase(passphrase)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(filepath.Join(t.TempDir(), "two"),
		Options{MaximumFragments: 8, Key: Passphrase(passphrase)})
	if err != nil {
		t.Fatal(err)
	}
	if first.key == second.key {
		t.Fatal("two queues under one passphrase derived the same key, so the salt is not in use")
	}
}

// Switching the key source on an existing queue derives a key that opens
// nothing. Left to surface at Next it would look exactly like an empty queue,
// which is the failure the verifier exists to prevent arriving through the
// flag instead of through the passphrase.
func TestSwitchingTheKeySourceOnAnExistingQueueIsRefused(t *testing.T) {
	for _, order := range []struct {
		name           string
		created, tried KeySource
	}{
		{"unprotected then passphrase", UnprotectedKeyFile(), Passphrase([]byte("correct horse"))},
		{"passphrase then unprotected", Passphrase([]byte("correct horse")), UnprotectedKeyFile()},
	} {
		t.Run(order.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "queue")
			queue, err := Open(root, Options{MaximumFragments: 8, Key: order.created})
			if err != nil {
				t.Fatal(err)
			}
			submitOne(t, queue, "the thing being published")

			_, err = Open(root, Options{MaximumFragments: 8, Key: order.tried})
			if !errors.Is(err, ErrKeySourceMismatch) {
				t.Fatalf("the switch was refused with %v, want ErrKeySourceMismatch", err)
			}
		})
	}
}

// A salt that is replaced derives a different key and leaves every fragment
// already queued unopenable, so creating one must not overwrite one.
func TestTheSaltIsNeverOverwritten(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	if _, err := Open(root, Options{MaximumFragments: 8,
		Key: Passphrase([]byte("correct horse"))}); err != nil {
		t.Fatal(err)
	}
	saltPath := filepath.Join(root, saltFileName)
	before, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(saltPath, encodeSaltRecord(make([]byte, saltSize))); !errors.Is(err, os.ErrExist) {
		t.Fatalf("creating the salt again returned %v, want an exists error", err)
	}
	after, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the salt changed under a second creation")
	}
}

// A build whose Argon2id parameters differ from the ones a queue was created
// under derives a key that opens nothing. Reported as the parameter mismatch
// it is: an operator told "wrong passphrase" would retype something that was
// never wrong.
func TestASaltFromDifferentDerivationParametersIsNamedAsSuch(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	if _, err := Open(root, Options{MaximumFragments: 8,
		Key: Passphrase([]byte("correct horse"))}); err != nil {
		t.Fatal(err)
	}
	saltPath := filepath.Join(root, saltFileName)
	record, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the memory parameter as if an older build had created this.
	binary.BigEndian.PutUint32(record[len(saltMagic)+4:], 19*1024)
	if err := os.WriteFile(saltPath, record, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(root, Options{MaximumFragments: 8, Key: Passphrase([]byte("correct horse"))})
	if err == nil {
		t.Fatal("a queue created under different parameters opened")
	}
	if errors.Is(err, ErrPassphraseRejected) {
		t.Fatalf("a parameter mismatch was reported as a wrong passphrase: %v", err)
	}
	if !strings.Contains(err.Error(), "m=19456") {
		t.Fatalf("the refusal does not name the parameters the queue was created "+
			"under: %v", err)
	}
}

// Two publishers opening one queue at once must agree on the salt. A salt
// replaced after another opener has already derived from it leaves that
// opener writing fragments nothing can later read, so the create is exclusive
// and the loser re-reads instead of overwriting.
func TestConcurrentOpensAgreeOnTheKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "queue")
	const openers = 8
	keys := make(chan [32]byte, openers)
	errs := make(chan error, openers)
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Add(openers)
	for range openers {
		go func() {
			defer group.Done()
			<-start
			queue, err := Open(root, Options{MaximumFragments: 8,
				Key: Passphrase([]byte("correct horse"))})
			if err != nil {
				errs <- err
				return
			}
			keys <- queue.key
		}()
	}
	close(start)
	group.Wait()
	close(keys)
	close(errs)

	for err := range errs {
		t.Fatalf("a concurrent open failed: %v", err)
	}
	var first [32]byte
	seen := 0
	for key := range keys {
		if seen == 0 {
			first = key
		} else if key != first {
			t.Fatal("two concurrent opens of one queue derived different keys, " +
				"so one of them overwrote the salt the other had already used")
		}
		seen++
	}
	if seen != openers {
		t.Fatalf("%d of %d opens returned a key", seen, openers)
	}
}
