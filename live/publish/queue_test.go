package publish

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func testPublisher(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func openQueue(t *testing.T, maximum int) (*Queue, string) {
	t.Helper()
	root := t.TempDir()
	queue, err := Open(root, Options{MaximumFragments: maximum})
	if err != nil {
		t.Fatal(err)
	}
	return queue, root
}

func TestSubmitIsIdempotent(t *testing.T) {
	queue, _ := openQueue(t, 64)
	publisher := testPublisher(t)
	object := bytes.Repeat([]byte("nomad publication idempotence "), 40)

	if err := queue.Submit(object, publisher); err != nil {
		t.Fatal(err)
	}
	first, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 {
		t.Fatal("submission produced no work")
	}
	if err := queue.Submit(object, publisher); err != nil {
		t.Fatalf("resubmitting the same object must succeed: %v", err)
	}
	second, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("resubmission must not duplicate work: %d then %d", first, second)
	}
}

func TestQueueIsBoundedAndFailsLocally(t *testing.T) {
	queue, _ := openQueue(t, 2)
	publisher := testPublisher(t)
	// An object needing more than two fragments cannot fit.
	large := bytes.Repeat([]byte("x"), 8*FragmentSize)
	if err := queue.Submit(large, publisher); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
	pending, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatal("a rejected submission must leave no partial work")
	}
}

func TestFragmentsAreEncryptedAtRest(t *testing.T) {
	queue, root := openQueue(t, 64)
	publisher := testPublisher(t)
	secret := []byte("the plaintext a user intended to publish")
	object := append(bytes.Repeat([]byte("padding "), 20), secret...)
	if err := queue.Submit(object, publisher); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".fragment" {
			continue
		}
		found = true
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, secret) {
			t.Fatal("pending publication content must not be readable on disk")
		}
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatal("queue entries must not be group or world readable")
		}
	}
	if !found {
		t.Fatal("no queue entry was written")
	}
}

func TestNextDrainsAndReconstructs(t *testing.T) {
	queue, _ := openQueue(t, 64)
	publisher := testPublisher(t)
	object := bytes.Repeat([]byte("reconstruct me "), 60)
	if err := queue.Submit(object, publisher); err != nil {
		t.Fatal(err)
	}
	pending, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	fragments := make([]Fragment, 0, pending)
	for {
		fragment, err := queue.Next()
		if errors.Is(err, ErrNoWork) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, fragment)
	}
	if len(fragments) != pending {
		t.Fatalf("expected %d fragments, drained %d", pending, len(fragments))
	}
	// Every fragment is exactly one cell payload, regardless of position.
	for _, fragment := range fragments {
		if len(fragment.Payload) != FragmentSize {
			t.Fatal("fragments must all be exactly one cell payload")
		}
		if fragment.Total != uint32(len(fragments)) {
			t.Fatal("fragment total mismatch")
		}
	}
	if remaining, err := queue.Pending(); err != nil || remaining != 0 {
		t.Fatalf("queue must be empty after draining, got %d (%v)", remaining, err)
	}
}

func TestQueueSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	queue, err := Open(root, Options{MaximumFragments: 64})
	if err != nil {
		t.Fatal(err)
	}
	publisher := testPublisher(t)
	object := bytes.Repeat([]byte("persisted work "), 30)
	if err := queue.Submit(object, publisher); err != nil {
		t.Fatal(err)
	}
	before, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root, Options{MaximumFragments: 64})
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restart must preserve pending work: %d then %d", before, after)
	}
	if _, err := reopened.Next(); err != nil {
		t.Fatalf("recovered work must be usable: %v", err)
	}
}

func TestCorruptEntryIsDroppedNotRetried(t *testing.T) {
	queue, root := openQueue(t, 64)
	publisher := testPublisher(t)
	if err := queue.Submit([]byte("small object"), publisher); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".fragment" {
			continue
		}
		path := filepath.Join(root, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 0xff
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := queue.Next(); err == nil {
		t.Fatal("a tampered entry must not authenticate")
	}
	if pending, err := queue.Pending(); err != nil || pending != 0 {
		t.Fatalf("a corrupt entry must be dropped, not retried: %d (%v)", pending, err)
	}
}

func TestDrainOrderIsContentDerivedNotSubmissionOrder(t *testing.T) {
	publisher := testPublisher(t)
	objects := [][]byte{
		bytes.Repeat([]byte("alpha "), 10),
		bytes.Repeat([]byte("beta "), 10),
		bytes.Repeat([]byte("gamma "), 10),
	}
	drain := func(order []int) []string {
		queue, _ := openQueue(t, 64)
		for _, index := range order {
			if err := queue.Submit(objects[index], publisher); err != nil {
				t.Fatal(err)
			}
		}
		ids := make([]string, 0, len(order))
		for {
			fragment, err := queue.Next()
			if errors.Is(err, ErrNoWork) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, string(fragment.ID[:]))
		}
		return ids
	}
	forward := drain([]int{0, 1, 2})
	reverse := drain([]int{2, 1, 0})
	if strings.Join(forward, "|") != strings.Join(reverse, "|") {
		t.Fatal("drain order must depend only on content identifiers, not on when the user published")
	}
}

// TestPackageHasNoNetworkCapability is an architectural gate. The airlock's
// central claim is that Publish cannot influence the network, so this
// package must not be able to reach a socket, a transport, a peer plan or a
// scheduler even transitively through its own imports.
func TestPackageHasNoNetworkCapability(t *testing.T) {
	forbidden := []string{
		"net", "net/http", "net/url", "os/exec", "syscall",
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
		"github.com/Jtensetti/nomad-testnet/live/node",
		"github.com/Jtensetti/nomad-testnet/live/hop",
		"github.com/Jtensetti/nomad-testnet/live/fetchplan",
		"github.com/Jtensetti/nomad-testnet/live/partialfetch",
	}
	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for name, file := range pkg.Files {
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, banned := range forbidden {
					if path == banned {
						t.Fatalf("%s imports %q: the publication API must have no network capability", name, path)
					}
				}
			}
		}
	}
}
