// Package publish is the local half of the publication airlock. It accepts
// an object from the user, canonicalizes and encrypts it into fixed-size
// fragments, and stores them in a bounded, crash-safe, idempotent local
// queue.
//
// This package deliberately has NO network capability. It imports no socket,
// transport, peer-selection or scheduler package, and it exposes no method
// that can transmit, advertise, flush, reprioritize or change the timing of
// anything. The only way a fragment leaves the queue is that a separate
// constant-rate scheduler, running on its own public clock, pulls one. That
// pull-only direction is what makes publication unable to modulate an
// observable network event, and it is enforced by the dependency gate in CI
// as well as by this package's API shape.
package publish

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	// FragmentSize is the plaintext payload carried by one uplink cell. It
	// matches the mix cleartext size so a fragment occupies exactly one
	// ordinary cell with no size signal.
	FragmentSize = 504

	// MaximumObjectBytes bounds a single publication.
	MaximumObjectBytes = 262_144

	fragmentIDDomain = "nomad-publication-fragment-v1"
	entryIDDomain    = "nomad-publication-entry-v1"
	keyFileName      = "queue.key"
)

var (
	// ErrQueueFull is returned when the bounded queue cannot accept more
	// work. Publication fails locally and silently; it never escalates into
	// extra traffic or a schedule change.
	ErrQueueFull = errors.New("publication queue is full")
	// ErrNoWork reports an empty queue. The scheduler treats this as "emit
	// cover" and must not distinguish it from any other condition.
	ErrNoWork = errors.New("no publication work available")
)

// Fragment is one encrypted, fixed-size unit of pending publication work.
type Fragment struct {
	// ID is deterministic in the object and index, which makes repeated
	// submission of the same object idempotent rather than duplicative.
	ID      [32]byte
	Index   uint32
	Total   uint32
	Payload [FragmentSize]byte
}

// Queue is a bounded, persistent, crash-safe publication queue.
type Queue struct {
	mu           sync.Mutex
	root         string
	maxFragments int
	key          [32]byte
}

// Options bound the queue and say where its key comes from. The limit is
// public deployment policy and is never derived from user behavior.
type Options struct {
	MaximumFragments int
	// Key is required and has no default. What a stolen disk yields differs
	// between the two sources, and that is the whole question for material a
	// user has written and not yet published, so it is stated rather than
	// inherited. See KeySource.
	Key KeySource
}

// Open prepares the queue directory and derives its encryption key from
// options.Key.
//
// What the key protects depends on which source supplied it, and the two are
// not interchangeable: Passphrase keeps nothing on the disk that opens the
// queue, while UnprotectedKeyFile writes the key beside the fragments and so
// gives binding and tamper-evidence rather than secrecy against disk theft.
func Open(root string, options Options) (*Queue, error) {
	if root == "" {
		return nil, errors.New("publication queue directory is required")
	}
	if options.MaximumFragments < 1 || options.MaximumFragments > 1<<20 {
		return nil, errors.New("queue fragment limit is outside the supported range")
	}
	if options.Key == nil {
		return nil, errors.New("publication queue requires a key source: " +
			"Passphrase for a disk that must not open the queue, " +
			"UnprotectedKeyFile to keep the key beside the fragments")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("publication queue root is not a directory")
	}
	queue := &Queue{root: root, maxFragments: options.MaximumFragments}
	key, err := options.Key.openKey(root)
	if err != nil {
		return nil, err
	}
	queue.key = key
	return queue, nil
}

// Submit is the entire public publication API. It is a purely local
// operation: it canonicalizes, fragments, encrypts and stores. It opens no
// socket, selects no peer, schedules nothing and returns no handle that
// could be used to transmit. Its only externally visible effect is disk
// state inside the queue directory.
//
// Submitting the same object twice is idempotent: fragment identifiers are
// deterministic, so the second submission rewrites identical bytes rather
// than enqueuing duplicate work.
func (queue *Queue) Submit(object []byte, publisher ed25519.PublicKey) error {
	if len(object) == 0 || len(object) > MaximumObjectBytes {
		return errors.New("object is empty or too large")
	}
	if len(publisher) != ed25519.PublicKeySize {
		return errors.New("publisher public key is required")
	}
	root := sha256.Sum256(object)
	fragments, err := queue.fragmentObject(root, object)
	if err != nil {
		return err
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	pending, err := queue.countLocked()
	if err != nil {
		return err
	}
	existing := 0
	for _, fragment := range fragments {
		if _, err := os.Lstat(queue.pathFor(fragment.ID)); err == nil {
			existing++
		}
	}
	if pending+len(fragments)-existing > queue.maxFragments {
		return ErrQueueFull
	}
	for _, fragment := range fragments {
		encoded, err := queue.sealFragment(fragment)
		if err != nil {
			return err
		}
		if err := writeOrCompare(queue.pathFor(fragment.ID), encoded); err != nil {
			return err
		}
	}
	return syncDir(queue.root)
}

func (queue *Queue) fragmentObject(root [32]byte, object []byte) ([]Fragment, error) {
	// Each fragment carries a header (index, total, object length, root)
	// followed by object bytes, padded to exactly FragmentSize. Every
	// fragment is the same size regardless of object length, so fragment
	// count is the only content-dependent quantity and it never reaches the
	// scheduler.
	const headerSize = 4 + 4 + 4 + 32
	const bodySize = FragmentSize - headerSize
	total := (len(object) + bodySize - 1) / bodySize
	if total == 0 || total > 1<<20 {
		return nil, errors.New("object fragment count is outside the supported range")
	}
	fragments := make([]Fragment, 0, total)
	for index := 0; index < total; index++ {
		start := index * bodySize
		end := start + bodySize
		if end > len(object) {
			end = len(object)
		}
		var fragment Fragment
		fragment.Index = uint32(index)
		fragment.Total = uint32(total)
		binary.BigEndian.PutUint32(fragment.Payload[0:4], uint32(index))
		binary.BigEndian.PutUint32(fragment.Payload[4:8], uint32(total))
		binary.BigEndian.PutUint32(fragment.Payload[8:12], uint32(len(object)))
		copy(fragment.Payload[12:44], root[:])
		copy(fragment.Payload[headerSize:], object[start:end])
		fragment.ID = fragmentID(root, uint32(index))
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func fragmentID(root [32]byte, index uint32) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(fragmentIDDomain))
	_, _ = h.Write(root[:])
	var integer [4]byte
	binary.BigEndian.PutUint32(integer[:], index)
	_, _ = h.Write(integer[:])
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// sealFragment encrypts a fragment at rest, under the key options.Key
// supplied -- so what this hides from whoever holds the disk is a property of
// the key source, not of this function. The fragment's own identifier is the
// additional data either way, so a fragment cannot be renamed, altered, or
// moved between queues whichever source is in use. The nonce is derived
// deterministically from the fragment identifier so that resubmitting the
// same object produces byte-identical files, which is what makes the
// idempotent write safe. A fragment identifier is never reused with a
// different plaintext because it commits to the object root and index.
func (queue *Queue) sealFragment(fragment Fragment) ([]byte, error) {
	block, err := aes.NewCipher(queue.key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	digest := sha256.Sum256(append([]byte(entryIDDomain), fragment.ID[:]...))
	copy(nonce, digest[:aead.NonceSize()])
	plaintext := make([]byte, 8, 8+FragmentSize)
	binary.BigEndian.PutUint32(plaintext[0:4], fragment.Index)
	binary.BigEndian.PutUint32(plaintext[4:8], fragment.Total)
	plaintext = append(plaintext, fragment.Payload[:]...)
	return aead.Seal(nil, nonce, plaintext, fragment.ID[:]), nil
}

func (queue *Queue) openFragment(id [32]byte, sealed []byte) (Fragment, error) {
	block, err := aes.NewCipher(queue.key[:])
	if err != nil {
		return Fragment{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Fragment{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	digest := sha256.Sum256(append([]byte(entryIDDomain), id[:]...))
	copy(nonce, digest[:aead.NonceSize()])
	plaintext, err := aead.Open(nil, nonce, sealed, id[:])
	if err != nil {
		return Fragment{}, errors.New("publication fragment failed authentication")
	}
	if len(plaintext) != 8+FragmentSize {
		return Fragment{}, errors.New("publication fragment has unexpected length")
	}
	fragment := Fragment{
		ID:    id,
		Index: binary.BigEndian.Uint32(plaintext[0:4]),
		Total: binary.BigEndian.Uint32(plaintext[4:8]),
	}
	copy(fragment.Payload[:], plaintext[8:])
	return fragment, nil
}

func (queue *Queue) pathFor(id [32]byte) string {
	return filepath.Join(queue.root, hex.EncodeToString(id[:])+".fragment")
}

// Next removes and returns one pending fragment. It is called only by the
// constant-rate scheduler on its own public clock. It reports ErrNoWork for
// an empty queue; the caller must respond by emitting cover, never by
// changing when or whether it emits.
func (queue *Queue) Next() (Fragment, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	names, err := queue.listLocked()
	if err != nil {
		return Fragment{}, err
	}
	if len(names) == 0 {
		return Fragment{}, ErrNoWork
	}
	name := names[0]
	idBytes, err := hex.DecodeString(name[:len(name)-len(".fragment")])
	if err != nil || len(idBytes) != 32 {
		return Fragment{}, errors.New("malformed queue entry name")
	}
	var id [32]byte
	copy(id[:], idBytes)
	path := filepath.Join(queue.root, name)
	sealed, err := os.ReadFile(path)
	if err != nil {
		return Fragment{}, err
	}
	fragment, err := queue.openFragment(id, sealed)
	if err != nil {
		// A corrupt entry is dropped rather than retried, so a damaged
		// queue cannot cause repeated work or distinguishable behavior.
		_ = os.Remove(path)
		return Fragment{}, err
	}
	if err := os.Remove(path); err != nil {
		return Fragment{}, err
	}
	return fragment, syncDir(queue.root)
}

// Pending reports the queue depth. It exists for local bounds enforcement
// and tests. It must never be exported into telemetry, logs or any
// network-visible behavior.
func (queue *Queue) Pending() (int, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.countLocked()
}

func (queue *Queue) countLocked() (int, error) {
	names, err := queue.listLocked()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

func (queue *Queue) listLocked() ([]string, error) {
	entries, err := os.ReadDir(queue.root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".fragment" {
			continue
		}
		names = append(names, name)
	}
	// Deterministic order by fragment identifier. The order is a function
	// of content identifiers only, never of submission time, so drain order
	// leaks no timing information about when the user published.
	sort.Strings(names)
	return names, nil
}

func writeOrCompare(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil {
		if len(existing) == len(data) {
			same := true
			for index := range existing {
				if existing[index] != data[index] {
					same = false
					break
				}
			}
			if same {
				return nil
			}
		}
		return fmt.Errorf("conflicting publication fragment at %s", filepath.Base(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeNewFile(path, data, 0o600)
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".publish-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
