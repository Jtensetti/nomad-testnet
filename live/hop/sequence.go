package hop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Jtensetti/nomad-testnet/live/durable"
)

const sequenceReservation = uint32(1 << 20)

// The three ways Next can fail are not the same kind of event, and a caller
// that cannot tell them apart cannot respond correctly to any of them.
//
// ErrSequenceWriteFailed is a disk that would not take the reservation: a
// local, transient condition. The other two are the nonce space itself being
// unusable -- exhausted, or its durable state unreadable -- and both mean
// authenticated sequence numbers can no longer be guaranteed unique. They
// must fail closed. Their own message says to rotate the epoch, and a caller
// that treats them as a lost cell would tick forever past the condition the
// message describes.
var (
	ErrSequenceWriteFailed  = errors.New("hop sequence reservation could not be written")
	ErrSequenceExhausted    = errors.New("hop sequence exhausted; rotate the topology epoch")
	ErrSequenceStateInvalid = errors.New("hop sequence state is invalid")
)

// FileSequence reserves sequence ranges durably before use. A crash skips the
// unused part of a range rather than reusing authenticated nonces. Deleting the
// state requires rotating the topology epoch and pairwise keys.
type FileSequence struct {
	mu       sync.Mutex
	path     string
	next     uint32
	reserved uint32
}

func OpenFileSequence(path string) (*FileSequence, error) {
	if path == "" {
		return nil, errors.New("sequence state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	sequence := &FileSequence{path: path}
	if err := sequence.reserve(); err != nil {
		return nil, err
	}
	return sequence, nil
}

func (sequence *FileSequence) Next() (uint32, error) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.next == 0 || sequence.next > sequence.reserved {
		if err := sequence.reserve(); err != nil {
			return 0, err
		}
	}
	value := sequence.next
	sequence.next++
	return value, nil
}

func (sequence *FileSequence) reserve() error {
	previous, err := readReservation(sequence.path)
	if err != nil {
		return err
	}
	if previous > ^uint32(0)-sequenceReservation {
		return ErrSequenceExhausted
	}
	reserved := previous + sequenceReservation
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], reserved)
	if err := atomicStateWrite(sequence.path, encoded[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrSequenceWriteFailed, err)
	}
	sequence.next = previous + 1
	sequence.reserved = reserved
	return nil
}

func readReservation(path string) (uint32, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	if !info.Mode().IsRegular() || info.Size() != 4 {
		return 0, ErrSequenceStateInvalid
	}
	var encoded [4]byte
	if _, err := io.ReadFull(file, encoded[:]); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	return binary.BigEndian.Uint32(encoded[:]), nil
}

func atomicStateWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sequence-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return durable.Directory(directory)
}

// Return gives back a sequence number that was issued but never reached the
// wire, so the next cell reuses it.
//
// This is safe precisely because the cell was not sent: uniqueness has to hold
// across cells a peer can observe, and a cell that failed at the socket is not
// one of those. It matters because the sequence is in the clear in every hop
// header, so a number that is issued and discarded leaves a visible gap -- an
// exact, per-cell count of local send failures, readable by the receiving peer
// and by any observer of the link.
//
// It returns only the most recently issued value, and only if nothing has been
// issued since. Anything else is a caller bug rather than a rollback, and is
// ignored rather than corrupting the counter.
func (sequence *FileSequence) Return(value uint32) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if value != 0 && sequence.next == value+1 {
		sequence.next = value
	}
}
