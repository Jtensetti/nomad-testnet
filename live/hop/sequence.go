package hop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const sequenceReservation = uint32(1 << 20)

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
		return errors.New("hop sequence exhausted; rotate the topology epoch")
	}
	reserved := previous + sequenceReservation
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], reserved)
	if err := atomicStateWrite(sequence.path, encoded[:]); err != nil {
		return fmt.Errorf("reserve hop sequence range: %w", err)
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
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() != 4 {
		return 0, errors.New("invalid hop sequence state")
	}
	var encoded [4]byte
	if _, err := io.ReadFull(file, encoded[:]); err != nil {
		return 0, err
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
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// ExhaustReservationForTest consumes the reserved range so that the next Next
// must reserve again. It exists so a test can drive the disk-backed
// reservation path without writing 2^20 cells, and it is a no-op on the
// production path: nothing outside a test calls it.
func (sequence *FileSequence) ExhaustReservationForTest() {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.next = sequence.reserved + 1
}
