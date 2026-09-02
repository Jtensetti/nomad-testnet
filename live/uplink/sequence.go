package uplink

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

// The uplink sequence is the AEAD nonce. That is the whole reason this file
// exists.
//
// Session.seal derives its nonce from the sequence it is given, so two cells
// sealed under one session key with the same sequence are a nonce reuse: with
// a stream cipher that hands an observer the XOR of two plaintexts, and with a
// polynomial MAC it can hand them the authentication key. Nothing about the
// protocol prevents it, because nothing about the protocol chooses the
// sequence -- the caller does.
//
// Every caller until now was an in-process test that counted from one and
// never restarted, so the question never arose. A publisher process does
// restart, and a publisher that counted from one again on each start would
// re-seal different fragments under nonces it had already used. This was found
// by trying to build the production path rather than by reading the code.
//
// So the publisher's sequence is durable and reserved ahead, the same shape as
// the operator's hop sequence: a crash skips the unused part of a reserved
// range rather than replaying it. Losing the file is not recoverable by
// restoring a backup -- see the operator runbook for why that is worse than
// losing it -- and requires a new session key.
const sequenceReservation = uint64(1 << 20)

// A failed reservation write is a local condition; an exhausted or unreadable
// nonce space is not. A caller that cannot tell them apart cannot respond
// correctly to either, and the second must always fail closed.
var (
	ErrSequenceWriteFailed  = errors.New("uplink sequence reservation could not be written")
	ErrSequenceExhausted    = errors.New("uplink sequence exhausted; establish a new session")
	ErrSequenceStateInvalid = errors.New("uplink sequence state is invalid")
)

// FileSequence hands out uplink sequence numbers that are never reused across
// restarts.
type FileSequence struct {
	mu       sync.Mutex
	path     string
	next     uint64
	reserved uint64
}

// OpenFileSequence opens or creates the durable sequence state at path.
//
// The state is per session key. Pointing two sessions at one file, or one
// session at two files, both reuse nonces; the caller owns that pairing and
// nothing here can check it.
func OpenFileSequence(path string) (*FileSequence, error) {
	if path == "" {
		return nil, errors.New("uplink sequence state path is required")
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

// Next returns a sequence number that has never been returned before, by this
// process or any earlier one sharing the same state file.
func (sequence *FileSequence) Next() (uint64, error) {
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
	if previous > ^uint64(0)-sequenceReservation {
		return ErrSequenceExhausted
	}
	reserved := previous + sequenceReservation
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], reserved)
	if err := atomicStateWrite(sequence.path, encoded[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrSequenceWriteFailed, err)
	}
	// A sequence of zero is refused by seal, so the first value is one.
	sequence.next = previous + 1
	sequence.reserved = reserved
	return nil
}

func readReservation(path string) (uint64, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	if !info.Mode().IsRegular() || info.Size() != 8 {
		return 0, ErrSequenceStateInvalid
	}
	var encoded [8]byte
	if _, err := io.ReadFull(file, encoded[:]); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSequenceStateInvalid, err)
	}
	return binary.BigEndian.Uint64(encoded[:]), nil
}

// atomicStateWrite replaces the state file or leaves the previous one intact.
// A half-written reservation that read back low would be a nonce replay, so
// the write is to a temporary file that is synced and renamed.
func atomicStateWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".uplink-sequence-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return durable.Directory(directory)
}
