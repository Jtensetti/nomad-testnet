// Package rawcache is the one-way boundary between the live network process
// and local reconstruction. It stores only authenticated mix ciphertext and
// public batch coordinates; it has no query, embedding or reconstruction API.
package rawcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Jtensetti/nomad-testnet/live/hop"
)

var (
	ErrEquivocation = errors.New("conflicting ciphertext for stream coordinate")
	ErrCacheFull    = errors.New("raw cache stream limit reached")
)

type Store struct {
	mu         sync.Mutex
	root       string
	maxStreams int
}

func Open(root string, maxStreams int) (*Store, error) {
	if root == "" {
		return nil, errors.New("raw cache path is required")
	}
	if maxStreams < 1 || maxStreams > 4096 {
		return nil, errors.New("raw cache stream limit is outside the supported range")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("raw cache root is not a directory")
	}
	return &Store{root: root, maxStreams: maxStreams}, nil
}

// Put writes an immutable work cell. It returns true only for a new cache
// coordinate; callers use that signal to avoid replay-driven relay work.
func (store *Store) Put(metadata hop.Metadata, payload [hop.CiphertextSize]byte) (bool, error) {
	if store == nil {
		return false, errors.New("raw cache is required")
	}
	if !hop.IsWork(metadata) {
		return false, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	streamPath := filepath.Join(store.root, hex.EncodeToString(metadata.Stream[:]))
	if _, err := os.Lstat(streamPath); errors.Is(err, os.ErrNotExist) {
		count, err := store.streamCount()
		if err != nil {
			return false, err
		}
		if count >= store.maxStreams {
			return false, ErrCacheFull
		}
		if err := os.Mkdir(streamPath, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return false, err
		}
		var batchSize [2]byte
		binary.BigEndian.PutUint16(batchSize[:], metadata.BatchSize)
		if err := writeImmutable(filepath.Join(streamPath, "batch-size"), batchSize[:]); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	}
	if err := verifyBatchSize(streamPath, metadata.BatchSize); err != nil {
		return false, err
	}
	cellPath := filepath.Join(streamPath, fmt.Sprintf("%05d.cell", metadata.Ordinal))
	created, err := writeOrCompare(cellPath, payload[:])
	if err != nil {
		return false, err
	}
	if created {
		if err := syncDirectory(streamPath); err != nil {
			return false, err
		}
	}
	return created, nil
}

func (store *Store) Complete(stream hop.StreamID) (bool, error) {
	_, complete, err := store.Load(stream)
	return complete, err
}

func (store *Store) Load(stream hop.StreamID) ([][hop.CiphertextSize]byte, bool, error) {
	if store == nil {
		return nil, false, errors.New("raw cache is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	streamPath := filepath.Join(store.root, hex.EncodeToString(stream[:]))
	batchSize, err := readBatchSize(streamPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	payloads := make([][hop.CiphertextSize]byte, batchSize)
	for ordinal := uint16(0); ordinal < batchSize; ordinal++ {
		cellPath := filepath.Join(streamPath, fmt.Sprintf("%05d.cell", ordinal))
		file, err := os.Open(cellPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != hop.CiphertextSize {
			_ = file.Close()
			return nil, false, errors.New("cached ciphertext has invalid type or size")
		}
		_, readErr := io.ReadFull(file, payloads[ordinal][:])
		closeErr := file.Close()
		if readErr != nil {
			return nil, false, readErr
		}
		if closeErr != nil {
			return nil, false, closeErr
		}
	}
	calculated, err := hop.StreamFor(payloads)
	if err != nil {
		return nil, false, err
	}
	if calculated != stream {
		return nil, false, ErrEquivocation
	}
	return payloads, true, nil
}

func (store *Store) CompleteStreams() ([]hop.StreamID, error) {
	if store == nil {
		return nil, errors.New("raw cache is required")
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	out := make([]hop.StreamID, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 32 {
			continue
		}
		decoded, err := hex.DecodeString(entry.Name())
		if err != nil || len(decoded) != len(hop.StreamID{}) {
			continue
		}
		var stream hop.StreamID
		copy(stream[:], decoded)
		complete, err := store.Complete(stream)
		if err != nil {
			return nil, err
		}
		if complete {
			out = append(out, stream)
		}
	}
	return out, nil
}

func (store *Store) streamCount() (int, error) {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) == 32 {
			count++
		}
	}
	return count, nil
}

func verifyBatchSize(streamPath string, expected uint16) error {
	observed, err := readBatchSize(streamPath)
	if err != nil {
		return err
	}
	if observed != expected {
		return ErrEquivocation
	}
	return nil
}

func readBatchSize(streamPath string) (uint16, error) {
	file, err := os.Open(filepath.Join(streamPath, "batch-size"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 2 {
		return 0, errors.New("invalid cached batch size")
	}
	var encoded [2]byte
	if _, err := io.ReadFull(file, encoded[:]); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint16(encoded[:])
	if value < 2 || value > hop.MaximumBatch {
		return 0, errors.New("cached batch size is outside the supported range")
	}
	return value, nil
}

func writeOrCompare(path string, data []byte) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return false, ErrEquivocation
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := writeImmutable(path, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			return writeOrCompare(path, data)
		}
		return false, err
	}
	return true, nil
}

func writeImmutable(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".incoming-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
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
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
