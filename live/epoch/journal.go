package epoch

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrConflictingSignature is returned when an operator is asked to sign a
// second distinct descriptor digest for the same epoch. The refusal is the
// operator-side half of the split-brain defense; the persisted journal entry
// is evidence.
var ErrConflictingSignature = errors.New("refusing to sign a second descriptor for this epoch")

// Journal is the per-operator record of which descriptor digest was signed
// for each (network, epoch). It must be consulted before producing any
// activation, approval or attestation signature.
type Journal struct {
	mu   sync.Mutex
	root string
}

func OpenJournal(root string) (*Journal, error) {
	if root == "" {
		return nil, errors.New("signature journal directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("signature journal root is not a directory")
	}
	return &Journal{root: root}, nil
}

// Record notes that this operator signs digest for (network, epoch). The
// first call for an epoch wins; identical repeats are idempotent; a distinct
// digest is refused permanently.
func (journal *Journal) Record(networkID string, epochNumber uint64, digest [32]byte) error {
	if networkID == "" {
		return errors.New("network ID is required")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	path := filepath.Join(journal.root, fmt.Sprintf("%s-%020d.signed", networkID, epochNumber))
	encoded := []byte(hex.EncodeToString(digest[:]) + "\n")
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) == string(encoded) {
			return nil
		}
		return fmt.Errorf("%w: epoch %d already signed as %s", ErrConflictingSignature, epochNumber, string(existing))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeNewFile(path, encoded, 0o600); err != nil {
		return err
	}
	return syncDir(journal.root)
}
