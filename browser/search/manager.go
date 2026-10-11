package search

import (
	"fmt"
	"path/filepath"
	"sync"
)

// IndexRoot is the directory under which every index lives, one per model.
const IndexRoot = "semantic-index"

// Manager holds one index per fingerprint.
//
// Embeddings from different models are not comparable, so they do not share a
// store. Keeping them apart rather than overwriting also makes switching models
// reversible: the previous index is still there and still correct, so a reader
// who tries a model and goes back does not re-embed their whole library.
type Manager struct {
	root string

	mutex   sync.Mutex
	indexes map[string]*Index
}

// NewManager returns a manager storing indexes under root.
func NewManager(root string) *Manager {
	return &Manager{root: root, indexes: map[string]*Index{}}
}

// Directory is where the index for one fingerprint belongs.
//
// The fingerprint is validated rather than trusted, because it is being used as
// a path component. A fingerprint that came from a manifest is hex by
// construction; one that came from a directory listing or a configuration file
// is whatever was there.
func (m *Manager) Directory(fingerprint string) (string, error) {
	if err := ValidFingerprint(fingerprint); err != nil {
		return "", err
	}
	return filepath.Join(m.root, IndexRoot, fingerprint), nil
}

// Open returns the index for a configuration, creating it on first use.
//
// Two configurations with the same fingerprint are the same index: that is what
// a fingerprint means. Two with different fingerprints never share one, even
// when they name the same model.
func (m *Manager) Open(config Config) (*Index, error) {
	if err := ValidFingerprint(config.Fingerprint); err != nil {
		return nil, err
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if existing, ok := m.indexes[config.Fingerprint]; ok {
		if existing.Provenance() != config.Provenance {
			// One fingerprint, two provenances means something that changes a
			// vector is not in the fingerprint, which is the failure the
			// fingerprint exists to prevent.
			return nil, fmt.Errorf("fingerprint %s is already open under provenance %q "+
				"and was requested under %q; one of the two identities is wrong",
				config.Fingerprint[:12], existing.Provenance(), config.Provenance)
		}
		return existing, nil
	}
	index, err := New(config)
	if err != nil {
		return nil, err
	}
	m.indexes[config.Fingerprint] = index
	return index, nil
}
