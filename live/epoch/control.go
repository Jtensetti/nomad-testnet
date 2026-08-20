package epoch

import (
	"errors"
)

// DescriptorIdentity reads the claimed network and epoch from a descriptor
// without treating them as trusted. Callers use this only to select the
// historical revocation scope; Chain.Append still performs full verification.
func DescriptorIdentity(encoded []byte) (string, uint64, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return "", 0, errors.New("epoch descriptor is empty or too large")
	}
	descriptor, err := decodeDescriptor(encoded)
	if err != nil {
		return "", 0, err
	}
	return embeddedIdentity(descriptor)
}

// ScopedSet returns the identities that were already revoked before the
// target epoch. A revocation observed during epoch N is forward-scoped: it
// must not retroactively invalidate N, but it blocks that identity from N+1
// and later descriptors and from approving the N -> N+1 transition.
func (store *RevocationStore) ScopedSet(targetEpoch uint64) (RevocationSet, error) {
	if targetEpoch == 0 {
		return nil, errors.New("target epoch must be non-zero")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	set := make(RevocationSet)
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".revocation" {
			continue
		}
		encoded, err := os.ReadFile(filepath.Join(store.root, entry.Name()))
		if err != nil {
			return nil, err
		}
		revocation, err := DecodeRevocation(encoded)
		if err != nil {
			return nil, err
		}
		if revocation.EpochObserved < targetEpoch {
			set[revocation.IdentityKey] = struct{}{}
		}
	}
	return set, nil
}
