package epoch

import "errors"

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

// ScopedSet returns identities whose verified revocations were observed before
// targetEpoch. Persisted revocation files loaded after a restart are not usable
// here until Revalidate has checked them against the exact historical chain.
func (store *RevocationStore) ScopedSet(targetEpoch uint64) (RevocationSet, error) {
	if targetEpoch == 0 {
		return nil, errors.New("target epoch must be non-zero")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.validated {
		return nil, errors.New("revocation store contains persisted state that has not been revalidated against the epoch chain")
	}
	set := make(RevocationSet)
	for key, revocation := range store.byKey {
		if revocation.EpochObserved < targetEpoch {
			set[key] = struct{}{}
		}
	}
	return set, nil
}
