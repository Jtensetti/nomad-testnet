package epoch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	RevocationVersion = "nomad-operator-revocation-v1"
	revocationDomain  = "nomad-operator-revocation-v1"

	ReasonSelf       = "self"
	ReasonCompromise = "compromise"
)

type Revocation struct {
	Version       string   `json:"version"`
	NetworkID     string   `json:"network_id"`
	OperatorID    string   `json:"operator_id"`
	IdentityKey   string   `json:"identity_key"`
	EpochObserved uint64   `json:"epoch_observed"`
	Reason        string   `json:"reason"`
	Signatures    []Signer `json:"signatures"`
}

type Signer struct {
	OperatorID string `json:"operator_id"`
	Signature  string `json:"signature"`
}

func revocationCanonicalBytes(revocation Revocation) ([]byte, error) {
	if revocation.Version != RevocationVersion {
		return nil, errors.New("unsupported revocation version")
	}
	if !networkIDPattern.MatchString(revocation.NetworkID) {
		return nil, errors.New("invalid revocation network ID")
	}
	if !networkIDPattern.MatchString(revocation.OperatorID) {
		return nil, errors.New("invalid revocation operator ID")
	}
	if revocation.EpochObserved == 0 {
		return nil, errors.New("revocation must name the epoch it was observed in")
	}
	switch revocation.Reason {
	case ReasonSelf, ReasonCompromise:
	default:
		return nil, errors.New("unsupported revocation reason")
	}
	identity, err := decodeBase64(revocation.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("invalid revocation identity key")
	}
	canonical := make([]byte, 0, 192)
	canonical = appendString(canonical, revocation.Version)
	canonical = appendString(canonical, revocation.NetworkID)
	canonical = appendString(canonical, revocation.OperatorID)
	canonical = appendBytes(canonical, identity)
	canonical = appendUint64(canonical, revocation.EpochObserved)
	canonical = appendString(canonical, revocation.Reason)
	return canonical, nil
}

func RevocationMessage(revocation Revocation) ([]byte, error) {
	canonical, err := revocationCanonicalBytes(revocation)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(revocationDomain)+32)
	message = append(message, revocationDomain...)
	digest := sha256.Sum256(canonical)
	message = append(message, digest[:]...)
	return message, nil
}

func SignRevocation(revocation Revocation, operatorID string, identity ed25519.PrivateKey) (Revocation, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return Revocation{}, errors.New("signing identity is required")
	}
	message, err := RevocationMessage(revocation)
	if err != nil {
		return Revocation{}, err
	}
	signed := revocation
	signed.Signatures = append(append([]Signer(nil), revocation.Signatures...), Signer{
		OperatorID: operatorID,
		Signature:  base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message)),
	})
	return signed, nil
}

func VerifyRevocation(revocation Revocation, observed Verified) error {
	if revocation.NetworkID != observed.NetworkID {
		return errors.New("revocation belongs to a different network")
	}
	if revocation.EpochObserved != observed.Epoch {
		return errors.New("revocation does not match the supplied epoch")
	}
	message, err := RevocationMessage(revocation)
	if err != nil {
		return err
	}
	target, err := observed.Topology.OperatorByID(revocation.OperatorID)
	if err != nil {
		return fmt.Errorf("revoked operator %q is not in the observed epoch", revocation.OperatorID)
	}
	if target.IdentityKey != revocation.IdentityKey {
		return errors.New("revocation identity key does not match the observed epoch")
	}

	verified := make(map[string]struct{}, len(revocation.Signatures))
	for _, signer := range revocation.Signatures {
		if _, duplicate := verified[signer.OperatorID]; duplicate {
			return errors.New("duplicate revocation signer")
		}
		operator, err := observed.Topology.OperatorByID(signer.OperatorID)
		if err != nil {
			return fmt.Errorf("revocation signer %q is not in the observed epoch", signer.OperatorID)
		}
		public, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid signer identity key")
		}
		signature, err := decodeBase64(signer.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			return fmt.Errorf("invalid revocation signature from %s", signer.OperatorID)
		}
		verified[operator.ID] = struct{}{}
	}

	if revocation.Reason == ReasonSelf {
		if _, ok := verified[target.ID]; !ok {
			return errors.New("self-revocation requires the revoked operator's own signature")
		}
		return nil
	}
	peers := 0
	for id := range verified {
		if id != target.ID {
			peers++
		}
	}
	quorum := ApprovalQuorum(observed)
	if peers < quorum {
		return fmt.Errorf("compromise revocation requires %d peer signatures, got %d", quorum, peers)
	}
	return nil
}

func EncodeRevocation(revocation Revocation) ([]byte, error) {
	if _, err := revocationCanonicalBytes(revocation); err != nil {
		return nil, err
	}
	return json.MarshalIndent(revocation, "", "  ")
}

func DecodeRevocation(encoded []byte) (Revocation, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Revocation{}, errors.New("revocation is empty or too large")
	}
	var revocation Revocation
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&revocation); err != nil {
		return Revocation{}, fmt.Errorf("decode revocation: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Revocation{}, errors.New("trailing revocation data")
	}
	return revocation, nil
}

type persistedRevocation struct {
	Name       string
	Encoded    []byte
	Digest     [32]byte
	Revocation Revocation
}

// RevocationStore separates "present on local disk" from "verified against
// the signed epoch chain". Persisted files loaded after a restart are never
// used for future admission until Revalidate has checked their signatures and
// quorum against the exact EpochObserved descriptor.
type RevocationStore struct {
	mu        sync.Mutex
	root      string
	persisted map[string]persistedRevocation
	byKey     map[string]Revocation
	sorted    []string
	validated bool
}

func OpenRevocationStore(root string) (*RevocationStore, error) {
	if root == "" {
		return nil, errors.New("revocation store directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("revocation store root must be a real directory")
	}
	persisted, err := loadPersistedRevocations(root)
	if err != nil {
		return nil, err
	}
	store := &RevocationStore{
		root: root, persisted: persisted, byKey: make(map[string]Revocation),
		validated: len(persisted) == 0,
	}
	store.reindexLocked()
	return store, nil
}

// Revalidate verifies every persisted revocation against the exact historical
// epoch it names. It then re-reads the directory and requires byte-identical
// files before publishing the verified set, closing the TOCTOU window where a
// local process could replace a revocation during validation.
func (store *RevocationStore) Revalidate(chain *Chain) error {
	if chain == nil {
		return errors.New("verified epoch chain is required to revalidate revocations")
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	before, err := loadPersistedRevocations(store.root)
	if err != nil {
		store.validated = false
		store.byKey = make(map[string]Revocation)
		return err
	}
	verifiedByKey := make(map[string]Revocation)
	names := sortedPersistedNames(before)
	for _, name := range names {
		item := before[name]
		observed, found, err := chain.FreshEpoch(item.Revocation.EpochObserved)
		if err != nil {
			store.validated = false
			store.byKey = make(map[string]Revocation)
			return fmt.Errorf("load observed epoch for %s: %w", name, err)
		}
		if !found {
			store.validated = false
			store.byKey = make(map[string]Revocation)
			return fmt.Errorf("revocation %s names unstored epoch %d", name, item.Revocation.EpochObserved)
		}
		if err := VerifyRevocation(item.Revocation, observed); err != nil {
			store.validated = false
			store.byKey = make(map[string]Revocation)
			return fmt.Errorf("stored revocation %s failed verification: %w", name, err)
		}
		mergeRevocation(verifiedByKey, item.Revocation)
	}
	after, err := loadPersistedRevocations(store.root)
	if err != nil {
		store.validated = false
		store.byKey = make(map[string]Revocation)
		return err
	}
	if !samePersistedRevocations(before, after) {
		store.validated = false
		store.byKey = make(map[string]Revocation)
		return errors.New("revocation store changed during revalidation")
	}
	store.persisted = after
	store.byKey = verifiedByKey
	store.validated = true
	store.reindexLocked()
	return nil
}

// Accept verifies and persists a revocation. A store that was already fully
// validated remains validated after accepting a new verified statement. If
// another process changed the directory since this object opened, the store
// falls back to unvalidated state until Revalidate is run again.
func (store *RevocationStore) Accept(encoded []byte, observed Verified) error {
	revocation, err := DecodeRevocation(encoded)
	if err != nil {
		return err
	}
	if err := VerifyRevocation(revocation, observed); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	disk, err := loadPersistedRevocations(store.root)
	if err != nil {
		return err
	}
	if !samePersistedRevocations(store.persisted, disk) {
		store.validated = false
		store.byKey = make(map[string]Revocation)
	}
	store.persisted = disk

	digest := sha256.Sum256(encoded)
	name := fmt.Sprintf("%s-%x.revocation", revocation.OperatorID, digest[:8])
	path := filepath.Join(store.root, name)
	if existing, exists := store.persisted[name]; exists {
		if !bytes.Equal(existing.Encoded, encoded) {
			return errors.New("revocation filename collision with different bytes")
		}
	} else {
		if err := writeNewFile(path, encoded, 0o600); err != nil {
			return err
		}
		if err := syncDir(store.root); err != nil {
			return err
		}
		store.persisted[name] = persistedRevocation{Name: name, Encoded: append([]byte(nil), encoded...), Digest: digest, Revocation: revocation}
	}
	if store.validated {
		mergeRevocation(store.byKey, revocation)
	}
	store.reindexLocked()
	return nil
}

// Set is retained for existing in-process callers. Fresh stores and stores
// that have run Revalidate return only verified identities. If persisted state
// exists but has not been revalidated, it conservatively exposes those keys as
// revoked rather than silently permitting future admission. Production code
// should use Revalidate + ScopedSet, which can report validation failure.
func (store *RevocationStore) Set() RevocationSet {
	store.mu.Lock()
	defer store.mu.Unlock()
	set := make(RevocationSet)
	if store.validated {
		for key := range store.byKey {
			set[key] = struct{}{}
		}
		return set
	}
	for _, item := range store.persisted {
		set[item.Revocation.IdentityKey] = struct{}{}
	}
	return set
}

func (store *RevocationStore) Revoked(identityKey string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.validated && len(store.persisted) > 0 {
		return true
	}
	_, exists := store.byKey[identityKey]
	return exists
}

func (store *RevocationStore) reindexLocked() {
	store.sorted = store.sorted[:0]
	for key := range store.byKey {
		store.sorted = append(store.sorted, key)
	}
	sort.Strings(store.sorted)
}

func loadPersistedRevocations(root string) (map[string]persistedRevocation, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := make(map[string]persistedRevocation)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".revocation" {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumFileBytes {
			return nil, fmt.Errorf("stored revocation %s is not a bounded regular file", entry.Name())
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		revocation, err := DecodeRevocation(encoded)
		if err != nil {
			return nil, fmt.Errorf("stored revocation %s: %w", entry.Name(), err)
		}
		result[entry.Name()] = persistedRevocation{
			Name: entry.Name(), Encoded: append([]byte(nil), encoded...), Digest: sha256.Sum256(encoded), Revocation: revocation,
		}
	}
	return result, nil
}

func samePersistedRevocations(left, right map[string]persistedRevocation) bool {
	if len(left) != len(right) {
		return false
	}
	for name, item := range left {
		other, ok := right[name]
		if !ok || item.Digest != other.Digest || !bytes.Equal(item.Encoded, other.Encoded) {
			return false
		}
	}
	return true
}

func sortedPersistedNames(values map[string]persistedRevocation) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func mergeRevocation(target map[string]Revocation, candidate Revocation) {
	current, exists := target[candidate.IdentityKey]
	if !exists || candidate.EpochObserved < current.EpochObserved {
		target[candidate.IdentityKey] = candidate
	}
}
