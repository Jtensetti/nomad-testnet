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

	// ReasonSelf is a voluntary self-revocation by the operator itself.
	ReasonSelf = "self"
	// ReasonCompromise is a revocation asserted by a quorum of peers.
	ReasonCompromise = "compromise"
)

// Revocation withdraws an operator identity. It is authorized either by the
// revoked operator itself, or by an approval-quorum of the operators of the
// epoch in which the compromise was observed. Quorum authorization exists so
// that a compromised operator that will not cooperate can still be removed,
// while a single peer cannot evict another.
type Revocation struct {
	Version       string   `json:"version"`
	NetworkID     string   `json:"network_id"`
	OperatorID    string   `json:"operator_id"`
	IdentityKey   string   `json:"identity_key"`
	EpochObserved uint64   `json:"epoch_observed"`
	Reason        string   `json:"reason"`
	Signatures    []Signer `json:"signatures"`
}

// Signer is one signature over a revocation statement.
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

// RevocationMessage is the exact signing message for a revocation.
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

// SignRevocation adds one signature to a revocation statement.
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

// VerifyRevocation checks a revocation against the epoch in which the
// compromise was observed. Self-revocation needs the revoked identity's own
// signature; compromise revocation needs an approval quorum of that epoch's
// other operators, so no single peer can evict another.
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
	// Compromise: count only peers other than the target, and require the
	// same quorum that authorizes a membership transition.
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

// RevocationStore is the persisted set of accepted revocations. It is the
// source of the RevocationSet a chain admits new descriptors against.
type RevocationStore struct {
	mu     sync.Mutex
	root   string
	byKey  map[string]Revocation
	sorted []string
}

func OpenRevocationStore(root string) (*RevocationStore, error) {
	if root == "" {
		return nil, errors.New("revocation store directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	store := &RevocationStore{root: root, byKey: make(map[string]Revocation)}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".revocation" {
			continue
		}
		encoded, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		revocation, err := DecodeRevocation(encoded)
		if err != nil {
			return nil, fmt.Errorf("stored revocation %s: %w", entry.Name(), err)
		}
		store.byKey[revocation.IdentityKey] = revocation
	}
	store.reindexLocked()
	return store, nil
}

// Accept verifies and persists a revocation. Accepting the same revocation
// twice is idempotent.
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
	digest := sha256.Sum256(encoded)
	path := filepath.Join(store.root, fmt.Sprintf("%s-%x.revocation", revocation.OperatorID, digest[:8]))
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeNewFile(path, encoded, 0o600); err != nil {
			return err
		}
		if err := syncDir(store.root); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	store.byKey[revocation.IdentityKey] = revocation
	store.reindexLocked()
	return nil
}

// Set returns the revocation set for chain admission.
func (store *RevocationStore) Set() RevocationSet {
	store.mu.Lock()
	defer store.mu.Unlock()
	set := make(RevocationSet, len(store.byKey))
	for key := range store.byKey {
		set[key] = struct{}{}
	}
	return set
}

// Revoked reports whether an identity key has been revoked.
func (store *RevocationStore) Revoked(identityKey string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
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
