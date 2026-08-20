package epoch

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// ErrConflictingSignature is returned when an operator is asked to sign a
// second distinct descriptor digest for the same epoch and role. The refusal
// is the producer-side half of the split-brain defense: without it, a second
// valid descriptor for one epoch is a routine operational accident, and
// because any such descriptor permanently halts every verifier that sees it,
// that accident is a network-wide outage.
var ErrConflictingSignature = errors.New("refusing to sign a second descriptor for this epoch")

var networkIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const (
	roleActivation = "activation"
	roleApproval   = "approval"
)

// Journal is the per-operator record of which descriptor digest was signed
// for each (network, epoch, role). Signing goes through it, so an operator
// cannot produce a conflicting signature by forgetting to consult it.
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

// record notes that this operator signs digest for (network, epoch, role).
// The first call wins; identical repeats are idempotent; a distinct digest
// is refused permanently. The network identifier is validated against the
// topology identifier grammar so it cannot escape the journal directory.
func (journal *Journal) record(networkID string, epochNumber uint64, role string, digest [32]byte) error {
	if !networkIDPattern.MatchString(networkID) {
		return errors.New("invalid network ID for signature journal")
	}
	if role != roleActivation && role != roleApproval {
		return errors.New("invalid signature role")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	path := filepath.Join(journal.root, fmt.Sprintf("%s-%020d-%s.signed", networkID, epochNumber, role))
	encoded := []byte(hex.EncodeToString(digest[:]) + "\n")
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) == string(encoded) {
			return nil
		}
		return fmt.Errorf("%w: %s epoch %d %s already signed as %s",
			ErrConflictingSignature, networkID, epochNumber, role, string(existing))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeNewFile(path, encoded, 0o600); err != nil {
		return err
	}
	return syncDir(journal.root)
}

// ActivateWithJournal is the only supported way to produce an activation
// signature. It derives the network and epoch from the descriptor's own
// embedded topology rather than trusting the caller, records the intent, and
// signs only if the journal permits it.
func (journal *Journal) ActivateWithJournal(descriptor Descriptor, operator topology.Operator, identity ed25519.PrivateKey) (Activation, error) {
	if journal == nil {
		return Activation{}, errors.New("a signature journal is required to activate an epoch")
	}
	networkID, epochNumber, err := embeddedIdentity(descriptor)
	if err != nil {
		return Activation{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Activation{}, err
	}
	if err := journal.record(networkID, epochNumber, roleActivation, digest); err != nil {
		return Activation{}, err
	}
	return Activate(descriptor, operator, identity)
}

// ApproveWithJournal is the only supported way to produce a transition
// approval, with the same fail-closed journal semantics.
func (journal *Journal) ApproveWithJournal(descriptor Descriptor, previous Verified, operator topology.Operator, identity ed25519.PrivateKey) (Approval, error) {
	if journal == nil {
		return Approval{}, errors.New("a signature journal is required to approve a transition")
	}
	networkID, epochNumber, err := embeddedIdentity(descriptor)
	if err != nil {
		return Approval{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Approval{}, err
	}
	if err := journal.record(networkID, epochNumber, roleApproval, digest); err != nil {
		return Approval{}, err
	}
	return Approve(descriptor, previous, operator, identity)
}
