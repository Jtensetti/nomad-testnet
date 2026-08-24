package epoch

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// FreshStateOf reports an epoch's state after first synchronizing this process
// with descriptors and a halt marker persisted by another process. Production
// services that make serving/retirement decisions must use this rather than a
// stale in-memory snapshot.
func (chain *Chain) FreshStateOf(epochNumber uint64, now time.Time) (State, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return StateRetired, err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return StateRetired, err
	}
	return chain.stateOfLocked(epochNumber, now)
}

// FreshEpoch returns one stored epoch after synchronizing the on-disk chain.
func (chain *Chain) FreshEpoch(epochNumber uint64) (Verified, bool, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return Verified{}, false, err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return Verified{}, false, err
	}
	if chain.halted {
		return Verified{}, false, ErrHalted
	}
	for _, stored := range chain.epochs {
		if stored.Epoch == epochNumber {
			return stored, true, nil
		}
	}
	return Verified{}, false, nil
}

// FreshServingDeadline returns the public instant after which an already
// ACTIVE epoch must produce no more network work. Normally this is retire_at;
// a verified emergency successor shortens it to that successor's activate_at.
// The chain is refreshed first so a long-running node sees a descriptor
// imported by the lifecycle controller without relying on private activity or
// a process restart.
func (chain *Chain) FreshServingDeadline(epochNumber uint64) (time.Time, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return time.Time{}, err
	}
	if chain.halted {
		return time.Time{}, ErrHalted
	}
	for index, stored := range chain.epochs {
		if stored.Epoch != epochNumber {
			continue
		}
		deadline := stored.RetireAt
		if index+1 < len(chain.epochs) {
			successor := chain.epochs[index+1]
			if successor.Descriptor.Transition == TransitionEmergency && successor.ActivateAt.Before(deadline) {
				deadline = successor.ActivateAt
			}
		}
		return deadline, nil
	}
	return time.Time{}, fmt.Errorf("epoch %d is not stored", epochNumber)
}

func (chain *Chain) stateOfLocked(epochNumber uint64, now time.Time) (State, error) {
	if chain.halted {
		return StateRetired, ErrHalted
	}
	for index, stored := range chain.epochs {
		if stored.Epoch != epochNumber {
			continue
		}
		state := stored.stateAtIgnoringSuccessors(now)
		if state == StateActive && index+1 < len(chain.epochs) {
			successor := chain.epochs[index+1]
			if successor.Descriptor.Transition == TransitionEmergency && !now.Before(successor.ActivateAt) {
				return StateRetired, nil
			}
		}
		return state, nil
	}
	return StateRetired, fmt.Errorf("epoch %d is not stored", epochNumber)
}

// FreshGuard is the production threshold-work guard. It refreshes the
// persisted epoch chain before every decision so a running share service sees
// a successor or halt written by another process without a restart.
type FreshGuard struct {
	Chain *Chain
}

func (guard FreshGuard) ServesEpoch(epochNumber uint64, now time.Time) error {
	if guard.Chain == nil {
		return errors.New("epoch chain is required")
	}
	state, err := guard.Chain.FreshStateOf(epochNumber, now)
	if err != nil {
		return err
	}
	if state != StateActive {
		return fmt.Errorf("%w: epoch %d is %s", ErrEpochNotActive, epochNumber, state)
	}
	return nil
}

// EraseEpochMaterialDurable validates the operator identity before destroying
// anything, performs overwrite/unlink, then fsyncs every affected parent
// directory before returning a signed statement.
func EraseEpochMaterialDurable(networkID, operatorID string, retired Verified, paths []string, filesystem string, identity ed25519.PrivateKey, now time.Time) (ErasureStatement, error) {
	if networkID != retired.NetworkID {
		return ErasureStatement{}, errors.New("erasure network does not match the retired epoch")
	}
	operator, found := operatorByID(retired.Topology, operatorID)
	if !found {
		return ErasureStatement{}, fmt.Errorf("erasure operator %q is not in the retired epoch", operatorID)
	}
	if len(identity) != ed25519.PrivateKeySize {
		return ErasureStatement{}, errors.New("operator identity is required")
	}
	public := identity.Public().(ed25519.PublicKey)
	expected, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return ErasureStatement{}, errors.New("retired epoch contains an invalid operator identity key")
	}
	if !bytes.Equal(expected, public) {
		return ErasureStatement{}, errors.New("operator private key does not match the retired epoch identity")
	}

	if len(paths) == 0 {
		return ErasureStatement{}, errors.New("erasure requires at least one path")
	}
	seen := make(map[string]struct{}, len(paths))
	directories := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return ErasureStatement{}, err
		}
		clean := filepath.Clean(absolute)
		if _, duplicate := seen[clean]; duplicate {
			return ErasureStatement{}, fmt.Errorf("duplicate erasure path %q", path)
		}
		seen[clean] = struct{}{}
		directories[filepath.Dir(clean)] = struct{}{}
	}

	statement, err := EraseEpochMaterial(networkID, operatorID, retired, paths, filesystem, identity, now)
	if err != nil {
		return ErasureStatement{}, err
	}
	orderedDirectories := make([]string, 0, len(directories))
	for directory := range directories {
		orderedDirectories = append(orderedDirectories, directory)
	}
	sort.Strings(orderedDirectories)
	for _, directory := range orderedDirectories {
		if err := syncDir(directory); err != nil {
			return ErasureStatement{}, fmt.Errorf("persist erasure in %s: %w", directory, err)
		}
	}
	return statement, nil
}

func operatorByID(network topology.Verified, operatorID string) (topology.Operator, bool) {
	for _, operator := range network.Document.Operators {
		if operator.ID == operatorID {
			return operator, true
		}
	}
	return topology.Operator{}, false
}

// PathWithin reports whether candidate is equal to root or is contained by it
// after lexical absolute-path normalization.
func PathWithin(root, candidate string) (bool, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(filepath.Clean(rootAbs), filepath.Clean(candidateAbs))
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}
