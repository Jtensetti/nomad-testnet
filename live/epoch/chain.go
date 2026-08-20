package epoch

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrEquivocation is fatal: two distinct valid descriptors claimed the
	// same epoch. The chain halts and refuses all progression until a
	// manually authorized re-bootstrap replaces the store.
	ErrEquivocation = errors.New("epoch descriptor equivocation")
	// ErrHalted is returned for every operation on a halted chain.
	ErrHalted = errors.New("epoch chain is halted on recorded equivocation")
)

const haltedMarker = "HALTED"

// Chain is a persisted, append-only epoch descriptor store enforcing the
// verifier rules of docs/EPOCH_LIFECYCLE.md: chaining, monotonicity,
// fail-closed equivocation and single-active-epoch selection.
type Chain struct {
	mu        sync.Mutex
	root      string
	authority ed25519.PublicKey
	revoked   RevocationSet
	epochs    []Verified
	halted    bool
}

type equivocationProof struct {
	NetworkID      string `json:"network_id"`
	Epoch          uint64 `json:"epoch"`
	StoredDigest   string `json:"stored_digest"`
	OfferedDigest  string `json:"offered_digest"`
	OfferedEncoded string `json:"offered_descriptor_base64"`
}

// OpenChain loads and re-verifies every stored descriptor in epoch order.
func OpenChain(root string, authority ed25519.PublicKey, revoked RevocationSet) (*Chain, error) {
	if root == "" {
		return nil, errors.New("epoch chain directory is required")
	}
	if len(authority) != ed25519.PublicKeySize {
		return nil, errors.New("epoch chain authority key is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("epoch chain root is not a directory")
	}
	chain := &Chain{root: root, authority: authority, revoked: revoked}
	if _, err := os.Lstat(filepath.Join(root, haltedMarker)); err == nil {
		chain.halted = true
		return chain, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	numbers := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".epoch.json") {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimSuffix(name, ".epoch.json"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected epoch chain entry %q", name)
		}
		numbers = append(numbers, number)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	for _, number := range numbers {
		encoded, err := os.ReadFile(chain.pathFor(number))
		if err != nil {
			return nil, err
		}
		var previous *Verified
		if len(chain.epochs) > 0 {
			previous = &chain.epochs[len(chain.epochs)-1]
		}
		verified, err := Verify(encoded, authority, previous, revoked)
		if err != nil {
			return nil, fmt.Errorf("stored epoch %d: %w", number, err)
		}
		if verified.Epoch != number {
			return nil, fmt.Errorf("stored epoch %d contains descriptor for epoch %d", number, verified.Epoch)
		}
		chain.epochs = append(chain.epochs, verified)
	}
	return chain, nil
}

func (chain *Chain) pathFor(number uint64) string {
	return filepath.Join(chain.root, fmt.Sprintf("%020d.epoch.json", number))
}

// Append verifies and persists one descriptor. Re-appending identical bytes
// for a known epoch is idempotent. A distinct descriptor for a known epoch,
// or any epoch at or below the tip that is not stored, is fatal
// equivocation/rollback and halts the chain.
func (chain *Chain) Append(encoded []byte) (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted {
		return Verified{}, ErrHalted
	}
	var probe Descriptor
	if err := json.Unmarshal(encoded, &probe); err != nil {
		return Verified{}, fmt.Errorf("decode epoch descriptor: %w", err)
	}
	offeredDigest, err := Digest(probe)
	if err != nil {
		return Verified{}, err
	}
	if stored, storedIndex, exists := chain.lookupSlot(probe); exists {
		if stored.Digest == offeredDigest {
			return stored, nil
		}
		// Only a fully valid competing descriptor is equivocation. Invalid
		// bytes must not be able to halt the chain (that would hand any
		// unauthenticated sender a denial-of-service on epoch progression).
		var slotPrevious *Verified
		if storedIndex > 0 {
			slotPrevious = &chain.epochs[storedIndex-1]
		}
		competing, err := Verify(encoded, chain.authority, slotPrevious, chain.revoked)
		if err != nil {
			return Verified{}, fmt.Errorf("conflicting epoch descriptor is itself invalid: %w", err)
		}
		if competing.NetworkID != stored.NetworkID {
			return Verified{}, errors.New("descriptor belongs to a different network")
		}
		if err := chain.halt(stored, offeredDigest, encoded); err != nil {
			return Verified{}, err
		}
		return Verified{}, fmt.Errorf("%w: epoch %d has digests %s and %s",
			ErrEquivocation, stored.Epoch, hex.EncodeToString(stored.Digest[:]), hex.EncodeToString(offeredDigest[:]))
	}
	var previous *Verified
	if len(chain.epochs) > 0 {
		previous = &chain.epochs[len(chain.epochs)-1]
	}
	verified, err := Verify(encoded, chain.authority, previous, chain.revoked)
	if err != nil {
		return Verified{}, err
	}
	if previous != nil && verified.Epoch <= previous.Epoch {
		return Verified{}, errors.New("epoch descriptor rolls back the chain")
	}
	path := chain.pathFor(verified.Epoch)
	if err := writeNewFile(path, encoded, 0o644); err != nil {
		return Verified{}, err
	}
	if err := syncDir(chain.root); err != nil {
		return Verified{}, err
	}
	chain.epochs = append(chain.epochs, verified)
	return verified, nil
}

// lookupSlot finds the stored epoch competing with the probe for the same
// chain position. The probe's epoch number lives inside its embedded
// topology, which is expensive to verify up front, so slots are matched on
// the previous-epoch digest: the chain is linear, so each stored descriptor
// has a unique previous digest and a probe sharing it claims that slot.
func (chain *Chain) lookupSlot(probe Descriptor) (Verified, int, bool) {
	for index, stored := range chain.epochs {
		if stored.Descriptor.PreviousEpochDigest == probe.PreviousEpochDigest {
			return stored, index, true
		}
	}
	return Verified{}, 0, false
}

func (chain *Chain) halt(stored Verified, offeredDigest [32]byte, offered []byte) error {
	proof := equivocationProof{
		NetworkID:     stored.NetworkID,
		Epoch:         stored.Epoch,
		StoredDigest:  hex.EncodeToString(stored.Digest[:]),
		OfferedDigest: hex.EncodeToString(offeredDigest[:]),
	}
	proof.OfferedEncoded = base64.StdEncoding.EncodeToString(offered)
	encodedProof, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(chain.root, haltedMarker), encodedProof, 0o600); err != nil {
		return err
	}
	chain.halted = true
	return nil
}

// Halted reports whether the chain recorded a fatal equivocation.
func (chain *Chain) Halted() bool {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.halted
}

// Tip returns the highest stored epoch.
func (chain *Chain) Tip() (Verified, bool) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted || len(chain.epochs) == 0 {
		return Verified{}, false
	}
	return chain.epochs[len(chain.epochs)-1], true
}

// ActiveAt returns the single epoch that is ACTIVE at the given instant.
// Walking from the tip downward makes an activated emergency successor
// shadow (retire) its predecessor automatically.
func (chain *Chain) ActiveAt(now time.Time) (Verified, bool) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted {
		return Verified{}, false
	}
	for index := len(chain.epochs) - 1; index >= 0; index-- {
		candidate := chain.epochs[index]
		if now.Before(candidate.ActivateAt) {
			continue
		}
		if now.Before(candidate.RetireAt) {
			return candidate, true
		}
		return Verified{}, false
	}
	return Verified{}, false
}

// StateOf reports one stored epoch's chain-level state, including emergency
// retirement by an activated successor.
func (chain *Chain) StateOf(epochNumber uint64, now time.Time) (State, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted {
		return StateRetired, ErrHalted
	}
	for index, stored := range chain.epochs {
		if stored.Epoch != epochNumber {
			continue
		}
		state := stored.StateAt(now)
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

// HighestRetired returns the highest epoch number whose chain-level state is
// RETIRED at the given instant, or zero.
func (chain *Chain) HighestRetired(now time.Time) uint64 {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	highest := uint64(0)
	for index, stored := range chain.epochs {
		state := stored.StateAt(now)
		if state == StateActive && index+1 < len(chain.epochs) {
			successor := chain.epochs[index+1]
			if successor.Descriptor.Transition == TransitionEmergency && !now.Before(successor.ActivateAt) {
				state = StateRetired
			}
		}
		if state == StateRetired && stored.Epoch > highest {
			highest = stored.Epoch
		}
	}
	return highest
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
