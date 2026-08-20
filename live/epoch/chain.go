package epoch

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
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
	networkID string
	authority ed25519.PublicKey
	revoked   RevocationSet
	epochs    []Verified
	halted    bool
}

// equivocationProof is self-contained: both descriptors are recorded in
// full, so a third party can re-verify the conflict without the chain that
// observed it.
type equivocationProof struct {
	NetworkID      string `json:"network_id"`
	Epoch          uint64 `json:"epoch"`
	StoredDigest   string `json:"stored_digest"`
	OfferedDigest  string `json:"offered_digest"`
	StoredEncoded  string `json:"stored_descriptor_base64"`
	OfferedEncoded string `json:"offered_descriptor_base64"`
}

// OpenChain loads and re-verifies every stored descriptor in epoch order.
//
// networkID pins the network this store is for; a descriptor from any other
// network is rejected, including the very first genesis on an empty store.
//
// revoked applies to what this chain admits from now on. It is deliberately
// NOT applied when re-verifying already-accepted history: revocation is
// forward-scoped by specification, and re-checking history against it would
// make a compromise announcement render a verifier unable to open its own
// chain, exactly when it needs to accept the emergency successor that
// excludes the compromised operator.
func OpenChain(root, networkID string, authority ed25519.PublicKey, revoked RevocationSet) (*Chain, error) {
	if root == "" {
		return nil, errors.New("epoch chain directory is required")
	}
	if networkID == "" {
		return nil, errors.New("epoch chain network ID is required")
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
	chain := &Chain{root: root, networkID: networkID, authority: authority, revoked: revoked}
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
		// Historical epochs are re-verified without the revocation set; see
		// the OpenChain doc comment.
		verified, err := Verify(encoded, authority, previous, nil)
		if err != nil {
			return nil, fmt.Errorf("stored epoch %d: %w", number, err)
		}
		if verified.Epoch != number {
			return nil, fmt.Errorf("stored epoch %d contains descriptor for epoch %d", number, verified.Epoch)
		}
		if verified.NetworkID != networkID {
			return nil, fmt.Errorf("stored epoch %d belongs to network %q, not %q", number, verified.NetworkID, networkID)
		}
		chain.epochs = append(chain.epochs, verified)
	}
	return chain, nil
}

func (chain *Chain) pathFor(number uint64) string {
	return filepath.Join(chain.root, fmt.Sprintf("%020d.epoch.json", number))
}

// refreshLocked re-reads state another process may have changed. It is
// called under both the process mutex and the cross-process lock.
func (chain *Chain) refreshLocked() error {
	if chain.halted {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(chain.root, haltedMarker)); err == nil {
		chain.halted = true
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for {
		next := uint64(1)
		if len(chain.epochs) > 0 {
			next = chain.epochs[len(chain.epochs)-1].Epoch + 1
		}
		encoded, err := os.ReadFile(chain.pathFor(next))
		if errors.Is(err, os.ErrNotExist) {
			// Epoch numbers need not be contiguous across a re-bootstrap, so
			// a missing successor simply means nothing new to adopt here.
			return nil
		}
		if err != nil {
			return err
		}
		var previous *Verified
		if len(chain.epochs) > 0 {
			previous = &chain.epochs[len(chain.epochs)-1]
		}
		verified, err := Verify(encoded, chain.authority, previous, nil)
		if err != nil {
			return fmt.Errorf("stored epoch %d: %w", next, err)
		}
		if verified.NetworkID != chain.networkID {
			return fmt.Errorf("stored epoch %d belongs to network %q", next, verified.NetworkID)
		}
		chain.epochs = append(chain.epochs, verified)
	}
}

// Append verifies and persists one descriptor. Re-appending identical bytes
// for a known epoch is idempotent. A distinct descriptor for a known epoch,
// or any epoch at or below the tip that is not stored, is fatal
// equivocation/rollback and halts the chain.
func (chain *Chain) Append(encoded []byte) (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return Verified{}, err
	}
	defer func() { _ = lock.release() }()
	// Another process may have halted or advanced the store while this one
	// waited for the lock, so re-read the on-disk state before deciding.
	if err := chain.refreshLocked(); err != nil {
		return Verified{}, err
	}
	if chain.halted {
		return Verified{}, ErrHalted
	}
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Verified{}, errors.New("epoch descriptor is empty or too large")
	}
	probe, err := decodeDescriptor(encoded)
	if err != nil {
		return Verified{}, err
	}
	offeredDigest, err := Digest(probe)
	if err != nil {
		return Verified{}, err
	}
	probeNetwork, probeEpoch, err := embeddedIdentity(probe)
	if err != nil {
		return Verified{}, err
	}
	if chain.networkID != "" && probeNetwork != chain.networkID {
		return Verified{}, errors.New("epoch descriptor belongs to a different network")
	}
	if stored, storedIndex, exists := chain.lookupSlot(probeEpoch); exists {
		if stored.Digest == offeredDigest {
			// Identical bytes for a stored epoch are idempotent, but only
			// after they verify: a caller must never read success here as a
			// warrant to persist or relay unverified input.
			var slotPrevious *Verified
			if storedIndex > 0 {
				slotPrevious = &chain.epochs[storedIndex-1]
			}
			if _, err := Verify(encoded, chain.authority, slotPrevious, chain.revoked); err != nil {
				return Verified{}, fmt.Errorf("stored-epoch descriptor failed verification: %w", err)
			}
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
		// The halt itself has already taken effect in memory. A failure to
		// persist the evidence is reported alongside the equivocation, never
		// in place of it.
		persistErr := chain.halt(stored, offeredDigest, encoded)
		if persistErr != nil {
			return Verified{}, fmt.Errorf("%w: epoch %d has digests %s and %s (evidence not persisted: %v)",
				ErrEquivocation, stored.Epoch, hex.EncodeToString(stored.Digest[:]), hex.EncodeToString(offeredDigest[:]), persistErr)
		}
		return Verified{}, fmt.Errorf("%w: epoch %d has digests %s and %s",
			ErrEquivocation, stored.Epoch, hex.EncodeToString(stored.Digest[:]), hex.EncodeToString(offeredDigest[:]))
	}
	// Chain rule 2: an epoch number at or below the high-water mark was
	// already used and is burned permanently, even if its descriptor file
	// has since been removed from this store.
	watermark, err := chain.readWatermark()
	if err != nil {
		return Verified{}, err
	}
	if probeEpoch <= watermark {
		return Verified{}, fmt.Errorf("epoch %d is at or below the burned high-water mark %d", probeEpoch, watermark)
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
	if err := chain.raiseWatermark(verified.Epoch); err != nil {
		return Verified{}, err
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

// lookupSlot finds the stored epoch a candidate competes with. Slots are
// matched on the epoch number carried by the embedded topology, which is
// what the specification defines equivocation over. Matching on the
// previous-epoch digest instead would make every genesis collide, so a
// lawful re-bootstrap at a later epoch would be misrecorded as equivocation
// and would halt every verifier that saw it.
func (chain *Chain) lookupSlot(epochNumber uint64) (Verified, int, bool) {
	for index, stored := range chain.epochs {
		if stored.Epoch == epochNumber {
			return stored, index, true
		}
	}
	return Verified{}, 0, false
}

// embeddedIdentity reads the network and epoch a candidate claims, from the
// signed topology inside it. The bytes are already covered by the digest;
// this only reads them, and every signature check still happens in Verify.
func embeddedIdentity(descriptor Descriptor) (string, uint64, error) {
	topologyBytes, err := decodeBounded(descriptor.Topology)
	if err != nil {
		return "", 0, errors.New("invalid embedded topology encoding")
	}
	var signed topology.Signed
	decoder := json.NewDecoder(bytes.NewReader(topologyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return "", 0, fmt.Errorf("decode embedded topology: %w", err)
	}
	if signed.Document.Epoch == 0 || signed.Document.NetworkID == "" {
		return "", 0, errors.New("embedded topology has no network or epoch")
	}
	return signed.Document.NetworkID, signed.Document.Epoch, nil
}

func decodeDescriptor(encoded []byte) (Descriptor, error) {
	var descriptor Descriptor
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, fmt.Errorf("decode epoch descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Descriptor{}, errors.New("trailing epoch descriptor data")
	}
	return descriptor, nil
}

// halt records a detected equivocation. The in-memory halt is set first and
// is never cleared: a verifier that has seen two valid descriptors for one
// epoch must stop serving epochs even if it cannot persist the evidence
// (full disk, read-only mount, a marker another instance already wrote).
// Persistence failure is reported alongside the halt, never instead of it.
func (chain *Chain) halt(stored Verified, offeredDigest [32]byte, offered []byte) error {
	chain.halted = true
	proof := equivocationProof{
		NetworkID:      stored.NetworkID,
		Epoch:          stored.Epoch,
		StoredDigest:   hex.EncodeToString(stored.Digest[:]),
		OfferedDigest:  hex.EncodeToString(offeredDigest[:]),
		StoredEncoded:  base64.StdEncoding.EncodeToString(chain.encodedFor(stored.Epoch)),
		OfferedEncoded: base64.StdEncoding.EncodeToString(offered),
	}
	encodedProof, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(chain.root, haltedMarker)
	if err := writeNewFile(path, encodedProof, 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			// An existing marker means this chain is already halted, which
			// is the state we want, not a failure.
			return nil
		}
		return err
	}
	return nil
}

const watermarkFile = "HIGHEST_EPOCH"

// readWatermark returns the highest epoch number this store has ever
// accepted. It is persisted separately from the descriptor files so that
// deleting a descriptor cannot silently re-open a burned epoch number for a
// different successor.
func (chain *Chain) readWatermark() (uint64, error) {
	encoded, err := os.ReadFile(filepath.Join(chain.root, watermarkFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(encoded)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed epoch high-water mark: %w", err)
	}
	return value, nil
}

func (chain *Chain) raiseWatermark(epochNumber uint64) error {
	current, err := chain.readWatermark()
	if err != nil {
		return err
	}
	if epochNumber <= current {
		return fmt.Errorf("refusing to lower the epoch high-water mark from %d to %d", current, epochNumber)
	}
	path := filepath.Join(chain.root, watermarkFile)
	temporary, err := os.CreateTemp(chain.root, ".watermark-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(temporary, "%d\n", epochNumber); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	ok = true
	return syncDir(chain.root)
}

func (chain *Chain) encodedFor(epochNumber uint64) []byte {
	encoded, err := os.ReadFile(chain.pathFor(epochNumber))
	if err != nil {
		return nil
	}
	return encoded
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

// HighestRetired returns the highest epoch number whose chain-level state is
// RETIRED at the given instant, or zero.
func (chain *Chain) HighestRetired(now time.Time) uint64 {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	highest := uint64(0)
	for index, stored := range chain.epochs {
		state := stored.stateAtIgnoringSuccessors(now)
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
