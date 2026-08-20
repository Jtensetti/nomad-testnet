package mix

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const contextualShuffleProofLabel = "nomad-contextual-neff-shuffle-v1"

var (
	ErrRoundReplay      = errors.New("mix round receipt replay")
	ErrRoundEquivocate = errors.New("mix round receipt equivocation")
)

// RoundContext is public protocol state. Its fields must be fixed before a
// mixer sees a batch and must never be derived from private reader activity.
type RoundContext struct {
	CommitteeID CommitteeID
	Epoch       uint64
	BatchID     [32]byte
	Round       uint32
}

// RoundReceipt authenticates one verified shuffle result to a mixer identity,
// committee, epoch, batch and round. Output remains separate so applications
// can stream or store it independently of the accountability transcript.
type RoundReceipt struct {
	Context       RoundContext
	MixerPublic   [ed25519.PublicKeySize]byte
	InputDigest   [32]byte
	OutputDigest  [32]byte
	ProofDigest   [32]byte
	Signature     [ed25519.SignatureSize]byte
}

func ShuffleAndSign(ctx RoundContext, encryptionKey PublicKey, input *Batch, identity ed25519.PrivateKey) (*Batch, []byte, RoundReceipt, error) {
	if err := validateRoundContext(ctx); err != nil {
		return nil, nil, RoundReceipt{}, err
	}
	if len(identity) != ed25519.PrivateKeySize {
		return nil, nil, RoundReceipt{}, errors.New("mixer identity private key is required")
	}
	inputDigest, err := input.Digest()
	if err != nil {
		return nil, nil, RoundReceipt{}, err
	}
	if ctx.BatchID != inputDigest {
		return nil, nil, RoundReceipt{}, errors.New("round context batch ID must equal the input digest")
	}
	output, encodedProof, err := shuffleAndProveWithDomain(encryptionKey, input, contextualShuffleProofDomain(ctx))
	if err != nil {
		return nil, nil, RoundReceipt{}, err
	}
	outputDigest, err := output.Digest()
	if err != nil {
		return nil, nil, RoundReceipt{}, err
	}
	identityPublic, ok := identity.Public().(ed25519.PublicKey)
	if !ok || len(identityPublic) != ed25519.PublicKeySize {
		return nil, nil, RoundReceipt{}, errors.New("invalid mixer identity key")
	}
	receipt := RoundReceipt{
		Context:      ctx,
		InputDigest:  inputDigest,
		OutputDigest: outputDigest,
		ProofDigest:  sha256.Sum256(encodedProof),
	}
	copy(receipt.MixerPublic[:], identityPublic)
	signature := ed25519.Sign(identity, receiptSigningMessage(receipt, encryptionKey))
	copy(receipt.Signature[:], signature)
	return output, encodedProof, receipt, nil
}

func VerifySignedRound(encryptionKey PublicKey, input, output *Batch, encodedProof []byte, receipt RoundReceipt) error {
	if err := validateRoundContext(receipt.Context); err != nil {
		return err
	}
	inputDigest, err := input.Digest()
	if err != nil {
		return err
	}
	outputDigest, err := output.Digest()
	if err != nil {
		return err
	}
	if receipt.Context.BatchID != inputDigest || receipt.InputDigest != inputDigest {
		return errors.New("round receipt input digest mismatch")
	}
	if receipt.OutputDigest != outputDigest {
		return errors.New("round receipt output digest mismatch")
	}
	if receipt.ProofDigest != sha256.Sum256(encodedProof) {
		return errors.New("round receipt proof digest mismatch")
	}
	if !ed25519.Verify(receipt.MixerPublic[:], receiptSigningMessage(receipt, encryptionKey), receipt.Signature[:]) {
		return errors.New("invalid mixer receipt signature")
	}
	if err := verifyShuffleWithDomain(encryptionKey, input, output, encodedProof, contextualShuffleProofDomain(receipt.Context)); err != nil {
		return err
	}
	return nil
}

func validateRoundContext(ctx RoundContext) error {
	if isZeroCommitteeID(ctx.CommitteeID) {
		return errors.New("round committee ID is required")
	}
	if ctx.Epoch == 0 {
		return errors.New("round epoch must be non-zero")
	}
	if ctx.BatchID == [32]byte{} {
		return errors.New("round batch ID is required")
	}
	return nil
}

func contextualShuffleProofDomain(ctx RoundContext) string {
	digest := roundContextDigest(ctx)
	return contextualShuffleProofLabel + ":" + hex.EncodeToString(digest[:])
}

func roundContextDigest(ctx RoundContext) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-round-context-v1"))
	_, _ = h.Write(ctx.CommitteeID[:])
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], ctx.Epoch)
	_, _ = h.Write(integer[:])
	_, _ = h.Write(ctx.BatchID[:])
	binary.BigEndian.PutUint32(integer[:4], ctx.Round)
	_, _ = h.Write(integer[:4])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func receiptSigningMessage(receipt RoundReceipt, encryptionKey PublicKey) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-round-receipt-v1"))
	contextDigest := roundContextDigest(receipt.Context)
	_, _ = h.Write(contextDigest[:])
	_, _ = h.Write(encryptionKey[:])
	_, _ = h.Write(receipt.MixerPublic[:])
	_, _ = h.Write(receipt.InputDigest[:])
	_, _ = h.Write(receipt.OutputDigest[:])
	_, _ = h.Write(receipt.ProofDigest[:])
	return h.Sum(nil)
}

type receiptKey struct {
	BatchID [32]byte
	Round   uint32
}

// ReceiptTracker detects replay and equivocation after cryptographic receipt
// verification. It is scoped to one committee epoch and stores only public
// transcript digests.
type ReceiptTracker struct {
	mu          sync.Mutex
	committeeID CommitteeID
	epoch       uint64
	seen        map[receiptKey][32]byte
}

func NewReceiptTracker(committeeID CommitteeID, epoch uint64) (*ReceiptTracker, error) {
	if isZeroCommitteeID(committeeID) || epoch == 0 {
		return nil, errors.New("tracker requires a committee ID and non-zero epoch")
	}
	return &ReceiptTracker{
		committeeID: committeeID,
		epoch:       epoch,
		seen:        make(map[receiptKey][32]byte),
	}, nil
}

func (t *ReceiptTracker) Accept(receipt RoundReceipt) error {
	if t == nil {
		return errors.New("receipt tracker is required")
	}
	if receipt.Context.CommitteeID != t.committeeID || receipt.Context.Epoch != t.epoch {
		return errors.New("receipt is outside the tracked committee epoch")
	}
	digest := receiptDigest(receipt)
	key := receiptKey{BatchID: receipt.Context.BatchID, Round: receipt.Context.Round}
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous, exists := t.seen[key]; exists {
		if previous == digest {
			return ErrRoundReplay
		}
		return ErrRoundEquivocate
	}
	t.seen[key] = digest
	return nil
}

func receiptDigest(receipt RoundReceipt) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-receipt-digest-v1"))
	contextDigest := roundContextDigest(receipt.Context)
	_, _ = h.Write(contextDigest[:])
	_, _ = h.Write(receipt.MixerPublic[:])
	_, _ = h.Write(receipt.InputDigest[:])
	_, _ = h.Write(receipt.OutputDigest[:])
	_, _ = h.Write(receipt.ProofDigest[:])
	_, _ = h.Write(receipt.Signature[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (r RoundReceipt) String() string {
	return fmt.Sprintf("committee=%x epoch=%d batch=%x round=%d mixer=%x", r.Context.CommitteeID[:8], r.Context.Epoch, r.Context.BatchID[:8], r.Context.Round, r.MixerPublic[:8])
}
