package mix

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// A shuffle is verifiable by anyone. Nothing in a proof, a receipt or either
// batch is secret: that is the whole point of a verifiable shuffle, and it is
// what lets a committee be audited by people who are not on it.
//
// Until now that property existed only inside this package's tests. A third
// party who wanted to check a round had to write Go against the mix API and
// reconstruct the batches from whatever the committee happened to publish. In
// practice nobody does that, which means "individually verifiable" was true and
// unexercised.
//
// This is the published form. A committee writes a transcript; anyone reads it
// and checks every round, with no key, no network and no membership. What they
// establish is exactly what the proofs establish and no more -- the output of
// each round is a re-randomised permutation of its input, signed by the mixer
// that produced it -- which is correctness, not unlinkability. Unlinkability
// still needs one honest mixer, and no transcript can show that.

// TranscriptVersion is the frozen label for a published committee transcript.
const TranscriptVersion = "nomad-mix-transcript-v1"

// TranscriptRound is one mixer's round, as published.
type TranscriptRound struct {
	// Mixer is the position in the committee, from zero.
	Mixer int `json:"mixer"`
	// InputCells and OutputCells are the wire form of the two batches. The
	// input of round n must equal the output of round n-1, and this file
	// carries both rather than deduplicating them, so a verifier reads the
	// chain rather than assuming it.
	InputCells  []string `json:"input_cells"`
	OutputCells []string `json:"output_cells"`
	Proof       string   `json:"proof"`
	Receipt     Receipt  `json:"receipt"`
}

// Receipt is a published RoundReceipt.
type Receipt struct {
	CommitteeID  string `json:"committee_id"`
	Epoch        uint64 `json:"epoch"`
	BatchID      string `json:"batch_id"`
	Round        uint32 `json:"round"`
	MixerPublic  string `json:"mixer_public"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest"`
	ProofDigest  string `json:"proof_digest"`
	Signature    string `json:"signature"`
}

// Transcript is everything a third party needs to check a committee's work.
type Transcript struct {
	Version string `json:"version"`
	// EncryptionKey is the committee's public encryption key. It verifies a
	// shuffle and decrypts nothing.
	EncryptionKey string            `json:"encryption_key"`
	CommitteeID   string            `json:"committee_id"`
	Epoch         uint64            `json:"epoch"`
	Rounds        []TranscriptRound `json:"rounds"`
}

// zeroPadding makes the published encoding deterministic.
//
// MarshalWire fills the cell's trailing region with fresh randomness, which is
// right on the wire -- it is what makes cells indistinguishable -- and wrong
// here. Encoding one batch twice would produce different bytes, so a
// transcript's round n input would not compare equal to its round n-1 output
// and the chain could not be read from the file at all. Nothing in a transcript
// is secret, so there is nothing for padding to hide.
type zeroPadding struct{}

func (zeroPadding) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = 0
	}
	return len(destination), nil
}

func encodeCells(batch *Batch) ([]string, error) {
	cells, err := batch.MarshalWireWithPadding(zeroPadding{})
	if err != nil {
		return nil, err
	}
	out := make([]string, len(cells))
	for index, cell := range cells {
		out[index] = base64.StdEncoding.EncodeToString(cell[:])
	}
	return out, nil
}

func decodeCells(encoded []string) (*Batch, error) {
	if len(encoded) < 2 {
		return nil, errors.New("a batch is at least two cells")
	}
	cells := make([]WireCell, len(encoded))
	for index, value := range encoded {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("cell %d: %w", index, err)
		}
		if len(raw) != len(cells[index]) {
			return nil, fmt.Errorf("cell %d is %d bytes, not %d",
				index, len(raw), len(cells[index]))
		}
		copy(cells[index][:], raw)
	}
	return ParseWire(cells)
}

// ExportTranscript renders a committee's rounds in the published form.
func ExportTranscript(encryptionKey PublicKey, ctx RoundContext,
	rounds []Round, receipts []RoundReceipt) (Transcript, error) {
	if len(rounds) == 0 {
		return Transcript{}, errors.New("a transcript with no rounds establishes nothing")
	}
	if len(rounds) != len(receipts) {
		return Transcript{}, fmt.Errorf("%d rounds and %d receipts", len(rounds), len(receipts))
	}
	transcript := Transcript{
		Version:       TranscriptVersion,
		EncryptionKey: base64.StdEncoding.EncodeToString(encryptionKey[:]),
		CommitteeID:   base64.StdEncoding.EncodeToString(ctx.CommitteeID[:]),
		Epoch:         ctx.Epoch,
	}
	for index, round := range rounds {
		input, err := encodeCells(round.Input)
		if err != nil {
			return Transcript{}, fmt.Errorf("round %d input: %w", index, err)
		}
		output, err := encodeCells(round.Output)
		if err != nil {
			return Transcript{}, fmt.Errorf("round %d output: %w", index, err)
		}
		receipt := receipts[index]
		transcript.Rounds = append(transcript.Rounds, TranscriptRound{
			Mixer:       index,
			InputCells:  input,
			OutputCells: output,
			Proof:       base64.StdEncoding.EncodeToString(round.Proof),
			Receipt: Receipt{
				CommitteeID:  base64.StdEncoding.EncodeToString(receipt.Context.CommitteeID[:]),
				Epoch:        receipt.Context.Epoch,
				BatchID:      base64.StdEncoding.EncodeToString(receipt.Context.BatchID[:]),
				Round:        receipt.Context.Round,
				MixerPublic:  base64.StdEncoding.EncodeToString(receipt.MixerPublic[:]),
				InputDigest:  base64.StdEncoding.EncodeToString(receipt.InputDigest[:]),
				OutputDigest: base64.StdEncoding.EncodeToString(receipt.OutputDigest[:]),
				ProofDigest:  base64.StdEncoding.EncodeToString(receipt.ProofDigest[:]),
				Signature:    base64.StdEncoding.EncodeToString(receipt.Signature[:]),
			},
		})
	}
	return transcript, nil
}

// VerifyTranscript checks every round of a published transcript.
//
// It fails closed on everything: an unrecognised version, a malformed batch, a
// proof that does not verify, a receipt whose signature does not verify, a
// chain whose rounds do not join, and a transcript that claims a mixer the
// caller did not name. There is deliberately no partial verdict -- a committee
// transcript is either checkable end to end or it is not evidence.
//
// mixers is the committee's published identity keys in round order. Passing
// them separately is the point: trust does not come from the transcript, which
// would let a transcript name its own signers and authenticate nothing.
func VerifyTranscript(transcript Transcript, mixers []ed25519.PublicKey) error {
	if transcript.Version != TranscriptVersion {
		return fmt.Errorf("unrecognised transcript version %q, which is refused rather "+
			"than interpreted", transcript.Version)
	}
	if len(transcript.Rounds) == 0 {
		return errors.New("a transcript with no rounds establishes nothing")
	}
	if len(mixers) != len(transcript.Rounds) {
		return fmt.Errorf("%d mixer keys for %d rounds; a transcript that named its own "+
			"signers would authenticate nothing", len(mixers), len(transcript.Rounds))
	}

	keyBytes, err := base64.StdEncoding.DecodeString(transcript.EncryptionKey)
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	var encryptionKey PublicKey
	if len(keyBytes) != len(encryptionKey) {
		return fmt.Errorf("encryption key is %d bytes, not %d", len(keyBytes), len(encryptionKey))
	}
	copy(encryptionKey[:], keyBytes)

	var previousOutput []string
	for index, round := range transcript.Rounds {
		if round.Mixer != index {
			return fmt.Errorf("round %d is labelled mixer %d; the order is the chain",
				index, round.Mixer)
		}
		if previousOutput != nil && !equalCells(previousOutput, round.InputCells) {
			return fmt.Errorf("round %d does not take round %d's output as its input, so "+
				"the chain is broken and the rounds prove nothing about each other",
				index, index-1)
		}
		input, err := decodeCells(round.InputCells)
		if err != nil {
			return fmt.Errorf("round %d input: %w", index, err)
		}
		output, err := decodeCells(round.OutputCells)
		if err != nil {
			return fmt.Errorf("round %d output: %w", index, err)
		}
		proof, err := base64.StdEncoding.DecodeString(round.Proof)
		if err != nil {
			return fmt.Errorf("round %d proof: %w", index, err)
		}
		receipt, err := round.Receipt.decode()
		if err != nil {
			return fmt.Errorf("round %d receipt: %w", index, err)
		}
		if !ed25519.PublicKey(receipt.MixerPublic[:]).Equal(mixers[index]) {
			return fmt.Errorf("round %d is signed by a key the caller did not name as "+
				"mixer %d", index, index)
		}
		if err := VerifySignedRound(encryptionKey, input, output, proof, receipt); err != nil {
			return fmt.Errorf("round %d: %w", index, err)
		}
		previousOutput = round.OutputCells
	}
	return nil
}

func equalCells(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (receipt Receipt) decode() (RoundReceipt, error) {
	var out RoundReceipt
	fixed := func(encoded string, destination []byte, what string) error {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if len(raw) != len(destination) {
			return fmt.Errorf("%s is %d bytes, not %d", what, len(raw), len(destination))
		}
		copy(destination, raw)
		return nil
	}
	if err := fixed(receipt.CommitteeID, out.Context.CommitteeID[:], "committee identifier"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.BatchID, out.Context.BatchID[:], "batch identifier"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.MixerPublic, out.MixerPublic[:], "mixer identity"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.InputDigest, out.InputDigest[:], "input digest"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.OutputDigest, out.OutputDigest[:], "output digest"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.ProofDigest, out.ProofDigest[:], "proof digest"); err != nil {
		return RoundReceipt{}, err
	}
	if err := fixed(receipt.Signature, out.Signature[:], "signature"); err != nil {
		return RoundReceipt{}, err
	}
	out.Context.Epoch = receipt.Epoch
	out.Context.Round = receipt.Round
	return out, nil
}

// MarshalTranscript renders a transcript for publication.
func MarshalTranscript(transcript Transcript) ([]byte, error) {
	return json.MarshalIndent(transcript, "", "  ")
}

// UnmarshalTranscript reads a published transcript.
//
// Unknown members and trailing content are refused. Duplicate members are not
// scanned for, and that is a decision rather than an oversight: every value
// here is covered by a digest a mixer signed, so a duplicate that changed one
// would break the receipt signature and fail verification. Where a duplicate
// *could* decide an outcome -- the signed topology -- it is refused explicitly.
func UnmarshalTranscript(encoded []byte) (Transcript, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var transcript Transcript
	if err := decoder.Decode(&transcript); err != nil {
		return Transcript{}, err
	}
	if decoder.More() {
		return Transcript{}, errors.New("trailing content after the transcript")
	}
	return transcript, nil
}
