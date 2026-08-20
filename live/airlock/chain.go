package airlock

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

var (
	// ErrChainIncomplete reports a shuffle chain that did not cover every
	// committee member in the certified order.
	ErrChainIncomplete = errors.New("shuffle chain does not cover the committee")
	// ErrShuffleInvalid reports a shuffle whose proof or receipt did not
	// verify.
	ErrShuffleInvalid = errors.New("shuffle proof did not verify")
	// ErrChainNotRandomised reports a round that permuted without
	// re-randomising, leaving its input ciphertexts readable in its output.
	ErrChainNotRandomised = errors.New("shuffle round did not re-randomise")
	// ErrChainContext reports a chain presented for the wrong committee,
	// committee epoch, release epoch or sealed batch.
	ErrChainContext = errors.New("shuffle chain belongs to a different context")
)

// Round is one committee member's verifiable, authenticated shuffle.
//
// The receipt is what makes the member field mean anything. Previously a
// round carried a bare uint32 label and a Neff proof, and a Neff proof binds
// only to the encryption key and the input/output digests -- nothing tied a
// proof to the party that produced it. An entry operator holding no committee
// share at all could run every shuffle itself, label the rounds with the
// certified member indices, and be accepted, so it knew the whole
// ingress-to-egress map. The anytrust assumption inverted: the adversary
// needed to corrupt no shufflers rather than all of them.
//
// mix.RoundReceipt closes that. It is signed by the mixer's certified
// identity key and its proof domain is derived from the committee ID, the
// committee epoch, the batch ID and the round number, so a proof cannot be
// lifted to another member, another round, another batch or another epoch.
type Round struct {
	Member  uint32
	Output  []mix.WireCell
	Proof   []byte
	Receipt mix.RoundReceipt
}

// Sealed is what an airlock produced for one release epoch, with the
// commitment a verifier needs to know which epoch a chain belongs to.
type Sealed struct {
	ReleaseEpoch uint64
	Digest       [32]byte
	Columns      []mix.WireCell
	batch        *mix.Batch
}

// Batch returns the parsed sealed batch.
func (sealed Sealed) Batch() *mix.Batch { return sealed.batch }

// Shuffle produces one member's authenticated round.
func Shuffle(committee mix.ThresholdCommittee, member uint32, input *mix.Batch,
	identity ed25519.PrivateKey) (Round, *mix.Batch, error) {
	inputDigest, err := input.Digest()
	if err != nil {
		return Round{}, nil, err
	}
	context := mix.RoundContext{
		CommitteeID: committee.ID,
		Epoch:       committee.Epoch,
		BatchID:     inputDigest,
		Round:       member,
	}
	output, encodedProof, receipt, err := mix.ShuffleAndSign(context, committee.PublicKey, input, identity)
	if err != nil {
		return Round{}, nil, err
	}
	cells, err := output.MarshalWire()
	if err != nil {
		return Round{}, nil, err
	}
	return Round{Member: member, Output: cells, Proof: encodedProof, Receipt: receipt}, output, nil
}

// VerifyChain re-verifies a full shuffle chain against a sealed batch and
// returns the batch to decrypt.
//
// mixers holds the certified identity public key of each committee member, in
// the committee's order. Every member must appear exactly once, in that order,
// with a receipt signed by that member's key. This is the anytrust assumption
// made mechanical: the chain is unlinkable only if at least one shuffler is
// honest, so a chain that skipped a member is not a shorter chain but a chain
// with a smaller honest-party assumption. There is no partial-chain path and
// no degraded mode for an unreachable member.
func VerifyChain(committee mix.ThresholdCommittee, mixers []ed25519.PublicKey,
	sealed Sealed, releaseEpoch uint64, rounds []Round) (*mix.Batch, error) {
	if err := mix.ValidateThresholdCommittee(committee); err != nil {
		return nil, err
	}
	if sealed.batch == nil {
		return nil, errors.New("sealed batch is required")
	}
	if sealed.ReleaseEpoch != releaseEpoch {
		return nil, fmt.Errorf("%w: chain is for release epoch %d, expected %d",
			ErrChainContext, sealed.ReleaseEpoch, releaseEpoch)
	}
	sealedDigest, err := sealed.batch.Digest()
	if err != nil {
		return nil, err
	}
	if sealedDigest != sealed.Digest {
		return nil, fmt.Errorf("%w: sealed batch does not match its commitment", ErrChainContext)
	}
	if len(mixers) != len(committee.Members) {
		return nil, fmt.Errorf("%w: %d mixer identities for %d members",
			ErrChainIncomplete, len(mixers), len(committee.Members))
	}
	if len(rounds) != len(committee.Members) {
		return nil, fmt.Errorf("%w: %d rounds for %d members",
			ErrChainIncomplete, len(rounds), len(committee.Members))
	}

	current := sealed.batch
	for position, round := range rounds {
		expected := committee.Members[position].Index
		if round.Member != expected {
			return nil, fmt.Errorf("%w: round %d is from member %d, expected %d",
				ErrChainIncomplete, position, round.Member, expected)
		}
		if len(mixers[position]) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: member %d has no certified identity key",
				ErrChainIncomplete, expected)
		}
		if round.Receipt.Context.CommitteeID != committee.ID ||
			round.Receipt.Context.Epoch != committee.Epoch {
			return nil, fmt.Errorf("%w: round %d names committee %x epoch %d",
				ErrChainContext, position, round.Receipt.Context.CommitteeID[:8],
				round.Receipt.Context.Epoch)
		}
		if round.Receipt.Context.Round != expected {
			return nil, fmt.Errorf("%w: round %d carries a receipt for round %d",
				ErrChainIncomplete, position, round.Receipt.Context.Round)
		}
		// The receipt must be signed by the member the position belongs to,
		// not merely by somebody.
		if string(round.Receipt.MixerPublic[:]) != string(mixers[position]) {
			return nil, fmt.Errorf("%w: round %d is signed by a key that is not member %d's",
				ErrShuffleInvalid, position, expected)
		}
		if len(round.Output) != current.Len() {
			return nil, fmt.Errorf("%w: round %d changed the batch size from %d to %d",
				ErrShuffleInvalid, position, current.Len(), len(round.Output))
		}
		output, err := mix.ParseWire(round.Output)
		if err != nil {
			return nil, fmt.Errorf("%w: round %d output: %v", ErrShuffleInvalid, position, err)
		}
		if err := mix.VerifySignedRound(committee.PublicKey, current, output, round.Proof, round.Receipt); err != nil {
			return nil, fmt.Errorf("%w: round %d from member %d: %v",
				ErrShuffleInvalid, position, round.Member, err)
		}
		// A Neff proof shows that *some* permutation with *some* blinding
		// exists, and zero is a perfectly valid blinding: a chain of pure
		// permutations verifies, and then anyone who saw the sealed batch
		// reads the map straight off the bytes. Requiring every output column
		// to differ from every input column is exactly a zero-blinding
		// detector, and an honest round collides with negligible probability.
		if err := requireRerandomisation(current, output, position); err != nil {
			return nil, err
		}
		current = output
	}
	return current, nil
}

func requireRerandomisation(input, output *mix.Batch, position int) error {
	inputCells, err := input.MarshalWire()
	if err != nil {
		return err
	}
	outputCells, err := output.MarshalWire()
	if err != nil {
		return err
	}
	// Only the ciphertext region is compared: the trailing padding is fresh
	// randomness on both sides and would mask an unchanged ciphertext.
	seen := make(map[string]struct{}, len(inputCells))
	for _, cell := range inputCells {
		seen[string(cell[:DepositSize])] = struct{}{}
	}
	for index, cell := range outputCells {
		if _, repeated := seen[string(cell[:DepositSize])]; repeated {
			return fmt.Errorf("%w: round %d output column %d is byte-identical to an input column",
				ErrChainNotRandomised, position, index)
		}
	}
	return nil
}

// Release performs threshold decryption of a verified chain output and
// returns only the real fragments.
//
// Cover is dropped here and nowhere earlier: it is indistinguishable from a
// real deposit until it has been decrypted, which is the point of it. The
// number of fragments returned is therefore known only to a party holding
// threshold authority and is never part of the public record of the epoch.
//
// A column that cannot be decrypted is dropped rather than failing the batch.
// A ciphertext of valid points that is not a real encryption passes every
// shuffle proof and fails only here, so an all-or-nothing decryption would
// let one deposit censor every other publisher in the epoch.
func Release(committee mix.ThresholdCommittee, mixed *mix.Batch,
	partials []*mix.PartialDecryption) ([]mix.PlainCell, int, error) {
	columns, err := mix.ThresholdDecryptColumns(committee, mixed, partials)
	if err != nil {
		return nil, 0, err
	}
	fragments := make([]mix.PlainCell, 0, len(columns))
	undecryptable := 0
	for _, column := range columns {
		if column.Err != nil {
			undecryptable++
			continue
		}
		if IsCover(column.Cell) {
			continue
		}
		fragments = append(fragments, column.Cell)
	}
	return fragments, undecryptable, nil
}
