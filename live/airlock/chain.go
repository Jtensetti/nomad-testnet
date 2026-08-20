package airlock

import (
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

var (
	// ErrChainIncomplete reports a shuffle chain that did not cover every
	// committee member in the certified order.
	ErrChainIncomplete = errors.New("shuffle chain does not cover the committee")
	// ErrShuffleInvalid reports a shuffle whose proof did not verify.
	ErrShuffleInvalid = errors.New("shuffle proof did not verify")
)

// Round is one committee member's verifiable shuffle. The output is carried
// in wire form so that a round can be transmitted, stored and re-verified by
// anyone, which is what makes the chain publicly auditable rather than
// something the committee asserts about itself.
type Round struct {
	Member uint32
	Output []mix.WireCell
	Proof  []byte
}

// Shuffle produces one member's round from the previous batch.
func Shuffle(committee mix.PublicKey, member uint32, input *mix.Batch) (Round, *mix.Batch, error) {
	output, encodedProof, err := mix.ShuffleAndProve(committee, input)
	if err != nil {
		return Round{}, nil, err
	}
	cells, err := output.MarshalWire()
	if err != nil {
		return Round{}, nil, err
	}
	return Round{Member: member, Output: cells, Proof: encodedProof}, output, nil
}

// VerifyChain re-verifies a full shuffle chain against the sealed batch and
// returns the batch to decrypt.
//
// Every certified member must appear exactly once, in the committee's order.
// This is the anytrust assumption made mechanical: the chain is unlinkable
// only if at least one shuffler is honest, so a chain that skipped a member
// -- for any reason, including that the member was unreachable -- is not a
// shorter chain but a chain with a different, smaller honest-party
// assumption. It is refused rather than accepted with a warning, and there is
// no partial-chain path for an operator to fall back to.
func VerifyChain(committee mix.ThresholdCommittee, sealed *mix.Batch, rounds []Round) (*mix.Batch, error) {
	if err := mix.ValidateThresholdCommittee(committee); err != nil {
		return nil, err
	}
	if sealed == nil {
		return nil, errors.New("sealed batch is required")
	}
	if len(rounds) != len(committee.Members) {
		return nil, fmt.Errorf("%w: %d rounds for %d members",
			ErrChainIncomplete, len(rounds), len(committee.Members))
	}
	current := sealed
	for position, round := range rounds {
		expected := committee.Members[position].Index
		if round.Member != expected {
			return nil, fmt.Errorf("%w: round %d is from member %d, expected %d",
				ErrChainIncomplete, position, round.Member, expected)
		}
		if len(round.Output) != current.Len() {
			return nil, fmt.Errorf("%w: round %d changed the batch size from %d to %d",
				ErrShuffleInvalid, position, current.Len(), len(round.Output))
		}
		output, err := mix.ParseWire(round.Output)
		if err != nil {
			return nil, fmt.Errorf("%w: round %d output: %v", ErrShuffleInvalid, position, err)
		}
		if err := mix.VerifyShuffle(committee.PublicKey, current, output, round.Proof); err != nil {
			return nil, fmt.Errorf("%w: round %d from member %d: %v",
				ErrShuffleInvalid, position, round.Member, err)
		}
		current = output
	}
	return current, nil
}

// Release performs threshold decryption of a verified chain output and
// returns only the real fragments.
//
// Cover is dropped here and nowhere earlier: it is indistinguishable from a
// real deposit until it has been decrypted, which is the point of it. The
// number of fragments returned is therefore known only to a party holding
// threshold authority, and is never part of the public record of the epoch.
func Release(committee mix.ThresholdCommittee, mixed *mix.Batch,
	partials []*mix.PartialDecryption) ([]mix.PlainCell, error) {
	plaintexts, err := mix.ThresholdDecrypt(committee, mixed, partials)
	if err != nil {
		return nil, err
	}
	fragments := make([]mix.PlainCell, 0, len(plaintexts))
	for _, plaintext := range plaintexts {
		if IsCover(plaintext) {
			continue
		}
		fragments = append(fragments, plaintext)
	}
	return fragments, nil
}
