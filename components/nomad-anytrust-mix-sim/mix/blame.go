package mix

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Fault kinds a chain of shuffle rounds can exhibit.
const (
	// FaultUnsoundRound: the mixer signed a receipt committing to a
	// transformation whose proof does not verify. This is attributable to that
	// mixer and to nobody else: the receipt carries their signature over the
	// input, output and proof digests together.
	FaultUnsoundRound = "unsound-round"
	// FaultForgedReceipt: the receipt does not verify under the public key it
	// names, so it was not produced by that mixer. The named mixer is a
	// victim here, not a culprit, and the report says so.
	FaultForgedReceipt = "forged-receipt"
	// FaultBrokenLinkage: round i's output is not round i+1's input. Either
	// neighbour could have produced this, so it is attributed to whoever
	// assembled the chain rather than to a mixer.
	FaultBrokenLinkage = "broken-linkage"
	// FaultWrongCommittee: a round names a mixer outside the certified
	// committee, or the wrong committee or epoch.
	FaultWrongCommittee = "wrong-committee"
)

// SignedRound is one mixer's contribution together with the receipt they
// signed over it. It is Round plus the accountability material: a Round alone
// shows a transformation and cannot say who claimed it.
type SignedRound struct {
	Round
	Receipt RoundReceipt
}

// FaultReport names what is wrong with a chain and, where the protocol can
// actually attribute it, who is responsible.
//
// A report is evidence rather than testimony. Everything it asserts is
// re-derivable from material the accused signed, so VerifyFaultReport
// establishes the fault independently instead of trusting the reporter. That
// is the difference between accountability and an accusation: a blame report
// nobody else can check is worth nothing against a mixer who denies it, and
// worse than nothing against an honest mixer someone wants to remove.
type FaultReport struct {
	Kind string
	// Round is the zero-based index in the chain.
	Round int
	// Accused is the mixer this fault is attributable to, empty when the
	// protocol cannot attribute it to one.
	Accused []byte
	// Attributable records whether Accused is a culprit. False means the
	// fault is real but the responsible party cannot be identified from the
	// transcript alone.
	Attributable bool
	Reason       string
}

func (report FaultReport) Error() string {
	if report.Attributable {
		return fmt.Sprintf("round %d: %s by mixer %x: %s",
			report.Round, report.Kind, report.Accused, report.Reason)
	}
	return fmt.Sprintf("round %d: %s (not attributable to one mixer): %s",
		report.Round, report.Kind, report.Reason)
}

// AttributeFault verifies a chain of rounds and returns the first fault found,
// or nil when the chain is sound.
//
// mixers is the certified set of mixer identity keys; a round signed by
// anyone outside it is a fault regardless of whether its proof verifies.
func AttributeFault(encryptionKey PublicKey, committee ThresholdCommittee,
	mixers []ed25519.PublicKey, rounds []SignedRound) *FaultReport {
	if len(rounds) == 0 {
		return &FaultReport{Kind: FaultBrokenLinkage, Round: 0,
			Reason: "a transcript with no rounds proves no mixing occurred"}
	}
	members := map[string]struct{}{}
	for _, mixer := range mixers {
		members[string(mixer)] = struct{}{}
	}

	for index, round := range rounds {
		if round.Input == nil || round.Output == nil {
			return &FaultReport{Kind: FaultBrokenLinkage, Round: index,
				Reason: "round is missing its input or output batch"}
		}
		if _, member := members[string(round.Receipt.MixerPublic[:])]; !member {
			return &FaultReport{Kind: FaultWrongCommittee, Round: index,
				Accused:      append([]byte(nil), round.Receipt.MixerPublic[:]...),
				Attributable: true,
				Reason:       "the receipt names a key outside the certified committee"}
		}
		if round.Receipt.Context.CommitteeID != committee.ID ||
			round.Receipt.Context.Epoch != committee.Epoch {
			return &FaultReport{Kind: FaultWrongCommittee, Round: index,
				Accused:      append([]byte(nil), round.Receipt.MixerPublic[:]...),
				Attributable: true,
				Reason:       "the round is bound to a different committee or epoch"}
		}
		// Linkage before soundness: a mixer must not be accused of an unsound
		// round when they were handed the wrong input.
		if index > 0 {
			previous, err := rounds[index-1].Output.Digest()
			if err != nil {
				return &FaultReport{Kind: FaultBrokenLinkage, Round: index - 1,
					Reason: "the previous round's output could not be digested"}
			}
			current, err := round.Input.Digest()
			if err != nil {
				return &FaultReport{Kind: FaultBrokenLinkage, Round: index,
					Reason: "this round's input could not be digested"}
			}
			if previous != current {
				return &FaultReport{Kind: FaultBrokenLinkage, Round: index,
					Reason: "this round's input is not the previous round's output, " +
						"which either neighbour could have caused"}
			}
		}
		if err := VerifySignedRound(encryptionKey, round.Input, round.Output,
			round.Proof, round.Receipt); err != nil {
			// Distinguish a mixer who signed something unsound from a receipt
			// that was never theirs. Only the first is their fault.
			if !ed25519.Verify(round.Receipt.MixerPublic[:],
				receiptSigningMessage(round.Receipt, encryptionKey),
				round.Receipt.Signature[:]) {
				return &FaultReport{Kind: FaultForgedReceipt, Round: index,
					Accused:      append([]byte(nil), round.Receipt.MixerPublic[:]...),
					Attributable: false,
					Reason: "the receipt does not verify under the key it names, so " +
						"that mixer did not produce it"}
			}
			return &FaultReport{Kind: FaultUnsoundRound, Round: index,
				Accused:      append([]byte(nil), round.Receipt.MixerPublic[:]...),
				Attributable: true,
				Reason: "the mixer signed a receipt committing to this transformation " +
					"and it does not verify: " + err.Error()}
		}
	}
	return nil
}

// VerifyFaultReport re-derives a report from the transcript it accuses, so a
// third party can confirm the fault without trusting whoever reported it.
//
// It refuses a report that does not match what the transcript actually shows,
// which is what stops blame being usable as a weapon against an honest mixer.
func VerifyFaultReport(encryptionKey PublicKey, committee ThresholdCommittee,
	mixers []ed25519.PublicKey, rounds []SignedRound, report FaultReport) error {
	derived := AttributeFault(encryptionKey, committee, mixers, rounds)
	if derived == nil {
		return errors.New("the transcript is sound, so this report accuses a mixer of nothing")
	}
	if derived.Kind != report.Kind || derived.Round != report.Round ||
		derived.Attributable != report.Attributable {
		return fmt.Errorf("the transcript shows %q at round %d, not %q at round %d",
			derived.Kind, derived.Round, report.Kind, report.Round)
	}
	if string(derived.Accused) != string(report.Accused) {
		return errors.New("the report names a different mixer than the transcript does")
	}
	return nil
}
