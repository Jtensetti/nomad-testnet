package mix

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// Two guards in the accountability layer could be deleted with the whole suite
// still green. Both decide whether evidence of misbehaviour is believable, so
// both are worth a test that fails when they go.

// A receipt tracker is scoped to one committee epoch, and its own comment says
// so. Nothing held it to that.
//
// The scoping is what keeps the equivocation slot honest. Its key is the batch
// and the round -- not the committee, not the epoch -- so a tracker that
// accepted foreign receipts would put two unrelated committees into the same
// slot. That fails in both directions and each is worse than a missed check:
// two honest receipts from different epochs collide and the tracker reports
// equivocation against a mixer that did nothing, and a foreign receipt can
// occupy a slot first so a real equivocation afterwards reads as a difference
// from something that was never this committee's receipt at all.
func TestTheTrackerRefusesReceiptsFromAnotherCommitteeOrEpoch(t *testing.T) {
	committee := CommitteeID{4}
	const epoch = uint64(9)
	tracker, err := NewReceiptTracker(committee, epoch)
	if err != nil {
		t.Fatal(err)
	}

	receipt := func(id CommitteeID, at uint64) RoundReceipt {
		var out RoundReceipt
		out.Context = RoundContext{CommitteeID: id, Epoch: at, Round: 1}
		for index := range out.Context.BatchID {
			out.Context.BatchID[index] = 0x11
		}
		for index := range out.MixerPublic {
			out.MixerPublic[index] = 0x22
		}
		return out
	}

	// Vacuity: the tracker's own committee and epoch is accepted, so the
	// refusals below are about what was changed and not about the receipt.
	if err := tracker.Accept(receipt(committee, epoch)); err != nil {
		t.Fatalf("the tracker refused a receipt from its own committee epoch: %v", err)
	}

	for _, scenario := range []struct {
		name string
		id   CommitteeID
		at   uint64
	}{
		{"another committee", CommitteeID{5}, epoch},
		{"another epoch", committee, epoch + 1},
		{"an earlier epoch", committee, epoch - 1},
		{"both", CommitteeID{5}, epoch + 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fresh, err := NewReceiptTracker(committee, epoch)
			if err != nil {
				t.Fatal(err)
			}
			err = fresh.Accept(receipt(scenario.id, scenario.at))
			if err == nil {
				t.Fatalf("the tracker accepted a receipt from %s", scenario.name)
			}
			if errors.Is(err, ErrRoundEquivocate) || errors.Is(err, ErrRoundReplay) {
				t.Fatalf("a receipt from %s was reported as this committee's own "+
					"misbehaviour: %v", scenario.name, err)
			}
			if !strings.Contains(err.Error(), "committee epoch") {
				t.Fatalf("the refusal does not say what was wrong: %v", err)
			}
		})
	}

	// And the slot a foreign receipt would have taken is still free, so a
	// genuine equivocation there is still detected.
	second := receipt(committee, epoch)
	for index := range second.MixerPublic {
		second.MixerPublic[index] = 0x33
	}
	if err := tracker.Accept(second); !errors.Is(err, ErrRoundEquivocate) {
		t.Fatalf("a real equivocation in that slot was not detected: %v", err)
	}
}

// One operator signing the same observation several times must not reach a
// quorum by itself. The check exists and says exactly that in its comment;
// nothing exercised it, which is the same shape as the duplicate-key check in
// a witness policy and matters for the same reason -- a threshold is only
// worth anything if the signers are different parties.
func TestOneObserverCannotManufactureAQuorumByRepeatingItself(t *testing.T) {
	committee := ThresholdCommittee{Threshold: 2, Epoch: 3}
	for index := range committee.ID {
		committee.ID[index] = byte(index + 1)
	}
	ctx := RoundContext{CommitteeID: committee.ID, Epoch: committee.Epoch, Round: 1}
	for index := range ctx.BatchID {
		ctx.BatchID[index] = 0x77
	}
	const deadline = int64(1000)

	keys := make([]ed25519.PublicKey, 0, 4)
	privates := make([]ed25519.PrivateKey, 0, 4)
	for i := 0; i < 4; i++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, public)
		privates = append(privates, private)
	}
	var accused [ed25519.PublicKeySize]byte
	copy(accused[:], keys[0])

	sign := func(observer ed25519.PrivateKey) NonReceipt {
		t.Helper()
		statement, err := SignNonReceipt(ctx, deadline, accused, observer)
		if err != nil {
			t.Fatal(err)
		}
		return statement
	}

	// Vacuity: three distinct observers do reach a quorum of three, so the
	// refusal below is about the repetition rather than about the report.
	genuine := AvailabilityReport{Context: ctx, Deadline: deadline, Accused: accused,
		Observations: []NonReceipt{sign(privates[1]), sign(privates[2]), sign(privates[3])}}
	if err := VerifyAvailabilityReport(committee, keys, genuine, 3); err != nil {
		t.Fatalf("three distinct observers did not establish a quorum of three: %v", err)
	}

	// The same operator, three genuinely signed statements. Every signature
	// verifies; what must not happen is that they count as three parties.
	repeated := AvailabilityReport{Context: ctx, Deadline: deadline, Accused: accused,
		Observations: []NonReceipt{sign(privates[1]), sign(privates[1]), sign(privates[1])}}
	err := VerifyAvailabilityReport(committee, keys, repeated, 3)
	if err == nil {
		t.Fatal("one observer signing three times established a quorum of three")
	}
	if !strings.Contains(err.Error(), "repeats an observer") {
		t.Fatalf("the refusal does not name the repetition: %v", err)
	}

	// Mixed: two real observers and one of them again. Two parties, quorum of
	// three, and the third signature is not a third party.
	mixed := AvailabilityReport{Context: ctx, Deadline: deadline, Accused: accused,
		Observations: []NonReceipt{sign(privates[1]), sign(privates[2]), sign(privates[1])}}
	if err := VerifyAvailabilityReport(committee, keys, mixed, 3); err == nil {
		t.Fatal("two observers reached a quorum of three by one of them signing twice")
	}

	// The accused reporting itself is refused a step earlier than the report:
	// SignNonReceipt will not produce the statement at all, so there is
	// nothing for the quorum to count.
	if _, err := SignNonReceipt(ctx, deadline, accused, privates[0]); err == nil {
		t.Fatal("an operator signed a statement about its own absence")
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	outside := AvailabilityReport{Context: ctx, Deadline: deadline, Accused: accused,
		Observations: []NonReceipt{sign(privates[1]), sign(privates[2]), sign(stranger)}}
	if err := VerifyAvailabilityReport(committee, keys, outside, 3); err == nil {
		t.Fatal("a key outside the certified committee counted toward the quorum")
	}
}
