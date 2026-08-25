package availability

import (
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// Selective failure is the attack the quorum rule is weakest against, and the
// claim matrix recorded it as untested.
//
// An operator that fails everybody is caught: every peer signs a non-receipt
// and the quorum forms. An operator that serves *some* peers and starves others
// is choosing how many accusers it will have. If it keeps its non-deliveries
// below the quorum it is invisible to this mechanism entirely, and the peers it
// starved cannot escalate, because a report below quorum establishes nothing --
// which is the same property that stops one operator evicting a peer it
// dislikes. The two cannot be separated by tuning the number.
//
// So these tests do not assert that selective failure is detected. They
// establish where the boundary actually sits, so the registry can say what is
// and is not covered instead of leaving it blank.

// selectivelyDelivers answers Delivered per (observer, accused) pair, so one
// operator can appear healthy to some peers and absent to others.
type selectivelyDelivers struct {
	// starved lists the member indices this observer did not receive.
	starved map[uint32]struct{}
}

func (s selectivelyDelivers) Delivered(_ string, index uint32) (bool, error) {
	_, missing := s.starved[index]
	return !missing, nil
}

// gather runs each observer against its own view and returns every statement.
func gather(t *testing.T, f *fixture, views map[int]map[uint32]struct{}) []mix.NonReceipt {
	t.Helper()
	var statements []mix.NonReceipt
	for observer := 0; observer < len(f.operators); observer++ {
		starved := views[observer]
		if starved == nil {
			starved = map[uint32]struct{}{}
		}
		judgements, err := f.observer(t, observer, selectivelyDelivers{starved: starved}).Observe(f.position)
		if err != nil {
			t.Fatal(err)
		}
		for _, judgement := range judgements {
			if judgement.Statement != nil {
				statements = append(statements, *judgement.Statement)
			}
		}
	}
	return statements
}

// An operator that starves enough peers is caught exactly as a total failure is.
func TestAnOperatorThatStarvesAQuorumIsReported(t *testing.T) {
	f := newFixture(t, 5)
	// Member 4 does not deliver to observers 0, 1 and 2.
	statements := gather(t, f, map[int]map[uint32]struct{}{
		0: {4: {}}, 1: {4: {}}, 2: {4: {}},
	})
	reports, err := Assemble(f.committee, f.operators, statements, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("assembled %d reports, want 1: three observers starved by one operator "+
			"is a quorum", len(reports))
	}
}

// An operator that starves fewer peers than the quorum is invisible here. That
// is not a defect to fix by lowering the quorum: the same threshold is what
// stops a coalition evicting an honest operator, and one accuser must never be
// enough. The gap is recorded rather than closed.
func TestAnOperatorThatStarvesFewerThanAQuorumIsNotReported(t *testing.T) {
	f := newFixture(t, 5)
	statements := gather(t, f, map[int]map[uint32]struct{}{
		0: {4: {}}, 1: {4: {}},
	})
	reports, err := Assemble(f.committee, f.operators, statements, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Fatalf("assembled %d reports from two starved observers at a quorum of three", len(reports))
	}

	// The starved peers really did observe a failure -- they are not confused,
	// they are simply too few. Their statements exist and verify; what does not
	// exist is a quorum.
	if len(statements) != 2 {
		t.Fatalf("the starved observers produced %d statements, want 2", len(statements))
	}
	for index, statement := range statements {
		if err := mix.VerifyNonReceipt(statement); err != nil {
			t.Fatalf("statement %d does not verify: %v", index, err)
		}
	}
}

// Starving different peers on different rounds does not accumulate: each report
// is scoped to one position, so an operator can fail a minority every round
// forever and never assemble a quorum at any one of them.
//
// This is the sharpest form of the gap and the reason the registry must not
// claim selective failure is covered.
func TestStarvingADifferentMinorityEachRoundNeverAccumulates(t *testing.T) {
	f := newFixture(t, 5)
	total := 0
	for round := 0; round < 8; round++ {
		// Rotate which two observers member 4 starves.
		first := uint32(round % 4)
		second := uint32((round + 1) % 4)
		statements := gather(t, f, map[int]map[uint32]struct{}{
			int(first): {4: {}}, int(second): {4: {}},
		})
		reports, err := Assemble(f.committee, f.operators, statements, 3)
		if err != nil {
			t.Fatal(err)
		}
		total += len(reports)
	}
	if total != 0 {
		t.Fatalf("%d reports assembled; the rotation was expected to stay below quorum "+
			"every round, so this test no longer demonstrates the gap it documents", total)
	}
}

// And the mechanism must not be gameable in the other direction: an operator
// cannot escape by starving observers that do not exist, or by being reported
// by fewer distinct peers than it appears.
func TestOneStarvedObserverCannotBeCountedTwice(t *testing.T) {
	f := newFixture(t, 5)
	statements := gather(t, f, map[int]map[uint32]struct{}{0: {4: {}}})
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(statements))
	}
	repeated := []mix.NonReceipt{statements[0], statements[0], statements[0], statements[0]}
	reports, err := Assemble(f.committee, f.operators, repeated, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Fatal("one starved observer reached quorum by repetition")
	}
}
