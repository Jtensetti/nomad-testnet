package availability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type fixture struct {
	committee  mix.ThresholdCommittee
	operators  []topology.Operator
	identities []ed25519.PrivateKey
	schedule   mix.RoundSchedule
	position   Position
}

func newFixture(t *testing.T, count int) *fixture {
	t.Helper()
	var id mix.CommitteeID
	copy(id[:], []byte("availability-test-committee-0001"))
	committee, _, err := mix.GenerateDealerCommittee(id, 9, uint32(count), uint32(count/2+1))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		committee: committee,
		schedule: mix.RoundSchedule{
			EpochStart:    time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC).UnixNano(),
			BatchInterval: 30 * time.Second,
			RoundBudget:   3 * time.Second,
		},
	}
	for index := 0; index < count; index++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.identities = append(f.identities, private)
		f.operators = append(f.operators, topology.Operator{
			ID:          fmt.Sprintf("op-%d", index),
			Index:       uint16(index),
			IdentityKey: base64.StdEncoding.EncodeToString(public),
		})
	}
	var digest [32]byte
	copy(digest[:], []byte("availability-test-batch-digest-1"))
	f.position = Position{StreamID: "stream-a", BatchDigest: digest, Slot: 11}
	return f
}

func (f *fixture) observer(t *testing.T, self int, delivery Delivery) Observer {
	t.Helper()
	return Observer{
		Schedule:  f.schedule,
		Committee: f.committee,
		Operators: f.operators,
		Self:      f.operators[self].ID,
		Identity:  f.identities[self],
		Delivery:  delivery,
	}
}

// fakeDelivery answers from a fixed set of member indices.
type fakeDelivery map[uint32]bool

func (d fakeDelivery) Delivered(_ string, index uint32) (bool, error) { return d[index], nil }

// The shape of an observation must never depend on how many operators failed.
// If it did, the volume of reports a network emits would track operator load,
// and operator load tracks what people are reading.
func TestEveryCertifiedOperatorIsJudgedWhateverHappened(t *testing.T) {
	f := newFixture(t, 5)

	for name, delivered := range map[string]fakeDelivery{
		"everyone delivered": {0: true, 1: true, 2: true, 3: true, 4: true},
		"nobody delivered":   {},
		"one failed":         {0: true, 1: true, 2: true, 3: true},
	} {
		t.Run(name, func(t *testing.T) {
			judgements, err := f.observer(t, 0, delivered).Observe(f.position)
			if err != nil {
				t.Fatal(err)
			}
			if len(judgements) != len(f.operators) {
				t.Fatalf("judged %d operators, want %d: the number of judgements "+
					"must not vary with how many delivered", len(judgements), len(f.operators))
			}
			for index, judgement := range judgements {
				if judgement.MemberIndex != uint32(index) {
					t.Fatalf("judgement %d is about member %d: the order must be the "+
						"committee's, not arrival order", index, judgement.MemberIndex)
				}
			}
		})
	}
}

func TestStatementsAreSignedOnlyForPeersThatDidNotDeliver(t *testing.T) {
	f := newFixture(t, 5)
	// Member 0 is the observer itself and also did not deliver.
	judgements, err := f.observer(t, 0, fakeDelivery{1: true, 2: true}).Observe(f.position)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[uint32]bool{}
	for _, judgement := range judgements {
		if judgement.Statement == nil {
			continue
		}
		signed[judgement.MemberIndex] = true
		if err := mix.VerifyNonReceipt(*judgement.Statement); err != nil {
			t.Fatalf("member %d: %v", judgement.MemberIndex, err)
		}
	}
	want := map[uint32]bool{3: true, 4: true}
	if !reflect.DeepEqual(signed, want) {
		t.Fatalf("signed statements about %v, want %v", signed, want)
	}
	if signed[0] {
		t.Fatal("the observer signed a statement about itself")
	}
}

// The deadline must come from the timetable. A caller that could vary it could
// make the accusation depend on when the observer happened to run.
func TestStatementsCarryTheScheduledDeadline(t *testing.T) {
	f := newFixture(t, 5)
	expected, err := f.schedule.Deadline(f.position.Slot, 0)
	if err != nil {
		t.Fatal(err)
	}
	judgements, err := f.observer(t, 0, fakeDelivery{}).Observe(f.position)
	if err != nil {
		t.Fatal(err)
	}
	statements := 0
	for _, judgement := range judgements {
		if judgement.Statement == nil {
			continue
		}
		statements++
		if judgement.Statement.Deadline != expected {
			t.Fatalf("member %d carries deadline %d, want the scheduled %d",
				judgement.MemberIndex, judgement.Statement.Deadline, expected)
		}
		if judgement.Statement.Context.BatchID != f.position.BatchDigest {
			t.Fatal("a statement is not bound to the batch it is about")
		}
		if judgement.Statement.Context.Epoch != f.committee.Epoch {
			t.Fatal("a statement is not bound to the committee epoch")
		}
	}
	if statements != len(f.operators)-1 {
		t.Fatalf("signed %d statements, want %d", statements, len(f.operators)-1)
	}
}

// Observing the same position twice must produce the same accusations. A
// difference between two identical observations would be a channel.
func TestObservationIsDeterministicForAPosition(t *testing.T) {
	f := newFixture(t, 5)
	observer := f.observer(t, 0, fakeDelivery{1: true})

	first, err := observer.Observe(f.position)
	if err != nil {
		t.Fatal(err)
	}
	second, err := observer.Observe(f.position)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("two observations of one position judged %d and %d operators",
			len(first), len(second))
	}
	for index := range first {
		if first[index].OperatorID != second[index].OperatorID ||
			first[index].Delivered != second[index].Delivered {
			t.Fatalf("judgement %d differed between two observations of one position", index)
		}
		if (first[index].Statement == nil) != (second[index].Statement == nil) {
			t.Fatalf("judgement %d signed a statement in one observation and not the other", index)
		}
		if first[index].Statement == nil {
			continue
		}
		// Ed25519 is deterministic, so identical inputs must produce
		// identical signatures. A difference would mean something outside the
		// public position entered the message.
		if *first[index].Statement != *second[index].Statement {
			t.Fatalf("judgement %d produced two different statements for one position", index)
		}
	}
}

func TestAnObserverWithoutADeliverySourceIsRefused(t *testing.T) {
	f := newFixture(t, 5)
	observer := f.observer(t, 0, nil)
	if _, err := observer.Observe(f.position); err == nil {
		t.Fatal("an observer with no delivery source ran and accused everybody")
	}
}

func TestAnObserverOutsideTheCertifiedSetIsRefused(t *testing.T) {
	f := newFixture(t, 5)
	observer := f.observer(t, 0, fakeDelivery{})
	observer.Self = "op-not-certified"
	if _, err := observer.Observe(f.position); err == nil {
		t.Fatal("an operator outside the certified set signed statements about its peers")
	}
}

// Assembly is where statements become a report, so it is where a quorum is
// either enforced or lost.
func TestAssemblyReachesQuorumOnlyWithDistinctCertifiedObservers(t *testing.T) {
	f := newFixture(t, 5)
	delivered := fakeDelivery{0: true, 1: true, 2: true, 3: true}

	var statements []mix.NonReceipt
	for observerIndex := 0; observerIndex < 3; observerIndex++ {
		judgements, err := f.observer(t, observerIndex, delivered).Observe(f.position)
		if err != nil {
			t.Fatal(err)
		}
		for _, judgement := range judgements {
			if judgement.Statement != nil {
				statements = append(statements, *judgement.Statement)
			}
		}
	}

	reports, err := Assemble(f.committee, f.operators, statements, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("assembled %d reports, want 1 about the operator that did not deliver", len(reports))
	}
	var expected [ed25519.PublicKeySize]byte
	key, err := topology.OperatorIdentity(f.operators[4])
	if err != nil {
		t.Fatal(err)
	}
	copy(expected[:], key)
	if reports[0].Accused != expected {
		t.Fatalf("the report accuses %x, want operator 4 (%x)", reports[0].Accused[:8], expected[:8])
	}

	// The same statements must establish nothing at a higher quorum.
	higher, err := Assemble(f.committee, f.operators, statements, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(higher) != 0 {
		t.Fatalf("three observers established %d reports at a quorum of four", len(higher))
	}
}

// One operator repeating itself is the cheapest attack on a quorum rule, and
// the one an implementation is most likely to miss.
func TestOneObserverRepeatingItselfEstablishesNothing(t *testing.T) {
	f := newFixture(t, 5)
	judgements, err := f.observer(t, 0, fakeDelivery{0: true, 1: true, 2: true, 3: true}).Observe(f.position)
	if err != nil {
		t.Fatal(err)
	}
	var only mix.NonReceipt
	for _, judgement := range judgements {
		if judgement.Statement != nil {
			only = *judgement.Statement
		}
	}
	reports, err := Assemble(f.committee, f.operators,
		[]mix.NonReceipt{only, only, only, only}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Fatal("one operator repeating its own statement reached quorum")
	}
}

// A single malformed statement must not suppress the reports the honest
// observers established, or one operator could silence the whole mechanism by
// sending garbage.
func TestAMalformedStatementDoesNotSuppressTheOthers(t *testing.T) {
	f := newFixture(t, 5)
	delivered := fakeDelivery{0: true, 1: true, 2: true, 3: true}

	var statements []mix.NonReceipt
	for observerIndex := 0; observerIndex < 3; observerIndex++ {
		judgements, err := f.observer(t, observerIndex, delivered).Observe(f.position)
		if err != nil {
			t.Fatal(err)
		}
		for _, judgement := range judgements {
			if judgement.Statement != nil {
				statements = append(statements, *judgement.Statement)
			}
		}
	}
	forged := statements[0]
	forged.Signature[0] ^= 0xFF
	statements = append([]mix.NonReceipt{forged}, statements...)

	reports, err := Assemble(f.committee, f.operators, statements, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("a forged statement reduced the assembly to %d reports, want 1", len(reports))
	}
	if err := mix.VerifyAvailabilityReport(f.committee, mustKeys(t, f.operators), reports[0], 3); err != nil {
		t.Fatalf("the assembled report does not verify: %v", err)
	}
}

func mustKeys(t *testing.T, operators []topology.Operator) []ed25519.PublicKey {
	t.Helper()
	keys, err := CertifiedKeys(operators)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Presence is not delivery: an operator that writes something unusable has
// produced nothing a peer can combine.
func TestUnusablePartialsAreNotDeliveries(t *testing.T) {
	directory := t.TempDir()
	partials := VerifiedPartials{
		Directory: directory,
		Decode: func(encoded []byte) (*mix.PartialDecryption, error) {
			return batch.DecodePartial(encoded, batch.VerifiedDescriptor{})
		},
		Verify: func(*mix.PartialDecryption) error { return nil },
	}

	for name, content := range map[string][]byte{
		"empty":     {},
		"truncated": []byte(`{"version":"nomad-partial-v`),
		"not json":  []byte("this is not a partial"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, fmt.Sprintf("stream-a-%02d.partial.json", 3))
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			delivered, err := partials.Delivered("stream-a", 3)
			if err != nil {
				t.Fatalf("an unusable partial produced an error instead of a non-delivery: %v", err)
			}
			if delivered {
				t.Fatalf("a %s partial counted as a delivery", name)
			}
		})
	}

	t.Run("absent", func(t *testing.T) {
		delivered, err := partials.Delivered("stream-a", 4)
		if err != nil {
			t.Fatal(err)
		}
		if delivered {
			t.Fatal("an absent partial counted as a delivery")
		}
	})
}

func TestAPartialsSourceWithoutAVerifierIsRefused(t *testing.T) {
	for name, partials := range map[string]VerifiedPartials{
		"no verifier": {Directory: t.TempDir(),
			Decode: func([]byte) (*mix.PartialDecryption, error) { return nil, nil }},
		"no decoder": {Directory: t.TempDir(),
			Verify: func(*mix.PartialDecryption) error { return nil }},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := partials.Delivered("stream-a", 0); err == nil {
				t.Fatal("a partials source answered without checking anything")
			}
		})
	}
}

// SlotFor maps a batch to its timetable position and must depend on nothing
// but the schedule and the time the slot opened.
func TestSlotForFollowsTheTimetable(t *testing.T) {
	f := newFixture(t, 3)
	observer := f.observer(t, 0, fakeDelivery{})
	start := time.Unix(0, f.schedule.EpochStart)

	for offset, want := range map[time.Duration]uint64{
		0:                                  0,
		29 * time.Second:                   0,
		30 * time.Second:                   1,
		90 * time.Second:                   3,
		30 * time.Second * 1000:            1000,
		30*time.Second*7 + time.Nanosecond: 7,
	} {
		slot, err := observer.SlotFor(start.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if slot != want {
			t.Fatalf("%s after the epoch opened is slot %d, want %d", offset, slot, want)
		}
	}

	if _, err := observer.SlotFor(start.Add(-time.Nanosecond)); err == nil {
		t.Fatal("a batch before the epoch opened was given a slot")
	}
}
