package mix

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type availabilityFixture struct {
	*blameFixture
	// observers are certified operators who are not the accused.
	observerPublics  []ed25519.PublicKey
	observerPrivates []ed25519.PrivateKey
	accused          [ed25519.PublicKeySize]byte
	ctx              RoundContext
	deadline         int64
	// elsewhere is a sound round the accused mixer signed at a different
	// position. Answering a report with it must fail on the position alone,
	// with no help from the identity check.
	elsewhere SignedRound
}

// signElsewhere has the accused mixer shuffle an unrelated batch, so the test
// holds a round that is genuinely theirs and genuinely sound but belongs to a
// different committee position.
func (f *availabilityFixture) signElsewhere(t *testing.T) SignedRound {
	t.Helper()
	batch, err := Encrypt(f.committee.PublicKey, testCells(4))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := batch.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ctx := RoundContext{
		CommitteeID: f.committee.ID, Epoch: f.committee.Epoch,
		BatchID: digest, Round: f.ctx.Round,
	}
	if ctx.BatchID == f.ctx.BatchID {
		t.Fatal("the unrelated batch collided with the accused round's batch")
	}
	output, proof, receipt, err := ShuffleAndSign(ctx, f.committee.PublicKey, batch, f.privates[1])
	if err != nil {
		t.Fatal(err)
	}
	return SignedRound{Round: Round{Input: batch, Output: output, Proof: proof}, Receipt: receipt}
}

// buildAvailability produces a three-round sound chain plus four certified
// observers, and points a report at the middle mixer's round.
func buildAvailability(t *testing.T) *availabilityFixture {
	t.Helper()
	chain := buildChain(t, 3)
	fixture := &availabilityFixture{blameFixture: chain}
	copy(fixture.accused[:], chain.mixers[1])
	fixture.ctx = chain.rounds[1].Receipt.Context

	schedule := RoundSchedule{
		EpochStart:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).UnixNano(),
		BatchInterval: 30 * time.Second,
		RoundBudget:   2 * time.Second,
	}
	deadline, err := schedule.Deadline(7, fixture.ctx.Round)
	if err != nil {
		t.Fatal(err)
	}
	fixture.deadline = deadline

	for i := 0; i < 4; i++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixture.observerPublics = append(fixture.observerPublics, public)
		fixture.observerPrivates = append(fixture.observerPrivates, private)
		fixture.mixers = append(fixture.mixers, public)
	}
	fixture.elsewhere = fixture.signElsewhere(t)
	return fixture
}

func (f *availabilityFixture) report(t *testing.T, observers int) AvailabilityReport {
	t.Helper()
	report := AvailabilityReport{Context: f.ctx, Deadline: f.deadline, Accused: f.accused}
	for i := 0; i < observers; i++ {
		statement, err := SignNonReceipt(f.ctx, f.deadline, f.accused, f.observerPrivates[i])
		if err != nil {
			t.Fatal(err)
		}
		report.Observations = append(report.Observations, statement)
	}
	return report
}

// The deadline is the load-bearing public input: everything downstream is
// bound to it, so it must be a pure function of the timetable and position.
func TestDeadlineIsAPureFunctionOfThePublicTimetable(t *testing.T) {
	schedule := RoundSchedule{
		EpochStart:    1_800_000_000_000_000_000,
		BatchInterval: time.Minute,
		RoundBudget:   5 * time.Second,
	}
	first, err := schedule.Deadline(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	again, err := schedule.Deadline(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("the same public position produced two deadlines: %d and %d", first, again)
	}
	want := schedule.EpochStart + 3*int64(time.Minute) + 3*int64(5*time.Second)
	if first != want {
		t.Fatalf("deadline %d, want %d", first, want)
	}
	// Later positions are strictly later, so a mixer cannot gain time by
	// claiming a different slot.
	laterSlot, err := schedule.Deadline(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	laterRound, err := schedule.Deadline(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if laterSlot <= first || laterRound <= first {
		t.Fatalf("deadlines are not monotonic in slot or round: %d %d %d", first, laterSlot, laterRound)
	}
	if _, err := (RoundSchedule{}).Deadline(0, 0); err == nil {
		t.Fatal("an unconfigured schedule produced a deadline")
	}
}

func TestQuorumOfDistinctObserversEstablishesTheReport(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 3)
	if err := VerifyAvailabilityReport(f.committee, f.mixers, report, 3); err != nil {
		t.Fatalf("an honest quorum did not verify: %v", err)
	}
	fault := AvailabilityFault(report)
	if fault.Kind != FaultUnavailable {
		t.Fatalf("wrong kind: %+v", fault)
	}
	if fault.Attributable {
		t.Fatal("unavailability was reported as attributable, which asynchrony does not permit")
	}
}

// One operator must not be able to remove a peer on its own say-so.
func TestBelowQuorumEstablishesNothing(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 1)
	err := VerifyAvailabilityReport(f.committee, f.mixers, report, 3)
	if !errors.Is(err, ErrBelowQuorum) {
		t.Fatalf("a single observer reached quorum: %v", err)
	}
}

// Nor by signing the same statement several times.
func TestRepeatedObserverCannotManufactureQuorum(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 1)
	report.Observations = append(report.Observations, report.Observations[0], report.Observations[0])
	if err := VerifyAvailabilityReport(f.committee, f.mixers, report, 3); err == nil {
		t.Fatal("one observer manufactured a quorum by repeating itself")
	}
}

// Nor by recruiting keys the committee never certified.
func TestObserverOutsideTheCommitteeDoesNotCount(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 3)
	_, outsider, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := SignNonReceipt(f.ctx, f.deadline, f.accused, outsider)
	if err != nil {
		t.Fatal(err)
	}
	report.Observations = []NonReceipt{report.Observations[0], report.Observations[1], statement}
	if err := VerifyAvailabilityReport(f.committee, f.mixers, report, 3); err == nil {
		t.Fatal("an uncertified key counted toward the quorum")
	}
}

// A statement signed about round 0 must not be replayed into a report about
// round 1, or a report about a different epoch, batch or mixer.
func TestStatementsDoNotTransplantAcrossPositions(t *testing.T) {
	f := buildAvailability(t)
	honest := f.report(t, 3)

	for name, mutate := range map[string]func(*AvailabilityReport){
		"a different round":     func(r *AvailabilityReport) { r.Context.Round++ },
		"a different epoch":     func(r *AvailabilityReport) { r.Context.Epoch++ },
		"a different batch":     func(r *AvailabilityReport) { r.Context.BatchID[0] ^= 0xFF },
		"a different deadline":  func(r *AvailabilityReport) { r.Deadline += int64(time.Second) },
		"a different committee": func(r *AvailabilityReport) { r.Context.CommitteeID[0] ^= 0xFF },
	} {
		t.Run(name, func(t *testing.T) {
			moved := honest
			moved.Observations = append([]NonReceipt(nil), honest.Observations...)
			mutate(&moved)
			if err := VerifyAvailabilityReport(f.committee, f.mixers, moved, 3); err == nil {
				t.Fatalf("statements were transplanted to %s", name)
			}
		})
	}

	// Re-pointing the accusation at a different mixer must fail even when the
	// substitute is a certified member.
	repointed := honest
	copy(repointed.Accused[:], f.mixers[0])
	if err := VerifyAvailabilityReport(f.committee, f.mixers, repointed, 3); err == nil {
		t.Fatal("an accusation was re-pointed at an innocent mixer")
	}
}

// The cases above mutate the report and leave its statements alone, so the
// report-level consistency check rejects them before any signature is
// examined. That check is not the protection: an attacker holding the report
// rewrites the statements to match. What must stop it is the deadline being
// inside the signed message, and only a consistent rewrite tests that.
//
// This matters because the deadline is the whole accusation. A mixer that
// answered on time is unavailable under a deadline moved earlier, and the
// statements are otherwise exactly what its honest peers signed.
func TestConsistentlyRewrittenDeadlineIsStillRejected(t *testing.T) {
	f := buildAvailability(t)
	honest := f.report(t, 3)

	moved := honest
	moved.Deadline = honest.Deadline - int64(time.Second)
	moved.Observations = append([]NonReceipt(nil), honest.Observations...)
	for i := range moved.Observations {
		moved.Observations[i].Deadline = moved.Deadline
	}

	if err := VerifyAvailabilityReport(f.committee, f.mixers, moved, 3); err == nil {
		t.Fatal("the deadline was moved under signatures that still verified")
	}
}

// The same rewrite applied to the round position: every statement moved
// together, so nothing is internally inconsistent and only the signature
// coverage can refuse it.
func TestConsistentlyRewrittenPositionIsStillRejected(t *testing.T) {
	f := buildAvailability(t)
	honest := f.report(t, 3)

	moved := honest
	moved.Context.Round++
	moved.Observations = append([]NonReceipt(nil), honest.Observations...)
	for i := range moved.Observations {
		moved.Observations[i].Context = moved.Context
	}

	if err := VerifyAvailabilityReport(f.committee, f.mixers, moved, 3); err == nil {
		t.Fatal("statements were moved to another round under signatures that still verified")
	}
}

func TestTamperedStatementSignatureIsRejected(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 3)
	report.Observations[2].Signature[0] ^= 0xFF
	if err := VerifyAvailabilityReport(f.committee, f.mixers, report, 3); err == nil {
		t.Fatal("a forged non-receipt counted toward the quorum")
	}
}

func TestAnOperatorCannotReportItselfUnavailable(t *testing.T) {
	f := buildAvailability(t)
	var self [ed25519.PublicKeySize]byte
	copy(self[:], f.observerPublics[0])
	if _, err := SignNonReceipt(f.ctx, f.deadline, self, f.observerPrivates[0]); err == nil {
		t.Fatal("an operator signed a non-receipt about itself")
	}
}

// The refutation property: producing the round converts the report into
// evidence against the operators who signed it.
func TestProducingTheRoundRefutesTheReportAndNamesItsSigners(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 3)

	refutation, err := RefuteAvailabilityReport(f.encryptionKey, f.committee, f.mixers,
		report, 3, f.rounds[1])
	if err != nil {
		t.Fatalf("a mixer could not refute a report with its own sound round: %v", err)
	}
	if len(refutation.Contradicted) != 3 {
		t.Fatalf("named %d contradicted observers, want 3", len(refutation.Contradicted))
	}
	named := map[[ed25519.PublicKeySize]byte]bool{}
	for _, observer := range refutation.Contradicted {
		named[observer] = true
	}
	for i := 0; i < 3; i++ {
		var expected [ed25519.PublicKeySize]byte
		copy(expected[:], f.observerPublics[i])
		if !named[expected] {
			t.Fatalf("observer %d signed the report but was not named as contradicted", i)
		}
	}
	fault := RefutedFault(*refutation)
	if fault.Kind != FaultFalseAvailabilityReport {
		t.Fatalf("wrong kind: %+v", fault)
	}
}

// A mixer must not answer a report about one round with its work from another,
// nor with a round somebody else signed, nor with an unsound one.
func TestRefutationRequiresTheRoundTheReportNames(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 3)

	// f.elsewhere is the accused mixer's own key over its own sound shuffle, so
	// the identity check passes and only the position check can refuse it.
	t.Run("its own sound round from another position", func(t *testing.T) {
		if f.elsewhere.Receipt.MixerPublic != f.accused {
			t.Fatal("the fixture round is not the accused mixer's, so this case proves nothing")
		}
		if _, err := RefuteAvailabilityReport(f.encryptionKey, f.committee, f.mixers,
			report, 3, f.elsewhere); !errors.Is(err, ErrNotRefuted) {
			t.Fatalf("a report was answered with work from another position: %v", err)
		}
	})

	t.Run("another mixer's round", func(t *testing.T) {
		substitute := report
		copy(substitute.Accused[:], f.mixers[2])
		rebuilt := AvailabilityReport{Context: f.ctx, Deadline: f.deadline, Accused: substitute.Accused}
		for i := 0; i < 3; i++ {
			statement, err := SignNonReceipt(f.ctx, f.deadline, substitute.Accused, f.observerPrivates[i])
			if err != nil {
				t.Fatal(err)
			}
			rebuilt.Observations = append(rebuilt.Observations, statement)
		}
		if _, err := RefuteAvailabilityReport(f.encryptionKey, f.committee, f.mixers,
			rebuilt, 3, f.rounds[1]); !errors.Is(err, ErrNotRefuted) {
			t.Fatalf("one mixer refuted a report about another: %v", err)
		}
	})

	t.Run("an unsound round", func(t *testing.T) {
		unsound := f.rounds[1]
		broken := append([]byte(nil), unsound.Proof...)
		broken[len(broken)/2] ^= 0x40
		unsound.Proof = broken
		unsound.Receipt.ProofDigest = sha256Of(broken)
		unsound.Receipt.Signature = signReceipt(t, f.privates[1], unsound.Receipt, f.encryptionKey)
		if _, err := RefuteAvailabilityReport(f.encryptionKey, f.committee, f.mixers,
			report, 3, unsound); !errors.Is(err, ErrNotRefuted) {
			t.Fatalf("an unsound round was accepted as a defence: %v", err)
		}
	})
}

// A report that never established anything must not become a weapon in the
// other direction either: refuting garbage must fail before it names anyone.
func TestRefutingAnUnestablishedReportNamesNobody(t *testing.T) {
	f := buildAvailability(t)
	report := f.report(t, 1)
	refutation, err := RefuteAvailabilityReport(f.encryptionKey, f.committee, f.mixers,
		report, 3, f.rounds[1])
	if err == nil {
		t.Fatal("a below-quorum report was refuted, which would name observers who established nothing")
	}
	if refutation != nil {
		t.Fatal("a failed refutation still named observers")
	}
}
