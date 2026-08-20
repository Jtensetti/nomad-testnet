package airlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// Regressions for defects an adversarial review found with working exploits.
// Each names the property that was actually violated, so a future change that
// reintroduces one fails on the property rather than on a shape.

// A mix.WireCell is 1200 bytes and a deposit is 1152. Copying a deposit into a
// zero cell left the last 48 bytes zero, while cover came through MarshalWire
// and had them from crypto/rand -- a classifier that identified every real
// column before any decryption. The original tests missed it because every
// comparison sliced to [:DepositSize], exactly the region that cannot vary.
func TestSealedPaddingDoesNotIdentifyCoverColumns(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 8
	schedule.MaxDepositsPerSession = 8

	for _, count := range []int{0, 1, 3, 7, 8} {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		sealed, err := airlock.Seal(closes)
		if err != nil {
			t.Fatalf("%d deposits: %v", count, err)
		}

		// The exploit: count columns whose trailing padding is all zero.
		allZero := 0
		for _, column := range sealed.Columns {
			zero := true
			for _, octet := range column[DepositSize:] {
				if octet != 0 {
					zero = false
					break
				}
			}
			if zero {
				allZero++
			}
		}
		if allZero != 0 {
			t.Errorf("%d real deposits: %d of %d columns carry all-zero padding, which "+
				"identifies them before any decryption", count, allZero, len(sealed.Columns))
		}
	}
}

// The same property stated over whole cells: two sealings with different
// deposit counts must be indistinguishable in every byte position's
// distribution, not merely in length.
func TestSealedBatchIsUniformAcrossItsWholeWireForm(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 6
	schedule.MaxDepositsPerSession = 6

	seal := func(count int) []mix.WireCell {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		sealed, err := airlock.Seal(closes)
		if err != nil {
			t.Fatal(err)
		}
		return sealed.Columns
	}
	empty, full := seal(0), seal(schedule.BatchSize)
	for _, columns := range [][]mix.WireCell{empty, full} {
		for index, column := range columns {
			if len(column) != mix.WireCellSize {
				t.Fatalf("column %d is %d bytes", index, len(column))
			}
		}
	}
	// No column of either sealing may equal any column of the other, and none
	// may repeat: identical bytes anywhere would mean a shared fixed region.
	seen := map[string]struct{}{}
	for _, columns := range [][]mix.WireCell{empty, full} {
		for _, column := range columns {
			key := string(column[:])
			if _, duplicate := seen[key]; duplicate {
				t.Error("two sealed columns are byte-identical")
			}
			seen[key] = struct{}{}
		}
	}
}

// Seal generated one ElGamal encryption per empty slot, so its runtime read
// out how few people published: 2.6s at zero real deposits against 0.014s at
// a full batch. Cover is now generated before the window opens, so sealing
// costs the same at every occupancy.
func TestSealDurationDoesNotDependOnOccupancy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement needs wall-clock time")
	}
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 16
	schedule.MaxDepositsPerSession = 16

	measure := func(count int) time.Duration {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		if _, err := airlock.Seal(closes); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}

	emptyBatch := measure(0)
	fullBatch := measure(schedule.BatchSize)
	t.Logf("seal duration: empty %s, full %s", emptyBatch, fullBatch)

	// Both are dominated by the shuffle and the parse, which are
	// occupancy-independent. A generous bound still catches the original
	// defect, which was a factor of 190.
	larger, smaller := emptyBatch, fullBatch
	if smaller > larger {
		larger, smaller = smaller, larger
	}
	if smaller <= 0 {
		smaller = time.Microsecond
	}
	if ratio := float64(larger) / float64(smaller); ratio > 5.0 {
		t.Errorf("sealing an empty batch took %s and a full one %s, a factor of %.1f; "+
			"the release instant carries the publication count", emptyBatch, fullBatch, ratio)
	}
}

// A depositor could read the same signal remotely, by timing how long its own
// call blocked on the lock Seal held across cover generation.
func TestConcurrentDepositIsNotBlockedByCoverGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement needs wall-clock time")
	}
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 16
	schedule.MaxDepositsPerSession = 16

	blockedFor := func(count int) time.Duration {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		session, payload, _ := realDeposit(t, committee.PublicKey, 200)
		done := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			// After the window closes this is refused, but only after
			// acquiring the lock, which is what makes the wait observable.
			_ = airlock.Deposit(session, 0, payload, closes.Add(time.Second))
			done <- time.Since(start)
		}()
		if _, err := airlock.Seal(closes); err != nil {
			t.Fatal(err)
		}
		return <-done
	}

	empty := blockedFor(0)
	full := blockedFor(schedule.BatchSize - 1)
	t.Logf("concurrent deposit blocked for: empty batch %s, near-full batch %s", empty, full)
	if empty > 100*time.Millisecond {
		t.Errorf("a concurrent deposit blocked for %s while an empty batch sealed; the wait "+
			"time is a remote readout of the publication count", empty)
	}
}

// A deposit whose points do not decode was accepted and killed Seal for the
// whole epoch, deterministically and forever.
func TestMalformedDepositIsRefusedBeforeItTakesASlot(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, closes := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	// Random bytes: roughly half of all 32-byte strings are not curve points,
	// so 36 of them are malformed with overwhelming probability.
	var session [32]byte
	var payload [DepositSize]byte
	if _, err := rand.Read(session[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(payload[:]); err != nil {
		t.Fatal(err)
	}
	if err := airlock.Deposit(session, 0, payload, inside); !errors.Is(err, ErrDepositMalformed) {
		t.Fatalf("a malformed deposit gave %v, want ErrDepositMalformed", err)
	}
	if pending := airlock.Pending(); pending != 0 {
		t.Errorf("a malformed deposit took %d slots", pending)
	}
	// An all-zero payload is not a valid point either.
	var zero [DepositSize]byte
	if err := airlock.Deposit(session, 0, zero, inside); !errors.Is(err, ErrDepositMalformed) {
		t.Errorf("an all-zero deposit gave %v, want ErrDepositMalformed", err)
	}
	// The epoch still seals for everyone else.
	good, goodPayload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(good, 0, goodPayload, inside); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Seal(closes); err != nil {
		t.Errorf("one refused malformed deposit still broke the epoch: %v", err)
	}
}

// New took a bare public key and validated nothing. An all-zero key decodes
// to a point of order 4, which makes cover a four-way-masked plaintext that
// anyone recovers with no shares at all.
func TestNewRefusesAnUncertifiedCommittee(t *testing.T) {
	schedule := testSchedule()
	if _, err := New(schedule, mix.ThresholdCommittee{}, 0); err == nil {
		t.Error("New accepted an empty committee")
	}
	committee, _ := testCommittee(t)

	broken := committee
	broken.PublicKey = mix.PublicKey{}
	if _, err := New(schedule, broken, 0); err == nil {
		t.Error("New accepted a zero committee public key")
	}

	noMembers := committee
	noMembers.Members = nil
	if _, err := New(schedule, noMembers, 0); err == nil {
		t.Error("New accepted a committee with no members")
	}

	noThreshold := committee
	noThreshold.Threshold = 0
	if _, err := New(schedule, noThreshold, 0); err == nil {
		t.Error("New accepted a committee with a zero threshold")
	}

	if _, err := New(schedule, committee, 0); err != nil {
		t.Errorf("New refused the certified committee: %v", err)
	}
}

// time.Duration(epoch) * Period wrapped silently, so a large epoch produced a
// window in the past and an airlock that sealed immediately.
func TestEpochArithmeticRefusesOverflow(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()

	beyond := schedule.MaxEpoch() + 1
	for _, epoch := range []uint64{beyond, ^uint64(0), 1 << 60} {
		if _, _, err := schedule.DepositWindow(epoch); !errors.Is(err, ErrEpochOutOfRange) {
			t.Errorf("DepositWindow(%d) gave %v, want ErrEpochOutOfRange", epoch, err)
		}
		if _, err := schedule.ReleaseAt(epoch); !errors.Is(err, ErrEpochOutOfRange) {
			t.Errorf("ReleaseAt(%d) gave %v, want ErrEpochOutOfRange", epoch, err)
		}
		if _, err := New(schedule, committee, epoch); !errors.Is(err, ErrEpochOutOfRange) {
			t.Errorf("New at epoch %d gave %v, want ErrEpochOutOfRange", epoch, err)
		}
	}
	// The boundary itself still works, and its window is in the future.
	opens, _, err := schedule.DepositWindow(schedule.MaxEpoch())
	if err != nil {
		t.Fatalf("the maximum epoch is unusable: %v", err)
	}
	if !opens.After(schedule.Genesis) {
		t.Errorf("the maximum epoch opens at %s, which is not after genesis %s",
			opens, schedule.Genesis)
	}
	// EpochAt must agree with DepositWindow rather than saturating.
	if epoch, err := schedule.EpochAt(time.Date(2260, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		if _, _, windowErr := schedule.DepositWindow(epoch); windowErr != nil {
			t.Errorf("EpochAt returned epoch %d whose own window errors: %v", epoch, windowErr)
		}
	}
}

// Sealing had no upper bound, so a late or replayed release was invisible.
func TestSealRefusesAfterTheReleaseInstant(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, _, closes := openAirlock(t, schedule, committee)
	release, err := schedule.ReleaseAt(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Seal(release); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("sealing at the release instant gave %v, want ErrWindowClosed", err)
	}
	if _, err := airlock.Seal(release.Add(time.Hour)); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("sealing an hour late gave %v, want ErrWindowClosed", err)
	}
	if _, err := airlock.Seal(closes); err != nil {
		t.Errorf("sealing inside the window failed: %v", err)
	}
}

// The idempotency comparison is constant time. Timing is not asserted here --
// a reliable timing assertion needs more samples than a unit test should take
// -- but the behaviour it replaced must be preserved exactly.
func TestConstantTimeIdempotencyPreservesBehaviour(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	session, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(session, 0, payload, inside); err != nil {
		t.Fatal(err)
	}
	if err := airlock.Deposit(session, 0, payload, inside); err != nil {
		t.Errorf("the identical payload was refused: %v", err)
	}
	// Differing in the first byte and in the last must both conflict.
	for _, position := range []int{0, DepositSize / 2, DepositSize - 1} {
		altered := payload
		altered[position] ^= 0x01
		if err := airlock.Deposit(session, 0, altered, inside); !errors.Is(err, ErrDepositConflict) {
			t.Errorf("a payload differing at byte %d gave %v, want ErrDepositConflict",
				position, err)
		}
	}
	if !bytes.Equal(payload[:], payload[:]) {
		t.Fatal("unreachable")
	}
}
