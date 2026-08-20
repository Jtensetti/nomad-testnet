package airlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

func testCommittee(t *testing.T) (mix.ThresholdCommittee, []mix.MemberSecret) {
	t.Helper()
	committee, secrets, err := mix.GenerateDealerCommittee(mix.CommitteeID{7}, 3, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	return committee, secrets
}

// realDeposit seals one distinguishable fragment to the committee, exactly as
// a publishing client would.
func realDeposit(t *testing.T, committee mix.PublicKey, marker byte) ([32]byte, [DepositSize]byte, mix.PlainCell) {
	t.Helper()
	var fragment mix.PlainCell
	for index := range fragment {
		fragment[index] = marker
	}
	batch, err := mix.Encrypt(committee, []mix.PlainCell{fragment, fragment})
	if err != nil {
		t.Fatal(err)
	}
	cells, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	var payload [DepositSize]byte
	copy(payload[:], cells[0][:DepositSize])
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id, payload, fragment
}

func openAirlock(t *testing.T, schedule Schedule, committee mix.ThresholdCommittee) (*Airlock, time.Time, time.Time) {
	t.Helper()
	airlock, err := New(schedule, committee, 0)
	if err != nil {
		t.Fatal(err)
	}
	opens, closes, err := schedule.DepositWindow(0)
	if err != nil {
		t.Fatal(err)
	}
	return airlock, opens, closes
}

func TestDepositIsIdempotentAndRefusesConflict(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	id, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(id, payload, inside); err != nil {
		t.Fatal(err)
	}
	// A client that cannot tell whether its uplink cell arrived resends.
	for attempt := 0; attempt < 3; attempt++ {
		if err := airlock.Deposit(id, payload, inside); err != nil {
			t.Fatalf("resend %d rejected: %v", attempt, err)
		}
	}
	if pending := airlock.Pending(); pending != 1 {
		t.Errorf("three resends consumed %d slots, want 1", pending)
	}

	_, other, _ := realDeposit(t, committee.PublicKey, 2)
	if err := airlock.Deposit(id, other, inside); !errors.Is(err, ErrDepositConflict) {
		t.Errorf("a different payload under a held ID gave %v, want ErrDepositConflict", err)
	}
	if pending := airlock.Pending(); pending != 1 {
		t.Errorf("a rejected conflict changed the slot count to %d", pending)
	}
}

func TestDepositRefusedOutsideItsWindow(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, closes := openAirlock(t, schedule, committee)

	id, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(id, payload, opens.Add(-time.Nanosecond)); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit before the window gave %v", err)
	}
	// The closing instant is outside the window: the boundary belongs to the
	// mix, not to depositors.
	if err := airlock.Deposit(id, payload, closes); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit at the closing instant gave %v", err)
	}
	if err := airlock.Deposit(id, payload, closes.Add(time.Second)); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit after the window gave %v", err)
	}
	if pending := airlock.Pending(); pending != 0 {
		t.Errorf("out-of-window deposits took %d slots", pending)
	}
}

func TestFullEpochRefusesRatherThanGrowing(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	for index := 0; index < schedule.BatchSize; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, inside); err != nil {
			t.Fatalf("deposit %d: %v", index, err)
		}
	}
	id, payload, _ := realDeposit(t, committee.PublicKey, 99)
	if err := airlock.Deposit(id, payload, inside); !errors.Is(err, ErrEpochFull) {
		t.Errorf("deposit past capacity gave %v, want ErrEpochFull", err)
	}
	if pending := airlock.Pending(); pending != schedule.BatchSize {
		t.Errorf("capacity grew to %d, want %d", pending, schedule.BatchSize)
	}
}

// Sealing early is the signal that a batch filled. It is refused whatever the
// queue looks like.
func TestSealRefusesBeforeTheScheduledBoundary(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, closes := openAirlock(t, schedule, committee)

	for index := 0; index < schedule.BatchSize; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := airlock.Seal(opens.Add(time.Second)); !errors.Is(err, ErrWindowOpen) {
		t.Errorf("a full batch sealed early with %v", err)
	}
	if _, err := airlock.Seal(closes.Add(-time.Nanosecond)); !errors.Is(err, ErrWindowOpen) {
		t.Errorf("sealed one instant before the boundary with %v", err)
	}
	if _, err := airlock.Seal(closes); err != nil {
		t.Errorf("refused to seal at the boundary: %v", err)
	}
	if _, err := airlock.Seal(closes); !errors.Is(err, ErrSealed) {
		t.Errorf("sealed twice with %v", err)
	}
	id, payload, _ := realDeposit(t, committee.PublicKey, 42)
	if err := airlock.Deposit(id, payload, closes); !errors.Is(err, ErrSealed) {
		t.Errorf("accepted a deposit after sealing: %v", err)
	}
}

// The batch an observer sees must be the same size whether nobody published
// or the epoch filled, and the cover that pads it must be a real committee
// ciphertext rather than filler.
func TestSealedBatchSizeAndShapeDoNotDependOnDepositCount(t *testing.T) {
	committee, secrets := testCommittee(t)
	schedule := testSchedule()

	var encodings [][]byte
	for _, count := range []int{0, 1, schedule.BatchSize - 1, schedule.BatchSize} {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		sealed, err := airlock.Seal(closes)
		if err != nil {
			t.Fatalf("%d deposits: seal: %v", count, err)
		}
		if sealed.Batch().Len() != schedule.BatchSize {
			t.Errorf("%d deposits produced a batch of %d, want %d",
				count, sealed.Batch().Len(), schedule.BatchSize)
		}
		if len(sealed.Columns) != schedule.BatchSize {
			t.Errorf("%d deposits produced %d wire sealed.Columns", count, len(sealed.Columns))
		}
		flat := make([]byte, 0, len(sealed.Columns)*DepositSize)
		for _, column := range sealed.Columns {
			flat = append(flat, column[:DepositSize]...)
		}
		encodings = append(encodings, flat)

		// Every column, cover included, must decrypt: cover that is not a
		// valid ciphertext would fail the shuffle proofs and would announce
		// itself.
		partials := make([]*mix.PartialDecryption, 0, len(secrets))
		for _, secret := range secrets {
			partial, err := mix.CreatePartialDecryption(committee, secret, sealed.Batch())
			if err != nil {
				t.Fatal(err)
			}
			partials = append(partials, partial)
		}
		plaintexts, err := mix.ThresholdDecrypt(committee, sealed.Batch(), partials)
		if err != nil {
			t.Fatalf("%d deposits: decrypt sealed batch: %v", count, err)
		}
		real := 0
		for _, plaintext := range plaintexts {
			if !IsCover(plaintext) {
				real++
			}
		}
		if real != count {
			t.Errorf("%d deposits decrypted to %d real fragments", count, real)
		}
	}
	for index := 1; index < len(encodings); index++ {
		if len(encodings[index]) != len(encodings[0]) {
			t.Errorf("sealed batch byte length varies with deposit count: %d vs %d",
				len(encodings[index]), len(encodings[0]))
		}
		if bytes.Equal(encodings[index], encodings[0]) {
			t.Error("two sealed batches are byte-identical; cover is not randomised")
		}
	}
}

// A-06: nothing about the release boundary may be a function of how full the
// batch is. The previous test showed a full batch cannot seal early; this one
// walks every occupancy from empty to full and shows the boundary is the same
// instant in all of them, in both directions.
func TestSealBoundaryIsIdenticalAtEveryOccupancy(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 4

	for count := 0; count <= schedule.BatchSize; count++ {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(id, payload, opens.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := airlock.Seal(closes.Add(-time.Nanosecond)); !errors.Is(err, ErrWindowOpen) {
			t.Errorf("%d deposits: sealed before the boundary with %v", count, err)
		}
		if _, err := airlock.Seal(closes); err != nil {
			t.Errorf("%d deposits: refused to seal at the boundary: %v", count, err)
		}
	}
}

// A-07: a restart is not an event. An operator that loses its accumulator
// re-derives exactly the same window from public parameters, and the client's
// resend lands idempotently, so neither the crash nor the recovery changes
// what anyone outside can see.
func TestRestartRederivesTheSameWindowAndAcceptsTheResend(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	before, opens, closes := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	id, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := before.Deposit(id, payload, inside); err != nil {
		t.Fatal(err)
	}

	// The operator restarts: deposits held only in memory are gone. Losing
	// queued work is the intended trade -- the alternative is an operator
	// that persists publication ciphertexts, and a recovery step whose
	// existence depends on how much was queued.
	after, restartOpens, restartCloses := openAirlock(t, schedule, committee)
	if !restartOpens.Equal(opens) || !restartCloses.Equal(closes) {
		t.Errorf("restart moved the window from [%s, %s) to [%s, %s)",
			opens, closes, restartOpens, restartCloses)
	}
	if pending := after.Pending(); pending != 0 {
		t.Errorf("a restarted accumulator held %d deposits", pending)
	}
	if err := after.Deposit(id, payload, inside.Add(time.Second)); err != nil {
		t.Errorf("the client's resend was rejected after a restart: %v", err)
	}
	if err := after.Deposit(id, payload, inside.Add(2*time.Second)); err != nil {
		t.Errorf("a second resend was rejected: %v", err)
	}
	if pending := after.Pending(); pending != 1 {
		t.Errorf("resends after a restart took %d slots, want 1", pending)
	}
}

// Arrival order must not be recoverable from the sealed batch. The batch is
// deliberately not reproducible -- placement is a fresh uniform draw each
// time -- so the property to check is that a deposit's sealed position
// carries no stable information about when it arrived.
func TestSealedPositionDoesNotEncodeArrivalOrder(t *testing.T) {
	committee, secrets := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 4

	type deposit struct {
		id      [32]byte
		payload [DepositSize]byte
	}
	deposits := make([]deposit, 0, schedule.BatchSize)
	for index := 0; index < schedule.BatchSize; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		deposits = append(deposits, deposit{id: id, payload: payload})
	}

	// Marker 1 always arrives first. If placement encoded arrival, it would
	// land in the same slot every time.
	const trials = 8
	positions := map[int]int{}
	for trial := 0; trial < trials; trial++ {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for step, held := range deposits {
			at := opens.Add(time.Duration(step+1) * time.Second)
			if err := airlock.Deposit(held.id, held.payload, at); err != nil {
				t.Fatal(err)
			}
		}
		sealed, err := airlock.Seal(closes)
		if err != nil {
			t.Fatal(err)
		}
		plaintexts := decryptAll(t, committee, secrets, sealed.Batch())
		found := -1
		for index, plaintext := range plaintexts {
			if plaintext[0] == 1 {
				found = index
			}
		}
		if found < 0 {
			t.Fatalf("trial %d: the first-arriving deposit is not in the sealed batch", trial)
		}
		positions[found]++
	}
	if len(positions) < 2 {
		t.Errorf("the first-arriving deposit landed in the same slot in all %d trials "+
			"(slot histogram %v); sealed placement encodes arrival order", trials, positions)
	}
	t.Logf("first-arriving deposit slot histogram over %d trials: %v", trials, positions)
}

func TestShuffleColumnsPermutesEveryPosition(t *testing.T) {
	const size = 6
	original := make([]mix.WireCell, size)
	for index := range original {
		original[index][0] = byte(index + 1)
	}
	landed := make([]map[byte]struct{}, size)
	for index := range landed {
		landed[index] = map[byte]struct{}{}
	}
	for trial := 0; trial < 200; trial++ {
		columns := append([]mix.WireCell{}, original...)
		if err := shuffleColumns(columns); err != nil {
			t.Fatal(err)
		}
		seen := map[byte]struct{}{}
		for position, column := range columns {
			seen[column[0]] = struct{}{}
			landed[position][column[0]] = struct{}{}
		}
		if len(seen) != size {
			t.Fatalf("trial %d: shuffle lost or duplicated a column: %v", trial, seen)
		}
	}
	// Over 200 trials every column should have reached every position; a
	// shuffle that cannot is not uniform.
	for position, reached := range landed {
		if len(reached) != size {
			t.Errorf("position %d was only ever occupied by %d of %d sealed.Columns",
				position, len(reached), size)
		}
	}
}

// The airlock derives its deposit size from the mix parameters so that the
// package has no path to the transport. That derivation must stay equal to
// the size the uplink and hop layers actually carry.
func TestDepositSizeMatchesTheCarriedCiphertext(t *testing.T) {
	if DepositSize != hop.CiphertextSize {
		t.Errorf("DepositSize is %d but hop carries %d", DepositSize, hop.CiphertextSize)
	}
	if DepositSize != uplink.InnerSize {
		t.Errorf("DepositSize is %d but an uplink cell carries %d", DepositSize, uplink.InnerSize)
	}
}
