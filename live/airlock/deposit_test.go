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

	session, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(session, 0, payload, inside); err != nil {
		t.Fatal(err)
	}
	// A client that cannot tell whether its uplink cell arrived resends.
	for attempt := 0; attempt < 3; attempt++ {
		if err := airlock.Deposit(session, 0, payload, inside); err != nil {
			t.Fatalf("resend %d rejected: %v", attempt, err)
		}
	}
	if pending := airlock.Pending(); pending != 1 {
		t.Errorf("three resends consumed %d slots, want 1", pending)
	}

	_, other, _ := realDeposit(t, committee.PublicKey, 2)
	if err := airlock.Deposit(session, 0, other, inside); !errors.Is(err, ErrDepositConflict) {
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

	session, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(session, 0, payload, opens.Add(-time.Nanosecond)); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit before the window gave %v", err)
	}
	// The closing instant is outside the window: the boundary belongs to the
	// mix, not to depositors.
	if err := airlock.Deposit(session, 0, payload, closes); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit at the closing instant gave %v", err)
	}
	if err := airlock.Deposit(session, 0, payload, closes.Add(time.Second)); !errors.Is(err, ErrWindowClosed) {
		t.Errorf("a deposit after the window gave %v", err)
	}
	if pending := airlock.Pending(); pending != 0 {
		t.Errorf("out-of-window deposits took %d slots", pending)
	}
}

// A full epoch drops silently. Returning a distinguishable "epoch full" told
// any depositor the exact number of real deposits in the batch -- the one
// number the fixed batch size exists to hide -- and probing for it consumed
// every remaining slot.
func TestFullEpochDropsSilentlyRatherThanGrowingOrTelling(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.MaxDepositsPerSession = schedule.BatchSize
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	var session [32]byte
	session[0] = 9
	for index := 0; index < schedule.BatchSize; index++ {
		_, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(session, uint64(index), payload, inside); err != nil {
			t.Fatalf("deposit %d: %v", index, err)
		}
	}
	// The attacker probes past capacity. Every outcome must be identical to a
	// successful deposit from its point of view.
	for probe := 0; probe < 5; probe++ {
		_, payload, _ := realDeposit(t, committee.PublicKey, byte(100+probe))
		var attacker [32]byte
		attacker[0] = byte(probe + 20)
		if err := airlock.Deposit(attacker, 0, payload, inside); err != nil {
			t.Errorf("a deposit past capacity reported %v; the outcome must be "+
				"indistinguishable from acceptance", err)
		}
	}
	if pending := airlock.Pending(); pending != schedule.BatchSize {
		t.Errorf("capacity grew to %d, want %d", pending, schedule.BatchSize)
	}
	if full, _ := airlock.Dropped(); full != 5 {
		t.Errorf("operator-local accounting recorded %d full-batch drops, want 5", full)
	}
}

// One session must not be able to take the whole batch.
func TestOneSessionCannotOccupyTheWholeBatch(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 8
	schedule.MaxDepositsPerSession = 2
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	var greedy [32]byte
	greedy[0] = 1
	for index := 0; index < schedule.BatchSize; index++ {
		_, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(greedy, uint64(index), payload, inside); err != nil {
			t.Errorf("a quota drop reported %v; it must be silent", err)
		}
	}
	if pending := airlock.Pending(); pending != schedule.MaxDepositsPerSession {
		t.Errorf("one session took %d slots, want at most %d",
			pending, schedule.MaxDepositsPerSession)
	}
	if _, quota := airlock.Dropped(); quota != schedule.BatchSize-schedule.MaxDepositsPerSession {
		t.Errorf("recorded %d quota drops, want %d",
			quota, schedule.BatchSize-schedule.MaxDepositsPerSession)
	}
	// Another session is unaffected.
	var other [32]byte
	other[0] = 2
	_, payload, _ := realDeposit(t, committee.PublicKey, 50)
	if err := airlock.Deposit(other, 0, payload, inside); err != nil {
		t.Fatal(err)
	}
	if pending := airlock.Pending(); pending != schedule.MaxDepositsPerSession+1 {
		t.Errorf("a second session was blocked by the first: %d slots held", pending)
	}
}

// A depositor can only name its own slots, so it cannot probe whether another
// publisher deposited, nor squat their ID.
func TestDepositIDsAreScopedToTheirSession(t *testing.T) {
	var alice, mallory [32]byte
	alice[0], mallory[0] = 1, 2
	if DepositID(alice, 7) == DepositID(mallory, 7) {
		t.Error("two sessions derive the same deposit ID for the same sequence")
	}
	if DepositID(alice, 7) == DepositID(alice, 8) {
		t.Error("one session derives the same deposit ID for two sequences")
	}
	// Re-derive from a freshly built session so a derivation that carried
	// state between calls would show up as drift, not just be folded away.
	want := DepositID(alice, 7)
	for repeat := 0; repeat < 4; repeat++ {
		var again [32]byte
		again[0] = 1
		if DepositID(again, 7) != want {
			t.Errorf("derivation %d differs from the first", repeat)
		}
	}

	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, _ := openAirlock(t, schedule, committee)
	inside := opens.Add(time.Minute)

	_, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := airlock.Deposit(alice, 7, payload, inside); err != nil {
		t.Fatal(err)
	}
	// Mallory cannot collide with Alice's slot whatever sequence it uses.
	_, other, _ := realDeposit(t, committee.PublicKey, 2)
	for sequence := uint64(0); sequence < 16; sequence++ {
		if err := airlock.Deposit(mallory, sequence, other, inside); err != nil {
			t.Fatalf("mallory's own deposit at sequence %d was refused: %v", sequence, err)
		}
	}
	// Alice's slot still holds Alice's payload.
	if held, present := airlock.deposits[DepositID(alice, 7)]; !present || held != payload {
		t.Error("another session overwrote or blocked Alice's slot")
	}
}

// Sealing early is the signal that a batch filled. It is refused whatever the
// queue looks like.
func TestSealRefusesBeforeTheScheduledBoundary(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	airlock, opens, closes := openAirlock(t, schedule, committee)

	for index := 0; index < schedule.BatchSize; index++ {
		session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(session, 0, payload, opens.Add(time.Second)); err != nil {
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
	session, payload, _ := realDeposit(t, committee.PublicKey, 42)
	if err := airlock.Deposit(session, 0, payload, closes); !errors.Is(err, ErrSealed) {
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
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Minute)); err != nil {
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
	schedule.MaxDepositsPerSession = 4

	for count := 0; count <= schedule.BatchSize; count++ {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for index := 0; index < count; index++ {
			session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
			if err := airlock.Deposit(session, 0, payload, opens.Add(time.Second)); err != nil {
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

	session, payload, _ := realDeposit(t, committee.PublicKey, 1)
	if err := before.Deposit(session, 0, payload, inside); err != nil {
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
	if err := after.Deposit(session, 0, payload, inside.Add(time.Second)); err != nil {
		t.Errorf("the client's resend was rejected after a restart: %v", err)
	}
	if err := after.Deposit(session, 0, payload, inside.Add(2*time.Second)); err != nil {
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
	schedule.MaxDepositsPerSession = 4

	type deposit struct {
		id      [32]byte
		payload [DepositSize]byte
	}
	deposits := make([]deposit, 0, schedule.BatchSize)
	for index := 0; index < schedule.BatchSize; index++ {
		session, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		deposits = append(deposits, deposit{id: session, payload: payload})
	}

	// Marker 1 always arrives first. If placement encoded arrival, it would
	// land in the same slot every time.
	const trials = 8
	positions := map[int]int{}
	for trial := 0; trial < trials; trial++ {
		airlock, opens, closes := openAirlock(t, schedule, committee)
		for step, held := range deposits {
			at := opens.Add(time.Duration(step+1) * time.Second)
			if err := airlock.Deposit(held.id, 0, held.payload, at); err != nil {
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
