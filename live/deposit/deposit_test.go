package deposit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

func testSchedule() airlock.Schedule {
	return airlock.Schedule{
		Genesis:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Period:                10 * time.Minute,
		DepositCutoff:         2 * time.Minute,
		BatchSize:             8,
		MaxDepositsPerSession: 8,
	}
}

type pathFixture struct {
	committee mix.ThresholdCommittee
	members   []mix.MemberSecret
	session   *uplink.Session
	sessionID [32]byte
	airlock   *airlock.Airlock
	ingress   *Ingress
	now       time.Time
}

// A dealer committee costs seconds to generate and none of these tests depend
// on it being fresh, so it is built once for the package.
var (
	sharedCommitteeOnce sync.Once
	sharedCommittee     mix.ThresholdCommittee
	sharedMembers       []mix.MemberSecret
	sharedCommitteeErr  error
)

func testCommittee(t *testing.T) (mix.ThresholdCommittee, []mix.MemberSecret) {
	t.Helper()
	sharedCommitteeOnce.Do(func() {
		sharedCommittee, sharedMembers, sharedCommitteeErr =
			mix.GenerateDealerCommittee(mix.CommitteeID{3}, 12, 5, 3)
	})
	if sharedCommitteeErr != nil {
		t.Fatal(sharedCommitteeErr)
	}
	return sharedCommittee, sharedMembers
}

func newPathFixture(t *testing.T) *pathFixture {
	t.Helper()
	committee, members := testCommittee(t)
	var digest [32]byte
	copy(digest[:], []byte("deposit-path-topology-digest----"))
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "deposit-path", Epoch: 12, TopologyDigest: digest, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	schedule := testSchedule()
	// Epoch 1's deposit window: [genesis+period, genesis+2*period-cutoff).
	now := schedule.Genesis.Add(schedule.Period).Add(time.Minute)
	lock, err := airlock.New(schedule, committee, 1)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(lock)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID [32]byte
	copy(sessionID[:], []byte("uplink-session-identifier-------1"))
	return &pathFixture{committee: committee, members: members, session: session,
		sessionID: sessionID, airlock: lock, ingress: ingress, now: now}
}

// emitTicks drives one tick per sequence and returns the cleartext sequence
// prefix an observer reads off each emitted cell.
//
// The prefix is read back out of the cell rather than copied from the loop
// variable, or a comparison between two runs is a comparison between two
// copies of the same counter. Cell length is not part of what is returned:
// fabric.Cell is a fixed-size array, so every cell is CellSize bytes by
// construction and asserting it only restates the type.
//
// Both runs of a comparison are paced identically, so that one drain is not
// given more wall-clock to refill its buffer than the other.
func emitTicks(t *testing.T, label string, drain *Drain, ticks int) []uint64 {
	t.Helper()
	prefixes := make([]uint64, 0, ticks)
	for sequence := uint64(1); sequence <= uint64(ticks); sequence++ {
		cell, err := drain.Emit(sequence)
		if err != nil {
			t.Fatalf("%s tick %d: %v", label, sequence, err)
		}
		prefixes = append(prefixes, binary.BigEndian.Uint64(cell[:uplink.SequenceSize]))
		time.Sleep(time.Millisecond)
	}
	return prefixes
}

func newQueue(t *testing.T, objects ...string) *publish.Queue {
	t.Helper()
	queue, err := publish.Open(filepath.Join(t.TempDir(), "queue"),
		publish.Options{MaximumFragments: 64, Key: publish.UnprotectedKeyFile()})
	if err != nil {
		t.Fatal(err)
	}
	publisher, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if err := queue.Submit([]byte(object), publisher); err != nil {
			t.Fatal(err)
		}
	}
	return queue
}

// The path end to end: a publisher's queued object leaves as uplink cells, the
// entry operator deposits what it cannot read, and the epoch seals into a
// batch of fixed size.
func TestQueuedObjectReachesTheAirlockThroughTheUplink(t *testing.T) {
	f := newPathFixture(t)
	queue := newQueue(t, `{"title":"a publication","body":"through the airlock"}`)
	drain := newTestDrain(t, f.session, queue, f.now)

	// Emit for a while. Some ticks carry the object's fragments, the rest
	// carry cover; the operator deposits every one of them identically.
	accepted := 0
	for sequence := uint64(1); sequence <= 40; sequence++ {
		cell, err := drain.Emit(sequence)
		if err != nil {
			t.Fatalf("tick %d: %v", sequence, err)
		}
		if err := f.ingress.Accept(f.session, f.sessionID, cell, f.now); err != nil {
			t.Fatalf("tick %d: ingress refused a cell it produced itself: %v", sequence, err)
		}
		accepted++
		time.Sleep(time.Millisecond)
	}
	if accepted != 40 {
		t.Fatalf("accepted %d of 40", accepted)
	}
	work, cover := drain.Counts()
	if work == 0 {
		t.Fatal("no fragment ever left the queue, so the path was not exercised")
	}
	if cover == 0 {
		t.Fatal("every tick carried work, so cover was never exercised")
	}

	// The airlock holds at most its batch size and drops the rest silently.
	if pending := f.airlock.Pending(); pending == 0 || pending > testSchedule().BatchSize {
		t.Fatalf("airlock holds %d deposits", pending)
	}
	// Seal is only valid inside [closes, release) = 00:18 to 00:20.
	sealed, err := f.airlock.Seal(f.now.Add(8 * time.Minute))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := len(sealed.Columns); got != testSchedule().BatchSize {
		t.Fatalf("sealed %d columns, want the fixed batch size %d",
			got, testSchedule().BatchSize)
	}
}

// The core invariant at this boundary: how many cells the publisher emits, and
// when, must not depend on whether it has anything to publish. A drain with a
// full queue and a drain with no queue at all must produce the same number of
// cells for the same number of ticks, each indistinguishable on the wire.
func TestEmissionCountDoesNotDependOnHavingWork(t *testing.T) {
	const ticks = 60
	busy := newPathFixture(t)
	busyDrain := newTestDrain(t, busy.session, newQueue(t,
		`{"title":"one","body":"aaaa"}`, `{"title":"two","body":"bbbb"}`), busy.now)

	idle := newPathFixture(t)
	idleDrain := newTestDrain(t, idle.session, nil, idle.now)

	busyCells := emitTicks(t, "busy", busyDrain, ticks)
	idleCells := emitTicks(t, "idle", idleDrain, ticks)
	if !slices.Equal(busyCells, idleCells) {
		t.Fatalf("a busy publisher and an idle one are separable on the wire:\n"+
			" busy %v\n idle %v", busyCells, idleCells)
	}
	if work, _ := busyDrain.Counts(); work == 0 {
		t.Fatal("the busy drain never carried work, so the comparison is vacuous")
	}
	if work, _ := idleDrain.Counts(); work != 0 {
		t.Fatal("the idle drain carried work it did not have")
	}
}

// A drain must never decline a tick. A caller that skipped one because it had
// nothing to say would announce exactly that.
func TestDrainAlwaysProducesACellIncludingAfterClose(t *testing.T) {
	f := newPathFixture(t)
	drain := newTestDrain(t, f.session, newQueue(t, `{"title":"x","body":"y"}`), f.now)
	drain.Close()
	drain.Close() // idempotent
	for sequence := uint64(1); sequence <= 20; sequence++ {
		if _, err := drain.Emit(sequence); err != nil {
			t.Fatalf("tick %d after close: %v", sequence, err)
		}
	}
}

// The entry operator cannot separate work from cover. Only threshold
// decryption reveals which columns were the reserved empty fragment, and by
// then the shuffle chain has destroyed the link to the depositor.
func TestEntryOperatorCannotTellWorkFromCover(t *testing.T) {
	f := newPathFixture(t)
	drain := newTestDrain(t, f.session, newQueue(t, `{"title":"secret","body":"zzzz"}`), f.now)

	// What the operator can actually compute from the cell is the inner
	// ciphertext. Its length is fixed by the type, so the claim worth testing
	// is that work and cover ciphertexts come from one distribution: none is a
	// recognisable constant, and none repeats.
	seen := map[[uplink.InnerSize]byte]uint64{}
	for sequence := uint64(1); sequence <= 30; sequence++ {
		cell, err := drain.Emit(sequence)
		if err != nil {
			t.Fatal(err)
		}
		_, inner, err := f.session.Open(cell)
		if err != nil {
			t.Fatalf("tick %d: %v", sequence, err)
		}
		if inner == ([uplink.InnerSize]byte{}) {
			t.Fatalf("tick %d: the inner layer is all zero, which marks it as cover", sequence)
		}
		if earlier, repeat := seen[inner]; repeat {
			t.Fatalf("ticks %d and %d carry the same inner ciphertext, so the "+
				"operator can group cells without decrypting them", earlier, sequence)
		}
		seen[inner] = sequence
		time.Sleep(time.Millisecond)
	}
	if work, cover := drain.Counts(); work == 0 || cover == 0 {
		t.Fatalf("the run was not mixed (work=%d cover=%d), so nothing was compared",
			work, cover)
	}
}

// A cell from another session must not be deposited under this one's identity.
func TestIngressRefusesACellFromAnotherSession(t *testing.T) {
	f := newPathFixture(t)
	other := newPathFixture(t)
	drain := newTestDrain(t, other.session, nil, other.now)
	cell, err := drain.Emit(7)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ingress.Accept(f.session, f.sessionID, cell, f.now); err == nil {
		t.Fatal("a cell sealed under a different session key was accepted")
	}
}

// Depositing outside the window is refused as an epoch mismatch rather than
// as something a depositor could read occupancy from.
func TestIngressRefusesOutsideTheDepositWindow(t *testing.T) {
	f := newPathFixture(t)
	drain := newTestDrain(t, f.session, nil, f.now)
	cell, err := drain.Emit(3)
	if err != nil {
		t.Fatal(err)
	}
	late := f.now.Add(24 * time.Hour)
	if err := f.ingress.Accept(f.session, f.sessionID, cell, late); err == nil {
		t.Fatal("a deposit was accepted long after its epoch closed")
	}
}
