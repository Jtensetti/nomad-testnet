package entry

import (
	"testing"
	"time"

	"fmt"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// What an address may and may not do to the sessions bound to it.
//
// The entry operator associates a session with a source address because a data
// cell carries no session identifier. That association is the only routing
// decision it makes, and it is made on a value anyone on the path can forge, so
// the questions worth asking are all about what forging it can achieve.

func TestAPublisherThatRestartsOnTheSameAddressGetsASessionBack(t *testing.T) {
	fixture := newEntryFixture(t, 16)
	from := address(t, "198.51.100.7:41000")
	now := time.Now().UTC()

	first := fixture.publisher(t)
	fixture.service.handle(first.Cell(), from, now)
	if got := fixture.service.Snapshot().Handshakes; got != 1 {
		t.Fatalf("first handshake: got %d, want 1", got)
	}

	// The publisher restarts. Its NAT kept the mapping, so it comes back on the
	// same address with a new ephemeral key. Before an address could hold more
	// than one session this cell was tried against the session the publisher no
	// longer held, failed to open, and was counted as a refused cell -- and
	// because a bound address never reached the responder again, that publisher
	// was locked out of this operator until the process was restarted.
	second := fixture.publisher(t)
	fixture.service.handle(second.Cell(), from, now)
	stats := fixture.service.Snapshot()
	if stats.Handshakes != 2 {
		t.Fatalf("restarted publisher did not get a session back: %+v", stats)
	}
	if stats.RefusedCell != 0 {
		t.Fatalf("the restart was counted as a refused cell: %+v", stats)
	}

	// Both sessions work: the new one is live, and the old one is still held
	// rather than evicted, so a cell already in flight when the publisher
	// restarted is not lost.
	for name, initiator := range map[string]*uplink.Initiator{
		"restarted": second,
		"previous":  first,
	} {
		before := fixture.service.Snapshot().Accepted
		cell, err := initiator.Session().SealWork(2, payload())
		if err != nil {
			t.Fatal(err)
		}
		fixture.service.handle(cell, from, now)
		if got := fixture.service.Snapshot().Accepted; got != before+1 {
			t.Fatalf("%s session: deposit not accepted (%d -> %d)", name, before, got)
		}
	}
}

// A cell is deposited once. Trying an address's sessions in turn is only safe
// if the first one that opens the cell is the last one to see it, and the same
// holds for the handshake behind them.
func TestACellThatOpensUnderASessionIsNeverOfferedToAnother(t *testing.T) {
	fixture := newEntryFixture(t, 16)
	from := address(t, "198.51.100.8:41000")
	now := time.Now().UTC()

	first := fixture.publisher(t)
	second := fixture.publisher(t)
	fixture.service.handle(first.Cell(), from, now)
	fixture.service.handle(second.Cell(), from, now)

	cell, err := first.Session().SealWork(9, payload())
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.handle(cell, from, now)
	stats := fixture.service.Snapshot()
	if stats.Accepted != 1 {
		t.Fatalf("a cell that opens under one of two sessions was accepted %d times", stats.Accepted)
	}
	if stats.Handshakes != 2 {
		t.Fatalf("an opened cell reached the responder: %+v", stats)
	}

	// The same sealed cell again. It opens under the same session, lands in the
	// slot its session and sequence already name, and occupies one slot rather
	// than two: a publisher retransmitting a sealed cell must not spend two of
	// its own deposits, and a second session on the address must not give it a
	// second slot for the same cell either.
	occupied := fixture.service.airlock.Pending()
	fixture.service.handle(cell, from, now)
	if got := fixture.service.airlock.Pending(); got != occupied {
		t.Fatalf("a retransmitted cell took a second slot: %d -> %d", occupied, got)
	}
}

// An address holds a bounded number of sessions, and full refuses rather than
// evicting. Evicting would give an attacker the lockout back: filling a
// victim's address would push the victim's live session out of the table.
func TestAnAddressHoldsABoundedNumberOfSessionsAndFullRefusesRatherThanEvicts(t *testing.T) {
	fixture := newEntryFixture(t, 64)
	from := address(t, "198.51.100.9:41000")
	now := time.Now().UTC()

	victim := fixture.publisher(t)
	fixture.service.handle(victim.Cell(), from, now)

	for attempt := 0; attempt < maxSessionsPerAddress+3; attempt++ {
		fixture.service.handle(fixture.publisher(t).Cell(), from, now)
	}
	stats := fixture.service.Snapshot()
	if stats.Handshakes != maxSessionsPerAddress {
		t.Fatalf("address held %d sessions, want the cap of %d",
			stats.Handshakes, maxSessionsPerAddress)
	}

	// The victim's session is the one that was there first and it still opens
	// its cells, so the flood took nothing from it.
	cell, err := victim.Session().SealWork(4, payload())
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.handle(cell, from, now)
	if got := fixture.service.Snapshot().Accepted; got != 1 {
		t.Fatalf("the first session was evicted by later handshakes: accepted %d", got)
	}

	// A full address does not spend the operator's session budget. The
	// responder saw exactly the handshakes that were bound.
	if got := fixture.service.responder.Sessions(); got != maxSessionsPerAddress {
		t.Fatalf("the responder spent %d sessions on an address that could hold %d",
			got, maxSessionsPerAddress)
	}
}

// The session budget is spent, not occupied. This pins the property the
// configuration comment states, because it is the one an operator sizes for and
// the one an adversary attacks.
func TestTheSessionBudgetIsSpentAndNeverReturned(t *testing.T) {
	const limit = 3
	fixture := newEntryFixture(t, limit)
	now := time.Now().UTC()

	for index := 0; index < limit; index++ {
		fixture.service.handle(fixture.publisher(t).Cell(),
			address(t, addressAt(index)), now)
	}
	if got := fixture.service.Snapshot().Handshakes; got != limit {
		t.Fatalf("established %d sessions, want %d", got, limit)
	}

	// Nothing frees a slot: not a fresh address, not a publisher that never
	// sends again. The budget is gone until the service is restarted.
	fixture.service.handle(fixture.publisher(t).Cell(), address(t, addressAt(limit)), now)
	stats := fixture.service.Snapshot()
	if stats.Handshakes != limit {
		t.Fatalf("the limit was exceeded: %+v", stats)
	}
	if stats.HandshakesRefused != 1 {
		t.Fatalf("the refusal was not counted as a refused handshake: %+v", stats)
	}
	// Vacuity: with room in the budget the same cell would have established a
	// session, so what refused it was the budget and not the cell.
	roomy := newEntryFixture(t, limit+1)
	roomy.service.handle(roomy.publisher(t).Cell(), address(t, addressAt(limit)), now)
	if got := roomy.service.Snapshot().Handshakes; got != 1 {
		t.Fatalf("vacuity arm: an unexhausted operator refused the handshake too (%d)", got)
	}
}

// Garbage from an address that holds a session is a refused cell, not a refused
// handshake. The two counters mean opposite things to an operator watching for
// an attack, and the fall-through to the responder must not let an attacker
// choose which one moves.
func TestGarbageAtAnEstablishedAddressMovesTheCellCounter(t *testing.T) {
	fixture := newEntryFixture(t, 16)
	from := address(t, "198.51.100.10:41000")
	stranger := address(t, "198.51.100.11:41000")
	now := time.Now().UTC()

	fixture.service.handle(fixture.publisher(t).Cell(), from, now)
	var garbage fabric.Cell
	for index := range garbage {
		garbage[index] = byte(index)
	}
	fixture.service.handle(garbage, from, now)
	stats := fixture.service.Snapshot()
	if stats.RefusedCell != 1 || stats.HandshakesRefused != 0 {
		t.Fatalf("garbage at a bound address: %+v", stats)
	}

	// The same garbage from an address with no session is a refused handshake,
	// which is what makes the counter above a signal rather than noise.
	fixture.service.handle(garbage, stranger, now)
	stats = fixture.service.Snapshot()
	if stats.RefusedCell != 1 || stats.HandshakesRefused != 1 {
		t.Fatalf("garbage from a stranger: %+v", stats)
	}
}

func payload() [uplink.PayloadSize]byte {
	var out [uplink.PayloadSize]byte
	for index := range out {
		out[index] = byte(index % 251)
	}
	return out
}

func addressAt(index int) string {
	return fmt.Sprintf("203.0.113.%d:41000", index+1)
}
