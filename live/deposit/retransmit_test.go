package deposit_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/deposit"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// What a publisher must retain in order to retry, and what happens if it
// retains the wrong thing.
//
// The airlock is idempotent so that a client which cannot tell whether its cell
// arrived -- and it cannot, because the uplink carries no acknowledgement that
// would distinguish work from cover -- can send it again. That property is load
// bearing: without it, a cell lost in transit, or arriving after the deposit
// cutoff, or landing in a full epoch, is publication work destroyed.
//
// The property holds only for a byte-identical retransmission of the sealed
// cell. Sealing the same fragment a second time does not reproduce it: the
// inner layer is a fresh encryption to the committee every time, so the second
// seal presents a different payload for the same deposit slot, and the airlock
// classifies that as a conflict rather than a repeat. It is right to: a
// different payload for a held sequence is exactly what an overwrite attempt
// looks like, and resolving it silently would drop whichever publication lost.
//
// So a publisher that wants to retry must keep the sealed cell. Keeping the
// fragment is not enough, and keeping nothing -- which is what live/publish's
// queue and live/deposit's drain do today -- makes retry impossible. See
// DEC-020.
func TestOnlyAByteIdenticalRetransmissionIsIdempotent(t *testing.T) {
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{9}, 1, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("retransmit-topology-digest-----1"))
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "retransmit", Epoch: 1, TopologyDigest: digest, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mailbox, err := airlock.New(airlock.Schedule{
		Genesis: now.Add(-time.Minute), Period: time.Hour,
		DepositCutoff: time.Minute, BatchSize: 8, MaxDepositsPerSession: 4,
	}, committee, 0)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := deposit.NewIngress(mailbox)
	if err != nil {
		t.Fatal(err)
	}

	var payload [uplink.PayloadSize]byte
	copy(payload[:], "one publication fragment")
	var sessionID [32]byte
	copy(sessionID[:], "a session identifier -----------")

	sealed, err := session.SealWork(7, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Accept(session, sessionID, sealed, now); err != nil {
		t.Fatalf("the first deposit was refused: %v", err)
	}
	if held := mailbox.Pending(); held != 1 {
		t.Fatalf("the airlock holds %d after one deposit", held)
	}

	// The retransmission a publisher that kept its sealed cell would send.
	if err := ingress.Accept(session, sessionID, sealed, now); err != nil {
		t.Fatalf("a byte-identical retransmission was refused: %v", err)
	}
	if held := mailbox.Pending(); held != 1 {
		t.Fatalf("a retransmission consumed a second slot: the airlock holds %d", held)
	}

	// The re-seal a publisher that kept only the fragment would send. It is
	// refused, and it must be: the payload genuinely differs.
	resealed, err := session.SealWork(7, payload)
	if err != nil {
		t.Fatal(err)
	}
	err = ingress.Accept(session, sessionID, resealed, now)
	if !errors.Is(err, airlock.ErrDepositConflict) {
		t.Fatalf("re-sealing the same fragment gave %v, want a deposit conflict; if this "+
			"now succeeds the inner layer has stopped being re-randomised, which is a "+
			"much larger change than this test", err)
	}
	if held := mailbox.Pending(); held != 1 {
		t.Fatalf("a refused re-seal changed the airlock: it holds %d", held)
	}
}

// A cell that arrives when no window is open is refused, and the publisher is
// told nothing -- there is no acknowledgement on this path at all. This is the
// mechanism by which work is currently destroyed: the publisher emits at a
// constant cadence across a schedule that closes, and keeps nothing it could
// send again.
func TestACellOutsideTheDepositWindowIsRefusedSilently(t *testing.T) {
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{9}, 1, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("retransmit-topology-digest-----1"))
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "retransmit", Epoch: 1, TopologyDigest: digest, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	genesis := time.Now().UTC().Add(-time.Hour)
	schedule := airlock.Schedule{
		Genesis: genesis, Period: time.Minute, DepositCutoff: 15 * time.Second,
		BatchSize: 8, MaxDepositsPerSession: 4,
	}
	mailbox, err := airlock.New(schedule, committee, 0)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := deposit.NewIngress(mailbox)
	if err != nil {
		t.Fatal(err)
	}
	opens, closes, err := schedule.DepositWindow(0)
	if err != nil {
		t.Fatal(err)
	}

	var payload [uplink.PayloadSize]byte
	copy(payload[:], "work that will not survive")
	var sessionID [32]byte
	copy(sessionID[:], "a session identifier -----------")

	inside, err := session.SealWork(1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Accept(session, sessionID, inside, opens); err != nil {
		t.Fatalf("a cell inside the window was refused: %v", err)
	}

	// One tick after the cutoff. At the deployed cadence this is the next cell
	// the publisher emits, and there is nothing different about it.
	outside, err := session.SealWork(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	err = ingress.Accept(session, sessionID, outside, closes.Add(50*time.Millisecond))
	if !errors.Is(err, deposit.ErrNotForThisEpoch) {
		t.Fatalf("a cell after the cutoff gave %v, want ErrNotForThisEpoch", err)
	}
	if held := mailbox.Pending(); held != 1 {
		t.Fatalf("the refused cell reached the airlock anyway: it holds %d", held)
	}

	// The fraction of a period during which this happens is a deployment
	// parameter, and it is not small: the cutoff exists so the shuffle chain
	// and threshold decryption have a fixed budget, so it is a real slice of
	// every epoch.
	lost := float64(schedule.DepositCutoff) / float64(schedule.Period)
	if lost < 0.2 {
		t.Logf("at this schedule only %.0f%% of each period refuses deposits", 100*lost)
	}
	t.Logf("MEASURED: %.0f%% of every period refuses deposits at the default schedule "+
		"(period %s, cutoff %s); a publisher emitting at a constant cadence loses that "+
		"share of its work, because it retains nothing to send again",
		100*lost, schedule.Period, schedule.DepositCutoff)
}
