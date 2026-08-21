package airlock

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// This is the local cryptographic composition that the online publication
// path must preserve. It deliberately uses the production APIs at every
// boundary rather than fabricating a committee ciphertext inside airlock.
func TestPublicationQueueUplinkAirlockMixReleaseRoundTrip(t *testing.T) {
	committee, secrets := testCommittee(t)
	mixerPublic, mixerPrivate := mixerIdentities(t, len(committee.Members))

	queue, err := publish.Open(t.TempDir(), publish.Options{MaximumFragments: 16})
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	object := []byte("Nomad publication path: exact bytes must survive queue, uplink, airlock, shuffle and threshold release.")
	if err := queue.Submit(object, publisherPublic); err != nil {
		t.Fatal(err)
	}
	fragment, err := queue.Next()
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Total != 1 || fragment.Index != 0 {
		t.Fatalf("test object unexpectedly produced fragment %d/%d", fragment.Index, fragment.Total)
	}

	var sharedSecret [32]byte
	if _, err := rand.Read(sharedSecret[:]); err != nil {
		t.Fatal(err)
	}
	context := uplink.Context{
		NetworkID: "nomad-publication-e2e-test",
		Epoch: 1,
		TopologyDigest: [32]byte{1},
		EntryOperator: 0,
	}
	client, err := uplink.NewSession(sharedSecret[:], committee.PublicKey, context)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := uplink.NewSession(sharedSecret[:], committee.PublicKey, context)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := client.SealWork(1, fragment.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sequence, inner, err := entry.Open(cell)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 1 {
		t.Fatalf("entry recovered sequence %d, want 1", sequence)
	}

	schedule := testSchedule()
	schedule.BatchSize = 6
	schedule.MaxDepositsPerSession = 2
	const releaseEpoch uint64 = 1
	lock, err := New(schedule, committee, releaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	opens, closes, err := schedule.DepositWindow(releaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID [32]byte
	sessionID = sha256.Sum256(append([]byte("test-uplink-session:"), sharedSecret[:]...))
	var deposit [DepositSize]byte
	copy(deposit[:], inner[:])
	if err := lock.Deposit(sessionID, sequence, deposit, opens.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	sealed, err := lock.Seal(closes)
	if err != nil {
		t.Fatal(err)
	}
	rounds, _ := runChain(t, committee, mixerPrivate, sealed)
	mixed, err := VerifyChain(committee, mixerPublic, sealed, releaseEpoch, rounds)
	if err != nil {
		t.Fatal(err)
	}
	released, undecryptable, err := Release(committee, mixed, partialsFor(t, committee, secrets, mixed))
	if err != nil {
		t.Fatal(err)
	}
	if undecryptable != 0 {
		t.Fatalf("honest publication produced %d undecryptable columns", undecryptable)
	}
	if len(released) != 1 {
		t.Fatalf("released %d real fragments, want 1", len(released))
	}

	got := released[0]
	if index := binary.BigEndian.Uint32(got[0:4]); index != 0 {
		t.Fatalf("released fragment index %d, want 0", index)
	}
	if total := binary.BigEndian.Uint32(got[4:8]); total != 1 {
		t.Fatalf("released fragment total %d, want 1", total)
	}
	length := int(binary.BigEndian.Uint32(got[8:12]))
	if length != len(object) {
		t.Fatalf("released object length %d, want %d", length, len(object))
	}
	wantRoot := sha256.Sum256(object)
	if string(got[12:44]) != string(wantRoot[:]) {
		t.Fatal("released object commitment changed across publication path")
	}
	if string(got[44:44+length]) != string(object) {
		t.Fatal("released object bytes changed across publication path")
	}

	// The same path with no work must remain real committee ciphertext and
	// disappear only after threshold decryption.
	coverCell, err := client.SealCover(2)
	if err != nil {
		t.Fatal(err)
	}
	_, coverInner, err := entry.Open(coverCell)
	if err != nil {
		t.Fatal(err)
	}
	var coverDeposit [DepositSize]byte
	copy(coverDeposit[:], coverInner[:])
	if err := mix.ValidateCiphertextColumn(func() mix.WireCell {
		var wire mix.WireCell
		copy(wire[:DepositSize], coverDeposit[:])
		return wire
	}()); err != nil {
		t.Fatalf("uplink cover is not a valid committee ciphertext: %v", err)
	}
}
