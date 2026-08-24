package uplink_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

func benchSession(tb testing.TB) *uplink.Session {
	tb.Helper()
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{9}, 1, 3, 2)
	if err != nil {
		tb.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("uplink-cost-topology-digest-----1"))
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "uplink-cost", Epoch: 1, TopologyDigest: digest, EntryOperator: 0,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return session
}

// BenchmarkSealCover measures what a publisher pays per emitted cell. The
// number is the point: sealing performs a full ElGamal encryption of the
// fragment, and it decides whether a publisher can hold the cadence the
// topology sets.
//
// It was 87 ms when this benchmark was written, because seal built a
// two-column mix batch and discarded one column to satisfy mix.Encrypt's
// two-cell minimum. mix.EncryptCell removed that, halving it to about 43 ms.
// Half of a number that was already too large is still too large, which is why
// the test below still records a finding rather than a clean result.
func BenchmarkSealCover(b *testing.B) {
	session := benchSession(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := session.SealCover(uint64(i + 1)); err != nil {
			b.Fatal(err)
		}
	}
}

// A publisher that cannot seal a cell within its cell interval cannot emit at
// the cadence, and falls further behind on every tick. That is not a privacy
// leak by itself -- work and cover cost the same -- but a publisher whose
// emissions drift with machine load is a publisher whose timing carries load
// rather than schedule, and the topology permits intervals as short as 5 ms.
//
// This records the measurement rather than asserting a threshold, because the
// number is hardware-dependent and a CI runner is not a deployment. It fails
// only if sealing is slower than the longest interval the topology allows,
// which would make the uplink unusable everywhere rather than merely tight.
func TestSealCostAgainstTheCadenceItMustHold(t *testing.T) {
	if testing.Short() {
		t.Skip("measures per-cell sealing cost")
	}
	session := benchSession(t)
	const samples = 20
	started := time.Now()
	for index := 0; index < samples; index++ {
		if _, err := session.SealCover(uint64(index + 1)); err != nil {
			t.Fatal(err)
		}
	}
	perCell := time.Since(started) / samples

	// The public traffic class permits 5 ms to 60 s.
	const shortestInterval = 5 * time.Millisecond
	const longestInterval = 60 * time.Second
	if perCell >= longestInterval {
		t.Fatalf("sealing one cell takes %s, beyond the longest cell interval the "+
			"topology permits: no deployment could emit at cadence", perCell)
	}
	const deployedInterval = 50 * time.Millisecond
	switch {
	case perCell >= deployedInterval:
		t.Logf("sealing one uplink cell takes %s, at or beyond the %s the deployed "+
			"testnet uses: a publisher on hardware like this cannot hold its cadence "+
			"at all.", perCell, deployedInterval)
	case perCell >= shortestInterval:
		t.Logf("sealing one uplink cell takes %s. That fits inside the deployed %s "+
			"with no useful headroom, and is far beyond the %s the topology permits "+
			"as its shortest interval, so a publisher's emission timing still tracks "+
			"machine load rather than schedule at anything but the slowest cadences. "+
			"Discarding the companion mix column halved this from about 87ms; the "+
			"remainder is the fragment's own ElGamal encryption.",
			perCell, deployedInterval, shortestInterval)
	default:
		t.Logf("sealing one uplink cell takes %s, inside the shortest interval the "+
			"topology permits (%s).", perCell, shortestInterval)
	}
}
