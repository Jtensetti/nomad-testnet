package deposit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// publisherCount is kept small so a trial is affordable, and trials many so
// the rate has some resolution. Under anonymity the expected recovery rate is
// 1/publisherCount.
const (
	publisherCount = 4
	// Each full-path trial runs a complete shuffle chain and a threshold
	// decryption, so trials are the whole cost of this experiment. They are
	// also the whole resolution of it, and the first version bought the cost
	// down too far.
	//
	// It ran 12 trials -- 48 observations -- and failed when the recovered
	// rate exceeded twice chance. Two things were wrong with that, and they
	// pull in opposite directions, which is why neither was obvious.
	//
	// It failed by chance about once in 1500 runs. The exact null here is the
	// fixed-point count of a uniform permutation of 4, summed over the trials;
	// at 12 trials, P(hits >= 25) = 6.7e-4. That is often enough for a
	// security gate to cry wolf, and the usual response to a security gate
	// crying wolf is to loosen it.
	//
	// And it could barely detect the thing it exists to detect. Against a true
	// recovery rate of 0.5 -- double the chance rate, a serious linkage defect
	// -- a threshold of "more than twice chance" has about 50% power at 12
	// trials, and a threshold strict enough to fix the false failures would
	// have had 1.5%. The test was simultaneously too noisy to trust and too
	// blunt to catch anything.
	//
	// Both are the same shortage. 40 measurement trials give 160 observations:
	// the threshold below then fails by chance less than once in a million
	// runs and still detects a doubled recovery rate 85% of the time. The
	// control needs no such resolution -- full linkage scores 1.00, not
	// something near a boundary -- so it stays cheap.
	controlTrials = 12
	trials        = 40
)

// falseFailureBudget is how often this experiment may fail when nothing is
// wrong. It buys the threshold below, and it is stated rather than implied so
// that a later change to publisherCount or trials cannot quietly move it.
const falseFailureBudget = 1e-6

// nullHitCutoff is the smallest number of position hits whose probability
// under anonymity is at most falseFailureBudget.
//
// It is computed rather than written down. A magic number here would be a
// number nobody could check, and the first version's "twice chance" was
// exactly that: a threshold with no stated relationship to the distribution it
// was thresholding.
//
// The null is exact. Under anonymity the released order is a uniform
// permutation of the publishers, so per trial the adversary's hits are that
// permutation's fixed-point count; the distribution over trials is that pmf
// convolved with itself. Enumerating publisherCount! permutations is exact and
// costs nothing at this size.
func nullHitCutoff(publishers, trialCount int, budget float64) int {
	perTrial := make([]float64, publishers+1)
	total := 0
	var walk func(remaining []int, chosen []int)
	walk = func(remaining []int, chosen []int) {
		if len(remaining) == 0 {
			fixed := 0
			for position, value := range chosen {
				if position == value {
					fixed++
				}
			}
			perTrial[fixed]++
			total++
			return
		}
		for index, value := range remaining {
			rest := make([]int, 0, len(remaining)-1)
			rest = append(rest, remaining[:index]...)
			rest = append(rest, remaining[index+1:]...)
			walk(rest, append(chosen, value))
		}
	}
	order := make([]int, publishers)
	for index := range order {
		order[index] = index
	}
	walk(order, nil)
	for index := range perTrial {
		perTrial[index] /= float64(total)
	}

	distribution := []float64{1}
	for trial := 0; trial < trialCount; trial++ {
		next := make([]float64, len(distribution)+publishers)
		for hits, probability := range distribution {
			for extra, chance := range perTrial {
				next[hits+extra] += probability * chance
			}
		}
		distribution = next
	}
	tail := 0.0
	for hits := len(distribution) - 1; hits >= 0; hits-- {
		tail += distribution[hits]
		if tail > budget {
			return hits + 1
		}
	}
	return 0
}

// depositOne runs one publisher's deposit and returns the marker it deposited.
func depositOne(t *testing.T, committee mix.ThresholdCommittee, ingress *Ingress,
	index int, now time.Time) [uplink.PayloadSize]byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("correlation-experiment-topology-"))
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "correlation", Epoch: 12, TopologyDigest: digest,
		EntryOperator: uint16(index),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A marker the experiment can recognise after release. Real fragments are
	// indistinguishable ciphertext at this point; the marker exists only so
	// the *analysis* can tell whose plaintext came out, which is strictly more
	// information than the adversary being modelled has.
	var payload [uplink.PayloadSize]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(index+1))
	if _, err := rand.Read(payload[8:]); err != nil {
		t.Fatal(err)
	}
	cell, err := session.SealWork(uint64(index+1), payload)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID [32]byte
	binary.BigEndian.PutUint64(sessionID[:8], uint64(index+1))
	if err := ingress.Accept(session, sessionID, cell, now); err != nil {
		t.Fatalf("publisher %d: %v", index, err)
	}
	return payload
}

// The three configurations the experiment compares.
const (
	// modeRaw encrypts the markers in arrival order with no airlock at all.
	// The mapping is fully present, so a working matcher must recover it.
	modeRaw = iota
	// modeSealed goes through the airlock's seal but no shuffle chain. The
	// seal already orders by deposit ID and randomises placement, so this
	// measures what the airlock alone provides.
	modeSealed
	// modeFull is the production path: seal then the full shuffle chain.
	modeFull
)

// runRawTrial builds a batch directly from the markers in arrival order. It
// exists to give the matcher something it must be able to solve.
func runRawTrial(t *testing.T) ([][uplink.PayloadSize]byte, []mix.PlainCell) {
	t.Helper()
	committee, members := testCommittee(t)
	deposited := make([][uplink.PayloadSize]byte, publisherCount)
	cells := make([]mix.PlainCell, publisherCount)
	for index := range deposited {
		binary.BigEndian.PutUint64(deposited[index][:8], uint64(index+1))
		if _, err := rand.Read(deposited[index][8:]); err != nil {
			t.Fatal(err)
		}
		copy(cells[index][:], deposited[index][:])
	}
	batch, err := mix.Encrypt(committee.PublicKey, cells)
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*mix.PartialDecryption, int(committee.Threshold))
	for index := range partials {
		partials[index], err = mix.CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
	}
	released, _, err := airlock.Release(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	return deposited, released
}

// runTrial deposits publisherCount markers in a known order, seals, optionally
// shuffles, decrypts, and reports the released plaintexts in release order.
func runTrial(t *testing.T, shuffled bool) ([][uplink.PayloadSize]byte, []mix.PlainCell) {
	t.Helper()
	committee, members := testCommittee(t)
	schedule := testSchedule()
	now := schedule.Genesis.Add(schedule.Period).Add(time.Minute)
	lock, err := airlock.New(schedule, committee, 1)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(lock)
	if err != nil {
		t.Fatal(err)
	}

	deposited := make([][uplink.PayloadSize]byte, publisherCount)
	for index := 0; index < publisherCount; index++ {
		deposited[index] = depositOne(t, committee, ingress, index, now)
	}
	sealed, err := lock.Seal(now.Add(8 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	batch := sealed.Batch()
	if shuffled {
		for member := 0; member < len(committee.Members); member++ {
			_, identity, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			_, output, err := airlock.Shuffle(committee, uint32(member), batch, identity)
			if err != nil {
				t.Fatal(err)
			}
			batch = output
		}
	}

	partials := make([]*mix.PartialDecryption, int(committee.Threshold))
	for index := range partials {
		partials[index], err = mix.CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
	}
	released, _, err := airlock.Release(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	return deposited, released
}

// positionRecoveryRate is the adversary's best simple strategy: assume the
// k-th released plaintext belongs to the k-th publisher that deposited. It is
// the mapping the entry operator would guess from arrival order alone.
func positionRecoveryRate(t *testing.T, mode, trialCount int) (hits, total int) {
	t.Helper()
	for trial := 0; trial < trialCount; trial++ {
		var deposited [][uplink.PayloadSize]byte
		var released []mix.PlainCell
		switch mode {
		case modeRaw:
			deposited, released = runRawTrial(t)
		case modeSealed:
			deposited, released = runTrial(t, false)
		default:
			deposited, released = runTrial(t, true)
		}
		for position, cell := range released {
			if position >= len(deposited) {
				break
			}
			total++
			if bytes.Equal(cell[:], deposited[position][:]) {
				hits++
			}
		}
	}
	if total == 0 {
		t.Fatal("no plaintext was released, so nothing was measured")
	}
	return hits, total
}

// The experiment, with its own positive control.
//
// A previous unlinkability measurement in this project was withdrawn because
// it scored chance against a chain with zero anonymity: the matcher could not
// detect linkage that was fully present, so its failure to detect linkage
// proved nothing. This runs the same matcher against an unshuffled chain
// first. If it cannot recover the mapping there, the experiment is broken and
// says so rather than reporting a pass.
func TestPublisherToObjectMappingIsNotRecoverableFromDepositOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("correlation experiment runs a full mix per trial")
	}
	if raceDetectorEnabled {
		// This is a distribution measurement, not a concurrency test: it runs
		// no goroutines of its own, so the detector has nothing here to find.
		// What it does have is thirty-six full mixes of elliptic-curve work,
		// which the detector's instrumentation multiplies by about eight, and
		// that alone pushed the package past the ten-minute default timeout.
		// Drain's concurrency is exercised under -race by the emission and
		// close tests, and by the shortened campaign.
		t.Skip("correlation experiment measures a distribution and runs no goroutines; " +
			"under -race it costs eight times as much and measures nothing more")
	}

	chance := 1.0 / float64(publisherCount)
	cutoff := nullHitCutoff(publisherCount, trials, falseFailureBudget)

	controlHits, controlTotal := positionRecoveryRate(t, modeRaw, controlTrials)
	control := float64(controlHits) / float64(controlTotal)
	if control < 0.9 {
		t.Fatalf("positive control recovered only %.2f of the mapping from a batch "+
			"with no airlock and no shuffle: the matcher cannot detect linkage that "+
			"is fully present, so a low treatment score would prove nothing", control)
	}

	// The first draft used an unshuffled airlock batch as the control and it
	// scored chance, which looked like the retracted measurement failing again
	// and was in fact the airlock working: Seal orders by deposit ID and
	// randomises placement, so it destroys arrival order before any mixer
	// touches the batch. That is worth measuring rather than assuming, so it
	// is reported as its own configuration.
	sealedHits, sealedTotal := positionRecoveryRate(t, modeSealed, trials)
	sealedOnly := float64(sealedHits) / float64(sealedTotal)
	if sealedHits >= cutoff {
		t.Fatalf("the seal alone leaves deposit order recoverable at %.3f (%d of %d "+
			"positions) against a chance rate of %.3f; under anonymity %d or more "+
			"hits has probability at most %.0e",
			sealedOnly, sealedHits, sealedTotal, chance, cutoff, falseFailureBudget)
	}

	treatmentHits, treatmentTotal := positionRecoveryRate(t, modeFull, trials)
	treatment := float64(treatmentHits) / float64(treatmentTotal)
	if treatmentHits >= cutoff {
		t.Fatalf("deposit order still predicts release position at %.3f (%d of %d "+
			"positions) against a chance rate of %.3f; under anonymity %d or more "+
			"hits has probability at most %.0e",
			treatment, treatmentHits, treatmentTotal, chance, cutoff, falseFailureBudget)
	}
	t.Logf("position recovery, %d publishers: no defence %.2f (%d trials), "+
		"seal only %.3f, seal and shuffle chain %.3f, chance %.3f; "+
		"failing at %d of %d hits, which anonymity produces with probability <= %.0e",
		publisherCount, control, controlTrials, sealedOnly, treatment, chance,
		cutoff, treatmentTotal, falseFailureBudget)

	// What this does not establish, stated here because the previous
	// unlinkability claim in this project was withdrawn for being read wider
	// than its measurement.
	//
	// One adversary is modelled: an entry operator that knows the order
	// deposits arrived in and sees the released plaintexts, guessing that the
	// k-th release is the k-th deposit. That adversary fails, and the seal
	// alone is enough to make it fail. Nothing here measures an adversary who
	// observes the batch between hops, who controls some mixers, who
	// correlates across epochs, or who has any side information about which
	// publisher submits when -- and the shuffle chain exists for the first two
	// of those, so this experiment does not measure the thing the chain is
	// mainly for. It shows the deposit path does not hand the mapping away for
	// free, which is the weakest of the properties the airlock claims and the
	// only one a single-process experiment can reach.
}
