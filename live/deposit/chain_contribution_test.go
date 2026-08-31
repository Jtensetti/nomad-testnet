package deposit

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
)

// What the shuffle chain is for, measured.
//
// The correlation experiment next door models an entry operator matching
// arrival order to release position, and the seal alone defeats it: Seal
// orders by deposit ID and randomises placement before any mixer runs. So it
// measures the airlock and says nothing about the chain, which exists for an
// adversary inside the committee.
//
// This measures that one, under the anytrust assumption airlock.VerifyChain
// states mechanically: the chain is unlinkable if at least ONE shuffler is
// honest. Every corrupt mixer's permutation is handed to the adversary, which
// is definitional -- a corrupt mixer chose its own. Two configurations
// separate the assumption from nothing: every mixer corrupt, where composing
// the chain must recover the mapping completely; and exactly one honest, its
// position drawn per trial, where the adversary is left with one uniform
// permutation. The distance between them is the chain's contribution, which
// PROD-17 records as unmeasured.

// chainPublishers fills the batch exactly, with no cover: every cover column
// decrypts to the same reserved empty fragment, so two of them are
// indistinguishable and no permutation can be read off the plaintexts. A full
// batch also gives the adversary the easiest case it will ever see, which is
// the right direction for a test of whether it still fails.
const chainPublishers = 8

// chainTrials buys the null. With 8 publishers, 20 trials is 160 observations
// against a chance rate of 1/8; the cutoff below fails by chance less than
// once in a million runs and detects a recovery rate of 0.5 with certainty.
// It detects a mere doubling of chance only 16% of the time, which is stated
// rather than hidden: the failure this experiment is built for is a chain that
// contributes nothing, and that one reads 1.00.
const chainTrials = 20

// The control needs far fewer, because it is not a statistical measurement.
// With every mixer corrupt the adversary composes the whole chain, and the
// answer is exact arithmetic against a truth read end to end: it is 1.000 or
// the experiment is broken. Trials here buy repetition against a
// non-deterministic bug, not resolution, and five full chains is enough of
// that. Twenty was twenty runs of a check that cannot land between two values.
const chainControlTrials = 5

// decryptInOrder returns every column's plaintext in batch order. It cannot
// use airlock.Release, which drops cover and returns a list whose indices no
// longer mean anything.
func decryptInOrder(t *testing.T, committee mix.ThresholdCommittee,
	members []mix.MemberSecret, batch *mix.Batch) []mix.PlainCell {
	t.Helper()
	partials := make([]*mix.PartialDecryption, int(committee.Threshold))
	for index := range partials {
		partial, err := mix.CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
		partials[index] = partial
	}
	columns, err := mix.ThresholdDecryptColumns(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]mix.PlainCell, len(columns))
	for index, column := range columns {
		if column.Err != nil {
			t.Fatalf("column %d did not decrypt: %v", index, column.Err)
		}
		cells[index] = column.Cell
	}
	return cells
}

// sourceOf reads one round's permutation off its plaintexts: sourceOf[j] is
// the input position output position j came from. It refuses anything that is
// not a bijection -- tolerating one would let the adversary's composition be
// wrong in a direction that flatters the result.
func sourceOf(t *testing.T, before, after []mix.PlainCell) []int {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("round changed the column count from %d to %d", len(before), len(after))
	}
	position := make(map[mix.PlainCell]int, len(before))
	for index, cell := range before {
		if previous, seen := position[cell]; seen {
			t.Fatalf("columns %d and %d hold identical plaintexts, so no permutation "+
				"can be read from them; the batch must be filled with distinct markers",
				previous, index)
		}
		position[cell] = index
	}
	source := make([]int, len(after))
	for index, cell := range after {
		origin, ok := position[cell]
		if !ok {
			t.Fatalf("output column %d holds a plaintext that was not in the input", index)
		}
		source[index] = origin
	}
	return source
}

// chainTrial runs one full chain and returns, for each release position, the
// sealed position it truly came from, and the sealed position an adversary
// holding the named rounds would predict.
func chainTrial(t *testing.T, honest int) (truth, guess []int) {
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
	for index := 0; index < chainPublishers; index++ {
		depositOne(t, committee, ingress, index, now)
	}
	sealed, err := lock.Seal(now.Add(8 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	batch := sealed.Batch()
	plain := decryptInOrder(t, committee, members, batch)
	entering := plain
	if len(plain) != chainPublishers {
		t.Fatalf("the batch holds %d columns for %d publishers; this experiment needs "+
			"a full batch so that every column is distinct", len(plain), chainPublishers)
	}
	sources := make([][]int, 0, len(committee.Members))
	for member := 0; member < len(committee.Members); member++ {
		_, identity, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, output, err := airlock.Shuffle(committee, uint32(member), batch, identity)
		if err != nil {
			t.Fatal(err)
		}
		next := decryptInOrder(t, committee, members, output)
		sources = append(sources, sourceOf(t, plain, next))
		batch, plain = output, next
	}

	// The truth is read end to end, by matching the plaintexts entering the
	// chain against those leaving it -- not by composing the per-round
	// permutations the adversary uses. Deriving both the same way would make
	// the control below a tautology: composing every round would agree with
	// itself whether or not the composition described the chain at all.
	truth = sourceOf(t, entering, plain)

	guess = make([]int, chainPublishers)
	for position := 0; position < chainPublishers; position++ {
		predicted := position
		for round := len(sources) - 1; round >= 0; round-- {
			// The adversary substitutes the identity for the round it does
			// not hold, which is the best it can do: an honest mixer's
			// permutation is uniform and independent of everything it knows.
			if round != honest {
				predicted = sources[round][predicted]
			}
		}
		guess[position] = predicted
	}
	return truth, guess
}

func chainRecoveryRate(t *testing.T, everyMixerCorrupt bool) (hits, total int) {
	t.Helper()
	count := chainTrials
	if everyMixerCorrupt {
		count = chainControlTrials
	}
	for trial := 0; trial < count; trial++ {
		honest := -1
		if !everyMixerCorrupt {
			// Drawn per trial. A fixed position would measure one arrangement
			// and report it as the property.
			index, err := rand.Int(rand.Reader, big.NewInt(int64(mixerCount(t))))
			if err != nil {
				t.Fatal(err)
			}
			honest = int(index.Int64())
		}
		truth, guess := chainTrial(t, honest)
		for position := range truth {
			total++
			if truth[position] == guess[position] {
				hits++
			}
		}
	}
	return hits, total
}

// mixerCount is the number of rounds in the chain: one per committee member.
func mixerCount(t *testing.T) int {
	t.Helper()
	committee, _ := testCommittee(t)
	return len(committee.Members)
}

func TestOneHonestMixerIsEnoughAgainstACorruptCommittee(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a full shuffle chain and six threshold decryptions per trial")
	}
	if raceDetectorEnabled {
		t.Skip("distribution measurement with no goroutines; -race costs eight times " +
			"as much and measures nothing more")
	}

	chance := 1.0 / float64(chainPublishers)
	cutoff := nullHitCutoff(chainPublishers, chainTrials, falseFailureBudget)

	controlHits, controlTotal := chainRecoveryRate(t, true)
	control := float64(controlHits) / float64(controlTotal)
	if control < 1.0 {
		t.Fatalf("with every mixer corrupt the adversary recovered %.3f (%d of %d). "+
			"Composing the per-round permutations and matching plaintexts end to end "+
			"are two derivations of the same mapping and must agree exactly; a "+
			"shortfall means this experiment cannot see linkage that is fully present",
			control, controlHits, controlTotal)
	}

	treatmentHits, treatmentTotal := chainRecoveryRate(t, false)
	treatment := float64(treatmentHits) / float64(treatmentTotal)
	if treatmentHits >= cutoff {
		t.Fatalf("one honest mixer left the mapping recoverable at %.3f (%d of %d) "+
			"against chance %.3f; %d or more hits has probability <= %.0e under "+
			"anonymity. The anytrust assumption says one honest shuffler suffices",
			treatment, treatmentHits, treatmentTotal, chance, cutoff, falseFailureBudget)
	}
	t.Logf("chain contribution, %d publishers and %d mixers: every mixer corrupt "+
		"%.3f (%d trials, exact), one honest mixer %.3f (%d trials), chance %.3f; "+
		"failing at %d of %d hits, which anonymity produces with probability <= %.0e",
		chainPublishers, mixerCount(t), control, chainControlTrials,
		treatment, chainTrials, chance, cutoff, treatmentTotal, falseFailureBudget)

	// Stated because the previous unlinkability claim here was withdrawn for
	// being read wider than its measurement. This covers an adversary inside
	// the committee holding every corrupt mixer's permutation. It does not
	// cover correlation across epochs, side information about who submits
	// when, an attack on the proofs rather than the permutation, or a wholly
	// corrupt committee -- which is the assumption failing, not the chain.
}
