package airlock

import (
	"bytes"
	"errors"
	"math/bits"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// sealedEpoch fills an epoch with distinguishable real deposits and seals it.
// Every slot is real so that every input column has a ground-truth match in
// the output, which is what makes the linkage measurement below meaningful.
func sealedEpoch(t *testing.T, committee mix.ThresholdCommittee, schedule Schedule) (*mix.Batch, []mix.WireCell) {
	t.Helper()
	airlock, opens, closes := openAirlock(t, schedule, committee.PublicKey)
	for index := 0; index < schedule.BatchSize; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	batch, columns, err := airlock.Seal(closes)
	if err != nil {
		t.Fatal(err)
	}
	return batch, columns
}

func runChain(t *testing.T, committee mix.ThresholdCommittee, sealed *mix.Batch) ([]Round, *mix.Batch) {
	t.Helper()
	rounds := make([]Round, 0, len(committee.Members))
	current := sealed
	for _, member := range committee.Members {
		round, output, err := Shuffle(committee.PublicKey, member.Index, current)
		if err != nil {
			t.Fatalf("member %d shuffle: %v", member.Index, err)
		}
		rounds = append(rounds, round)
		current = output
	}
	return rounds, current
}

func decryptAll(t *testing.T, committee mix.ThresholdCommittee,
	secrets []mix.MemberSecret, batch *mix.Batch) []mix.PlainCell {
	t.Helper()
	partials := make([]*mix.PartialDecryption, 0, len(secrets))
	for _, secret := range secrets {
		partial, err := mix.CreatePartialDecryption(committee, secret, batch)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	plaintexts, err := mix.ThresholdDecrypt(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	return plaintexts
}

func TestChainRoundTripsAndReleasesOnlyRealFragments(t *testing.T) {
	committee, secrets := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 6

	airlock, opens, closes := openAirlock(t, schedule, committee.PublicKey)
	wanted := map[byte]struct{}{}
	for index := 0; index < 2; index++ {
		id, payload, fragment := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		wanted[fragment[0]] = struct{}{}
	}
	sealed, _, err := airlock.Seal(closes)
	if err != nil {
		t.Fatal(err)
	}
	rounds, _ := runChain(t, committee, sealed)

	mixed, err := VerifyChain(committee, sealed, rounds)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	partials := make([]*mix.PartialDecryption, 0, len(secrets))
	for _, secret := range secrets {
		partial, err := mix.CreatePartialDecryption(committee, secret, mixed)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	fragments, err := Release(committee, mixed, partials)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(fragments) != 2 {
		t.Fatalf("released %d fragments from a batch of %d with 2 real deposits",
			len(fragments), schedule.BatchSize)
	}
	for _, fragment := range fragments {
		if _, expected := wanted[fragment[0]]; !expected {
			t.Errorf("released an unexpected fragment marked %d", fragment[0])
		}
		delete(wanted, fragment[0])
	}
	if len(wanted) != 0 {
		t.Errorf("%d deposited fragments never came out", len(wanted))
	}
}

// A chain that skipped a member is not a shorter chain: it is a chain with a
// smaller honest-party assumption. Every one of these must fail closed, with
// no partial-chain path to fall back to.
func TestChainFailsClosedOnEveryDeviation(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 4
	sealed, _ := sealedEpoch(t, committee, schedule)
	rounds, _ := runChain(t, committee, sealed)

	cases := []struct {
		name    string
		mutate  func([]Round) []Round
		wantErr error
	}{
		{"a member is missing", func(in []Round) []Round {
			return append([]Round{}, in[:len(in)-1]...)
		}, ErrChainIncomplete},
		{"an extra round is appended", func(in []Round) []Round {
			return append(append([]Round{}, in...), in[len(in)-1])
		}, ErrChainIncomplete},
		{"members are out of order", func(in []Round) []Round {
			swapped := append([]Round{}, in...)
			swapped[0], swapped[1] = swapped[1], swapped[0]
			return swapped
		}, ErrChainIncomplete},
		{"one member shuffles twice in place of another", func(in []Round) []Round {
			doubled := append([]Round{}, in...)
			doubled[1].Member = doubled[0].Member
			return doubled
		}, ErrChainIncomplete},
		{"a proof is corrupted", func(in []Round) []Round {
			tampered := append([]Round{}, in...)
			proof := append([]byte{}, tampered[1].Proof...)
			proof[len(proof)/2] ^= 0x01
			tampered[1].Proof = proof
			return tampered
		}, ErrShuffleInvalid},
		{"a proof is replaced by another round's", func(in []Round) []Round {
			swapped := append([]Round{}, in...)
			swapped[1].Proof = in[0].Proof
			return swapped
		}, ErrShuffleInvalid},
		{"a ciphertext is substituted", func(in []Round) []Round {
			substituted := append([]Round{}, in...)
			output := make([]mix.WireCell, len(in[1].Output))
			copy(output, in[1].Output)
			output[0] = output[1]
			substituted[1].Output = output
			return substituted
		}, ErrShuffleInvalid},
		{"the batch shrinks", func(in []Round) []Round {
			shrunk := append([]Round{}, in...)
			shrunk[1].Output = in[1].Output[:len(in[1].Output)-1]
			return shrunk
		}, ErrShuffleInvalid},
		{"the batch grows", func(in []Round) []Round {
			grown := append([]Round{}, in...)
			grown[1].Output = append(append([]mix.WireCell{}, in[1].Output...), in[1].Output[0])
			return grown
		}, ErrShuffleInvalid},
		{"an output is not a valid ciphertext", func(in []Round) []Round {
			garbled := append([]Round{}, in...)
			output := make([]mix.WireCell, len(in[1].Output))
			copy(output, in[1].Output)
			for index := range output[0][:DepositSize] {
				output[0][index] = 0xff
			}
			garbled[1].Output = output
			return garbled
		}, ErrShuffleInvalid},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fresh := make([]Round, len(rounds))
			for index, round := range rounds {
				fresh[index] = Round{
					Member: round.Member,
					Output: append([]mix.WireCell{}, round.Output...),
					Proof:  append([]byte{}, round.Proof...),
				}
			}
			_, err := VerifyChain(committee, sealed, testCase.mutate(fresh))
			if err == nil {
				t.Fatalf("%s was accepted", testCase.name)
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("%s gave %v, want %v", testCase.name, err, testCase.wantErr)
			}
		})
	}
}

// hammingDistance over the ciphertext bytes. It stands in for any passive
// byte-level matcher an adversary holding both ends of the chain might try.
func hammingDistance(left, right mix.WireCell) int {
	total := 0
	for index := 0; index < DepositSize; index++ {
		total += bits.OnesCount8(left[index] ^ right[index])
	}
	return total
}

// nearestMatches links every input column to its closest output column and
// reports how many links were correct against the ground truth.
func nearestMatches(inputs, outputs []mix.WireCell, truth []int) int {
	correct := 0
	for inputIndex, input := range inputs {
		best, bestDistance := -1, 1<<30
		for outputIndex, output := range outputs {
			if distance := hammingDistance(input, output); distance < bestDistance {
				best, bestDistance = outputIndex, distance
			}
		}
		if best == truth[inputIndex] {
			correct++
		}
	}
	return correct
}

// TestEntryOperatorCannotLinkIngressToRelease is the A-05 claim measured
// rather than asserted.
//
// The adversary is the entry operator: it holds every sealed input column and
// knows which client deposited each one, and it sees the public chain output.
// Its task is to say which output column carries which client's fragment.
//
// The positive control is the same measurement against a permutation that
// does not re-randomise. There the adversary is perfect, which is what makes
// a result of chance on the real chain mean something: the measurement can
// detect linkage when linkage exists.
func TestEntryOperatorCannotLinkIngressToRelease(t *testing.T) {
	committee, secrets := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 8

	const trials = 6
	attempts := trials * schedule.BatchSize
	linked, exactMatches := 0, 0

	for trial := 0; trial < trials; trial++ {
		sealed, inputs := sealedEpoch(t, committee, schedule)
		rounds, mixed := runChain(t, committee, sealed)
		if _, err := VerifyChain(committee, sealed, rounds); err != nil {
			t.Fatalf("trial %d: chain did not verify: %v", trial, err)
		}
		outputs := rounds[len(rounds)-1].Output

		// Ground truth: decrypt both ends and match on the marker byte. Only
		// the test can do this; it needs threshold authority the adversary
		// does not have.
		inputPlain := decryptAll(t, committee, secrets, sealed)
		outputPlain := decryptAll(t, committee, secrets, mixed)
		position := make(map[byte]int, len(outputPlain))
		for index, plaintext := range outputPlain {
			position[plaintext[0]] = index
		}
		truth := make([]int, len(inputPlain))
		for index, plaintext := range inputPlain {
			match, found := position[plaintext[0]]
			if !found {
				t.Fatalf("trial %d: a deposited fragment is missing from the output", trial)
			}
			truth[index] = match
		}

		for _, input := range inputs {
			for _, output := range outputs {
				if bytes.Equal(input[:DepositSize], output[:DepositSize]) {
					exactMatches++
				}
			}
		}
		linked += nearestMatches(inputs, outputs, truth)
	}

	if exactMatches != 0 {
		t.Errorf("%d output ciphertexts appear verbatim in the input; the chain is not "+
			"re-randomising", exactMatches)
	}

	// Chance is one in BatchSize. The bound is five standard deviations of
	// the binomial, fixed here rather than after seeing the number.
	expected := float64(attempts) / float64(schedule.BatchSize)
	probability := 1.0 / float64(schedule.BatchSize)
	deviation := 5.0 * sqrt(float64(attempts)*probability*(1-probability))
	if float64(linked) > expected+deviation {
		t.Errorf("a byte-level matcher linked %d of %d ingress columns to their released "+
			"position, above the %.1f expected by chance plus %.1f (five sigma)",
			linked, attempts, expected, deviation)
	}
	t.Logf("real chain: %d/%d linked (chance %.1f, bound %.1f)",
		linked, attempts, expected, expected+deviation)

	// Positive control: the same matcher against a permutation with no
	// re-randomisation links everything.
	sealed, inputs := sealedEpoch(t, committee, schedule)
	permuted := make([]mix.WireCell, len(inputs))
	truth := make([]int, len(inputs))
	for index := range inputs {
		target := (index + 3) % len(inputs)
		permuted[target] = inputs[index]
		truth[index] = target
	}
	_ = sealed
	if control := nearestMatches(inputs, permuted, truth); control != len(inputs) {
		t.Errorf("positive control linked only %d of %d columns; the matcher cannot "+
			"detect linkage even when it is present, so the result above means nothing",
			control, len(inputs))
	}
}

func sqrt(value float64) float64 {
	if value <= 0 {
		return 0
	}
	guess := value
	for iteration := 0; iteration < 40; iteration++ {
		guess = (guess + value/guess) / 2
	}
	return guess
}
