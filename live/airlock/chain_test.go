package airlock

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// mixerIdentities gives every committee member a certified signing key. The
// chain is authenticated against these, so holding a committee share is no
// longer the same thing as being able to produce a round.
func mixerIdentities(t *testing.T, count int) ([]ed25519.PublicKey, []ed25519.PrivateKey) {
	t.Helper()
	publics := make([]ed25519.PublicKey, 0, count)
	privates := make([]ed25519.PrivateKey, 0, count)
	for index := 0; index < count; index++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publics = append(publics, public)
		privates = append(privates, private)
	}
	return publics, privates
}

func sealedEpoch(t *testing.T, committee mix.ThresholdCommittee, schedule Schedule) Sealed {
	t.Helper()
	airlock, opens, closes := openAirlock(t, schedule, committee)
	for index := 0; index < schedule.BatchSize; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := airlock.Seal(closes)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func runChain(t *testing.T, committee mix.ThresholdCommittee, identities []ed25519.PrivateKey,
	sealed Sealed) ([]Round, *mix.Batch) {
	t.Helper()
	rounds := make([]Round, 0, len(committee.Members))
	current := sealed.Batch()
	for position, member := range committee.Members {
		round, output, err := Shuffle(committee, member.Index, current, identities[position])
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
	plaintexts, err := mix.ThresholdDecrypt(committee, batch, partialsFor(t, committee, secrets, batch))
	if err != nil {
		t.Fatal(err)
	}
	return plaintexts
}

func partialsFor(t *testing.T, committee mix.ThresholdCommittee,
	secrets []mix.MemberSecret, batch *mix.Batch) []*mix.PartialDecryption {
	t.Helper()
	partials := make([]*mix.PartialDecryption, 0, len(secrets))
	for _, secret := range secrets {
		partial, err := mix.CreatePartialDecryption(committee, secret, batch)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	return partials
}

func TestChainRoundTripsAndReleasesOnlyRealFragments(t *testing.T) {
	committee, secrets := testCommittee(t)
	mixers, identities := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 6

	airlock, opens, closes := openAirlock(t, schedule, committee)
	wanted := map[byte]struct{}{}
	for index := 0; index < 2; index++ {
		id, payload, fragment := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		wanted[fragment[0]] = struct{}{}
	}
	sealed, err := airlock.Seal(closes)
	if err != nil {
		t.Fatal(err)
	}
	rounds, _ := runChain(t, committee, identities, sealed)

	mixed, err := VerifyChain(committee, mixers, sealed, 0, rounds)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	fragments, undecryptable, err := Release(committee, mixed, partialsFor(t, committee, secrets, mixed))
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if undecryptable != 0 {
		t.Errorf("%d columns failed to decrypt in an honest epoch", undecryptable)
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

// The Sev1 that voided the whole boundary: a party holding no committee share
// ran every shuffle itself, labelled the rounds with the certified member
// indices, and was accepted, so it knew the entire ingress-to-egress map.
func TestAForgedChainFromANonMemberIsRefused(t *testing.T) {
	committee, _ := testCommittee(t)
	mixers, _ := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 4
	sealed := sealedEpoch(t, committee, schedule)

	// The forger holds one key of its own and uses it for every round.
	_, forgerKeys := mixerIdentities(t, len(committee.Members))
	forged := make([]Round, 0, len(committee.Members))
	current := sealed.Batch()
	for position, member := range committee.Members {
		round, output, err := Shuffle(committee, member.Index, current, forgerKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		_ = position
		forged = append(forged, round)
		current = output
	}
	_, err := VerifyChain(committee, mixers, sealed, 0, forged)
	if err == nil {
		t.Fatal("a chain in which no certified member participated was accepted")
	}
	if !errors.Is(err, ErrShuffleInvalid) {
		t.Errorf("forged chain gave %v, want ErrShuffleInvalid", err)
	}

	// Even one substituted member fails: a chain is not partly certified.
	honestMixers, honestKeys := mixerIdentities(t, len(committee.Members))
	rounds, _ := runChain(t, committee, honestKeys, sealed)
	stolen := append([]Round{}, rounds...)
	stolen[1].Receipt.MixerPublic = [32]byte{}
	if _, err := VerifyChain(committee, honestMixers, sealed, 0, stolen); !errors.Is(err, ErrShuffleInvalid) {
		t.Errorf("a round with a substituted signer gave %v, want ErrShuffleInvalid", err)
	}
}

// A Neff proof shows that some permutation with some blinding exists, and zero
// is a valid blinding: a chain of pure permutations verified, and anyone who
// saw the sealed batch read the map off the bytes.
func TestARoundThatDoesNotRerandomiseIsRefused(t *testing.T) {
	committee, _ := testCommittee(t)
	schedule := testSchedule()
	schedule.BatchSize = 4
	sealed := sealedEpoch(t, committee, schedule)

	// A pure permutation: the same ciphertexts, reordered.
	cells := append([]mix.WireCell{}, sealed.Columns...)
	cells[0], cells[1] = cells[1], cells[0]
	permuted, err := mix.ParseWire(cells)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireRerandomisation(sealed.Batch(), permuted, 0); !errors.Is(err, ErrChainNotRandomised) {
		t.Errorf("a pure permutation gave %v, want ErrChainNotRandomised", err)
	}
	// The identity is caught too: unchanged output is the degenerate case.
	if err := requireRerandomisation(sealed.Batch(), sealed.Batch(), 0); !errors.Is(err, ErrChainNotRandomised) {
		t.Errorf("an unchanged output gave %v, want ErrChainNotRandomised", err)
	}
	// A genuine shuffle passes.
	_, identities := mixerIdentities(t, len(committee.Members))
	_, output, err := Shuffle(committee, 0, sealed.Batch(), identities[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := requireRerandomisation(sealed.Batch(), output, 0); err != nil {
		t.Errorf("a genuine shuffle was rejected as unrandomised: %v", err)
	}
}

// Nothing bound a chain to an epoch, a committee, or the batch it was built
// for, so whole chains replayed between epochs.
func TestAChainDoesNotReplayIntoAnotherEpochOrCommittee(t *testing.T) {
	committee, _ := testCommittee(t)
	mixers, identities := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 4
	sealed := sealedEpoch(t, committee, schedule)
	rounds, _ := runChain(t, committee, identities, sealed)

	if _, err := VerifyChain(committee, mixers, sealed, 0, rounds); err != nil {
		t.Fatalf("the honest chain did not verify: %v", err)
	}
	// Presented as a different release epoch.
	if _, err := VerifyChain(committee, mixers, sealed, 5, rounds); !errors.Is(err, ErrChainContext) {
		t.Errorf("a chain replayed into release epoch 5 gave %v, want ErrChainContext", err)
	}
	// Presented under a different committee.
	other := committee
	other.ID = mix.CommitteeID{99}
	if _, err := VerifyChain(other, mixers, sealed, 0, rounds); !errors.Is(err, ErrChainContext) {
		t.Errorf("a chain replayed under another committee gave %v, want ErrChainContext", err)
	}
	otherEpoch := committee
	otherEpoch.Epoch = committee.Epoch + 1
	if _, err := VerifyChain(otherEpoch, mixers, sealed, 0, rounds); !errors.Is(err, ErrChainContext) {
		t.Errorf("a chain replayed into another committee epoch gave %v, want ErrChainContext", err)
	}
	// A sealed commitment that does not match its batch.
	tampered := sealed
	tampered.Digest = [32]byte{1}
	if _, err := VerifyChain(committee, mixers, tampered, 0, rounds); !errors.Is(err, ErrChainContext) {
		t.Errorf("a mismatched sealed commitment gave %v, want ErrChainContext", err)
	}
}

func TestChainFailsClosedOnEveryDeviation(t *testing.T) {
	committee, _ := testCommittee(t)
	mixers, identities := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 4
	sealed := sealedEpoch(t, committee, schedule)
	rounds, _ := runChain(t, committee, identities, sealed)

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
		{"a receipt is replaced by another round's", func(in []Round) []Round {
			swapped := append([]Round{}, in...)
			swapped[1].Receipt = in[0].Receipt
			return swapped
		}, ErrChainIncomplete},
		{"a receipt signature is corrupted", func(in []Round) []Round {
			tampered := append([]Round{}, in...)
			tampered[1].Receipt.Signature[0] ^= 0x01
			return tampered
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
					Member:  round.Member,
					Output:  append([]mix.WireCell{}, round.Output...),
					Proof:   append([]byte{}, round.Proof...),
					Receipt: round.Receipt,
				}
			}
			_, err := VerifyChain(committee, mixers, sealed, 0, testCase.mutate(fresh))
			if err == nil {
				t.Fatalf("%s was accepted", testCase.name)
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("%s gave %v, want %v", testCase.name, err, testCase.wantErr)
			}
		})
	}
}

// TestPermutationIsUniform is the A-05 measurement, rebuilt.
//
// The previous version scored byte similarity between ingress and egress
// ciphertexts. Re-randomised ElGamal points are uniform, so that matcher
// scores chance whenever re-randomisation happens, whether or not the
// permutation hides anything: it passed against a chain that preserved order
// exactly. What actually has to hold is that the ingress-to-egress
// permutation is uniform, so this measures the permutation directly, using
// threshold authority the adversary does not have to recover ground truth.
func TestPermutationIsUniform(t *testing.T) {
	committee, secrets := testCommittee(t)
	_, identities := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 4

	const trials = 24
	// landings[i][j] counts how often the deposit marked i+1 came out at
	// released position j.
	landings := make([][]int, schedule.BatchSize)
	for index := range landings {
		landings[index] = make([]int, schedule.BatchSize)
	}

	for trial := 0; trial < trials; trial++ {
		sealed := sealedEpoch(t, committee, schedule)
		_, mixed := runChain(t, committee, identities, sealed)
		outputPlain := decryptAll(t, committee, secrets, mixed)
		for position, plaintext := range outputPlain {
			marker := int(plaintext[0]) - 1
			if marker < 0 || marker >= schedule.BatchSize {
				t.Fatalf("trial %d: unexpected marker %d", trial, plaintext[0])
			}
			landings[marker][position]++
		}
	}

	// Every deposit must have reached more than one released position. A
	// chain that preserved order -- the case the old measurement missed --
	// puts every deposit in exactly one column every time.
	for marker, row := range landings {
		distinct := 0
		for _, count := range row {
			if count > 0 {
				distinct++
			}
		}
		if distinct < 2 {
			t.Errorf("the deposit marked %d landed in %d distinct positions over %d trials "+
				"(histogram %v); the chain is not permuting", marker+1, distinct, trials, row)
		}
	}

	// And the landings must look uniform rather than merely varied. With
	// BatchSize slots the expected count per cell is trials/BatchSize; the
	// bound is four standard deviations of the binomial, fixed here rather
	// than after seeing the numbers.
	expected := float64(trials) / float64(schedule.BatchSize)
	probability := 1.0 / float64(schedule.BatchSize)
	deviation := 4.0 * sqrt(float64(trials)*probability*(1-probability))
	for marker, row := range landings {
		for position, count := range row {
			if float64(count) > expected+deviation || float64(count) < expected-deviation {
				t.Errorf("deposit %d landed at position %d %d times over %d trials; "+
					"expected %.1f +/- %.1f", marker+1, position, count, trials, expected, deviation)
			}
		}
		t.Logf("deposit %d landing histogram: %v", marker+1, row)
	}
}

// One deposit that is valid points but not a real encryption used to destroy
// the whole epoch at release, after the committee had spent its budget.
func TestAPoisonedColumnDoesNotCensorTheEpoch(t *testing.T) {
	committee, secrets := testCommittee(t)
	mixers, identities := mixerIdentities(t, len(committee.Members))
	schedule := testSchedule()
	schedule.BatchSize = 4

	airlock, opens, closes := openAirlock(t, schedule, committee)
	for index := 0; index < 2; index++ {
		id, payload, _ := realDeposit(t, committee.PublicKey, byte(index+1))
		if err := airlock.Deposit(id, payload, opens.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// Splice one deposit's y-points from another: valid points, not an
	// encryption of anything embeddable.
	_, first, _ := realDeposit(t, committee.PublicKey, 10)
	_, second, _ := realDeposit(t, committee.PublicKey, 11)
	poison := second
	for row := 0; row < mix.ChunkCount; row++ {
		offset := row*2*32 + 32
		copy(poison[offset:offset+32], first[offset:offset+32])
	}
	var poisonID [32]byte
	if _, err := rand.Read(poisonID[:]); err != nil {
		t.Fatal(err)
	}
	if err := airlock.Deposit(poisonID, poison, opens.Add(time.Minute)); err != nil {
		t.Fatalf("the poisoned deposit was refused at deposit time, so this test no longer "+
			"exercises release-time tolerance: %v", err)
	}

	sealed, err := airlock.Seal(closes)
	if err != nil {
		t.Fatalf("one poisoned deposit broke sealing for the epoch: %v", err)
	}
	rounds, _ := runChain(t, committee, identities, sealed)
	mixed, err := VerifyChain(committee, mixers, sealed, 0, rounds)
	if err != nil {
		t.Fatalf("one poisoned deposit broke the chain for the epoch: %v", err)
	}
	fragments, undecryptable, err := Release(committee, mixed, partialsFor(t, committee, secrets, mixed))
	if err != nil {
		t.Fatalf("one poisoned deposit censored the whole epoch: %v", err)
	}
	if undecryptable != 1 {
		t.Errorf("%d columns failed to decrypt, want exactly the poisoned one", undecryptable)
	}
	if len(fragments) != 2 {
		t.Errorf("released %d honest fragments, want 2", len(fragments))
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
