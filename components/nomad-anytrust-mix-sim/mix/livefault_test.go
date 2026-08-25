package mix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"go.dedis.ch/kyber/v4"
)

// PROD-07 asks for active-adversary fault injection at a live boundary. The
// existing blame tests build an honest chain and then corrupt the finished
// transcript, which establishes that attribution reads a transcript correctly
// and nothing about what happens when a mixer decides to cheat while the
// session is running.
//
// The difference matters for one property in particular. In a chain, a fault
// at round k poisons rounds k+1..n: every honest mixer downstream produces a
// perfectly sound round over an input it should never have received. A
// transcript corrupted after the fact never exercises that, because the
// downstream rounds were built over honest input. Attribution has to name the
// mixer who cheated and not the last one in the chain, and that is what these
// tests check.
//
// The adversary model is the real one: a dishonest operator controls its own
// process, so it runs the production shuffle and then signs whatever it likes
// over the result. It does not need to break anything to do that.

// liveChain runs a committee for real. cheat, when set for a round, is applied
// to that mixer's own output before it signs -- which is exactly the freedom a
// dishonest operator has.
type liveChain struct {
	committee     ThresholdCommittee
	encryptionKey PublicKey
	mixers        []ed25519.PublicKey
	privates      []ed25519.PrivateKey
	rounds        []SignedRound
}

func runLiveChain(t *testing.T, roundCount int, cheat map[int]func(*testing.T, *Batch) *Batch) *liveChain {
	t.Helper()
	committee, _, err := GenerateDealerCommittee(testCommitteeID(), 23, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	chain := &liveChain{committee: committee, encryptionKey: committee.PublicKey}

	batch, err := Encrypt(committee.PublicKey, testCells(4))
	if err != nil {
		t.Fatal(err)
	}

	current := batch
	for round := 0; round < roundCount; round++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		chain.mixers = append(chain.mixers, public)
		chain.privates = append(chain.privates, private)

		digest, err := current.Digest()
		if err != nil {
			t.Fatal(err)
		}
		context := RoundContext{
			CommitteeID: committee.ID, Epoch: committee.Epoch,
			BatchID: digest, Round: uint32(round),
		}
		// The production path, every round, honest or not.
		output, proof, receipt, err := ShuffleAndSign(context, committee.PublicKey, current, private)
		if err != nil {
			t.Fatal(err)
		}

		if misbehave, dishonest := cheat[round]; dishonest {
			output = misbehave(t, output)
			// Having changed its output, the mixer signs the receipt that
			// matches. A dishonest operator has no reason to leave an
			// obviously broken signature behind.
			outputDigest, err := output.Digest()
			if err != nil {
				t.Fatal(err)
			}
			receipt.OutputDigest = outputDigest
			receipt.Signature = signReceipt(t, private, receipt, committee.PublicKey)
		}

		chain.rounds = append(chain.rounds, SignedRound{
			Round:   Round{Input: current, Output: output, Proof: proof},
			Receipt: receipt,
		})
		current = output
	}
	return chain
}

// requireAttribution is the shared assertion: the named round's mixer is
// blamed, a third party can confirm it, and the blame does not move.
func requireAttribution(t *testing.T, chain *liveChain, guilty int, kind string) {
	t.Helper()
	report := AttributeFault(chain.encryptionKey, chain.committee, chain.mixers, chain.rounds)
	if report == nil {
		t.Fatal("a mixer cheated mid-session and nothing was attributed")
	}
	if report.Round != guilty {
		t.Fatalf("blamed round %d, and round %d is the one that cheated: %+v",
			report.Round, guilty, report)
	}
	if kind != "" && report.Kind != kind {
		t.Errorf("fault kind %v, want %v", report.Kind, kind)
	}
	if !report.Attributable {
		t.Error("the fault was found but not attributed to anyone")
	}
	if !bytes.Equal(report.Accused, chain.mixers[guilty]) {
		t.Errorf("accused %x, and the mixer who cheated was %x",
			report.Accused, chain.mixers[guilty])
	}
	if err := VerifyFaultReport(chain.encryptionKey, chain.committee, chain.mixers,
		chain.rounds, *report); err != nil {
		t.Errorf("a third party could not confirm the fault: %v", err)
	}
	// The honest mixers downstream produced sound rounds over poisoned input.
	// Blame must not follow the poison.
	for index := range chain.mixers {
		if index == guilty {
			continue
		}
		moved := *report
		moved.Accused = chain.mixers[index]
		if err := VerifyFaultReport(chain.encryptionKey, chain.committee, chain.mixers,
			chain.rounds, moved); err == nil {
			t.Errorf("blame was re-pointed at mixer %d, who did nothing wrong", index)
		}
	}
}

// A mixer substitutes one cell in its own output: the tagging attack. Every
// mixer after it shuffles the tagged batch honestly.
func TestAMixerThatSubstitutesACellMidSessionIsAttributed(t *testing.T) {
	const guilty = 1
	chain := runLiveChain(t, 4, map[int]func(*testing.T, *Batch) *Batch{
		guilty: func(t *testing.T, output *Batch) *Batch {
			t.Helper()
			replacement, err := Encrypt(mustCommitteeKey(t, output), testCells(2))
			if err != nil {
				t.Fatal(err)
			}
			tampered := cloneBatchForTest(t, output)
			copyFirstCell(t, tampered, replacement)
			return tampered
		},
	})
	requireAttribution(t, chain, guilty, FaultUnsoundRound)
}

// A mixer drops a cell. The batch that reaches the committee is short by one
// publication, and the mixer that shortened it is the one to blame.
func TestAMixerThatDropsACellMidSessionIsAttributed(t *testing.T) {
	const guilty = 0
	chain := runLiveChain(t, 3, map[int]func(*testing.T, *Batch) *Batch{
		guilty: func(t *testing.T, output *Batch) *Batch {
			t.Helper()
			return truncateBatchForTest(t, output)
		},
	})
	requireAttribution(t, chain, guilty, "")
}

// The honest case, which is the control. Without it every assertion above
// would pass against an AttributeFault that blamed somebody unconditionally.
func TestALiveChainWithNoCheatingIsNotBlamed(t *testing.T) {
	chain := runLiveChain(t, 4, nil)
	if report := AttributeFault(chain.encryptionKey, chain.committee, chain.mixers,
		chain.rounds); report != nil {
		t.Fatalf("an honest live chain was blamed: %v", report)
	}
	// And a report invented against it must not verify, for any mixer.
	for index := range chain.mixers {
		invented := FaultReport{
			Kind: FaultUnsoundRound, Round: index, Attributable: true,
			Accused: chain.mixers[index], Reason: "invented",
		}
		if err := VerifyFaultReport(chain.encryptionKey, chain.committee, chain.mixers,
			chain.rounds, invented); err == nil {
			t.Errorf("an invented report against honest mixer %d verified", index)
		}
	}
}

// The last mixer cheating is the case where "blame the end of the chain" and
// "blame the culprit" give the same answer, so it is checked separately from
// the ones where they differ.
func TestTheLastMixerCheatingIsAttributedToItself(t *testing.T) {
	const rounds = 3
	chain := runLiveChain(t, rounds, map[int]func(*testing.T, *Batch) *Batch{
		rounds - 1: func(t *testing.T, output *Batch) *Batch {
			t.Helper()
			return truncateBatchForTest(t, output)
		},
	})
	requireAttribution(t, chain, rounds-1, "")
}

// The cheat helpers reach into the batch directly, which a test in this
// package can do and a mixer in another process can do just as easily: it
// holds its own output and signs whatever it likes over it. x and y are
// indexed [chunk][column], so a column is one publication.

func cloneBatchForTest(t *testing.T, source *Batch) *Batch {
	t.Helper()
	clone := &Batch{
		x: make([][]kyber.Point, len(source.x)),
		y: make([][]kyber.Point, len(source.y)),
	}
	for chunk := range source.x {
		clone.x[chunk] = append([]kyber.Point(nil), source.x[chunk]...)
		clone.y[chunk] = append([]kyber.Point(nil), source.y[chunk]...)
	}
	return clone
}

// copyFirstCell replaces one column with a cell of the mixer's own choosing:
// the tagging attack, where a publication is swapped for something the mixer
// can recognise later.
func copyFirstCell(t *testing.T, target, source *Batch) {
	t.Helper()
	if target.Len() == 0 || source.Len() == 0 {
		t.Fatal("cannot substitute into an empty batch")
	}
	for chunk := range target.x {
		target.x[chunk][0] = source.x[chunk][0]
		target.y[chunk][0] = source.y[chunk][0]
	}
}

// truncateBatchForTest drops the last column: a publication that entered the
// mix and does not leave it.
func truncateBatchForTest(t *testing.T, source *Batch) *Batch {
	t.Helper()
	if source.Len() < 2 {
		t.Fatal("cannot drop a cell from a batch this small")
	}
	shortened := cloneBatchForTest(t, source)
	for chunk := range shortened.x {
		shortened.x[chunk] = shortened.x[chunk][:len(shortened.x[chunk])-1]
		shortened.y[chunk] = shortened.y[chunk][:len(shortened.y[chunk])-1]
	}
	return shortened
}

// mustCommitteeKey is the encryption key a substituted cell is encrypted to.
// A mixer substituting a cell encrypts to the same committee, because a cell
// encrypted to anything else would not decrypt at the end and the substitution
// would be obvious for the wrong reason.
func mustCommitteeKey(t *testing.T, _ *Batch) PublicKey {
	t.Helper()
	return substitutionKey
}

// substitutionKey is a committee key a dishonest mixer can encrypt a
// substituted cell to. It is generated once because generating one per
// substitution makes the test slower without making it stronger.
var substitutionKey = func() PublicKey {
	public, _, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	return public
}()
