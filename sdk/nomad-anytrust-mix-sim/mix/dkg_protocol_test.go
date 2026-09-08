package mix

import (
	"crypto/rand"
	"strings"
	"testing"

	"go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// The distributed Pedersen DKG is the ceremony that produces a threshold
// committee without a dealer, and every function on its path measured 0.0%
// coverage *in this repository*. It is well covered from nomad-testnet, which
// vendors this module and drives it through live/dkg -- which means a change
// made here, tested here, and green here can break the ceremony, and only the
// other repository's gate would notice.
//
// The rule that the implementer must not be the only judge of its own change
// applies to repositories as well: the module that owns this code has to be
// able to fail on it.
//
// This drives Kyber's own DistKeyGenerator across a committee in-process,
// exchanging the real bundles, and hands the result to MaterializePedersenDKG
// exactly as the runner does.

func runDistributedDKG(t *testing.T, members int, threshold uint32) (
	[]DKGPublicIdentity, []DKGPrivateIdentity, []*dkg.DealBundle,
	[]*dkg.ResponseBundle, []*dkg.JustificationBundle, []*dkg.Result, []byte) {
	t.Helper()
	privates := make([]DKGPrivateIdentity, members)
	publics := make([]DKGPublicIdentity, members)
	for index := range privates {
		public, private, err := GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		privates[index], publics[index] = private, public
	}
	nonce := make([]byte, dkg.NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	generators := make([]*dkg.DistKeyGenerator, members)
	for index := range generators {
		config, err := NewPedersenDKGConfig(privates[index], publics, threshold, nonce)
		if err != nil {
			t.Fatalf("member %d could not configure the DKG: %v", index, err)
		}
		generator, err := dkg.NewDistKeyHandler(config)
		if err != nil {
			t.Fatalf("member %d could not start the DKG: %v", index, err)
		}
		generators[index] = generator
	}

	deals := make([]*dkg.DealBundle, 0, members)
	for index, generator := range generators {
		bundle, err := generator.Deals()
		if err != nil {
			t.Fatalf("member %d could not deal: %v", index, err)
		}
		deals = append(deals, bundle)
	}
	responses := make([]*dkg.ResponseBundle, 0, members)
	for index, generator := range generators {
		bundle, err := generator.ProcessDeals(deals)
		if err != nil {
			t.Fatalf("member %d could not process deals: %v", index, err)
		}
		if bundle != nil {
			responses = append(responses, bundle)
		}
	}
	results := make([]*dkg.Result, members)
	var justifications []*dkg.JustificationBundle
	for index, generator := range generators {
		result, optional, err := generator.ProcessResponses(responses)
		if err != nil {
			t.Fatalf("member %d could not process responses: %v", index, err)
		}
		if result == nil {
			t.Fatalf("member %d reached no result with every member honest", index)
		}
		results[index] = result
		_ = optional
	}
	return publics, privates, deals, responses, justifications, results, nonce
}

// The ceremony completes and every member materialises the same committee.
// A DKG where members disagreed on the public key would produce a committee
// that can never decrypt anything, and it would do so silently.
func TestTheDistributedCeremonyProducesOneCommitteeForEveryMember(t *testing.T) {
	const members = 3
	const threshold = uint32(2)
	publics, _, deals, responses, justifications, results, nonce := runDistributedDKG(t, members, threshold)

	id := CommitteeID{9}
	const epoch = uint64(4)
	var first ThresholdCommittee
	secrets := make([]MemberSecret, members)
	for index := range results {
		committee, secret, transcript, err := MaterializePedersenDKG(
			id, epoch, threshold, nonce, publics, deals, responses, justifications, results[index])
		if err != nil {
			t.Fatalf("member %d could not materialise the ceremony: %v", index, err)
		}
		if index == 0 {
			first = committee
		} else if committee.PublicKey != first.PublicKey {
			t.Fatalf("member %d derived a different committee key", index)
		}
		if committee.Epoch != epoch || committee.ID != id {
			t.Fatalf("member %d bound the committee to %d/%x", index, committee.Epoch, committee.ID)
		}
		if transcript.Digest == ([32]byte{}) || len(transcript.Qualified) != members {
			t.Fatalf("member %d produced a transcript with digest %x over %d qualified",
				index, transcript.Digest, len(transcript.Qualified))
		}
		if secret.Index != uint32(index) {
			t.Fatalf("member %d received share index %d", index, secret.Index)
		}
		secrets[index] = secret
	}
	if err := ValidateThresholdCommittee(first); err != nil {
		t.Fatalf("the ceremony produced a committee that does not validate: %v", err)
	}

	// The shares are usable: a threshold of them decrypts, and fewer does not.
	var cell PlainCell
	for index := range cell {
		cell[index] = byte(index)
	}
	batch, err := Encrypt(first.PublicKey, []PlainCell{cell, cell})
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*PartialDecryption, 0, threshold)
	for index := 0; index < int(threshold); index++ {
		partial, err := CreatePartialDecryption(first, secrets[index], batch)
		if err != nil {
			t.Fatalf("member %d could not produce a partial: %v", index, err)
		}
		if err := VerifyPartialDecryption(first, batch, partial); err != nil {
			t.Fatalf("member %d produced a partial that does not verify: %v", index, err)
		}
		partials = append(partials, partial)
	}
	if _, err := ThresholdDecrypt(first, batch, partials); err != nil {
		t.Fatalf("a threshold of shares could not decrypt: %v", err)
	}
	if _, err := ThresholdDecrypt(first, batch, partials[:threshold-1]); err == nil {
		t.Fatal("fewer than the threshold decrypted the batch")
	}
}

// The transcript is what an outside party checks the ceremony by, so it must
// be bound to the ceremony's context and not merely to its output. A committee
// materialised under a different epoch, identifier or nonce is a different
// committee, and must not verify against this one's packets.
func TestMaterialisingRefusesADifferentCeremonyContext(t *testing.T) {
	const members = 3
	const threshold = uint32(2)
	publics, _, deals, responses, justifications, results, nonce := runDistributedDKG(t, members, threshold)

	id := CommitteeID{9}
	const epoch = uint64(4)
	good, _, transcript, err := MaterializePedersenDKG(
		id, epoch, threshold, nonce, publics, deals, responses, justifications, results[0])
	if err != nil {
		t.Fatal(err)
	}

	otherNonce := make([]byte, dkg.NonceLength)
	copy(otherNonce, nonce)
	otherNonce[0] ^= 0xff
	reversed := make([]DKGPublicIdentity, len(publics))
	for index := range publics {
		reversed[index] = publics[len(publics)-1-index]
	}

	for _, scenario := range []struct {
		name string
		call func() error
	}{
		{"a zero committee identifier", func() error {
			_, _, _, err := MaterializePedersenDKG(CommitteeID{}, epoch, threshold, nonce,
				publics, deals, responses, justifications, results[0])
			return err
		}},
		{"epoch zero", func() error {
			_, _, _, err := MaterializePedersenDKG(id, 0, threshold, nonce,
				publics, deals, responses, justifications, results[0])
			return err
		}},
		{"another ceremony's nonce", func() error {
			_, _, _, err := MaterializePedersenDKG(id, epoch, threshold, otherNonce,
				publics, deals, responses, justifications, results[0])
			return err
		}},
		{"a different membership order", func() error {
			_, _, _, err := MaterializePedersenDKG(id, epoch, threshold, nonce,
				reversed, deals, responses, justifications, results[0])
			return err
		}},
		{"a missing deal", func() error {
			_, _, _, err := MaterializePedersenDKG(id, epoch, threshold, nonce,
				publics, deals[:len(deals)-1], responses, justifications, results[0])
			return err
		}},
		{"a missing response", func() error {
			_, _, _, err := MaterializePedersenDKG(id, epoch, threshold, nonce,
				publics, deals, responses[:len(responses)-1], justifications, results[0])
			return err
		}},
		{"no result at all", func() error {
			_, _, _, err := MaterializePedersenDKG(id, epoch, threshold, nonce,
				publics, deals, responses, justifications, nil)
			return err
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if err := scenario.call(); err == nil {
				t.Fatalf("%s was accepted", scenario.name)
			}
		})
	}

	// Vacuity: the unchanged call still succeeds and still produces the same
	// transcript, so the refusals above are about what was changed.
	_, _, again, err := MaterializePedersenDKG(
		id, epoch, threshold, nonce, publics, deals, responses, justifications, results[0])
	if err != nil {
		t.Fatalf("the unmodified ceremony stopped materialising: %v", err)
	}
	if again.Digest != transcript.Digest || again.SessionID != transcript.SessionID {
		t.Fatal("materialising the same ceremony twice produced two transcripts")
	}
	if good.PublicKey != (PublicKey{}) && again.Digest == ([32]byte{}) {
		t.Fatal("a committee with a key produced an empty transcript commitment")
	}
}

func TestTheDKGConfigRefusesAMembershipItCannotBeIn(t *testing.T) {
	public, private, err := GenerateDKGIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateDKGIdentity()
	if err != nil {
		t.Fatal(err)
	}
	third, _, err := GenerateDKGIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fourth, _, err := GenerateDKGIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, dkg.NonceLength)
	members := []DKGPublicIdentity{public, other, third}

	if _, err := NewPedersenDKGConfig(private, members, 2, nonce); err != nil {
		t.Fatalf("a member of its own committee was refused: %v", err)
	}
	for _, scenario := range []struct {
		name      string
		members   []DKGPublicIdentity
		threshold uint32
		nonce     []byte
		mustSay   string
	}{
		{"a membership this member is not in", []DKGPublicIdentity{other, third, fourth},
			2, nonce, "not in the public membership"},
		{"a duplicated member", []DKGPublicIdentity{public, other, other},
			2, nonce, "duplicate"},
		{"a threshold of one", members, 1, nonce, "invalid DKG threshold"},
		{"a threshold above the membership", members, 4, nonce, "invalid DKG threshold"},
		{"a nonce of the wrong length", members, 2, nonce[:8], "nonce length"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, err := NewPedersenDKGConfig(private, scenario.members, scenario.threshold, scenario.nonce)
			if err == nil {
				t.Fatalf("%s was accepted", scenario.name)
			}
			if !strings.Contains(err.Error(), scenario.mustSay) {
				t.Fatalf("the refusal does not say why: %v", err)
			}
		})
	}
}
