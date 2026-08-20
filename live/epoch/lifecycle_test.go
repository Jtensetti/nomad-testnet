package epoch

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/committee"
)

func buildGenesis(t *testing.T, f *fixture, operators int, threshold uint32, label string) ([]byte, Verified, []mix.MemberSecret, mix.ThresholdCommittee) {
	t.Helper()
	session := sha256.Sum256([]byte(label))
	topologyBytes, network := f.buildSignedTopology(t, 1, threshold, genesisTimes(), session, 10)
	certificateBytes, secrets := f.buildCertificate(t, network)
	encoded, verified := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)
	return encoded, verified, secrets, verified.Certificate.Committee
}

func newRevocation(f *fixture, genesis Verified, target int, reason string) Revocation {
	operator := genesis.Topology.Document.Operators[target]
	return Revocation{
		Version: RevocationVersion, NetworkID: genesis.NetworkID,
		OperatorID: operator.ID, IdentityKey: operator.IdentityKey,
		EpochObserved: genesis.Epoch, Reason: reason,
	}
}

func TestSelfRevocationRequiresTheRevokedOperator(t *testing.T) {
	f := newFixture(t, 5)
	_, genesis, _, _ := buildGenesis(t, f, 5, 3, "self-revocation")

	unsigned := newRevocation(f, genesis, 2, ReasonSelf)
	if err := VerifyRevocation(unsigned, genesis); err == nil {
		t.Fatal("an unsigned self-revocation must be rejected")
	}
	// Signed by a different operator: not a self-revocation.
	byOther, err := SignRevocation(unsigned, genesis.Topology.Document.Operators[1].ID, f.Operators[1].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(byOther, genesis); err == nil {
		t.Fatal("a self-revocation signed by someone else must be rejected")
	}
	signed, err := SignRevocation(unsigned, genesis.Topology.Document.Operators[2].ID, f.Operators[2].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(signed, genesis); err != nil {
		t.Fatalf("a correctly signed self-revocation must verify: %v", err)
	}
}

func TestCompromiseRevocationNeedsPeerQuorum(t *testing.T) {
	f := newFixture(t, 5)
	_, genesis, _, _ := buildGenesis(t, f, 5, 3, "compromise-revocation")
	base := newRevocation(f, genesis, 4, ReasonCompromise)

	// One peer is not enough: a single operator must not evict another.
	single, err := SignRevocation(base, genesis.Topology.Document.Operators[0].ID, f.Operators[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(single, genesis); err == nil {
		t.Fatal("one peer must not be able to revoke another operator")
	}
	// The target signing for itself does not count toward the peer quorum.
	withTarget := single
	withTarget, err = SignRevocation(withTarget, genesis.Topology.Document.Operators[4].ID, f.Operators[4].Identity)
	if err != nil {
		t.Fatal(err)
	}
	withTarget, err = SignRevocation(withTarget, genesis.Topology.Document.Operators[1].ID, f.Operators[1].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(withTarget, genesis); err == nil {
		t.Fatal("the revoked operator's own signature must not count toward the peer quorum")
	}
	// Three distinct peers reach the 3-of-5 quorum.
	quorum := single
	for _, index := range []int{1, 2} {
		quorum, err = SignRevocation(quorum, genesis.Topology.Document.Operators[index].ID, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyRevocation(quorum, genesis); err != nil {
		t.Fatalf("a peer quorum must authorize a compromise revocation: %v", err)
	}
}

func TestRevocationRejectsForeignSignersAndWrongEpoch(t *testing.T) {
	f := newFixture(t, 5)
	_, genesis, _, _ := buildGenesis(t, f, 5, 3, "revocation-foreign")
	outsider := newNamedFixture(t, "outsider", 5)
	base := newRevocation(f, genesis, 3, ReasonCompromise)

	forged := base
	message, err := RevocationMessage(base)
	if err != nil {
		t.Fatal(err)
	}
	// An outsider's signature attributed to a real operator ID.
	forged.Signatures = []Signer{{
		OperatorID: genesis.Topology.Document.Operators[0].ID,
		Signature:  base64.StdEncoding.EncodeToString(ed25519.Sign(outsider.Operators[0].Identity, message)),
	}}
	if err := VerifyRevocation(forged, genesis); err == nil {
		t.Fatal("a signature from a key outside the epoch must be rejected")
	}

	wrongEpoch := base
	wrongEpoch.EpochObserved = genesis.Epoch + 5
	signed, err := SignRevocation(wrongEpoch, genesis.Topology.Document.Operators[0].ID, f.Operators[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(signed, genesis); err == nil {
		t.Fatal("a revocation naming another epoch must be rejected")
	}
}

func TestRevocationStorePersistsAndFeedsChainAdmission(t *testing.T) {
	f := newFixture(t, 5)
	genesisEncoded, genesis, _, _ := buildGenesis(t, f, 5, 3, "revocation-store")
	base := newRevocation(f, genesis, 4, ReasonCompromise)
	revocation := base
	var err error
	for _, index := range []int{0, 1, 2} {
		revocation, err = SignRevocation(revocation, genesis.Topology.Document.Operators[index].ID, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := EncodeRevocation(revocation)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	store, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(encoded, genesis); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(encoded, genesis); err != nil {
		t.Fatalf("accepting the same revocation twice must be idempotent: %v", err)
	}
	if !store.Revoked(genesis.Topology.Document.Operators[4].IdentityKey) {
		t.Fatal("store must report the revoked identity")
	}
	reopened, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Revoked(genesis.Topology.Document.Operators[4].IdentityKey) {
		t.Fatal("revocations must survive reopening")
	}

	// The revoked identity can no longer appear in a new epoch, but the
	// existing chain remains usable.
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, reopened.Set())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err == nil {
		t.Fatal("a new chain must not admit an epoch containing a revoked identity")
	}
}

func TestErasureDestroysMaterialAndProducesVerifiableStatement(t *testing.T) {
	f := newFixture(t, 3)
	_, genesis, _, _ := buildGenesis(t, f, 3, 2, "erasure")
	directory := t.TempDir()
	sharePath := filepath.Join(directory, "share.json")
	secret := []byte(`{"private_share":"this is the operator's private threshold share"}`)
	if err := os.WriteFile(sharePath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(directory, "dkg-journal.json")
	if err := os.WriteFile(journalPath, []byte("ceremony transcript"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(directory, "already-gone.json")

	statement, err := EraseEpochMaterial("nomad-test", genesis.Topology.Document.Operators[0].ID,
		genesis, []string{sharePath, journalPath, absent}, "tmpfs", f.Operators[0].Identity, fixtureBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sharePath); !os.IsNotExist(err) {
		t.Fatal("the private share must not remain on disk")
	}
	if _, err := os.Lstat(journalPath); !os.IsNotExist(err) {
		t.Fatal("the ceremony journal must not remain on disk")
	}
	if err := VerifyErasureStatement(statement, genesis); err != nil {
		t.Fatalf("the erasure statement must verify: %v", err)
	}
	if !strings.Contains(statement.Limitations, "does not guarantee physical destruction") {
		t.Fatal("the statement must carry its own limitations")
	}
	if len(statement.Files) != 3 {
		t.Fatalf("expected three file records, got %d", len(statement.Files))
	}
	// Tampering with any recorded fact invalidates the signature.
	tampered := statement
	tampered.Files = append([]ErasedFile(nil), statement.Files...)
	tampered.Files[0].SizeBytes++
	if err := VerifyErasureStatement(tampered, genesis); err == nil {
		t.Fatal("a tampered erasure statement must not verify")
	}
	// A statement from one operator cannot be attributed to another.
	misattributed := statement
	misattributed.OperatorID = genesis.Topology.Document.Operators[1].ID
	if err := VerifyErasureStatement(misattributed, genesis); err == nil {
		t.Fatal("an erasure statement must not verify for another operator")
	}
}

// TestForwardSecrecyAfterErasure is the adversarial experiment required by
// C-15. Ciphertext captured during an epoch is decryptable while the shares
// exist, and must not be decryptable from the complete persisted state of
// every operator after retirement and erasure.
func TestForwardSecrecyAfterErasure(t *testing.T) {
	f := newFixture(t, 5)
	_, genesis, secrets, committeeValue := buildGenesis(t, f, 5, 3, "forward-secrecy")

	// Capture epoch ciphertext, exactly as a network observer would.
	var plain mix.PlainCell
	copy(plain[:], "epoch-N ciphertext captured by an observer")
	batch, err := mix.Encrypt(committeeValue.PublicKey, []mix.PlainCell{plain, plain})
	if err != nil {
		t.Fatal(err)
	}

	// Persist each operator's private share the way the share service does.
	directory := t.TempDir()
	sharePaths := make([]string, 0, len(secrets))
	for index, secret := range secrets {
		share := committee.ShareFromSecret(secret, genesis.Topology.Document.Operators[index], genesis.Topology)
		encoded, err := committee.EncodeShare(share)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "share-"+genesis.Topology.Document.Operators[index].ID+".json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		sharePaths = append(sharePaths, path)
	}

	// Control: with the shares present, a threshold of operators decrypts.
	partials := make([]*mix.PartialDecryption, 0, 3)
	for index := 0; index < 3; index++ {
		partial, err := mix.CreatePartialDecryption(committeeValue, secrets[index], batch)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	if _, err := mix.ThresholdDecrypt(committeeValue, batch, partials); err != nil {
		t.Fatalf("control run must succeed before erasure: %v", err)
	}

	// Retire and erase on every operator.
	for index, path := range sharePaths {
		statement, err := EraseEpochMaterial("nomad-test", genesis.Topology.Document.Operators[index].ID,
			genesis, []string{path}, "tmpfs", f.Operators[index].Identity, fixtureBase)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyErasureStatement(statement, genesis); err != nil {
			t.Fatal(err)
		}
	}

	// The adversary now receives the complete persisted state of every
	// operator and attempts to decrypt the captured ciphertext.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := committee.VerifyShare(contents, genesis.Certificate, genesis.Topology); err == nil {
			t.Fatalf("post-erasure state still yields a usable share from %s", entry.Name())
		}
	}
	if len(entries) != 0 {
		t.Fatalf("expected no residual share files, found %d", len(entries))
	}
	// The captured ciphertext remains, and without shares it cannot be
	// opened: no threshold of partial decryptions can be formed at all.
	if _, err := mix.ThresholdDecrypt(committeeValue, batch, nil); err == nil {
		t.Fatal("decryption must be impossible without shares")
	}
}

func TestErasureStatementRejectsMissingLimitations(t *testing.T) {
	f := newFixture(t, 3)
	_, genesis, _, _ := buildGenesis(t, f, 3, 2, "erasure-limitations")
	statement := ErasureStatement{
		Version: ErasureVersion, NetworkID: "nomad-test",
		OperatorID: genesis.Topology.Document.Operators[0].ID, Epoch: genesis.Epoch,
		DescriptorDigest: hex.EncodeToString(genesis.Digest[:]),
		Method:           "overwrite-random-then-unlink", Filesystem: "tmpfs",
		ErasedAt:    fixtureBase.UTC().Format(time.RFC3339),
		Limitations: "erased securely",
	}
	if _, err := ErasureMessage(ErasementInput(statement)); err == nil {
		t.Fatal("a statement that understates its limitations must be rejected")
	}
}
