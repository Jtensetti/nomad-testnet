package epoch

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func revocationStoreFixture(t *testing.T) (*Chain, Verified, *fixture) {
	t.Helper()
	f := newNamedFixture(t, "revocation-store", 3)
	times := genesisTimes()
	session := sha256.Sum256([]byte("revocation-store-genesis"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, times, session, 70)
	certificateBytes, _ := f.buildCertificate(t, network)
	encoded, verified := f.buildDescriptor(t, nil, nil, TransitionGenesis, times, network, topologyBytes, certificateBytes)
	chain, err := OpenChain(t.TempDir(), verified.NetworkID, f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(encoded); err != nil {
		t.Fatal(err)
	}
	return chain, verified, f
}

func selfRevocation(t *testing.T, observed Verified, f *fixture, index int) []byte {
	t.Helper()
	target := observed.Topology.Document.Operators[index]
	statement := Revocation{
		Version: RevocationVersion, NetworkID: observed.NetworkID,
		OperatorID: target.ID, IdentityKey: target.IdentityKey,
		EpochObserved: observed.Epoch, Reason: ReasonSelf,
	}
	signed, err := SignRevocation(statement, target.ID, f.Operators[index].Identity)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRevocation(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPersistedRevocationRequiresChainRevalidationAfterRestart(t *testing.T) {
	chain, observed, f := revocationStoreFixture(t)
	root := t.TempDir()
	store, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded := selfRevocation(t, observed, f, 0)
	revocation, err := DecodeRevocation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(encoded, observed); err != nil {
		t.Fatal(err)
	}
	if scoped, err := store.ScopedSet(2); err != nil {
		t.Fatal(err)
	} else if _, ok := scoped[revocation.IdentityKey]; !ok {
		t.Fatal("newly accepted verified revocation did not enter the future scope")
	}

	restarted, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ScopedSet(2); err == nil {
		t.Fatal("persisted revocation became trusted after restart without chain revalidation")
	}
	if err := restarted.Revalidate(chain); err != nil {
		t.Fatal(err)
	}
	scoped, err := restarted.ScopedSet(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scoped[revocation.IdentityKey]; !ok {
		t.Fatal("chain-revalidated revocation was not applied to a future epoch")
	}
}

func TestTamperedPersistedRevocationCannotEnterScopedSet(t *testing.T) {
	chain, observed, f := revocationStoreFixture(t)
	root := t.TempDir()
	store, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded := selfRevocation(t, observed, f, 0)
	if err := store.Accept(encoded, observed); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".revocation") {
			path = filepath.Join(root, entry.Name())
			break
		}
	}
	if path == "" {
		t.Fatal("accepted revocation was not persisted")
	}
	var tampered Revocation
	if err := json.Unmarshal(encoded, &tampered); err != nil {
		t.Fatal(err)
	}
	if len(tampered.Signatures) == 0 {
		t.Fatal("fixture revocation has no signature")
	}
	// Keep valid JSON/base64 shape but make the signature cryptographically
	// invalid. Decode-on-open alone must therefore be insufficient.
	signature := []byte(tampered.Signatures[0].Signature)
	if signature[len(signature)-2] == 'A' {
		signature[len(signature)-2] = 'B'
	} else {
		signature[len(signature)-2] = 'A'
	}
	tampered.Signatures[0].Signature = string(signature)
	changed, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenRevocationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Revalidate(chain); err == nil {
		t.Fatal("tampered persisted revocation passed chain revalidation")
	}
	if _, err := restarted.ScopedSet(2); err == nil {
		t.Fatal("tampered persisted revocation store remained usable after failed revalidation")
	}
}
