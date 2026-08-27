package rotation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscardEvidenceRejectsDuplicateJSONKeys(t *testing.T) {
	_, err := decodeDiscard([]byte(`{"version":"first","version":"second"}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate discard-evidence key was not rejected: %v", err)
	}
}

func discardFixture(t *testing.T) (string, string, ed25519.PrivateKey, string) {
	t.Helper()
	root := t.TempDir()
	share := filepath.Join(root, "epoch-2-attempt-1.share.json")
	statement := filepath.Join(root, "epoch-2-attempt-1.discard.json")
	if err := os.WriteFile(share, []byte("private failed threshold share"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, identity, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	topologyDigest := sha256.Sum256([]byte("signed attempt topology"))
	return share, statement, identity, hex.EncodeToString(topologyDigest[:])
}

func TestDiscardFailedShareIsDurableAndIdempotent(t *testing.T) {
	share, evidence, identity, topologyDigest := discardFixture(t)
	now := time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC)
	first, err := DiscardFailedShare("nomad-test", 2, 1, topologyDigest, "operator-a", share, evidence, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(share); !os.IsNotExist(err) {
		t.Fatal("failed DKG share still exists after discard")
	}
	if _, err := os.Lstat(evidence + ".pending"); !os.IsNotExist(err) {
		t.Fatal("pending discard intent remained after completion")
	}
	second, err := DiscardFailedShare("nomad-test", 2, 1, topologyDigest, "operator-a", share, evidence, identity, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Signature != second.Signature || first.FileSHA256 != second.FileSHA256 || first.DiscardedAt != second.DiscardedAt {
		t.Fatal("idempotent discard invented new evidence")
	}
}

func TestPendingDiscardResumesAfterCrashBeforeDestruction(t *testing.T) {
	share, evidence, identity, topologyDigest := discardFixture(t)
	contents, err := os.ReadFile(share)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	statement := DiscardStatement{
		Version: DiscardVersion, NetworkID: "nomad-test", Epoch: 2, Attempt: 1,
		TopologyDigest: topologyDigest, OperatorID: "operator-a", File: filepath.Base(share),
		SizeBytes: int64(len(contents)), FileSHA256: hex.EncodeToString(digest[:]),
		DiscardedAt: time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Method:      "overwrite-random-then-unlink", Limitations: DiscardLimitations,
	}
	message, err := discardMessage(statement)
	if err != nil {
		t.Fatal(err)
	}
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	encoded, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(evidence+".pending", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	resumed, err := DiscardFailedShare("nomad-test", 2, 1, topologyDigest, "operator-a", share, evidence, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if resumed.FileSHA256 != statement.FileSHA256 || resumed.Signature != statement.Signature {
		t.Fatal("resume did not preserve the pre-crash signed evidence")
	}
	if _, err := os.Lstat(share); !os.IsNotExist(err) {
		t.Fatal("resumed discard did not remove the failed share")
	}
}

func TestPendingDiscardRefusesChangedShare(t *testing.T) {
	share, evidence, identity, topologyDigest := discardFixture(t)
	contents, err := os.ReadFile(share)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	statement := DiscardStatement{
		Version: DiscardVersion, NetworkID: "nomad-test", Epoch: 2, Attempt: 1,
		TopologyDigest: topologyDigest, OperatorID: "operator-a", File: filepath.Base(share),
		SizeBytes: int64(len(contents)), FileSHA256: hex.EncodeToString(digest[:]),
		DiscardedAt: time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Method:      "overwrite-random-then-unlink", Limitations: DiscardLimitations,
	}
	message, _ := discardMessage(statement)
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	encoded, _ := json.MarshalIndent(statement, "", "  ")
	if err := writeExclusive(evidence+".pending", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), contents...)
	changed[0] ^= 0xff
	if err := os.WriteFile(share, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscardFailedShare("nomad-test", 2, 1, topologyDigest, "operator-a", share, evidence, identity, time.Now().UTC()); err == nil {
		t.Fatal("changed failed share was erased under stale pre-erasure evidence")
	}
	if _, err := os.Lstat(share); err != nil {
		t.Fatal("tampered share was destroyed instead of failing closed")
	}
}
