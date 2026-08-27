package epoch

import (
	"os"
	"path/filepath"
	"testing"
)

// Serving processes mount the verified epoch chain read-only. The writer has
// already created LOCK during import; fresh serving decisions must therefore
// be able to synchronize through that existing file without opening it for
// write. On ordinary non-root test runners the 0400 mode makes an accidental
// O_RDWR regression fail immediately; the Compose E2E additionally exercises
// this against a genuinely read-only filesystem mount.
func TestFreshReadersDoNotRequireWritableChainLock(t *testing.T) {
	fixture, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	root := t.TempDir()
	writer, err := OpenChain(root, "nomad-test", fixture.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(root, "LOCK")
	if err := os.Chmod(lockPath, 0o400); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenChain(root, "nomad-test", fixture.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := reader.FreshStateOf(genesis.Epoch, genesis.ActivateAt)
	if err != nil {
		t.Fatalf("fresh state required write access to the chain lock: %v", err)
	}
	if state != StateActive {
		t.Fatalf("fresh state = %s, want ACTIVE", state)
	}
	stored, found, err := reader.FreshEpoch(genesis.Epoch)
	if err != nil {
		t.Fatalf("fresh epoch required write access to the chain lock: %v", err)
	}
	if !found || stored.Epoch != genesis.Epoch {
		t.Fatal("fresh epoch did not return the stored descriptor")
	}
	deadline, err := reader.FreshServingDeadline(genesis.Epoch)
	if err != nil {
		t.Fatalf("fresh deadline required write access to the chain lock: %v", err)
	}
	if !deadline.Equal(genesis.RetireAt) {
		t.Fatalf("fresh deadline = %s, want %s", deadline, genesis.RetireAt)
	}
}
