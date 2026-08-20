package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateErasePathsProtectsControlPlaneFiles(t *testing.T) {
	root := t.TempDir()
	chain := filepath.Join(root, "epoch-chain")
	if err := os.MkdirAll(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "operator-secret.json")
	authority := filepath.Join(root, "authority.pub")
	output := filepath.Join(root, "erasure.json")
	share := filepath.Join(root, "share.json")
	for _, path := range []string{secret, authority, share} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := validateErasePaths(chain, secret, authority, output, []string{share}); err != nil {
		t.Fatalf("ordinary epoch-private file should be erasable: %v", err)
	}
	for _, protected := range []string{secret, authority, output, filepath.Join(chain, "00000000000000000001.epoch.json")} {
		if err := validateErasePaths(chain, secret, authority, output, []string{protected}); err == nil {
			t.Fatalf("protected path %s must be refused", protected)
		}
	}
	if err := validateErasePaths(chain, secret, authority, output, []string{share, share}); err == nil {
		t.Fatal("duplicate erase targets must be refused")
	}
}
