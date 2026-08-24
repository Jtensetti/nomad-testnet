package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/epoch"
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
	pending := output + ".pending"
	share := filepath.Join(root, "share.json")
	chainFile := filepath.Join(chain, "00000000000000000001.epoch.json")
	for _, path := range []string{secret, authority, share, chainFile} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := validateErasePaths(chain, secret, authority, output, pending, []string{share}); err != nil {
		t.Fatalf("ordinary epoch-private file should be erasable: %v", err)
	}
	for _, protected := range []string{secret, authority, output, pending, chainFile} {
		if err := validateErasePaths(chain, secret, authority, output, pending, []string{protected}); err == nil {
			t.Fatalf("protected path %s must be refused", protected)
		}
	}
	if err := validateErasePaths(chain, secret, authority, output, pending, []string{share, share}); err == nil {
		t.Fatal("duplicate erase targets must be refused")
	}
}

func TestValidateErasePathsRejectsHardLinksToProtectedState(t *testing.T) {
	root := t.TempDir()
	chain := filepath.Join(root, "epoch-chain")
	if err := os.MkdirAll(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "operator-secret.json")
	authority := filepath.Join(root, "authority.pub")
	chainFile := filepath.Join(chain, "00000000000000000001.epoch.json")
	for _, path := range []string{secret, authority, chainFile} {
		if err := os.WriteFile(path, []byte("protected"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(root, "erasure.json")
	for name, protected := range map[string]string{"secret": secret, "chain": chainFile} {
		t.Run(name, func(t *testing.T) {
			alias := filepath.Join(root, name+"-alias")
			if err := os.Link(protected, alias); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			if err := validateErasePaths(chain, secret, authority, output, output+".pending", []string{alias}); err == nil {
				t.Fatal("hard-link alias to protected state was accepted for erasure")
			}
		})
	}
}

func TestExistingErasureStatementMustMatchRequestedPaths(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "share.json")
	second := filepath.Join(root, "dkg-private.json")
	statement := epoch.ErasureStatement{Files: []epoch.ErasedFile{{Path: first}, {Path: second}}}
	if err := statementMatchesPaths(statement, []string{second, first}); err != nil {
		t.Fatalf("the same canonical path set was refused: %v", err)
	}
	if err := statementMatchesPaths(statement, []string{first}); err == nil {
		t.Fatal("recovery accepted evidence for a different path set")
	}
}
