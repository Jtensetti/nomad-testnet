package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestRotateCreatesFreshEpochKeysAndSignedEnrollment(t *testing.T) {
	root := t.TempDir()
	previousPath := filepath.Join(root, "epoch-1.secrets.json")
	secretPath := filepath.Join(root, "epoch-2.secrets.json")
	enrollmentPath := filepath.Join(root, "epoch-2.enrollment.json")
	previous, err := topology.GenerateSecrets("operator-a")
	if err != nil {
		t.Fatal(err)
	}
	previousBytes, err := topology.EncodeSecrets(previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPath, previousBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rotate([]string{
		"--from-secret", previousPath,
		"--endpoint", "127.0.0.1:4200",
		"--partial-endpoint", "http://127.0.0.1:4300",
		"--dkg-endpoint", "http://127.0.0.1:4400",
		"--secret", secretPath,
		"--enrollment", enrollmentPath,
	}); err != nil {
		t.Fatal(err)
	}
	oldKeys, err := topology.LoadPrivateKeys(previousPath)
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := topology.LoadPrivateKeys(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldKeys.Identity, newKeys.Identity) {
		t.Fatal("rotation did not preserve the transition-signing identity")
	}
	if bytes.Equal(oldKeys.KEX.Bytes(), newKeys.KEX.Bytes()) || bytes.Equal(oldKeys.DKG[:], newKeys.DKG[:]) {
		t.Fatal("rotation reused epoch-private KEX or DKG material")
	}
	enrollmentBytes, err := os.ReadFile(enrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := ceremony.DecodeEnrollment(enrollmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.OperatorID != newKeys.OperatorID {
		t.Fatal("rotated enrollment belongs to another operator")
	}
	if err := rotate([]string{
		"--from-secret", previousPath,
		"--endpoint", "127.0.0.1:4200",
		"--partial-endpoint", "http://127.0.0.1:4300",
		"--dkg-endpoint", "http://127.0.0.1:4400",
		"--secret", secretPath,
		"--enrollment", enrollmentPath,
	}); err == nil {
		t.Fatal("rotation overwrote an existing epoch secret or enrollment")
	}
}

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
