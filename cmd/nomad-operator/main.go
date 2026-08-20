package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-operator:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("required subcommand: init, inspect, attest, verify or erase")
	}
	switch arguments[0] {
	case "init":
		return initialize(arguments[1:])
	case "inspect":
		return inspect(arguments[1:])
	case "attest":
		return attest(arguments[1:])
	case "verify":
		return verify(arguments[1:])
	case "erase":
		return erase(arguments[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

func initialize(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	operatorID := flags.String("id", "", "stable operator identifier")
	endpoint := flags.String("endpoint", "", "public UDP host:port")
	partialEndpoint := flags.String("partial-endpoint", "", "public threshold-partial URL")
	dkgEndpoint := flags.String("dkg-endpoint", "", "public inter-operator DKG URL")
	secretPath := flags.String("secret", "", "new private operator-secret path")
	enrollmentPath := flags.String("enrollment", "", "new public enrollment path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *operatorID == "" || *endpoint == "" || *partialEndpoint == "" || *dkgEndpoint == "" || *secretPath == "" || *enrollmentPath == "" {
		return errors.New("--id, --endpoint, --partial-endpoint, --dkg-endpoint, --secret and --enrollment are required")
	}
	if filepath.Clean(*secretPath) == filepath.Clean(*enrollmentPath) {
		return errors.New("secret and enrollment paths must differ")
	}
	secrets, err := topology.GenerateSecrets(*operatorID)
	if err != nil {
		return err
	}
	secretBytes, err := topology.EncodeSecrets(secrets)
	if err != nil {
		return err
	}
	keys, err := topology.DecodePrivateKeys(secretBytes)
	if err != nil {
		return err
	}
	enrollment, err := ceremony.NewEnrollment(keys, *endpoint, *partialEndpoint, *dkgEndpoint)
	if err != nil {
		return err
	}
	enrollmentBytes, err := ceremony.EncodeEnrollment(enrollment)
	if err != nil {
		return err
	}
	if err := writeNew(*secretPath, secretBytes, 0o600); err != nil {
		return err
	}
	if err := writeNew(*enrollmentPath, enrollmentBytes, 0o644); err != nil {
		_ = os.Remove(*secretPath)
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID string `json:"operator_id"`
		Enrollment string `json:"enrollment"`
	}{*operatorID, *enrollmentPath})
}

// inspect prints the PUBLIC identity an operator holds, so an administrator
// can confirm what they enrolled without ever opening the secret by hand.
// It prints public keys only; no private material reaches stdout.
func inspect(arguments []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "private operator-secret path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *secretPath == "" {
		return errors.New("--secret is required")
	}
	keys, err := topology.LoadPrivateKeys(*secretPath)
	if err != nil {
		return err
	}
	dkgPublic, err := mix.DKGPublicFromPrivate(keys.DKG)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID     string `json:"operator_id"`
		IdentityKey    string `json:"identity_key"`
		KEXKey         string `json:"kex_key"`
		DKGIdentityKey string `json:"dkg_identity_key"`
	}{
		keys.OperatorID,
		base64.StdEncoding.EncodeToString(keys.Identity.Public().(ed25519.PublicKey)),
		base64.StdEncoding.EncodeToString(keys.KEX.PublicKey().Bytes()),
		base64.StdEncoding.EncodeToString(dkgPublic[:]),
	})
}

// erase destroys this operator's private material for an epoch that the
// persisted verified chain currently classifies as RETIRED. Looking the epoch
// up through the chain is essential: a non-genesis descriptor cannot be
// verified without its predecessor, and an emergency successor can retire an
// epoch before that descriptor's own scheduled RetireAt.
func erase(arguments []string) error {
	flags := flag.NewFlagSet("erase", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "private operator-secret path")
	chainPath := flags.String("chain", "", "persisted verified epoch-chain directory")
	epochNumber := flags.Uint64("epoch", 0, "retired epoch number")
	authorityPath := flags.String("authority-key", "", "pinned public authority-key path")
	networkID := flags.String("network", "", "network identifier")
	filesystem := flags.String("filesystem", "", "filesystem type of the erased paths, recorded in the statement")
	outputPath := flags.String("out", "", "new signed erasure-statement path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *secretPath == "" || *chainPath == "" || *epochNumber == 0 || *authorityPath == "" || *networkID == "" || *filesystem == "" || *outputPath == "" {
		return errors.New("--secret, --chain, --epoch, --authority-key, --network, --filesystem and --out are required")
	}
	if flags.NArg() == 0 {
		return errors.New("at least one path to erase is required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return fmt.Errorf("open epoch chain: %w", err)
	}
	retired, exists, err := chain.FreshEpoch(*epochNumber)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("epoch %d is not present in the verified chain", *epochNumber)
	}
	now := time.Now().UTC()
	state, err := chain.FreshStateOf(*epochNumber, now)
	if err != nil {
		return err
	}
	if state != epoch.StateRetired {
		return fmt.Errorf("refusing to erase material for epoch %d while state is %s", *epochNumber, state)
	}
	keys, err := topology.LoadPrivateKeys(*secretPath)
	if err != nil {
		return err
	}
	if err := validateErasePaths(*chainPath, *secretPath, *authorityPath, *outputPath, flags.Args()); err != nil {
		return err
	}
	statement, err := epoch.EraseEpochMaterialDurable(*networkID, keys.OperatorID, retired, flags.Args(), *filesystem, keys.Identity, now)
	if err != nil {
		return err
	}
	encoded, err := epoch.EncodeErasureStatement(statement)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID string `json:"operator_id"`
		Epoch      uint64 `json:"epoch"`
		Files      int    `json:"files_erased"`
	}{statement.OperatorID, statement.Epoch, len(statement.Files)})
}

func validateErasePaths(chainPath, secretPath, authorityPath, outputPath string, paths []string) error {
	protectedFiles := []string{secretPath, authorityPath, outputPath}
	protected := make(map[string]struct{}, len(protectedFiles))
	for _, path := range protectedFiles {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		protected[filepath.Clean(absolute)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		clean := filepath.Clean(absolute)
		if _, exists := protected[clean]; exists {
			return fmt.Errorf("refusing to erase protected operator path %q", path)
		}
		insideChain, err := epoch.PathWithin(chainPath, clean)
		if err != nil {
			return err
		}
		if insideChain {
			return fmt.Errorf("refusing to erase epoch-chain path %q", path)
		}
		if _, duplicate := seen[clean]; duplicate {
			return fmt.Errorf("duplicate erasure path %q", path)
		}
		seen[clean] = struct{}{}
	}
	return nil
}

func attest(arguments []string) error {
	flags := flag.NewFlagSet("attest", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "private operator-secret path")
	draftPath := flags.String("draft", "", "public topology draft path")
	outputPath := flags.String("out", "", "new public attestation path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *secretPath == "" || *draftPath == "" || *outputPath == "" {
		return errors.New("--secret, --draft and --out are required")
	}
	keys, err := topology.LoadPrivateKeys(*secretPath)
	if err != nil {
		return err
	}
	draftBytes, err := readBoundedRegular(*draftPath)
	if err != nil {
		return err
	}
	draft, err := ceremony.DecodeDraft(draftBytes)
	if err != nil {
		return err
	}
	attestation, err := ceremony.CreateAttestation(draft, keys)
	if err != nil {
		return err
	}
	encoded, err := ceremony.EncodeAttestation(attestation)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID  string `json:"operator_id"`
		DraftDigest string `json:"draft_digest"`
	}{attestation.OperatorID, attestation.DraftDigest})
}

func verify(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "private operator-secret path")
	topologyPath := flags.String("topology", "", "authority-signed topology path")
	authorityPath := flags.String("authority-key", "", "pinned topology authority public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *secretPath == "" || *topologyPath == "" || *authorityPath == "" {
		return errors.New("--secret, --topology and --authority-key are required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	network, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	secrets, err := topology.LoadSecrets(*secretPath, network)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID     string `json:"operator_id"`
		TopologyDigest string `json:"topology_digest"`
		Outgoing       int    `json:"outgoing"`
		Incoming       int    `json:"incoming"`
	}{secrets.Operator.ID, fmt.Sprintf("%x", network.Digest), len(secrets.OutboundKeys), len(secrets.InboundKeys)})
}

func readBoundedRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > ceremony.MaximumArtifact {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output parent must be a real directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	written = true
	return syncOutputDirectory(parent)
}

func syncOutputDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

// Keep strconv and strings in the import set checked by the compiler if the
// flag/help surface changes during rebases; both are intentionally referenced
// by this file's production path checks.
var (
	_ = strconv.IntSize
	_ = strings.Compare
)
