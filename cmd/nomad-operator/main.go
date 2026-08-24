package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	// This process holds key material, so a panic must not print goroutine
	// stacks: Go renders frame arguments as raw machine words and an init
	// system retains whatever a crashing service wrote. Only GOTRACEBACK can
	// turn that off, and only from outside, so the process checks and says so.
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-operator:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("required subcommand: init, rotate, inspect, attest, verify or erase")
	}
	switch arguments[0] {
	case "init":
		return initialize(arguments[1:])
	case "rotate":
		return rotate(arguments[1:])
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

// rotate creates a new epoch-scoped secret file without ever overwriting the
// predecessor. The stable Ed25519 operator identity is retained so it can
// approve the transition; KEX and DKG private material are freshly generated.
func rotate(arguments []string) error {
	flags := flag.NewFlagSet("rotate", flag.ContinueOnError)
	previousPath := flags.String("from-secret", "", "previous epoch private operator-secret path")
	endpoint := flags.String("endpoint", "", "public UDP host:port")
	partialEndpoint := flags.String("partial-endpoint", "", "public threshold-partial URL")
	dkgEndpoint := flags.String("dkg-endpoint", "", "public inter-operator DKG URL")
	secretPath := flags.String("secret", "", "new epoch private operator-secret path")
	enrollmentPath := flags.String("enrollment", "", "new public epoch enrollment path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *previousPath == "" || *endpoint == "" || *partialEndpoint == "" || *dkgEndpoint == "" || *secretPath == "" || *enrollmentPath == "" {
		return errors.New("--from-secret, --endpoint, --partial-endpoint, --dkg-endpoint, --secret and --enrollment are required")
	}
	paths := map[string]struct{}{}
	for _, path := range []string{*previousPath, *secretPath, *enrollmentPath} {
		clean := filepath.Clean(path)
		if _, exists := paths[clean]; exists {
			return errors.New("previous secret, new secret and enrollment paths must differ")
		}
		paths[clean] = struct{}{}
	}
	previous, err := topology.LoadPrivateKeys(*previousPath)
	if err != nil {
		return err
	}
	secrets, err := topology.RotateEpochSecrets(previous)
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
	}{keys.OperatorID, *enrollmentPath})
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

// erase destroys epoch-private material only after the persisted verified
// chain says the epoch is RETIRED. A signed pending intent is written before
// destruction so a crash between unlink and statement persistence can resume
// with the original pre-erasure digests. The public statement is persisted
// before the chain acknowledgement; a retry can therefore repair a missing
// acknowledgement without destroying anything again.
func erase(arguments []string) error {
	flags := flag.NewFlagSet("erase", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "private operator-secret path")
	chainPath := flags.String("chain", "", "persisted verified epoch-chain directory")
	epochNumber := flags.Uint64("epoch", 0, "retired epoch number")
	authorityPath := flags.String("authority-key", "", "pinned public authority-key path")
	networkID := flags.String("network", "", "network identifier")
	filesystem := flags.String("filesystem", "", "filesystem type of the erased paths, recorded in the statement")
	sharePath := flags.String("share", "", "retired threshold-share path; must verify against the selected epoch")
	retiredSecretPath := flags.String("retired-secret", "", "retired epoch secret path; must match the selected epoch and is erased")
	outputPath := flags.String("out", "", "signed erasure-statement path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *secretPath == "" || *chainPath == "" || *epochNumber == 0 || *authorityPath == "" || *networkID == "" || *filesystem == "" || *sharePath == "" || *retiredSecretPath == "" || *outputPath == "" {
		return errors.New("--secret, --chain, --epoch, --authority-key, --network, --filesystem, --share, --retired-secret and --out are required")
	}
	erasePaths := append([]string{*sharePath, *retiredSecretPath}, flags.Args()...)
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
	operator, err := retired.Topology.OperatorByID(keys.OperatorID)
	if err != nil {
		return fmt.Errorf("local operator is not a member of retired epoch %d: %w", retired.Epoch, err)
	}
	pendingPath := *outputPath + ".pending"
	if err := validateErasePaths(*chainPath, *secretPath, *authorityPath, *outputPath, pendingPath, erasePaths); err != nil {
		return err
	}

	// Crash recovery path 1: the public statement reached disk but the chain
	// acknowledgement did not. Verify and acknowledge it without touching
	// private files again.
	if encoded, found, err := readOptionalBounded(*outputPath); err != nil {
		return err
	} else if found {
		statement, err := epoch.DecodeErasureStatement(encoded)
		if err != nil {
			return err
		}
		if statement.OperatorID != keys.OperatorID {
			return errors.New("existing erasure statement belongs to another operator")
		}
		if err := epoch.VerifyErasureStatement(statement, retired); err != nil {
			return err
		}
		if err := statementMatchesPaths(statement, erasePaths); err != nil {
			return err
		}
		if err := chain.RecordErasureStatement(statement, keys.OperatorID); err != nil {
			return err
		}
		if err := removeDurable(pendingPath); err != nil {
			return err
		}
		return emitErasureResult(statement, true)
	}

	if recorded, err := chain.ErasureRecorded(*epochNumber, keys.OperatorID); err != nil {
		return err
	} else if recorded {
		return errors.New("chain already records erasure but the requested evidence output is missing; restore the recorded statement instead of creating new evidence")
	}

	var intent epoch.ErasureIntent
	if encoded, found, err := readOptionalBounded(pendingPath); err != nil {
		return err
	} else if found {
		intent, err = epoch.DecodeErasureIntent(encoded)
		if err != nil {
			return err
		}
		if err := epoch.VerifyErasureIntent(intent, retired); err != nil {
			return err
		}
		if intent.OperatorID != keys.OperatorID || intent.Filesystem != *filesystem {
			return errors.New("pending erasure intent does not match this operator or filesystem")
		}
		if err := intentMatchesPaths(intent, erasePaths); err != nil {
			return err
		}
	} else {
		if err := validateRetiredEpochSecret(*retiredSecretPath, retired, keys); err != nil {
			return err
		}
		share, err := committee.LoadShare(*sharePath, retired.Certificate, retired.Topology)
		if err != nil {
			return fmt.Errorf("verify retired threshold share before erasure: %w", err)
		}
		if share.Index != uint32(operator.Index) {
			return errors.New("retired threshold share belongs to another operator")
		}
		intent, err = epoch.NewErasureIntent(retired, keys.OperatorID, erasePaths, *filesystem, keys.Identity, now)
		if err != nil {
			return err
		}
		encoded, err := epoch.EncodeErasureIntent(intent)
		if err != nil {
			return err
		}
		if err := writeNew(pendingPath, encoded, 0o600); err != nil {
			return fmt.Errorf("persist erasure intent before destruction: %w", err)
		}
	}

	statement, err := epoch.ExecuteErasureIntent(intent, retired, keys.Identity, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := epoch.EncodeErasureStatement(statement)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return fmt.Errorf("persist erasure statement: %w", err)
	}
	if err := chain.RecordErasureStatement(statement, keys.OperatorID); err != nil {
		return fmt.Errorf("record erasure acknowledgement: %w", err)
	}
	if err := removeDurable(pendingPath); err != nil {
		return err
	}
	return emitErasureResult(statement, false)
}

func validateRetiredEpochSecret(path string, retired epoch.Verified, signer topology.PrivateKeys) error {
	verified, err := topology.LoadSecrets(path, retired.Topology)
	if err != nil {
		return fmt.Errorf("verify retired epoch secret before erasure: %w", err)
	}
	if verified.Operator.ID != signer.OperatorID || !bytes.Equal(verified.Identity, signer.Identity) {
		return errors.New("retired epoch secret and erasure signer do not share the verified operator identity")
	}
	return nil
}

func emitErasureResult(statement epoch.ErasureStatement, recovered bool) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID string `json:"operator_id"`
		Epoch      uint64 `json:"epoch"`
		Files      int    `json:"files_erased"`
		Recovered  bool   `json:"recovered"`
	}{statement.OperatorID, statement.Epoch, len(statement.Files), recovered})
}

func intentMatchesPaths(intent epoch.ErasureIntent, paths []string) error {
	requested := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		requested = append(requested, filepath.Clean(absolute))
	}
	sort.Strings(requested)
	if len(requested) != len(intent.Files) {
		return errors.New("pending erasure intent names a different path set")
	}
	for index := range requested {
		if requested[index] != intent.Files[index].Path {
			return errors.New("pending erasure intent names a different path set")
		}
	}
	return nil
}

func statementMatchesPaths(statement epoch.ErasureStatement, paths []string) error {
	requested := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		requested = append(requested, filepath.Clean(absolute))
	}
	sort.Strings(requested)
	recorded := make([]string, 0, len(statement.Files))
	for _, file := range statement.Files {
		recorded = append(recorded, filepath.Clean(file.Path))
	}
	sort.Strings(recorded)
	if len(requested) != len(recorded) {
		return errors.New("existing erasure statement names a different path set")
	}
	for index := range requested {
		if requested[index] != recorded[index] {
			return errors.New("existing erasure statement names a different path set")
		}
	}
	return nil
}

func validateErasePaths(chainPath, secretPath, authorityPath, outputPath, pendingPath string, paths []string) error {
	protectedFiles := []string{secretPath, authorityPath, outputPath, pendingPath}
	protected := make(map[string]struct{}, len(protectedFiles))
	protectedInodes := make([]os.FileInfo, 0, len(protectedFiles))
	for _, path := range protectedFiles {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		clean := filepath.Clean(absolute)
		protected[clean] = struct{}{}
		if info, err := os.Lstat(clean); err == nil {
			protectedInodes = append(protectedInodes, info)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := filepath.Walk(chainPath, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			protectedInodes = append(protectedInodes, info)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("inspect protected epoch chain: %w", err)
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
		if info, err := os.Lstat(clean); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular erasure path %q", path)
			}
			for _, protectedInfo := range protectedInodes {
				if os.SameFile(info, protectedInfo) {
					return fmt.Errorf("refusing erasure path %q because it aliases protected state", path)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
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
	authorityPath := flags.String("authority-key", "", "pinned public authority-key path")
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

func readOptionalBounded(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > ceremony.MaximumArtifact {
		return nil, false, errors.New("existing recovery artifact must be a non-empty bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	return encoded, true, err
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
	return syncDirectory(parent)
}

func removeDurable(path string) error {
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
