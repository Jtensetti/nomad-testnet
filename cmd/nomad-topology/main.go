package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-topology:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("required subcommand: authority-init, draft or finalize")
	}
	switch arguments[0] {
	case "authority-init":
		return authorityInit(arguments[1:])
	case "draft":
		return draft(arguments[1:])
	case "finalize":
		return finalize(arguments[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

func authorityInit(arguments []string) error {
	flags := flag.NewFlagSet("authority-init", flag.ContinueOnError)
	privatePath := flags.String("private", "", "new private authority-key path")
	publicPath := flags.String("public", "", "new public authority-key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("--private and --public are required")
	}
	if filepath.Clean(*privatePath) == filepath.Clean(*publicPath) {
		return errors.New("private and public authority paths must differ")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeNew(*privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeNew(*publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		_ = os.Remove(*privatePath)
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		PublicKey string `json:"public_key"`
	}{base64.StdEncoding.EncodeToString(publicKey)})
}

func draft(arguments []string) error {
	flags := flag.NewFlagSet("draft", flag.ContinueOnError)
	enrollmentPaths := flags.String("enrollments", "", "comma-separated public enrollment paths")
	outputPath := flags.String("out", "", "new topology draft path")
	networkID := flags.String("network-id", "", "public network identifier")
	epoch := flags.Uint64("epoch", 1, "public topology epoch")
	cellInterval := flags.Uint("cell-interval-ms", 50, "public fixed cell interval")
	validFor := flags.Duration("valid-for", 24*time.Hour, "topology validity period")
	dkgStartDelay := flags.Duration("dkg-start-delay", 2*time.Minute, "delay before the public DKG schedule starts")
	dkgPhaseDuration := flags.Duration("dkg-phase-duration", 30*time.Second, "duration of each public DKG phase")
	dkgThreshold := flags.Uint("dkg-threshold", 0, "DKG threshold; zero selects majority")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	paths := splitList(*enrollmentPaths)
	if flags.NArg() != 0 || len(paths) < 3 || *outputPath == "" || *networkID == "" {
		return errors.New("--enrollments with three or more paths, --out and --network-id are required")
	}
	if *validFor < time.Hour || *validFor > 365*24*time.Hour {
		return errors.New("--valid-for must be between one hour and one year")
	}
	if *dkgStartDelay < 10*time.Second || *dkgStartDelay > 24*time.Hour {
		return errors.New("--dkg-start-delay must be between ten seconds and one day")
	}
	if *dkgPhaseDuration < time.Second || *dkgPhaseDuration > 10*time.Minute {
		return errors.New("--dkg-phase-duration must be between one second and ten minutes")
	}
	enrollments := make([]ceremony.Enrollment, len(paths))
	for index, path := range paths {
		encoded, err := readBoundedRegular(path, false)
		if err != nil {
			return err
		}
		enrollment, err := ceremony.DecodeEnrollment(encoded)
		if err != nil {
			return fmt.Errorf("enrollment %s: %w", path, err)
		}
		enrollments[index] = enrollment
	}
	now := time.Now().UTC().Truncate(time.Second)
	document, err := ceremony.BuildDraft(enrollments, ceremony.DraftConfig{
		NetworkID: *networkID, Epoch: *epoch,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(*validFor),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: uint32(*cellInterval),
			MaxLatenessMillis: uint32(*cellInterval * 4), QueueCapacity: 256,
		},
		DKGStart: now.Add(*dkgStartDelay), DKGPhaseDuration: *dkgPhaseDuration,
		DKGThreshold: uint32(*dkgThreshold),
	})
	if err != nil {
		return err
	}
	encoded, err := ceremony.EncodeDraft(document)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	digest, err := topology.DraftDigest(document)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		NetworkID   string `json:"network_id"`
		Epoch       uint64 `json:"epoch"`
		DraftDigest string `json:"draft_digest"`
		Operators   int    `json:"operators"`
	}{document.NetworkID, document.Epoch, fmt.Sprintf("%x", digest), len(document.Operators)})
}

func finalize(arguments []string) error {
	flags := flag.NewFlagSet("finalize", flag.ContinueOnError)
	draftPath := flags.String("draft", "", "public topology draft path")
	attestationPaths := flags.String("attestations", "", "comma-separated operator attestation paths")
	authorityPath := flags.String("authority-private", "", "private authority-key path")
	outputPath := flags.String("out", "", "new signed topology path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	paths := splitList(*attestationPaths)
	if flags.NArg() != 0 || *draftPath == "" || len(paths) < 3 || *authorityPath == "" || *outputPath == "" {
		return errors.New("--draft, --attestations with three or more paths, --authority-private and --out are required")
	}
	draftBytes, err := readBoundedRegular(*draftPath, false)
	if err != nil {
		return err
	}
	document, err := ceremony.DecodeDraft(draftBytes)
	if err != nil {
		return err
	}
	attestations := make([]ceremony.Attestation, len(paths))
	for index, path := range paths {
		encoded, err := readBoundedRegular(path, false)
		if err != nil {
			return err
		}
		attestation, err := ceremony.DecodeAttestation(encoded)
		if err != nil {
			return fmt.Errorf("attestation %s: %w", path, err)
		}
		attestations[index] = attestation
	}
	attested, err := ceremony.ApplyAttestations(document, attestations)
	if err != nil {
		return err
	}
	authority, err := loadAuthorityPrivate(*authorityPath)
	if err != nil {
		return err
	}
	signed, err := topology.Finalize(attested, authority)
	if err != nil {
		return err
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		NetworkID string `json:"network_id"`
		Epoch     uint64 `json:"epoch"`
		Operators int    `json:"operators"`
	}{signed.Document.NetworkID, signed.Document.Epoch, len(signed.Document.Operators)})
}

func loadAuthorityPrivate(path string) (ed25519.PrivateKey, error) {
	encoded, err := readBoundedRegular(path, true)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("authority private key must be one strict-base64 Ed25519 private key")
	}
	key := ed25519.PrivateKey(append([]byte(nil), decoded...))
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return nil, errors.New("authority private key is not canonical")
	}
	return key, nil
}

func readBoundedRegular(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > ceremony.MaximumArtifact {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key permissions must be 0600 or stricter")
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
	return nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
