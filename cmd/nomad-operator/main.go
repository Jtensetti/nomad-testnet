package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/ceremony"
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
		return errors.New("required subcommand: init, attest or verify")
	}
	switch arguments[0] {
	case "init":
		return initialize(arguments[1:])
	case "attest":
		return attest(arguments[1:])
	case "verify":
		return verify(arguments[1:])
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
