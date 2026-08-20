// nomad-fixture-publisher is a non-anonymous integration publisher. It binds
// a test object to a real, all-operator-certified distributed DKG committee,
// then runs the current verified shuffle harness. It is deliberately named as
// a fixture tool: it is not the publication airlock and must not be presented
// as an anonymous publisher.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/fetchplan"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-fixture-publisher:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "authority-signed topology path")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	authorityPrivatePath := flag.String("authority-private", "", "0600 descriptor authority private key")
	certificatePath := flag.String("dkg-certificate", "", "all-operator-certified distributed DKG certificate")
	envelopePath := flag.String("envelope", "", "signed .nomadobject or catalog JSON")
	catalogIndex := flag.Int("catalog-index", 0, "zero-based envelope index when input is a catalog")
	mixerSecretsValue := flag.String("mixer-secrets", "", "comma-separated operator secret paths; integration fixtures only")
	output := flag.String("out", "", "empty output directory")
	flag.Parse()
	secretPaths := splitList(*mixerSecretsValue)
	if flag.NArg() != 0 || *topologyPath == "" || *authorityPath == "" || *authorityPrivatePath == "" || *certificatePath == "" || *envelopePath == "" || *output == "" || len(secretPaths) < 3 {
		return errors.New("--topology, --authority-key, --authority-private, --dkg-certificate, --envelope, --mixer-secrets and --out are required")
	}
	if err := requireEmptyDirectory(*output); err != nil {
		return err
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	authorityPrivate, err := topology.LoadAuthorityPrivateKey(*authorityPrivatePath)
	if err != nil {
		return err
	}
	if !bytes.Equal(authorityPrivate.Public().(ed25519.PublicKey), authority) {
		return errors.New("authority private key does not match pinned public key")
	}
	topologyBytes, err := readBounded(*topologyPath, committee.MaximumFileBytes)
	if err != nil {
		return err
	}
	network, err := topology.Verify(topologyBytes, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	if len(secretPaths) != len(network.Document.Operators) {
		return errors.New("fixture publisher requires exactly one mixer secret per configured operator")
	}
	identities := make(map[string]ed25519.PrivateKey, len(secretPaths))
	for _, path := range secretPaths {
		secrets, err := topology.LoadSecrets(path, network)
		if err != nil {
			return fmt.Errorf("mixer secret %s: %w", path, err)
		}
		if _, exists := identities[secrets.Operator.ID]; exists {
			return fmt.Errorf("duplicate mixer secret for %s", secrets.Operator.ID)
		}
		identities[secrets.Operator.ID] = secrets.Identity
	}
	certificateBytes, err := readBounded(*certificatePath, committee.MaximumFileBytes)
	if err != nil {
		return err
	}
	certificate, certified, err := committee.Decode(certificateBytes, network)
	if err != nil {
		return err
	}

	epochDescriptor, err := buildGenesisEpochDescriptor(network, topologyBytes, certificateBytes, identities)
	if err != nil {
		return err
	}
	epochDescriptorBytes, err := epoch.Encode(epochDescriptor)
	if err != nil {
		return err
	}
	if _, err := epoch.Verify(epochDescriptorBytes, authority, nil, nil); err != nil {
		return fmt.Errorf("self-verify fixture epoch descriptor: %w", err)
	}

	envelopeBytes, err := readBounded(*envelopePath, batch.MaximumFileBytes)
	if err != nil {
		return err
	}
	envelope, err := batch.DecodeEnvelope(envelopeBytes, *catalogIndex)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	generated, err := batch.GenerateCertified(ctx, envelope, network, authorityPrivate, identities, certificate)
	if err != nil {
		return err
	}
	descriptorBytes, err := batch.EncodeDescriptor(generated.Descriptor)
	if err != nil {
		return err
	}
	seedBytes, err := bundle.Encode(generated.Bundle)
	if err != nil {
		return err
	}
	plan, err := fetchplan.Sign(fetchplan.Plan{
		Version: fetchplan.Version, NetworkID: network.Document.NetworkID,
		TopologyEpoch: network.Document.Epoch, TopologyDigest: fmt.Sprintf("%x", network.Digest),
		StreamID: generated.Descriptor.StreamID,
	}, authorityPrivate)
	if err != nil {
		return err
	}
	planBytes, err := fetchplan.Encode(plan)
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		"descriptor.json":       descriptorBytes,
		"epoch-descriptor.json": epochDescriptorBytes,
		"seed.json":             seedBytes,
		"fetch-plan.json":       planBytes,
	} {
		if err := writeNew(filepath.Join(*output, name), content, 0o644); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		NetworkID            string `json:"network_id"`
		StreamID             string `json:"stream_id"`
		DKGCertificateDigest string `json:"dkg_certificate_digest"`
	}{network.Document.NetworkID, generated.Descriptor.StreamID, fmt.Sprintf("%x", certified.Digest)})
}

func buildGenesisEpochDescriptor(network topology.Verified, topologyBytes, certificateBytes []byte, identities map[string]ed25519.PrivateKey) (epoch.Descriptor, error) {
	dkgStart, err := time.Parse(time.RFC3339, network.Document.DKG.StartAt)
	if err != nil {
		return epoch.Descriptor{}, err
	}
	phase := time.Duration(network.Document.DKG.PhaseDurationMillis) * time.Millisecond
	activateAt := dkgStart.Add(4 * phase).UTC().Format(time.RFC3339)
	retireAt := network.Document.NotAfter
	descriptor, err := epoch.New(nil, epoch.TransitionGenesis, activateAt, retireAt, topologyBytes, certificateBytes)
	if err != nil {
		return epoch.Descriptor{}, err
	}
	for _, operator := range network.Document.Operators {
		identity, exists := identities[operator.ID]
		if !exists {
			return epoch.Descriptor{}, fmt.Errorf("missing fixture identity for epoch activation by %s", operator.ID)
		}
		activation, err := epoch.Activate(descriptor, operator, identity)
		if err != nil {
			return epoch.Descriptor{}, err
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	return descriptor, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func readBounded(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}

func requireEmptyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output must be a real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("output directory must be empty")
	}
	return nil
}

func writeNew(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
