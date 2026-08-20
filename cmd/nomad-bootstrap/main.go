package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/fetchplan"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	output := flag.String("out", "", "empty output directory")
	envelopePath := flag.String("envelope", "", "signed .nomadobject or catalog JSON")
	catalogIndex := flag.Int("catalog-index", 0, "zero-based envelope index when input is a catalog")
	networkID := flag.String("network-id", "nomad-live-demo", "public network identifier")
	operatorIDsValue := flag.String("operators", "operator-a,operator-b,operator-c", "comma-separated operator IDs")
	endpointsValue := flag.String("endpoints", "operator-a:4200,operator-b:4200,operator-c:4200", "comma-separated signed UDP endpoints")
	partialEndpointsValue := flag.String("partial-endpoints", "http://share-a:4300,http://share-b:4300,http://share-c:4300", "comma-separated public partial-proof endpoints")
	dkgEndpointsValue := flag.String("dkg-endpoints", "https://dkg-a:4400,https://dkg-b:4400,https://dkg-c:4400", "comma-separated inter-operator DKG endpoints")
	cellInterval := flag.Uint("cell-interval-ms", 50, "public fixed cell interval")
	validFor := flag.Duration("valid-for", 24*time.Hour, "topology validity period")
	dkgStartDelay := flag.Duration("dkg-start-delay", 2*time.Minute, "delay before the signed DKG schedule")
	dkgPhaseDuration := flag.Duration("dkg-phase-duration", 30*time.Second, "duration of each signed DKG phase")
	authorityPrivateOutput := flag.String("authority-private-out", "", "optional new 0600 authority private-key path for integration fixtures")
	emitDKGTestTLS := flag.Bool("emit-dkg-test-tls", false, "generate a private test CA and DKG server certificates")
	flag.Parse()
	if *output == "" || *envelopePath == "" {
		return errors.New("--out and --envelope are required")
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
	operatorIDs := splitList(*operatorIDsValue)
	endpoints := splitList(*endpointsValue)
	partialEndpoints := splitList(*partialEndpointsValue)
	dkgEndpoints := splitList(*dkgEndpointsValue)
	if len(operatorIDs) < 3 || len(operatorIDs) != len(endpoints) || len(operatorIDs) != len(partialEndpoints) || len(operatorIDs) != len(dkgEndpoints) {
		return errors.New("operators, UDP endpoints, partial endpoints and DKG endpoints must contain the same three-or-more entries")
	}
	if len(operatorIDs) > 64 {
		return errors.New("at most 64 operators are supported")
	}
	if err := requireEmptyDirectory(*output); err != nil {
		return err
	}
	envelopeBytes, err := os.ReadFile(*envelopePath)
	if err != nil {
		return err
	}
	envelope, err := batch.DecodeEnvelope(envelopeBytes, *catalogIndex)
	if err != nil {
		return err
	}
	if _, _, _, _, err := batch.VerifyEnvelope(envelope); err != nil {
		return err
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identities := make(map[string]ed25519.PrivateKey, len(operatorIDs))
	kexKeys := make(map[string]*ecdh.PrivateKey, len(operatorIDs))
	dkgKeys := make(map[string]mix.DKGPrivateIdentity, len(operatorIDs))
	dkgSession := [32]byte{}
	if _, err := rand.Read(dkgSession[:]); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: *networkID, Epoch: 1,
		NotBefore: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		NotAfter:  time.Now().UTC().Add(*validFor).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: uint32(*cellInterval),
			MaxLatenessMillis: uint32(*cellInterval * 4), QueueCapacity: 256,
		},
		DKG:       topology.DKGProfile{Threshold: batch.DefaultThreshold, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]), StartAt: now.Add(*dkgStartDelay).Format(time.RFC3339), PhaseDurationMillis: uint32(*dkgPhaseDuration / time.Millisecond)},
		Operators: make([]topology.Operator, len(operatorIDs)),
	}
	for index, id := range operatorIDs {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		kexKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		dkgPublic, dkgPrivate, err := mix.GenerateDKGIdentity()
		if err != nil {
			return err
		}
		identities[id] = privateKey
		kexKeys[id] = kexKey
		dkgKeys[id] = dkgPrivate
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: endpoints[index],
			PartialEndpoint: partialEndpoints[index],
			DKGEndpoint:     dkgEndpoints[index],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % len(operatorIDs))},
		}
	}
	signedTopology, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		return err
	}
	topologyBytes, err := topology.Encode(signedTopology)
	if err != nil {
		return err
	}
	verifiedTopology, err := topology.Verify(topologyBytes, authorityPublic, time.Now().UTC())
	if err != nil {
		return err
	}
	secrets, err := buildSecrets(verifiedTopology, identities, kexKeys, dkgKeys)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	generated, err := batch.GenerateInMemoryFixture(ctx, envelope, verifiedTopology, authorityPrivate, identities, dkgKeys)
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
	partialPlan, err := fetchplan.Sign(fetchplan.Plan{
		Version: fetchplan.Version, NetworkID: verifiedTopology.Document.NetworkID,
		TopologyEpoch:  verifiedTopology.Document.Epoch,
		TopologyDigest: fmt.Sprintf("%x", verifiedTopology.Digest),
		StreamID:       generated.Descriptor.StreamID,
	}, authorityPrivate)
	if err != nil {
		return err
	}
	partialPlanBytes, err := fetchplan.Encode(partialPlan)
	if err != nil {
		return err
	}
	publicDirectory := filepath.Join(*output, "public")
	if err := os.MkdirAll(publicDirectory, 0o755); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(publicDirectory, "authority.pub"), []byte(base64.StdEncoding.EncodeToString(authorityPublic)+"\n"), 0o644); err != nil {
		return err
	}
	if *authorityPrivateOutput != "" {
		if err := requireRealParent(*authorityPrivateOutput); err != nil {
			return err
		}
		if err := writeNew(*authorityPrivateOutput, []byte(base64.StdEncoding.EncodeToString(authorityPrivate)+"\n"), 0o600); err != nil {
			return err
		}
	}
	for path, content := range map[string][]byte{
		"topology.json": topologyBytes, "descriptor.json": descriptorBytes,
		"seed.json": seedBytes, "fetch-plan.json": partialPlanBytes,
	} {
		if err := writeNew(filepath.Join(publicDirectory, path), content, 0o644); err != nil {
			return err
		}
	}
	for index, operator := range verifiedTopology.Document.Operators {
		operatorDirectory := filepath.Join(*output, "operators", operator.ID)
		if err := os.MkdirAll(operatorDirectory, 0o700); err != nil {
			return err
		}
		secretBytes, err := topology.EncodeSecrets(secrets[index])
		if err != nil {
			return err
		}
		shareBytes, err := batch.EncodeShare(generated.Shares[index])
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(operatorDirectory, "node-secrets.json"), secretBytes, 0o600); err != nil {
			return err
		}
		if err := writeNew(filepath.Join(operatorDirectory, "threshold-share.json"), shareBytes, 0o600); err != nil {
			return err
		}
	}
	if *emitDKGTestTLS {
		if err := generateDKGTestTLS(publicDirectory, *output, verifiedTopology); err != nil {
			return err
		}
	}
	summary := struct {
		NetworkID string   `json:"network_id"`
		Operators []string `json:"operators"`
		StreamID  string   `json:"stream_id"`
		BatchSize uint16   `json:"batch_size"`
		Threshold uint32   `json:"threshold"`
	}{*networkID, operatorIDs, generated.Descriptor.StreamID, generated.Descriptor.BatchSize, generated.Descriptor.DKGCertificate.Manifest.Committee.Threshold}
	return json.NewEncoder(os.Stdout).Encode(summary)
}

func buildSecrets(network topology.Verified, identities map[string]ed25519.PrivateKey, kexKeys map[string]*ecdh.PrivateKey, dkgKeys map[string]mix.DKGPrivateIdentity) ([]topology.Secrets, error) {
	files := make([]topology.Secrets, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		identity := identities[operator.ID]
		kexKey := kexKeys[operator.ID]
		dkgKey, dkgFound := dkgKeys[operator.ID]
		if len(identity) != ed25519.PrivateKeySize || kexKey == nil || !dkgFound {
			return nil, fmt.Errorf("missing private material for %s", operator.ID)
		}
		files[index] = topology.Secrets{
			Version: topology.SecretVersion, OperatorID: operator.ID,
			IdentityPrivate: base64.StdEncoding.EncodeToString(identity),
			KEXPrivate:      base64.StdEncoding.EncodeToString(kexKey.Bytes()),
			DKGPrivate:      base64.StdEncoding.EncodeToString(dkgKey[:]),
		}
	}
	return files, nil
}

// generateDKGTestTLS creates an ephemeral private PKI solely for the isolated
// Compose acceptance network. Real operators provision independently managed
// certificates from their normal trust infrastructure.
func generateDKGTestTLS(publicDirectory, outputRoot string, network topology.Verified) error {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter, err := time.Parse(time.RFC3339, network.Document.NotAfter)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Nomad isolated DKG test CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := writeNew(filepath.Join(publicDirectory, "dkg-test-ca.pem"), caPEM, 0o644); err != nil {
		return err
	}
	for index, operator := range network.Document.Operators {
		endpoint, err := url.Parse(operator.DKGEndpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
			return fmt.Errorf("test TLS requires an HTTPS DKG endpoint for %s", operator.ID)
		}
		serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(index + 2)), Subject: pkix.Name{CommonName: endpoint.Hostname()},
			NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
			template.IPAddresses = []net.IP{ip}
		} else {
			template.DNSNames = []string{endpoint.Hostname()}
		}
		certificateDER, err := x509.CreateCertificate(rand.Reader, template, caTemplate, serverPublic, caPrivate)
		if err != nil {
			return err
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
		if err != nil {
			return err
		}
		operatorDirectory := filepath.Join(outputRoot, "operators", operator.ID)
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
		if err := writeNew(filepath.Join(operatorDirectory, "dkg-tls.crt"), certificatePEM, 0o644); err != nil {
			return err
		}
		if err := writeNew(filepath.Join(operatorDirectory, "dkg-tls.key"), privatePEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func requireEmptyDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if current == path || entry.IsDir() {
			return nil
		}
		return errors.New("output directory contains files; refuse to overwrite operator secrets")
	})
}

func requireRealParent(path string) error {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output parent must be a real directory")
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
