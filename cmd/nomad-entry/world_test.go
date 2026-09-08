package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// entryWorld is a complete epoch on loopback: three enrolled operators, an
// authority-signed topology, a real distributed key generation, and the files
// the entry operator and the publisher each load at startup.
//
// It is built through the ceremony package rather than by assembling a document
// by hand, so the fixture follows the same route an operator would: generate
// secrets locally, publish an enrollment, build a draft from the enrollments,
// attest it, and sign. A fixture that hand-wrote the document could hold a
// topology no ceremony can produce, and then the boundary test would be
// exercising a world that cannot exist.
type entryWorld struct {
	directory string

	topologyPath    string
	authorityPath   string
	secretsPath     string
	certificatePath string
	committeePath   string
	publisherPath   string
	queuePath       string
	batchDirectory  string
	healthPath      string

	entryID      string
	entryAddress *net.UDPAddr
	network      topology.Verified
	// notBefore is what the release schedule is anchored to, so a test can
	// compute the same boundaries the service will.
	notBefore time.Time
}

func newEntryWorld(t *testing.T) *entryWorld {
	t.Helper()
	directory := t.TempDir()

	// A free loopback port, released before the topology names it so the entry
	// operator's own socket can bind it.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	entryAddress := probe.LocalAddr().(*net.UDPAddr)
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	names := []string{"operator-a", "operator-b", "operator-c"}
	keys := make([]topology.PrivateKeys, len(names))
	encodedSecrets := make([][]byte, len(names))
	enrollments := make([]ceremony.Enrollment, len(names))
	for index, name := range names {
		secrets, err := topology.GenerateSecrets(name)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := topology.EncodeSecrets(secrets)
		if err != nil {
			t.Fatal(err)
		}
		encodedSecrets[index] = encoded
		private, err := topology.DecodePrivateKeys(encoded)
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = private

		endpoint := entryAddress.String()
		if index != 0 {
			endpoint = "127.0.0.1:" + []string{"0", "45021", "45031"}[index]
		}
		enrollments[index], err = ceremony.NewEnrollment(private, endpoint,
			"http://127.0.0.1:"+[]string{"45111", "45112", "45113"}[index],
			"http://127.0.0.1:"+[]string{"45211", "45212", "45213"}[index])
		if err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(-time.Hour)
	var session [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		t.Fatal(err)
	}
	draft, err := ceremony.BuildDraft(enrollments, ceremony.DraftConfig{
		NetworkID: "entry-boundary", Epoch: 5,
		NotBefore: notBefore, NotAfter: now.Add(time.Hour),
		// 200 ms rather than the deployed 50 ms, and the number is not what
		// this test is about. A publisher's seal costs about 9.5 ms on a quiet
		// machine (live/capacity), and this test runs alongside every other
		// package under -race on a shared container, where it costs far more.
		// A publisher that cannot seal within its interval fails closed and
		// stops, which is correct behaviour and would leave this test measuring
		// the machine rather than the boundary. The extra headroom buys the
		// boundary the room to be the thing under test.
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 200,
			MaxLatenessMillis: 1000, QueueCapacity: 32,
		},
		DKGStart: now, DKGPhaseDuration: time.Second,
		DKGThreshold: 2, DKGSessionID: session,
	})
	if err != nil {
		t.Fatal(err)
	}
	attestations := make([]ceremony.Attestation, len(names))
	for index := range names {
		attestations[index], err = ceremony.CreateAttestation(draft, keys[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	attested, err := ceremony.ApplyAttestations(draft, attestations)
	if err != nil {
		t.Fatal(err)
	}

	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]ed25519.PrivateKey{}
	for index, name := range names {
		identities[name] = keys[index].Identity
	}
	signed, err := topology.Sign(attested, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	network, err := topology.Verify(encoded, authorityPublic, now)
	if err != nil {
		t.Fatal(err)
	}

	world := &entryWorld{
		directory:       directory,
		topologyPath:    filepath.Join(directory, "topology.json"),
		authorityPath:   filepath.Join(directory, "authority.pub"),
		secretsPath:     filepath.Join(directory, "operator-a-secrets.json"),
		certificatePath: filepath.Join(directory, "dkg-certificate.json"),
		committeePath:   filepath.Join(directory, "committee.key"),
		publisherPath:   filepath.Join(directory, "publisher.pub"),
		queuePath:       filepath.Join(directory, "queue"),
		batchDirectory:  filepath.Join(directory, "batches"),
		healthPath:      filepath.Join(directory, "entry-health.json"),
		entryID:         names[0],
		entryAddress:    entryAddress,
		network:         network,
		notBefore:       notBefore,
	}
	writeWorldFile(t, world.topologyPath, encoded, 0o600)
	writeWorldFile(t, world.authorityPath,
		[]byte(base64.StdEncoding.EncodeToString(authorityPublic)), 0o600)
	// 0600: the loader refuses a secrets file readable by group or other, and
	// that refusal is part of what this test exercises.
	writeWorldFile(t, world.secretsPath, encodedSecrets[0], 0o600)

	certificate, committeeKey := runWorldDKG(t, network, keys)
	writeWorldFile(t, world.certificatePath, certificate, 0o600)
	writeWorldFile(t, world.committeePath,
		[]byte(hex.EncodeToString(committeeKey[:])+"\n"), 0o600)

	sitePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeWorldFile(t, world.publisherPath,
		[]byte(base64.StdEncoding.EncodeToString(sitePublic)), 0o600)
	return world
}

// runWorldDKG performs the authenticated distributed key generation for this
// topology and assembles the all-operator certificate.
//
// The committee key the publisher encrypts to therefore comes from the same
// ceremony the entry operator verifies, rather than from a bare key file both
// sides were handed. If they disagreed, every deposit would fail to open, which
// is a failure mode worth being unable to construct.
func runWorldDKG(t *testing.T, network topology.Verified,
	keys []topology.PrivateKeys) ([]byte, mix.PublicKey) {
	t.Helper()
	committeeID, err := committee.IDForTopology(network)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(network.Document.DKG.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	privates := make([]mix.DKGPrivateIdentity, len(keys))
	for index := range keys {
		privates[index] = keys[index].DKG
	}
	public, _, transcript, err := mix.RunAuthenticatedDKGWithIdentities(
		committeeID, network.Document.Epoch, privates,
		network.Document.DKG.Threshold, nonce)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := committee.NewManifest(network, public, transcript)
	if err != nil {
		t.Fatal(err)
	}
	attestations := make([]committee.Attestation, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		attestations[index], err = committee.CreateAttestation(manifest, operator,
			keys[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := committee.Assemble(manifest, attestations, network)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := committee.Encode(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, public.PublicKey
}

func writeWorldFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
