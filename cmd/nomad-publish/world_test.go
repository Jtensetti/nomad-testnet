package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// publisherWorld is a signed topology plus the files the publisher needs, and
// the entry operator's side of the session so a test can open what it emits.
type publisherWorld struct {
	directory     string
	queue         string
	topologyPath  string
	authorityPath string
	secretPath    string
	committeePath string
	publisherPath string
	entryID       string
	entryAddress  *net.UDPAddr
	session       *uplink.Session
}

func newPublisherWorld(t *testing.T) *publisherWorld {
	t.Helper()
	directory := t.TempDir()

	// A free loopback port for the entry operator, released before the
	// topology names it so the operator's own socket can bind it.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	entryAddress := probe.LocalAddr().(*net.UDPAddr)
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]ed25519.PrivateKey{}
	dkgSession := [32]byte{7}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: "publish-test", Epoch: 5,
		NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 500, QueueCapacity: 32,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]),
			StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, 3),
	}
	names := []string{"operator-a", "operator-b", "operator-c"}
	for index := range document.Operators {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		kexKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dkgPublic, _, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		identities[names[index]] = privateKey
		endpoint := entryAddress.String()
		if index != 0 {
			endpoint = "127.0.0.1:" + []string{"0", "4502", "4503"}[index]
		}
		document.Operators[index] = topology.Operator{
			ID: names[index], Index: uint16(index), Endpoint: endpoint,
			PartialEndpoint: "http://127.0.0.1:" + []string{"4311", "4312", "4313"}[index],
			DKGEndpoint:     "http://127.0.0.1:" + []string{"4411", "4412", "4413"}[index],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	signed, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := topology.Verify(encoded, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	world := &publisherWorld{
		directory:     directory,
		queue:         filepath.Join(directory, "queue"),
		topologyPath:  filepath.Join(directory, "topology.json"),
		authorityPath: filepath.Join(directory, "authority.pub"),
		secretPath:    filepath.Join(directory, "session.secret"),
		committeePath: filepath.Join(directory, "committee.key"),
		publisherPath: filepath.Join(directory, "publisher.pub"),
		entryID:       names[0],
		entryAddress:  entryAddress,
	}
	writeFile(t, world.topologyPath, encoded, 0o600)
	writeFile(t, world.authorityPath, []byte(base64.StdEncoding.EncodeToString(authorityPublic)), 0o600)

	committee, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeHex(t, world.committeePath, committee[:])

	sitePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, world.publisherPath,
		[]byte(base64.StdEncoding.EncodeToString(sitePublic)), 0o600)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	writeHex(t, world.secretPath, secret)

	// The entry operator derives the same session from the same secret and
	// the same public context. If the publisher's context differed in any
	// field, Open would fail and the test would say so.
	world.session, err = uplink.NewSession(secret, committee, uplink.Context{
		NetworkID:      verified.Document.NetworkID,
		Epoch:          verified.Document.Epoch,
		TopologyDigest: verified.Digest,
		EntryOperator:  0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return world
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
