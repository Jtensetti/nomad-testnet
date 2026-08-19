package materialize

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestEncryptedFabricCacheToVerifiedBrowserObject(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]ed25519.PrivateKey)
	dkgIdentities := make(map[string]mix.DKGPrivateIdentity)
	dkgSession := [32]byte{1}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: "materializer-test", Epoch: 1,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Traffic:   topology.TrafficClass{CellSize: topology.CellSize, CellIntervalMillis: 10, MaxLatenessMillis: 40, QueueCapacity: 64},
		DKG:       topology.DKGProfile{Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]), StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000},
		Operators: make([]topology.Operator, 3),
	}
	for index := range document.Operators {
		id := []string{"operator-a", "operator-b", "operator-c"}[index]
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		kexKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dkgPublic, dkgPrivate, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = privateKey
		dkgIdentities[id] = dkgPrivate
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: []string{"127.0.0.1:4201", "127.0.0.1:4202", "127.0.0.1:4203"}[index],
			PartialEndpoint: []string{"http://127.0.0.1:4301", "http://127.0.0.1:4302", "http://127.0.0.1:4303"}[index],
			DKGEndpoint:     []string{"http://127.0.0.1:4401", "http://127.0.0.1:4402", "http://127.0.0.1:4403"}[index],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	signedTopology, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	topologyBytes, _ := topology.Encode(signedTopology)
	network, err := topology.Verify(topologyBytes, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"title":"Live Nomad","summary":"fabric to cache","body":"verified locally","tags":["nomad"],"publishedAt":"2026-08-19","publisherName":"Nomad test","mediaType":"text/plain; charset=utf-8"}`)
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := sha256.Sum256(payload)
	envelope := batch.SignedEnvelope{
		Version: batch.EnvelopeVersion, Payload: base64.StdEncoding.EncodeToString(payload),
		ContentHash: hex.EncodeToString(root[:]), PublisherKey: base64.StdEncoding.EncodeToString(publisherPublic),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(publisherPrivate, reconstruct.SigningMessage(root))),
	}
	generated, err := batch.Generate(context.Background(), envelope, network, authorityPrivate, identities, dkgIdentities)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBytes, _ := batch.EncodeDescriptor(generated.Descriptor)
	descriptor, err := batch.VerifyDescriptor(descriptorBytes, authorityPublic, network)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	for ordinal, payload := range generated.Bundle.Cells {
		decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		var ciphertext [hop.CiphertextSize]byte
		copy(ciphertext[:], decoded)
		metadata, _ := hop.WorkMetadata(descriptor.Stream, uint16(ordinal), generated.Descriptor.BatchSize)
		if _, err := cache.Put(metadata, ciphertext); err != nil {
			t.Fatal(err)
		}
	}
	payloads, complete, err := cache.Load(descriptor.Stream)
	if err != nil || !complete {
		t.Fatalf("raw cache complete=%v err=%v", complete, err)
	}
	wire := make([]mix.WireCell, len(payloads))
	for index, payload := range payloads {
		copy(wire[index][:hop.CiphertextSize], payload[:])
	}
	encrypted, err := mix.ParseWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	partialsDir := filepath.Join(t.TempDir(), "partials")
	if err := os.MkdirAll(partialsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < int(descriptor.Committee.Threshold); index++ {
		shareBytes, _ := batch.EncodeShare(generated.Shares[index])
		secret, err := batch.VerifyShare(shareBytes, descriptor, network)
		if err != nil {
			t.Fatal(err)
		}
		partial, err := mix.CreatePartialDecryption(descriptor.Committee, secret, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		partialFile, _ := batch.PartialToFile(descriptor.Descriptor.StreamID, partial)
		partialBytes, _ := batch.EncodePartial(partialFile)
		path := filepath.Join(partialsDir, descriptor.Descriptor.StreamID+"-0"+string(rune('0'+index))+".partial.json")
		if err := os.WriteFile(path, partialBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outputDir := filepath.Join(t.TempDir(), "objects")
	worker := Materializer{Cache: cache, Descriptor: descriptor, PartialsDir: partialsDir, OutputDir: outputDir, Interval: time.Second}
	created, err := worker.ProcessOnce()
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	outputPath := filepath.Join(outputDir, hex.EncodeToString(root[:])+".nomadobject")
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOutput(output, descriptor); err != nil {
		t.Fatal(err)
	}
}
