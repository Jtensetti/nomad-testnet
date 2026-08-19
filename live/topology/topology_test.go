package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestSignedOperatorAttestedTopologyAndSecrets(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]ed25519.PrivateKey)
	document := Document{
		Version: Version, NetworkID: "testnet", Epoch: 3,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Traffic:   TrafficClass{CellSize: CellSize, CellIntervalMillis: 10, MaxLatenessMillis: 40, QueueCapacity: 64},
		Operators: make([]Operator, 3),
	}
	for index := range document.Operators {
		id := "operator-" + string(rune('a'+index))
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = privateKey
		document.Operators[index] = Operator{
			ID: id, Index: uint16(index), Endpoint: "127.0.0.1:" + string(rune('1'+index)) + "200",
			PartialEndpoint: "http://127.0.0.1:" + string(rune('1'+index)) + "300",
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey), PeerPlan: []uint16{uint16((index + 1) % 3)},
		}
	}
	signed, err := Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(encoded, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.StableOperatorIDs()) != 3 || verified.Digest == [32]byte{} {
		t.Fatal("verified topology lost public membership evidence")
	}

	keyBytes := make([]byte, 32)
	keyBytes[0] = 1
	key := base64.StdEncoding.EncodeToString(keyBytes)
	secrets := Secrets{
		Version: SecretVersion, OperatorID: "operator-a",
		IdentityPrivate: base64.StdEncoding.EncodeToString(identities["operator-a"]),
		OutboundKeys:    map[string]string{"operator-b": key},
		InboundKeys:     map[string]string{"operator-c": key},
	}
	secretBytes, err := EncodeSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecrets(secretBytes, verified); err != nil {
		t.Fatal(err)
	}

	tampered := signed
	tampered.Document.Operators[0].Endpoint = "127.0.0.1:9999"
	tamperedBytes, _ := Encode(tampered)
	if _, err := Verify(tamperedBytes, authorityPublic, time.Now()); err == nil {
		t.Fatal("tampered signed topology was accepted")
	}
}
