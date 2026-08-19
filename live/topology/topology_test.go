package topology

import (
	"bytes"
	"crypto/ecdh"
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
	kexKeys := make(map[string]*ecdh.PrivateKey)
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
		kexKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = privateKey
		kexKeys[id] = kexKey
		document.Operators[index] = Operator{
			ID: id, Index: uint16(index), Endpoint: "127.0.0.1:" + string(rune('1'+index)) + "200",
			PartialEndpoint: "http://127.0.0.1:" + string(rune('1'+index)) + "300",
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	attested := document
	for _, operator := range document.Operators {
		attested, err = Attest(attested, operator.ID, identities[operator.ID])
		if err != nil {
			t.Fatal(err)
		}
	}
	signed, err := Finalize(attested, authorityPrivate)
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

	secretsA := Secrets{
		Version: SecretVersion, OperatorID: "operator-a",
		IdentityPrivate: base64.StdEncoding.EncodeToString(identities["operator-a"]),
		KEXPrivate:      base64.StdEncoding.EncodeToString(kexKeys["operator-a"].Bytes()),
	}
	secretBytesA, err := EncodeSecrets(secretsA)
	if err != nil {
		t.Fatal(err)
	}
	verifiedA, err := VerifySecrets(secretBytesA, verified)
	if err != nil {
		t.Fatal(err)
	}
	secretsB := Secrets{
		Version: SecretVersion, OperatorID: "operator-b",
		IdentityPrivate: base64.StdEncoding.EncodeToString(identities["operator-b"]),
		KEXPrivate:      base64.StdEncoding.EncodeToString(kexKeys["operator-b"].Bytes()),
	}
	secretBytesB, err := EncodeSecrets(secretsB)
	if err != nil {
		t.Fatal(err)
	}
	verifiedB, err := VerifySecrets(secretBytesB, verified)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedA.OutboundKeys[1] != verifiedB.InboundKeys[0] {
		t.Fatal("operators derived different keys for the same directed hop")
	}
	reverseA, err := deriveMACKey(verified, kexKeys["operator-a"], verified.Document.Operators[1], verified.Document.Operators[0])
	if err != nil {
		t.Fatal(err)
	}
	reverseB, err := deriveMACKey(verified, kexKeys["operator-b"], verified.Document.Operators[1], verified.Document.Operators[0])
	if err != nil {
		t.Fatal(err)
	}
	if reverseA != reverseB || reverseA == verifiedA.OutboundKeys[1] {
		t.Fatal("directed hop KDF does not agree or does not separate directions")
	}
	if bytes.Contains(secretBytesA, []byte("outbound_keys")) || bytes.Contains(secretBytesA, []byte("inbound_keys")) {
		t.Fatal("serialized operator secrets contain centrally distributed peer keys")
	}
	wrongKEX := secretsA
	wrongKEX.KEXPrivate = secretsB.KEXPrivate
	wrongKEXBytes, _ := EncodeSecrets(wrongKEX)
	if _, err := VerifySecrets(wrongKEXBytes, verified); err == nil {
		t.Fatal("operator secret with a mismatched key-agreement key was accepted")
	}

	tampered := signed
	tampered.Document.Operators[0].Endpoint = "127.0.0.1:9999"
	tamperedBytes, _ := Encode(tampered)
	if _, err := Verify(tamperedBytes, authorityPublic, time.Now()); err == nil {
		t.Fatal("tampered signed topology was accepted")
	}
	attestationTamper := attested
	attestationTamper.Operators[1].KEXKey = attestationTamper.Operators[2].KEXKey
	if _, err := Finalize(attestationTamper, authorityPrivate); err == nil {
		t.Fatal("authority finalized a topology changed after operator attestation")
	}
	disconnected := document
	disconnected.Operators = append([]Operator(nil), document.Operators...)
	disconnected.Operators[0].PeerPlan = []uint16{1}
	disconnected.Operators[1].PeerPlan = []uint16{0}
	disconnected.Operators[2].PeerPlan = []uint16{0}
	if err := ValidateDraft(disconnected); err == nil {
		t.Fatal("non-strongly-connected topology draft was accepted")
	}
	duplicatePeer := document
	duplicatePeer.Operators = append([]Operator(nil), document.Operators...)
	duplicatePeer.Operators[0].PeerPlan = []uint16{1, 1}
	if err := ValidateDraft(duplicatePeer); err == nil {
		t.Fatal("duplicate peer slot was accepted")
	}
	lowOrderKEX := document
	lowOrderKEX.Operators = append([]Operator(nil), document.Operators...)
	lowOrderKEX.Operators[0].KEXKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := ValidateDraft(lowOrderKEX); err == nil {
		t.Fatal("non-contributory X25519 public key was accepted")
	}
}
