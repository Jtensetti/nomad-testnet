package dkgnet

import (
	"encoding/base64"
	"testing"
)

func TestEnvelopeRejectsTamperWrongContextAndNonCanonicalEncoding(t *testing.T) {
	network, secrets := singleTestContext(t)
	payload := []byte(`{"manifest":"one"}`)
	envelope, err := NewEnvelope(network, secrets.Operator, secrets.Identity, ResultPhase, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedPayload, err := DecodeEnvelope(encoded, network)
	if err != nil || decoded.SenderID != secrets.Operator.ID || string(decodedPayload) != string(payload) {
		t.Fatalf("valid envelope rejected: sender=%s err=%v", decoded.SenderID, err)
	}

	tampered := envelope
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{"manifest":"two"}`))
	tamperedBytes, _ := EncodeEnvelope(tampered)
	if _, _, err := DecodeEnvelope(tamperedBytes, network); err == nil {
		t.Fatal("payload tampering was accepted")
	}

	wrongSender := envelope
	wrongSender.SenderIndex = 1
	wrongSenderBytes, _ := EncodeEnvelope(wrongSender)
	if _, _, err := DecodeEnvelope(wrongSenderBytes, network); err == nil {
		t.Fatal("sender rebinding was accepted")
	}

	wrongNetwork := network
	wrongNetwork.Digest[0] ^= 0xff
	if _, _, err := DecodeEnvelope(encoded, wrongNetwork); err == nil {
		t.Fatal("cross-topology envelope replay was accepted")
	}

	nonCanonical := append(append([]byte(nil), encoded...), '\n')
	if _, _, err := DecodeEnvelope(nonCanonical, network); err == nil {
		t.Fatal("non-canonical envelope encoding was accepted")
	}
}
