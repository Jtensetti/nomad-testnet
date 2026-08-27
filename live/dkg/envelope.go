package dkgnet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Jtensetti/nomad-testnet/live/strictjson"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	EnvelopeVersion     = "nomad-dkg-envelope-v1"
	MaximumEnvelopeSize = 512 << 10
)

type Envelope struct {
	Version        string `json:"version"`
	NetworkID      string `json:"network_id"`
	TopologyDigest string `json:"topology_digest"`
	Epoch          uint64 `json:"epoch"`
	SessionID      string `json:"session_id"`
	Phase          Phase  `json:"phase"`
	SenderID       string `json:"sender_id"`
	SenderIndex    uint32 `json:"sender_index"`
	Payload        string `json:"payload"`
	PayloadDigest  string `json:"payload_digest"`
	Signature      string `json:"signature"`
}

func NewEnvelope(network topology.Verified, sender topology.Operator, identity ed25519.PrivateKey, phase Phase, payload []byte) (Envelope, error) {
	if !validPhase(phase) || len(payload) == 0 || len(payload) > MaximumPacketSize {
		return Envelope{}, errors.New("invalid DKG envelope phase or payload")
	}
	if len(identity) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("operator identity private key is required")
	}
	configured, err := decodeBase64(sender.IdentityKey, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(configured, identity.Public().(ed25519.PublicKey)) {
		return Envelope{}, errors.New("operator identity does not match envelope sender")
	}
	payloadDigest := sha256.Sum256(payload)
	envelope := Envelope{
		Version: EnvelopeVersion, NetworkID: network.Document.NetworkID,
		TopologyDigest: hex.EncodeToString(network.Digest[:]), Epoch: network.Document.Epoch,
		SessionID: network.Document.DKG.SessionID, Phase: phase, SenderID: sender.ID,
		SenderIndex: uint32(sender.Index), Payload: base64.StdEncoding.EncodeToString(payload),
		PayloadDigest: hex.EncodeToString(payloadDigest[:]),
	}
	message, err := envelopeSigningMessage(envelope)
	if err != nil {
		return Envelope{}, err
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	return envelope, nil
}

func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	return json.Marshal(envelope)
}

func DecodeEnvelope(encoded []byte, network topology.Verified) (Envelope, []byte, error) {
	if len(encoded) == 0 || len(encoded) > MaximumEnvelopeSize {
		return Envelope{}, nil, errors.New("DKG envelope is empty or too large")
	}
	if err := strictjson.RejectDuplicateKeys(encoded); err != nil {
		return Envelope{}, nil, fmt.Errorf("DKG envelope is ambiguous: %w", err)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, nil, fmt.Errorf("decode DKG envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Envelope{}, nil, errors.New("trailing DKG envelope data")
	}
	if envelope.Version != EnvelopeVersion || envelope.NetworkID != network.Document.NetworkID || envelope.TopologyDigest != hex.EncodeToString(network.Digest[:]) || envelope.Epoch != network.Document.Epoch || envelope.SessionID != network.Document.DKG.SessionID || !validPhase(envelope.Phase) {
		return Envelope{}, nil, errors.New("DKG envelope context mismatch")
	}
	if int(envelope.SenderIndex) >= len(network.Document.Operators) {
		return Envelope{}, nil, errors.New("DKG envelope sender is outside topology")
	}
	sender := network.Document.Operators[envelope.SenderIndex]
	if sender.ID != envelope.SenderID {
		return Envelope{}, nil, errors.New("DKG envelope sender binding mismatch")
	}
	payload, err := decodeVariable(envelope.Payload, 1, MaximumPacketSize)
	if err != nil {
		return Envelope{}, nil, errors.New("invalid DKG envelope payload")
	}
	payloadDigest := sha256.Sum256(payload)
	if envelope.PayloadDigest != hex.EncodeToString(payloadDigest[:]) {
		return Envelope{}, nil, errors.New("DKG envelope payload digest mismatch")
	}
	signature, err := decodeBase64(envelope.Signature, ed25519.SignatureSize)
	public, publicErr := decodeBase64(sender.IdentityKey, ed25519.PublicKeySize)
	message, messageErr := envelopeSigningMessage(envelope)
	if err != nil || publicErr != nil || messageErr != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return Envelope{}, nil, errors.New("DKG envelope signature verification failed")
	}
	canonical, err := EncodeEnvelope(envelope)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Envelope{}, nil, errors.New("DKG envelope encoding is not canonical")
	}
	if envelope.Phase != ResultPhase {
		packet, err := DecodePacket(envelope.Phase, payload)
		if err != nil || packet.Index() != envelope.SenderIndex {
			return Envelope{}, nil, errors.New("DKG inner packet sender or encoding mismatch")
		}
	}
	return envelope, payload, nil
}

func envelopeSigningMessage(envelope Envelope) ([]byte, error) {
	envelope.Signature = ""
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-dkg-envelope-signature-v1"))
	_, _ = h.Write(canonical)
	return h.Sum(nil), nil
}

func validPhase(phase Phase) bool {
	return phase == DealPhase || phase == ResponsePhase || phase == JustificationPhase || phase == ResultPhase
}
