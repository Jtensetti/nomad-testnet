// Package ceremony implements the offline, multi-administrator topology
// ceremony. Operators generate secrets locally, publish self-signed
// enrollments, inspect one common draft and return independent attestations.
package ceremony

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
	"sort"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	EnrollmentVersion  = "nomad-operator-enrollment-v1"
	AttestationVersion = "nomad-topology-attestation-v1"
	MaximumArtifact    = 1 << 20
)

type Enrollment struct {
	Version         string `json:"version"`
	OperatorID      string `json:"operator_id"`
	Endpoint        string `json:"endpoint"`
	PartialEndpoint string `json:"partial_endpoint"`
	IdentityKey     string `json:"identity_key"`
	KEXKey          string `json:"kex_key"`
	Signature       string `json:"signature"`
}

type Attestation struct {
	Version     string `json:"version"`
	OperatorID  string `json:"operator_id"`
	DraftDigest string `json:"draft_digest"`
	Signature   string `json:"signature"`
}

type DraftConfig struct {
	NetworkID string
	Epoch     uint64
	NotBefore time.Time
	NotAfter  time.Time
	Traffic   topology.TrafficClass
}

func NewEnrollment(keys topology.PrivateKeys, endpoint, partialEndpoint string) (Enrollment, error) {
	if len(keys.Identity) != ed25519.PrivateKeySize || keys.KEX == nil {
		return Enrollment{}, errors.New("complete operator private keys are required")
	}
	enrollment := Enrollment{
		Version: EnrollmentVersion, OperatorID: keys.OperatorID,
		Endpoint: endpoint, PartialEndpoint: partialEndpoint,
		IdentityKey: base64.StdEncoding.EncodeToString(keys.Identity.Public().(ed25519.PublicKey)),
		KEXKey:      base64.StdEncoding.EncodeToString(keys.KEX.PublicKey().Bytes()),
	}
	message, err := enrollmentMessage(enrollment)
	if err != nil {
		return Enrollment{}, err
	}
	enrollment.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(keys.Identity, message))
	return enrollment, nil
}

func EncodeEnrollment(enrollment Enrollment) ([]byte, error) {
	if err := VerifyEnrollment(enrollment); err != nil {
		return nil, err
	}
	return json.MarshalIndent(enrollment, "", "  ")
}

func DecodeEnrollment(encoded []byte) (Enrollment, error) {
	var enrollment Enrollment
	if err := strictJSON(encoded, &enrollment); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment: %w", err)
	}
	if err := VerifyEnrollment(enrollment); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

func VerifyEnrollment(enrollment Enrollment) error {
	if enrollment.Version != EnrollmentVersion {
		return errors.New("unsupported enrollment version")
	}
	identity, err := decodeFixed(enrollment.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return errors.New("invalid enrollment identity key")
	}
	signature, err := decodeFixed(enrollment.Signature, ed25519.SignatureSize)
	if err != nil {
		return errors.New("invalid enrollment signature")
	}
	message, err := enrollmentMessage(enrollment)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(identity), message, signature) {
		return errors.New("enrollment signature verification failed")
	}
	return nil
}

func BuildDraft(enrollments []Enrollment, config DraftConfig) (topology.Document, error) {
	if len(enrollments) < 3 || len(enrollments) > 64 {
		return topology.Document{}, errors.New("a ceremony requires between three and 64 enrollments")
	}
	ordered := append([]Enrollment(nil), enrollments...)
	for _, enrollment := range ordered {
		if err := VerifyEnrollment(enrollment); err != nil {
			return topology.Document{}, fmt.Errorf("operator %s: %w", enrollment.OperatorID, err)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].OperatorID < ordered[j].OperatorID })
	document := topology.Document{
		Version: topology.Version, NetworkID: config.NetworkID, Epoch: config.Epoch,
		NotBefore: config.NotBefore.UTC().Truncate(time.Second).Format(time.RFC3339),
		NotAfter:  config.NotAfter.UTC().Truncate(time.Second).Format(time.RFC3339),
		Traffic:   config.Traffic, Operators: make([]topology.Operator, len(ordered)),
	}
	for index, enrollment := range ordered {
		document.Operators[index] = topology.Operator{
			ID: enrollment.OperatorID, Index: uint16(index), Endpoint: enrollment.Endpoint,
			PartialEndpoint: enrollment.PartialEndpoint, IdentityKey: enrollment.IdentityKey,
			KEXKey: enrollment.KEXKey, PeerPlan: []uint16{uint16((index + 1) % len(ordered))},
		}
	}
	if err := topology.ValidateDraft(document); err != nil {
		return topology.Document{}, err
	}
	return document, nil
}

func EncodeDraft(document topology.Document) ([]byte, error) {
	if err := topology.ValidateDraft(document); err != nil {
		return nil, err
	}
	for _, operator := range document.Operators {
		if operator.Attestation != "" {
			return nil, errors.New("topology draft already contains an attestation")
		}
	}
	return json.MarshalIndent(document, "", "  ")
}

func DecodeDraft(encoded []byte) (topology.Document, error) {
	var document topology.Document
	if err := strictJSON(encoded, &document); err != nil {
		return topology.Document{}, fmt.Errorf("decode topology draft: %w", err)
	}
	if _, err := EncodeDraft(document); err != nil {
		return topology.Document{}, err
	}
	return document, nil
}

func CreateAttestation(document topology.Document, keys topology.PrivateKeys) (Attestation, error) {
	operator, err := operatorByID(document, keys.OperatorID)
	if err != nil {
		return Attestation{}, err
	}
	configuredKEX, err := decodeFixed(operator.KEXKey, 32)
	if err != nil || keys.KEX == nil || !bytes.Equal(configuredKEX, keys.KEX.PublicKey().Bytes()) {
		return Attestation{}, errors.New("operator key-agreement private key does not match topology draft")
	}
	attested, err := topology.Attest(document, keys.OperatorID, keys.Identity)
	if err != nil {
		return Attestation{}, err
	}
	operator, err = operatorByID(attested, keys.OperatorID)
	if err != nil {
		return Attestation{}, err
	}
	digest, err := topology.DraftDigest(document)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{
		Version: AttestationVersion, OperatorID: keys.OperatorID,
		DraftDigest: hex.EncodeToString(digest[:]), Signature: operator.Attestation,
	}, nil
}

func EncodeAttestation(attestation Attestation) ([]byte, error) {
	if err := validateAttestation(attestation); err != nil {
		return nil, err
	}
	return json.MarshalIndent(attestation, "", "  ")
}

func DecodeAttestation(encoded []byte) (Attestation, error) {
	var attestation Attestation
	if err := strictJSON(encoded, &attestation); err != nil {
		return Attestation{}, fmt.Errorf("decode topology attestation: %w", err)
	}
	if err := validateAttestation(attestation); err != nil {
		return Attestation{}, err
	}
	return attestation, nil
}

func ApplyAttestations(document topology.Document, attestations []Attestation) (topology.Document, error) {
	if len(attestations) != len(document.Operators) {
		return topology.Document{}, errors.New("one attestation per operator is required")
	}
	digest, err := topology.DraftDigest(document)
	if err != nil {
		return topology.Document{}, err
	}
	expectedDigest := hex.EncodeToString(digest[:])
	result := document
	result.Operators = append([]topology.Operator(nil), document.Operators...)
	seen := make(map[string]struct{}, len(attestations))
	for _, attestation := range attestations {
		if err := validateAttestation(attestation); err != nil {
			return topology.Document{}, err
		}
		if attestation.DraftDigest != expectedDigest {
			return topology.Document{}, fmt.Errorf("operator %s attested a different topology draft", attestation.OperatorID)
		}
		if _, exists := seen[attestation.OperatorID]; exists {
			return topology.Document{}, fmt.Errorf("duplicate attestation for %s", attestation.OperatorID)
		}
		seen[attestation.OperatorID] = struct{}{}
		found := false
		for index := range result.Operators {
			if result.Operators[index].ID == attestation.OperatorID {
				result.Operators[index].Attestation = attestation.Signature
				found = true
				break
			}
		}
		if !found {
			return topology.Document{}, fmt.Errorf("unknown attesting operator %s", attestation.OperatorID)
		}
	}
	if err := topology.ValidateAttestations(result); err != nil {
		return topology.Document{}, err
	}
	return result, nil
}

func enrollmentMessage(enrollment Enrollment) ([]byte, error) {
	enrollment.Signature = ""
	encoded, err := json.Marshal(enrollment)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("nomad-operator-enrollment-v1"), encoded...))
	return digest[:], nil
}

func validateAttestation(attestation Attestation) error {
	if attestation.Version != AttestationVersion {
		return errors.New("unsupported topology attestation version")
	}
	if len(attestation.OperatorID) == 0 || len(attestation.OperatorID) > 63 {
		return errors.New("invalid attesting operator ID")
	}
	if decoded, err := hex.DecodeString(attestation.DraftDigest); err != nil || len(decoded) != 32 {
		return errors.New("invalid topology draft digest")
	}
	if _, err := decodeFixed(attestation.Signature, ed25519.SignatureSize); err != nil {
		return errors.New("invalid topology attestation signature")
	}
	return nil
}

func operatorByID(document topology.Document, id string) (topology.Operator, error) {
	for _, operator := range document.Operators {
		if operator.ID == id {
			return operator, nil
		}
	}
	return topology.Operator{}, fmt.Errorf("operator %q is not in topology", id)
}

func strictJSON(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > MaximumArtifact {
		return errors.New("ceremony artifact is empty or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing ceremony artifact data")
	}
	return nil
}

func decodeFixed(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}
