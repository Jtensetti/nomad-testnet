package epoch

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// CanonicalBytes returns the exact canonical binary preimage that the
// descriptor digest is computed over, excluding the digest domain prefix.
// Independent implementations reproduce this byte string to confirm their
// encoder before checking digests.
func CanonicalBytes(descriptor Descriptor) ([]byte, error) {
	if descriptor.Version != Version {
		return nil, errors.New("unsupported epoch descriptor version")
	}
	previousDigest, err := decodeHex(descriptor.PreviousEpochDigest, 32)
	if err != nil {
		return nil, errors.New("invalid previous epoch digest")
	}
	switch descriptor.Transition {
	case TransitionGenesis, TransitionScheduled, TransitionEmergency:
	default:
		return nil, errors.New("unsupported epoch transition kind")
	}
	if err := validateCanonicalTime(descriptor.ActivateAt); err != nil {
		return nil, fmt.Errorf("activate_at: %w", err)
	}
	if err := validateCanonicalTime(descriptor.RetireAt); err != nil {
		return nil, fmt.Errorf("retire_at: %w", err)
	}
	topologyBytes, err := decodeBounded(descriptor.Topology)
	if err != nil {
		return nil, errors.New("invalid embedded topology encoding")
	}
	certificateBytes, err := decodeBounded(descriptor.DKGCertificate)
	if err != nil {
		return nil, errors.New("invalid embedded DKG certificate encoding")
	}
	uplinkBytes, err := decodeBounded(descriptor.UplinkProfile)
	if err != nil {
		return nil, errors.New("invalid uplink profile encoding")
	}
	canonical := make([]byte, 0, 256+len(topologyBytes)+len(certificateBytes)+len(uplinkBytes))
	canonical = appendString(canonical, descriptor.Version)
	canonical = append(canonical, previousDigest...)
	canonical = appendString(canonical, descriptor.Transition)
	canonical = appendString(canonical, descriptor.ActivateAt)
	canonical = appendString(canonical, descriptor.RetireAt)
	canonical = appendBytes(canonical, topologyBytes)
	canonical = appendBytes(canonical, certificateBytes)
	canonical = appendBytes(canonical, uplinkBytes)
	return canonical, nil
}

// ActivationMessageHex exposes the exact activation signing message for
// cross-implementation vectors.
func ActivationMessageHex(digest [32]byte) string {
	return hex.EncodeToString(activationMessage(digest))
}

// ApprovalMessageHex exposes the exact approval signing message for
// cross-implementation vectors.
func ApprovalMessageHex(previousDigest, digest [32]byte) string {
	return hex.EncodeToString(approvalMessage(previousDigest, digest))
}

// Vector is one published cross-implementation test vector.
type Vector struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	PreviousDigestHex string `json:"previous_epoch_digest"`
	Transition        string `json:"transition"`
	ActivateAt        string `json:"activate_at"`
	RetireAt          string `json:"retire_at"`
	TopologyBase64    string `json:"topology_base64"`
	CertificateBase64 string `json:"dkg_certificate_base64"`
	UplinkBase64      string `json:"uplink_profile_base64"`
	CanonicalHex      string `json:"canonical_preimage_hex"`
	DigestHex         string `json:"descriptor_digest_hex"`
	ActivationMessage string `json:"activation_message_hex"`
	ApprovalMessage   string `json:"approval_message_hex"`
}

// BuildVector derives a complete published vector from descriptor fields.
func BuildVector(name string, descriptor Descriptor) (Vector, error) {
	canonical, err := CanonicalBytes(descriptor)
	if err != nil {
		return Vector{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Vector{}, err
	}
	previous, err := decodeHex(descriptor.PreviousEpochDigest, 32)
	if err != nil {
		return Vector{}, err
	}
	var previousDigest [32]byte
	copy(previousDigest[:], previous)
	return Vector{
		Name: name, Version: descriptor.Version,
		PreviousDigestHex: descriptor.PreviousEpochDigest, Transition: descriptor.Transition,
		ActivateAt: descriptor.ActivateAt, RetireAt: descriptor.RetireAt,
		TopologyBase64: descriptor.Topology, CertificateBase64: descriptor.DKGCertificate,
		UplinkBase64: descriptor.UplinkProfile,
		CanonicalHex: hex.EncodeToString(canonical), DigestHex: hex.EncodeToString(digest[:]),
		ActivationMessage: ActivationMessageHex(digest),
		ApprovalMessage:   ApprovalMessageHex(previousDigest, digest),
	}, nil
}

// CheckVector recomputes a vector from its inputs and reports any mismatch.
func CheckVector(vector Vector) error {
	descriptor := Descriptor{
		Version: vector.Version, PreviousEpochDigest: vector.PreviousDigestHex,
		Transition: vector.Transition, ActivateAt: vector.ActivateAt, RetireAt: vector.RetireAt,
		Topology: vector.TopologyBase64, DKGCertificate: vector.CertificateBase64,
		UplinkProfile: vector.UplinkBase64,
	}
	rebuilt, err := BuildVector(vector.Name, descriptor)
	if err != nil {
		return err
	}
	if rebuilt.CanonicalHex != vector.CanonicalHex {
		return fmt.Errorf("vector %s: canonical preimage mismatch", vector.Name)
	}
	if rebuilt.DigestHex != vector.DigestHex {
		return fmt.Errorf("vector %s: descriptor digest mismatch", vector.Name)
	}
	if rebuilt.ActivationMessage != vector.ActivationMessage {
		return fmt.Errorf("vector %s: activation message mismatch", vector.Name)
	}
	if rebuilt.ApprovalMessage != vector.ApprovalMessage {
		return fmt.Errorf("vector %s: approval message mismatch", vector.Name)
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(vector.TopologyBase64); err != nil {
		return fmt.Errorf("vector %s: invalid embedded topology encoding", vector.Name)
	}
	return nil
}
