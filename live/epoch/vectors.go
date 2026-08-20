package epoch

import (
	"crypto/ed25519"
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
// cross-implementation vectors. The approver's identity key is part of the
// message, so a vector must name the approver it applies to.
func ApprovalMessageHex(previousDigest, digest [32]byte, approver ed25519.PublicKey) string {
	return hex.EncodeToString(approvalMessage(previousDigest, digest, approver))
}

// Vector is one published cross-implementation test vector. Besides the
// digest preimages it pins real signatures produced by a fixed, published
// test key, so an independent implementation can validate its whole signing
// path and not merely its encoder.
type Vector struct {
	Name                string `json:"name"`
	Version             string `json:"version"`
	PreviousDigestHex   string `json:"previous_epoch_digest"`
	Transition          string `json:"transition"`
	ActivateAt          string `json:"activate_at"`
	RetireAt            string `json:"retire_at"`
	TopologyBase64      string `json:"topology_base64"`
	CertificateBase64   string `json:"dkg_certificate_base64"`
	UplinkBase64        string `json:"uplink_profile_base64"`
	CanonicalHex        string `json:"canonical_preimage_hex"`
	DigestHex           string `json:"descriptor_digest_hex"`
	SignerSeedHex       string `json:"signer_ed25519_seed_hex"`
	SignerPublicHex     string `json:"signer_ed25519_public_hex"`
	ActivationMessage   string `json:"activation_message_hex"`
	ActivationSignature string `json:"activation_signature_hex"`
	ApprovalMessage     string `json:"approval_message_hex"`
	ApprovalSignature   string `json:"approval_signature_hex"`
}

// VectorSignerSeed is the published, deliberately non-secret Ed25519 seed
// used to produce signature vectors. It exists only so that independent
// implementations can reproduce exact signature bytes, and it must never
// appear in any deployment.
var VectorSignerSeed = [32]byte{
	0x6e, 0x6f, 0x6d, 0x61, 0x64, 0x2d, 0x65, 0x70,
	0x6f, 0x63, 0x68, 0x2d, 0x76, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x65,
	0x72, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x31,
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

	signer := ed25519.NewKeyFromSeed(VectorSignerSeed[:])
	public := signer.Public().(ed25519.PublicKey)
	activationMsg := activationMessage(digest)
	approvalMsg := approvalMessage(previousDigest, digest, public)
	return Vector{
		Name: name, Version: descriptor.Version,
		PreviousDigestHex: descriptor.PreviousEpochDigest, Transition: descriptor.Transition,
		ActivateAt: descriptor.ActivateAt, RetireAt: descriptor.RetireAt,
		TopologyBase64: descriptor.Topology, CertificateBase64: descriptor.DKGCertificate,
		UplinkBase64: descriptor.UplinkProfile,
		CanonicalHex: hex.EncodeToString(canonical), DigestHex: hex.EncodeToString(digest[:]),
		SignerSeedHex:       hex.EncodeToString(VectorSignerSeed[:]),
		SignerPublicHex:     hex.EncodeToString(public),
		ActivationMessage:   hex.EncodeToString(activationMsg),
		ActivationSignature: hex.EncodeToString(ed25519.Sign(signer, activationMsg)),
		ApprovalMessage:     hex.EncodeToString(approvalMsg),
		ApprovalSignature:   hex.EncodeToString(ed25519.Sign(signer, approvalMsg)),
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
	if rebuilt.ActivationSignature != vector.ActivationSignature {
		return fmt.Errorf("vector %s: activation signature mismatch", vector.Name)
	}
	if rebuilt.ApprovalSignature != vector.ApprovalSignature {
		return fmt.Errorf("vector %s: approval signature mismatch", vector.Name)
	}
	// The published signatures must verify under the published key, so a
	// reader can check them without trusting this implementation.
	public, err := hex.DecodeString(vector.SignerPublicHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("vector %s: invalid signer public key", vector.Name)
	}
	for label, pair := range map[string][2]string{
		"activation": {vector.ActivationMessage, vector.ActivationSignature},
		"approval":   {vector.ApprovalMessage, vector.ApprovalSignature},
	} {
		message, messageErr := hex.DecodeString(pair[0])
		signature, signatureErr := hex.DecodeString(pair[1])
		if messageErr != nil || signatureErr != nil {
			return fmt.Errorf("vector %s: invalid %s encoding", vector.Name, label)
		}
		if !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			return fmt.Errorf("vector %s: %s signature does not verify", vector.Name, label)
		}
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(vector.TopologyBase64); err != nil {
		return fmt.Errorf("vector %s: invalid embedded topology encoding", vector.Name)
	}
	return nil
}
