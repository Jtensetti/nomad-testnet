package epoch

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Jtensetti/nomad-testnet/live/strictjson"
)

const SignatureArtifactVersion = "nomad-epoch-signature-artifact-v1"

// SignatureArtifact is a detached operator signature over one exact epoch
// descriptor digest. Detached artifacts let independently administered
// operators inspect and sign the same unsigned draft without passing a
// mutable, partially signed descriptor between trust domains.
type SignatureArtifact struct {
	Version          string `json:"version"`
	Role             string `json:"role"`
	NetworkID        string `json:"network_id"`
	Epoch            uint64 `json:"epoch"`
	DescriptorDigest string `json:"descriptor_digest"`
	OperatorID       string `json:"operator_id"`
	Index            uint32 `json:"index"`
	Signature        string `json:"signature"`
}

// DecodeDescriptor strictly decodes a bounded descriptor. It does not
// authenticate the descriptor; callers must use ValidateUnsignedDraft or
// Verify with the pinned authority and chain context before trusting it.
func DecodeDescriptor(encoded []byte) (Descriptor, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Descriptor{}, errors.New("epoch descriptor is empty or too large")
	}
	return decodeDescriptor(encoded)
}

// ValidateUnsignedDraft verifies every digest-bearing descriptor input and
// requires the independently distributed draft to contain no signatures.
// This prevents a signer UI or operator from mistaking an attacker-selected
// partial signature set for part of the content it reviewed.
func ValidateUnsignedDraft(descriptor Descriptor, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet) (Verified, error) {
	if len(descriptor.Approvals) != 0 || len(descriptor.Activations) != 0 {
		return Verified{}, errors.New("epoch signing draft must not contain approvals or activations")
	}
	return ValidateDraft(descriptor, authority, previous, revoked)
}

// CreateApprovalArtifact validates an unsigned successor draft against the
// previous epoch and revocation state, records the digest in the durable
// anti-equivocation journal, and only then creates a detached approval.
func (journal *Journal) CreateApprovalArtifact(descriptor Descriptor, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet, operatorID string, identity ed25519.PrivateKey) (SignatureArtifact, error) {
	verified, err := ValidateUnsignedDraft(descriptor, authority, previous, revoked)
	if err != nil {
		return SignatureArtifact{}, err
	}
	if descriptor.Transition == TransitionGenesis || previous == nil {
		return SignatureArtifact{}, errors.New("genesis descriptors do not accept transition approvals")
	}
	operator, err := previous.Topology.OperatorByID(operatorID)
	if err != nil {
		return SignatureArtifact{}, errors.New("approving operator is not in the previous epoch")
	}
	if revokedIdentity(revoked, operator.IdentityKey) {
		return SignatureArtifact{}, fmt.Errorf("approving operator %s is revoked", operator.ID)
	}
	if err := requireMatchingIdentity(operator, identity); err != nil {
		return SignatureArtifact{}, err
	}
	if journal == nil {
		return SignatureArtifact{}, errors.New("a signature journal is required to approve a transition")
	}
	if err := journal.record(verified.NetworkID, verified.Epoch, roleApproval, verified.Digest); err != nil {
		return SignatureArtifact{}, err
	}
	approval, err := signApproval(descriptor, *previous, operator, identity)
	if err != nil {
		return SignatureArtifact{}, err
	}
	return signatureArtifact(verified, roleApproval, approval.OperatorID, approval.Index, approval.Signature), nil
}

// CreateActivationArtifact performs the corresponding checked and journaled
// operation for an incoming-epoch activation signature.
func (journal *Journal) CreateActivationArtifact(descriptor Descriptor, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet, operatorID string, identity ed25519.PrivateKey) (SignatureArtifact, error) {
	verified, err := ValidateUnsignedDraft(descriptor, authority, previous, revoked)
	if err != nil {
		return SignatureArtifact{}, err
	}
	operator, err := verified.Topology.OperatorByID(operatorID)
	if err != nil {
		return SignatureArtifact{}, errors.New("activating operator is not in the incoming epoch")
	}
	if err := requireMatchingIdentity(operator, identity); err != nil {
		return SignatureArtifact{}, err
	}
	if journal == nil {
		return SignatureArtifact{}, errors.New("a signature journal is required to activate an epoch")
	}
	if err := journal.record(verified.NetworkID, verified.Epoch, roleActivation, verified.Digest); err != nil {
		return SignatureArtifact{}, err
	}
	activation, err := signActivation(descriptor, operator, identity)
	if err != nil {
		return SignatureArtifact{}, err
	}
	return signatureArtifact(verified, roleActivation, activation.OperatorID, activation.Index, activation.Signature), nil
}

func signatureArtifact(verified Verified, role, operatorID string, index uint32, signature string) SignatureArtifact {
	return SignatureArtifact{
		Version: SignatureArtifactVersion, Role: role,
		NetworkID: verified.NetworkID, Epoch: verified.Epoch,
		DescriptorDigest: hex.EncodeToString(verified.Digest[:]),
		OperatorID:       operatorID, Index: index, Signature: signature,
	}
}

func EncodeSignatureArtifact(artifact SignatureArtifact) ([]byte, error) {
	if err := validateSignatureArtifact(artifact); err != nil {
		return nil, err
	}
	return json.MarshalIndent(artifact, "", "  ")
}

func DecodeSignatureArtifact(encoded []byte) (SignatureArtifact, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return SignatureArtifact{}, errors.New("epoch signature artifact is empty or too large")
	}
	var artifact SignatureArtifact
	if err := strictDecode(encoded, &artifact, "epoch signature artifact"); err != nil {
		return SignatureArtifact{}, err
	}
	if err := validateSignatureArtifact(artifact); err != nil {
		return SignatureArtifact{}, err
	}
	return artifact, nil
}

func validateSignatureArtifact(artifact SignatureArtifact) error {
	if artifact.Version != SignatureArtifactVersion {
		return errors.New("unsupported epoch signature artifact version")
	}
	if artifact.Role != roleApproval && artifact.Role != roleActivation {
		return errors.New("unsupported epoch signature role")
	}
	if !networkIDPattern.MatchString(artifact.NetworkID) || artifact.Epoch == 0 {
		return errors.New("invalid epoch signature network or epoch")
	}
	if _, err := decodeHex(artifact.DescriptorDigest, 32); err != nil {
		return errors.New("invalid epoch signature descriptor digest")
	}
	if artifact.OperatorID == "" || len(artifact.OperatorID) > 63 {
		return errors.New("invalid epoch signature operator ID")
	}
	if _, err := decodeBase64(artifact.Signature, ed25519.SignatureSize); err != nil {
		return errors.New("invalid epoch signature encoding")
	}
	return nil
}

// VerifySignatureArtifact authenticates one detached artifact without
// requiring the rest of the quorum. Network collectors use it to ignore one
// malicious peer's invalid response while continuing to gather the remaining
// independently signed artifacts; final assembly still enforces the complete
// quorum/all-members rules.
func VerifySignatureArtifact(descriptor Descriptor, artifact SignatureArtifact, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet) error {
	verified, err := ValidateUnsignedDraft(descriptor, authority, previous, revoked)
	if err != nil {
		return err
	}
	if err := validateSignatureArtifact(artifact); err != nil {
		return err
	}
	if artifact.NetworkID != verified.NetworkID || artifact.Epoch != verified.Epoch ||
		artifact.DescriptorDigest != hex.EncodeToString(verified.Digest[:]) {
		return fmt.Errorf("operator %s signed a different epoch descriptor", artifact.OperatorID)
	}
	probe := descriptor
	switch artifact.Role {
	case roleApproval:
		if descriptor.Transition == TransitionGenesis || previous == nil {
			return errors.New("genesis descriptors do not accept transition approvals")
		}
		probe.Approvals = []Approval{{
			OperatorID: artifact.OperatorID, Index: artifact.Index, Signature: artifact.Signature,
		}}
		return verifyApprovalSet(probe, verified.Digest, previous, revoked, false)
	case roleActivation:
		probe.Activations = []Activation{{
			OperatorID: artifact.OperatorID, Index: artifact.Index, Signature: artifact.Signature,
		}}
		return verifyActivationSet(probe, verified.Digest, verified.Topology, false)
	default:
		return errors.New("unsupported epoch signature role")
	}
}

func strictDecode(encoded []byte, destination any, label string) error {
	if err := strictjson.RejectDuplicateKeys(encoded); err != nil {
		return fmt.Errorf("%s is ambiguous: %w", label, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing %s data", label)
	}
	return nil
}

// Assemble combines detached signatures only after checking that every
// artifact names the exact unsigned draft. Verify then enforces the previous
// committee quorum, complete incoming committee activation set, membership,
// revocation and every cryptographic signature.
func Assemble(descriptor Descriptor, artifacts []SignatureArtifact, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet) ([]byte, Verified, error) {
	verifiedDraft, err := ValidateUnsignedDraft(descriptor, authority, previous, revoked)
	if err != nil {
		return nil, Verified{}, err
	}
	expectedDigest := hex.EncodeToString(verifiedDraft.Digest[:])
	assembled := descriptor
	assembled.Approvals = nil
	assembled.Activations = nil
	for _, artifact := range artifacts {
		if err := validateSignatureArtifact(artifact); err != nil {
			return nil, Verified{}, err
		}
		if artifact.NetworkID != verifiedDraft.NetworkID || artifact.Epoch != verifiedDraft.Epoch || artifact.DescriptorDigest != expectedDigest {
			return nil, Verified{}, fmt.Errorf("operator %s signed a different epoch descriptor", artifact.OperatorID)
		}
		switch artifact.Role {
		case roleApproval:
			assembled.Approvals = append(assembled.Approvals, Approval{
				OperatorID: artifact.OperatorID, Index: artifact.Index, Signature: artifact.Signature,
			})
		case roleActivation:
			assembled.Activations = append(assembled.Activations, Activation{
				OperatorID: artifact.OperatorID, Index: artifact.Index, Signature: artifact.Signature,
			})
		}
	}
	sort.Slice(assembled.Approvals, func(i, j int) bool { return assembled.Approvals[i].Index < assembled.Approvals[j].Index })
	sort.Slice(assembled.Activations, func(i, j int) bool { return assembled.Activations[i].Index < assembled.Activations[j].Index })
	encoded, err := Encode(assembled)
	if err != nil {
		return nil, Verified{}, err
	}
	verified, err := Verify(encoded, authority, previous, revoked)
	if err != nil {
		return nil, Verified{}, err
	}
	return encoded, verified, nil
}
