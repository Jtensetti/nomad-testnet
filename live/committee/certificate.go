// Package committee owns networkless, operator-certified DKG artifacts.
// It deliberately contains no transport, socket, or reader-query code.
package committee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	ManifestVersion    = "nomad-dkg-manifest-v1"
	CertificateVersion = "nomad-dkg-certificate-v1"
	MaximumFileBytes   = 1 << 20
)

type MemberFile struct {
	Index uint32 `json:"index"`
	Share string `json:"share"`
}

type CommitteeFile struct {
	ID        string       `json:"id"`
	Epoch     uint64       `json:"epoch"`
	Threshold uint32       `json:"threshold"`
	PublicKey string       `json:"public_key"`
	Members   []MemberFile `json:"members"`
}

type TranscriptFile struct {
	SessionID  string   `json:"session_id"`
	Digest     string   `json:"digest"`
	Identities []string `json:"identities"`
	Qualified  []uint32 `json:"qualified"`
}

type Manifest struct {
	Version        string         `json:"version"`
	NetworkID      string         `json:"network_id"`
	TopologyDigest string         `json:"topology_digest"`
	Committee      CommitteeFile  `json:"committee"`
	Transcript     TranscriptFile `json:"transcript"`
}

type Attestation struct {
	OperatorID string `json:"operator_id"`
	Index      uint32 `json:"index"`
	Signature  string `json:"signature"`
}

type Certificate struct {
	Version      string        `json:"version"`
	Manifest     Manifest      `json:"manifest"`
	Attestations []Attestation `json:"attestations"`
}

type Verified struct {
	Manifest   Manifest
	Digest     [32]byte
	Committee  mix.ThresholdCommittee
	Transcript mix.DKGTranscript
}

func IDForTopology(network topology.Verified) (mix.CommitteeID, error) {
	session, err := decodeBase64(network.Document.DKG.SessionID, 32)
	if err != nil {
		return mix.CommitteeID{}, errors.New("invalid topology DKG session")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-epoch-committee-v2"))
	_, _ = h.Write(network.Digest[:])
	_, _ = h.Write(session)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], network.Document.Epoch)
	_, _ = h.Write(integer[:])
	binary.BigEndian.PutUint32(integer[:4], network.Document.DKG.Threshold)
	_, _ = h.Write(integer[:4])
	var id mix.CommitteeID
	copy(id[:], h.Sum(nil))
	return id, nil
}

func NewManifest(network topology.Verified, value mix.ThresholdCommittee, transcript mix.DKGTranscript) (Manifest, error) {
	manifest := Manifest{
		Version: ManifestVersion, NetworkID: network.Document.NetworkID,
		TopologyDigest: hex.EncodeToString(network.Digest[:]),
		Committee: CommitteeFile{
			ID: hex.EncodeToString(value.ID[:]), Epoch: value.Epoch, Threshold: value.Threshold,
			PublicKey: base64.StdEncoding.EncodeToString(value.PublicKey[:]), Members: make([]MemberFile, len(value.Members)),
		},
		Transcript: TranscriptFile{
			SessionID: base64.StdEncoding.EncodeToString(transcript.SessionID[:]),
			Digest:    hex.EncodeToString(transcript.Digest[:]), Identities: make([]string, len(transcript.Identities)),
			Qualified: append([]uint32(nil), transcript.Qualified...),
		},
	}
	for index, member := range value.Members {
		manifest.Committee.Members[index] = MemberFile{Index: member.Index, Share: base64.StdEncoding.EncodeToString(member.Share[:])}
	}
	for index, identity := range transcript.Identities {
		manifest.Transcript.Identities[index] = base64.StdEncoding.EncodeToString(identity[:])
	}
	if _, _, err := verifyManifest(manifest, network); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ManifestDigest(manifest Manifest) ([32]byte, error) {
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-dkg-manifest-digest-v1"))
	_, _ = h.Write(canonical)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func CreateAttestation(manifest Manifest, operator topology.Operator, identity ed25519.PrivateKey) (Attestation, error) {
	if len(identity) != ed25519.PrivateKeySize || !bytes.Equal(identity.Public().(ed25519.PublicKey), mustDecode(operator.IdentityKey, ed25519.PublicKeySize)) {
		return Attestation{}, errors.New("operator identity does not match DKG attestation signer")
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return Attestation{}, err
	}
	signature := ed25519.Sign(identity, attestationMessage(digest))
	return Attestation{OperatorID: operator.ID, Index: uint32(operator.Index), Signature: base64.StdEncoding.EncodeToString(signature)}, nil
}

func Assemble(manifest Manifest, attestations []Attestation, network topology.Verified) (Certificate, error) {
	certificate := Certificate{Version: CertificateVersion, Manifest: manifest, Attestations: append([]Attestation(nil), attestations...)}
	if _, err := Verify(certificate, network); err != nil {
		return Certificate{}, err
	}
	return certificate, nil
}

func Verify(certificate Certificate, network topology.Verified) (Verified, error) {
	if certificate.Version != CertificateVersion {
		return Verified{}, errors.New("unsupported DKG certificate version")
	}
	value, transcript, err := verifyManifest(certificate.Manifest, network)
	if err != nil {
		return Verified{}, err
	}
	if len(certificate.Attestations) != len(network.Document.Operators) {
		return Verified{}, errors.New("DKG activation requires one attestation from every configured operator")
	}
	digest, err := ManifestDigest(certificate.Manifest)
	if err != nil {
		return Verified{}, err
	}
	attestations := append([]Attestation(nil), certificate.Attestations...)
	sort.Slice(attestations, func(i, j int) bool { return attestations[i].Index < attestations[j].Index })
	for index, attestation := range attestations {
		operator := network.Document.Operators[index]
		if attestation.Index != uint32(index) || attestation.OperatorID != operator.ID {
			return Verified{}, errors.New("DKG activation attestations do not exactly match topology membership")
		}
		signature, err := decodeBase64(attestation.Signature, ed25519.SignatureSize)
		public, publicErr := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
		if err != nil || publicErr != nil || !ed25519.Verify(ed25519.PublicKey(public), attestationMessage(digest), signature) {
			return Verified{}, fmt.Errorf("invalid DKG activation attestation for %s", operator.ID)
		}
	}
	return Verified{Manifest: certificate.Manifest, Digest: digest, Committee: value, Transcript: transcript}, nil
}

func verifyManifest(manifest Manifest, network topology.Verified) (mix.ThresholdCommittee, mix.DKGTranscript, error) {
	if manifest.Version != ManifestVersion || manifest.NetworkID != network.Document.NetworkID || manifest.TopologyDigest != hex.EncodeToString(network.Digest[:]) {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("DKG manifest belongs to a different topology")
	}
	expectedID, err := IDForTopology(network)
	if err != nil {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, err
	}
	idBytes, err := decodeHex(manifest.Committee.ID, len(mix.CommitteeID{}))
	if err != nil || !bytes.Equal(idBytes, expectedID[:]) || manifest.Committee.Epoch != network.Document.Epoch || manifest.Committee.Threshold != network.Document.DKG.Threshold {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("DKG committee context does not match topology")
	}
	publicBytes, err := decodeBase64(manifest.Committee.PublicKey, len(mix.PublicKey{}))
	if err != nil || len(manifest.Committee.Members) != len(network.Document.Operators) {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("invalid DKG committee public material")
	}
	value := mix.ThresholdCommittee{ID: expectedID, Epoch: manifest.Committee.Epoch, Threshold: manifest.Committee.Threshold, Members: make([]mix.PublicMember, len(manifest.Committee.Members))}
	copy(value.PublicKey[:], publicBytes)
	for index, member := range manifest.Committee.Members {
		share, err := decodeBase64(member.Share, len(mix.SharePublicKey{}))
		if err != nil || member.Index != uint32(index) {
			return mix.ThresholdCommittee{}, mix.DKGTranscript{}, fmt.Errorf("invalid DKG public share %d", index)
		}
		value.Members[index].Index = uint32(index)
		copy(value.Members[index].Share[:], share)
	}
	if err := mix.ValidateThresholdCommittee(value); err != nil {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, err
	}

	session, err := decodeBase64(manifest.Transcript.SessionID, 32)
	digest, digestErr := decodeHex(manifest.Transcript.Digest, 32)
	if err != nil || digestErr != nil || manifest.Transcript.SessionID != network.Document.DKG.SessionID || bytes.Equal(digest, make([]byte, 32)) {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("invalid DKG transcript context")
	}
	if len(manifest.Transcript.Identities) != len(network.Document.Operators) || len(manifest.Transcript.Qualified) != len(network.Document.Operators) {
		return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("DKG transcript does not contain the complete configured committee")
	}
	transcript := mix.DKGTranscript{Identities: make([]mix.SharePublicKey, len(manifest.Transcript.Identities)), Qualified: append([]uint32(nil), manifest.Transcript.Qualified...)}
	copy(transcript.SessionID[:], session)
	copy(transcript.Digest[:], digest)
	for index, encoded := range manifest.Transcript.Identities {
		identity, err := decodeBase64(encoded, len(mix.DKGPublicIdentity{}))
		if err != nil || encoded != network.Document.Operators[index].DKGIdentityKey || transcript.Qualified[index] != uint32(index) {
			return mix.ThresholdCommittee{}, mix.DKGTranscript{}, errors.New("DKG transcript membership does not exactly match topology")
		}
		copy(transcript.Identities[index][:], identity)
	}
	return value, transcript, nil
}

func Encode(certificate Certificate) ([]byte, error) {
	return json.MarshalIndent(certificate, "", "  ")
}

func Decode(encoded []byte, network topology.Verified) (Certificate, Verified, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Certificate{}, Verified{}, errors.New("DKG certificate is empty or too large")
	}
	var certificate Certificate
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&certificate); err != nil {
		return Certificate{}, Verified{}, fmt.Errorf("decode DKG certificate: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Certificate{}, Verified{}, errors.New("trailing DKG certificate data")
	}
	verified, err := Verify(certificate, network)
	return certificate, verified, err
}

func attestationMessage(digest [32]byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-dkg-result-attestation-v1"))
	_, _ = h.Write(digest[:])
	return h.Sum(nil)
}

func decodeBase64(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}

func decodeHex(encoded string, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || encoded != hex.EncodeToString(decoded) {
		return nil, errors.New("invalid hex or length")
	}
	return decoded, nil
}

func mustDecode(encoded string, size int) []byte {
	decoded, _ := decodeBase64(encoded, size)
	return decoded
}
