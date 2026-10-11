// Package batch owns the private-side description of one encrypted object
// batch. Network nodes do not import this package.
package batch

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
	"os"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/strictjson"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	DescriptorVersion   = "nomad-batch-descriptor-v3"
	EnvelopeVersion     = 1
	MaximumFileBytes    = 4 << 20
	DefaultBatchSize    = 16
	DefaultThreshold    = 2
	MaximumPayloadBytes = 262_144
)

type SignedEnvelope struct {
	Version      int    `json:"version"`
	Payload      string `json:"payload"`
	ContentHash  string `json:"contentHash"`
	PublisherKey string `json:"publisherKey"`
	Signature    string `json:"signature"`
}

type ReceiptFile struct {
	CommitteeID  string `json:"committee_id"`
	Epoch        uint64 `json:"epoch"`
	BatchID      string `json:"batch_id"`
	Round        uint32 `json:"round"`
	MixerPublic  string `json:"mixer_public"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest"`
	ProofDigest  string `json:"proof_digest"`
	Signature    string `json:"signature"`
}

type MixRoundFile struct {
	Input   []string    `json:"input"`
	Output  []string    `json:"output"`
	Proof   string      `json:"proof"`
	Receipt ReceiptFile `json:"receipt"`
}

type Descriptor struct {
	Version            string                `json:"version"`
	NetworkID          string                `json:"network_id"`
	TopologyEpoch      uint64                `json:"topology_epoch"`
	TopologyDigest     string                `json:"topology_digest"`
	StreamID           string                `json:"stream_id"`
	BatchSize          uint16                `json:"batch_size"`
	Generation         string                `json:"generation"`
	K                  uint16                `json:"k"`
	SymbolSize         uint16                `json:"symbol_size"`
	OriginalSize       uint32                `json:"original_size"`
	ContentHash        string                `json:"content_hash"`
	SourceCommitments  []string              `json:"source_commitments"`
	PublisherKey       string                `json:"publisher_key"`
	ObjectSignature    string                `json:"object_signature"`
	DKGCertificate     committee.Certificate `json:"dkg_certificate"`
	MixRounds          []MixRoundFile        `json:"mix_rounds"`
	AuthoritySignature string                `json:"authority_signature"`
}

type VerifiedDescriptor struct {
	Descriptor  Descriptor
	Stream      hop.StreamID
	Generation  rlnc.GenerationID
	Root        [32]byte
	Publisher   ed25519.PublicKey
	Signature   []byte
	Committee   mix.ThresholdCommittee
	Transcript  mix.DKGTranscript
	Certificate committee.Verified
	Commitments rlnc.SourceCommitments
}

func LoadDescriptor(path string, authority ed25519.PublicKey, network topology.Verified) (VerifiedDescriptor, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return VerifiedDescriptor{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return VerifiedDescriptor{}, errors.New("batch descriptor must be a bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return VerifiedDescriptor{}, err
	}
	return VerifyDescriptor(encoded, authority, network)
}

func VerifyDescriptor(encoded []byte, authority ed25519.PublicKey, network topology.Verified) (VerifiedDescriptor, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return VerifiedDescriptor{}, errors.New("batch descriptor is empty or too large")
	}
	if len(authority) != ed25519.PublicKeySize {
		return VerifiedDescriptor{}, errors.New("descriptor authority key is invalid")
	}
	// An encoding more than one parser can read differently is refused before
	// anything is decoded: a signature check verifies against whatever this
	// implementation parsed, so a duplicate key makes one implementation
	// accept a descriptor another refuses.
	if err := strictjson.RejectDuplicateKeys(encoded); err != nil {
		return VerifiedDescriptor{}, fmt.Errorf("descriptor encoding is ambiguous: %w", err)
	}
	var descriptor Descriptor
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return VerifiedDescriptor{}, fmt.Errorf("decode batch descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerifiedDescriptor{}, errors.New("trailing batch descriptor data")
	}
	unsigned := descriptor
	unsigned.AuthoritySignature = ""
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return VerifiedDescriptor{}, err
	}
	authoritySignature, err := decodeBase64(descriptor.AuthoritySignature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(authority, signingMessage("nomad-batch-descriptor-authority-v1", canonical), authoritySignature) {
		return VerifiedDescriptor{}, errors.New("batch descriptor authority signature verification failed")
	}
	if descriptor.Version != DescriptorVersion || descriptor.NetworkID != network.Document.NetworkID || descriptor.TopologyEpoch != network.Document.Epoch {
		return VerifiedDescriptor{}, errors.New("batch descriptor belongs to a different network or epoch")
	}
	if descriptor.TopologyDigest != hex.EncodeToString(network.Digest[:]) {
		return VerifiedDescriptor{}, errors.New("batch descriptor topology commitment mismatch")
	}
	streamBytes, err := decodeHex(descriptor.StreamID, len(hop.StreamID{}))
	if err != nil {
		return VerifiedDescriptor{}, errors.New("invalid descriptor stream ID")
	}
	var stream hop.StreamID
	copy(stream[:], streamBytes)
	if len(descriptor.MixRounds) != len(network.Document.Operators) || len(descriptor.MixRounds) == 0 {
		return VerifiedDescriptor{}, errors.New("mix transcript does not contain one round per operator")
	}
	if descriptor.BatchSize < 2 || descriptor.BatchSize > hop.MaximumBatch || int(descriptor.BatchSize) != len(descriptor.MixRounds[0].Output) {
		return VerifiedDescriptor{}, errors.New("invalid descriptor batch size")
	}
	rootBytes, err := decodeHex(descriptor.ContentHash, sha256.Size)
	if err != nil {
		return VerifiedDescriptor{}, errors.New("invalid descriptor content hash")
	}
	var root [32]byte
	copy(root[:], rootBytes)
	publisher, err := decodeBase64(descriptor.PublisherKey, ed25519.PublicKeySize)
	if err != nil {
		return VerifiedDescriptor{}, errors.New("invalid descriptor publisher key")
	}
	objectSignature, err := decodeBase64(descriptor.ObjectSignature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publisher, reconstruct.SigningMessage(root), objectSignature) {
		return VerifiedDescriptor{}, errors.New("descriptor object signature verification failed")
	}
	generationBytes, err := decodeHex(descriptor.Generation, len(rlnc.GenerationID{}))
	if err != nil {
		return VerifiedDescriptor{}, errors.New("invalid descriptor generation")
	}
	var generation rlnc.GenerationID
	copy(generation[:], generationBytes)
	expectedGeneration := reconstruct.GenerationFor(root)
	if !bytes.Equal(generation[:], expectedGeneration[:]) {
		return VerifiedDescriptor{}, errors.New("descriptor generation does not match content commitment")
	}
	if descriptor.K == 0 || descriptor.SymbolSize == 0 || descriptor.OriginalSize == 0 || descriptor.OriginalSize > MaximumPayloadBytes ||
		uint64(descriptor.K)*uint64(descriptor.SymbolSize) < uint64(descriptor.OriginalSize) ||
		int(descriptor.K)+int(descriptor.SymbolSize) > rlnc.PacketSize-rlnc.PacketHeaderSize {
		return VerifiedDescriptor{}, errors.New("invalid descriptor RLNC dimensions")
	}
	// One commitment per source symbol, required, under the authority
	// signature. A descriptor without them cannot support pre-admission
	// verification, and accepting one would quietly re-open the window in
	// which a polluted systematic symbol spends decoder budget before the
	// envelope check catches it.
	if len(descriptor.SourceCommitments) != int(descriptor.K) {
		return VerifiedDescriptor{}, errors.New("descriptor must commit to every source symbol")
	}
	commitments := make(rlnc.SourceCommitments, len(descriptor.SourceCommitments))
	for index, encodedCommitment := range descriptor.SourceCommitments {
		commitmentBytes, err := decodeHex(encodedCommitment, sha256.Size)
		if err != nil {
			return VerifiedDescriptor{}, fmt.Errorf("invalid source commitment %d", index)
		}
		copy(commitments[index][:], commitmentBytes)
	}
	certified, err := committee.Verify(descriptor.DKGCertificate, network)
	if err != nil {
		return VerifiedDescriptor{}, fmt.Errorf("verify DKG certificate: %w", err)
	}
	finalPayloads, err := verifyMixRounds(descriptor.MixRounds, certified.Committee, network)
	if err != nil {
		return VerifiedDescriptor{}, err
	}
	calculatedStream, err := hop.StreamFor(finalPayloads)
	if err != nil || calculatedStream != stream {
		return VerifiedDescriptor{}, errors.New("mix transcript does not match descriptor stream")
	}
	return VerifiedDescriptor{
		Descriptor: descriptor, Stream: stream, Generation: generation, Root: root,
		Publisher: ed25519.PublicKey(publisher), Signature: objectSignature,
		Committee: certified.Committee, Transcript: certified.Transcript, Certificate: certified,
		Commitments: commitments,
	}, nil
}

func EncodeDescriptor(descriptor Descriptor) ([]byte, error) {
	return json.MarshalIndent(descriptor, "", "  ")
}

func SignDescriptor(descriptor Descriptor, authority ed25519.PrivateKey) (Descriptor, error) {
	if len(authority) != ed25519.PrivateKeySize {
		return Descriptor{}, errors.New("descriptor authority private key is invalid")
	}
	descriptor.AuthoritySignature = ""
	canonical, err := json.Marshal(descriptor)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor.AuthoritySignature = base64.StdEncoding.EncodeToString(ed25519.Sign(authority, signingMessage("nomad-batch-descriptor-authority-v1", canonical)))
	return descriptor, nil
}

func verifyMixRounds(rounds []MixRoundFile, committee mix.ThresholdCommittee, network topology.Verified) ([][hop.CiphertextSize]byte, error) {
	tracker, err := mix.NewReceiptTracker(committee.ID, committee.Epoch)
	if err != nil {
		return nil, err
	}
	var previous [32]byte
	for index, roundFile := range rounds {
		inputPayloads, err := decodePayloads(roundFile.Input)
		if err != nil {
			return nil, fmt.Errorf("mix round %d input: %w", index, err)
		}
		outputPayloads, err := decodePayloads(roundFile.Output)
		if err != nil {
			return nil, fmt.Errorf("mix round %d output: %w", index, err)
		}
		if len(inputPayloads) != len(outputPayloads) || len(inputPayloads) != int(rounds[0].receiptBatchSize()) {
			return nil, errors.New("mix transcript changed batch size")
		}
		input, err := parsePayloadBatch(inputPayloads)
		if err != nil {
			return nil, err
		}
		output, err := parsePayloadBatch(outputPayloads)
		if err != nil {
			return nil, err
		}
		proof, err := strictjson.DecodeBase64(roundFile.Proof)
		if err != nil || len(proof) == 0 {
			return nil, errors.New("invalid mix proof encoding")
		}
		receipt, err := roundFile.Receipt.toMix()
		if err != nil {
			return nil, err
		}
		if receipt.Context.Round != uint32(index) || receipt.Context.CommitteeID != committee.ID || receipt.Context.Epoch != committee.Epoch {
			return nil, errors.New("mix receipt context mismatch")
		}
		operator, _ := network.Operator(uint16(index))
		expectedIdentity, _ := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
		if !bytes.Equal(receipt.MixerPublic[:], expectedIdentity) {
			return nil, fmt.Errorf("mix round %d is signed by the wrong operator", index)
		}
		if index > 0 && receipt.InputDigest != previous {
			return nil, errors.New("mix transcript chain is discontinuous")
		}
		if err := mix.VerifySignedRound(committee.PublicKey, input, output, proof, receipt); err != nil {
			return nil, fmt.Errorf("verify mix round %d: %w", index, err)
		}
		if err := tracker.Accept(receipt); err != nil {
			return nil, err
		}
		previous = receipt.OutputDigest
		if index+1 < len(rounds) && !equalEncodedPayloads(roundFile.Output, rounds[index+1].Input) {
			return nil, errors.New("mix transcript round payloads are discontinuous")
		}
	}
	return decodePayloads(rounds[len(rounds)-1].Output)
}

func (round MixRoundFile) receiptBatchSize() uint16 { return uint16(len(round.Output)) }

func decodePayloads(encoded []string) ([][hop.CiphertextSize]byte, error) {
	if len(encoded) < 2 || len(encoded) > hop.MaximumBatch {
		return nil, errors.New("payload batch size is outside the supported range")
	}
	payloads := make([][hop.CiphertextSize]byte, len(encoded))
	for index, item := range encoded {
		decoded, err := decodeBase64(item, hop.CiphertextSize)
		if err != nil {
			return nil, fmt.Errorf("payload %d: %w", index, err)
		}
		copy(payloads[index][:], decoded)
	}
	return payloads, nil
}

func parsePayloadBatch(payloads [][hop.CiphertextSize]byte) (*mix.Batch, error) {
	cells := make([]mix.WireCell, len(payloads))
	for index, payload := range payloads {
		copy(cells[index][:hop.CiphertextSize], payload[:])
	}
	return mix.ParseWire(cells)
}

func encodeBatch(input *mix.Batch) ([]string, error) {
	cells, err := input.MarshalWire()
	if err != nil {
		return nil, err
	}
	encoded := make([]string, len(cells))
	for index, cell := range cells {
		encoded[index] = base64.StdEncoding.EncodeToString(cell[:hop.CiphertextSize])
	}
	return encoded, nil
}

func equalEncodedPayloads(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func signingMessage(domain string, payload []byte) []byte {
	message := make([]byte, 0, len(domain)+len(payload))
	message = append(message, domain...)
	message = append(message, payload...)
	return message
}

func decodeBase64(encoded string, size int) ([]byte, error) {
	decoded, err := strictjson.DecodeBase64(encoded)
	if err != nil || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}

func decodeHex(encoded string, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || encoded != hex.EncodeToString(decoded) {
		return nil, errors.New("invalid canonical hex or length")
	}
	return decoded, nil
}
