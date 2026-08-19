package batch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type Generated struct {
	Descriptor Descriptor
	Bundle     bundle.File
	Shares     []ShareFile
}

func DecodeEnvelope(encoded []byte, catalogIndex int) (SignedEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return SignedEnvelope{}, errors.New("signed envelope input is empty or too large")
	}
	var single SignedEnvelope
	if err := strictJSON(encoded, &single); err == nil && single.Version != 0 {
		if catalogIndex != 0 {
			return SignedEnvelope{}, errors.New("catalog index must be zero for a single envelope")
		}
		return single, nil
	}
	var catalog []SignedEnvelope
	if err := strictJSON(encoded, &catalog); err != nil {
		return SignedEnvelope{}, errors.New("input is neither a signed envelope nor an envelope catalog")
	}
	if catalogIndex < 0 || catalogIndex >= len(catalog) {
		return SignedEnvelope{}, errors.New("catalog index is outside the envelope catalog")
	}
	return catalog[catalogIndex], nil
}

func VerifyEnvelope(envelope SignedEnvelope) ([]byte, [32]byte, ed25519.PublicKey, []byte, error) {
	if envelope.Version != EnvelopeVersion {
		return nil, [32]byte{}, nil, nil, errors.New("unsupported signed envelope version")
	}
	payload, err := decodeBase64(envelope.Payload, -1)
	if err != nil || len(payload) == 0 || len(payload) > MaximumPayloadBytes {
		return nil, [32]byte{}, nil, nil, errors.New("invalid or oversized envelope payload")
	}
	root := sha256.Sum256(payload)
	if envelope.ContentHash != hex.EncodeToString(root[:]) {
		return nil, [32]byte{}, nil, nil, errors.New("envelope content commitment mismatch")
	}
	publisher, err := decodeBase64(envelope.PublisherKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, [32]byte{}, nil, nil, errors.New("invalid envelope publisher key")
	}
	signature, err := decodeBase64(envelope.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publisher, reconstruct.SigningMessage(root), signature) {
		return nil, [32]byte{}, nil, nil, errors.New("envelope signature verification failed")
	}
	return payload, root, ed25519.PublicKey(publisher), signature, nil
}

// Generate builds the publication fixture. It uses the authenticated in-memory
// DKG harness and then one established Kyber Neff shuffle per operator. This is
// not the anonymous publication airlock and is kept out of every reader path.
func Generate(
	ctx context.Context,
	envelope SignedEnvelope,
	network topology.Verified,
	authority ed25519.PrivateKey,
	identities map[string]ed25519.PrivateKey,
	dkgIdentities map[string]mix.DKGPrivateIdentity,
) (Generated, error) {
	if ctx == nil {
		return Generated{}, errors.New("context is required")
	}
	select {
	case <-ctx.Done():
		return Generated{}, ctx.Err()
	default:
	}
	payload, root, publisher, objectSignature, err := VerifyEnvelope(envelope)
	if err != nil {
		return Generated{}, err
	}
	symbolSize, err := chooseSymbolSize(len(payload), DefaultBatchSize)
	if err != nil {
		return Generated{}, err
	}
	encoder, err := rlnc.NewEncoder(payload, symbolSize)
	if err != nil {
		return Generated{}, err
	}
	if encoder.K() > DefaultBatchSize {
		return Generated{}, errors.New("object exceeds the live single-generation profile")
	}
	var generation rlnc.GenerationID
	expectedGeneration := reconstruct.GenerationFor(root)
	copy(generation[:], expectedGeneration[:])
	plainCells := make([]mix.PlainCell, DefaultBatchSize)
	for index := range plainCells {
		var symbol rlnc.Symbol
		if index < encoder.K() {
			symbol, err = encoder.Systematic(index)
		} else {
			symbol, err = encoder.Encode()
		}
		if err != nil {
			return Generated{}, err
		}
		packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(), symbol)
		if err != nil {
			return Generated{}, err
		}
		encodedPacket, err := packet.MarshalBinary()
		if err != nil {
			return Generated{}, err
		}
		copy(plainCells[index][:], encodedPacket)
	}

	committeeID, err := committee.IDForTopology(network)
	if err != nil {
		return Generated{}, err
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(network.Document.DKG.SessionID)
	if err != nil || len(nonce) != 32 {
		return Generated{}, errors.New("invalid topology DKG session")
	}
	privateDKG := make([]mix.DKGPrivateIdentity, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		private, exists := dkgIdentities[operator.ID]
		if !exists {
			return Generated{}, fmt.Errorf("missing DKG identity for %s", operator.ID)
		}
		privateDKG[index] = private
	}
	publicCommittee, memberSecrets, transcript, err := mix.RunAuthenticatedDKGWithIdentities(
		committeeID, network.Document.Epoch, privateDKG, network.Document.DKG.Threshold, nonce,
	)
	if err != nil {
		return Generated{}, fmt.Errorf("authenticated DKG: %w", err)
	}
	manifest, err := committee.NewManifest(network, publicCommittee, transcript)
	if err != nil {
		return Generated{}, err
	}
	attestations := make([]committee.Attestation, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		attestations[index], err = committee.CreateAttestation(manifest, operator, identities[operator.ID])
		if err != nil {
			return Generated{}, err
		}
	}
	certificate, err := committee.Assemble(manifest, attestations, network)
	if err != nil {
		return Generated{}, err
	}
	certified, err := committee.Verify(certificate, network)
	if err != nil {
		return Generated{}, err
	}
	publicCommittee = certified.Committee
	current, err := mix.Encrypt(publicCommittee.PublicKey, plainCells)
	if err != nil {
		return Generated{}, err
	}
	rounds := make([]MixRoundFile, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		select {
		case <-ctx.Done():
			return Generated{}, ctx.Err()
		default:
		}
		identity := identities[operator.ID]
		if len(identity) != ed25519.PrivateKeySize {
			return Generated{}, fmt.Errorf("missing mixer identity for %s", operator.ID)
		}
		inputEncoded, err := encodeBatch(current)
		if err != nil {
			return Generated{}, err
		}
		inputDigest, err := current.Digest()
		if err != nil {
			return Generated{}, err
		}
		roundContext := mix.RoundContext{
			CommitteeID: publicCommittee.ID, Epoch: publicCommittee.Epoch, BatchID: inputDigest, Round: uint32(index),
		}
		output, proof, receipt, err := mix.ShuffleAndSign(roundContext, publicCommittee.PublicKey, current, identity)
		if err != nil {
			return Generated{}, fmt.Errorf("operator %s shuffle: %w", operator.ID, err)
		}
		if err := mix.VerifySignedRound(publicCommittee.PublicKey, current, output, proof, receipt); err != nil {
			return Generated{}, fmt.Errorf("operator %s shuffle verification: %w", operator.ID, err)
		}
		outputEncoded, err := encodeBatch(output)
		if err != nil {
			return Generated{}, err
		}
		rounds[index] = MixRoundFile{
			Input: inputEncoded, Output: outputEncoded,
			Proof: base64.StdEncoding.EncodeToString(proof), Receipt: receiptToFile(receipt),
		}
		current = output
	}
	finalPayloads, err := decodePayloads(rounds[len(rounds)-1].Output)
	if err != nil {
		return Generated{}, err
	}
	seed, err := bundle.New(finalPayloads)
	if err != nil {
		return Generated{}, err
	}
	streamBytes, _ := hex.DecodeString(seed.StreamID)
	var stream hop.StreamID
	copy(stream[:], streamBytes)
	descriptor := Descriptor{
		Version: DescriptorVersion, NetworkID: network.Document.NetworkID,
		TopologyEpoch: network.Document.Epoch, TopologyDigest: hex.EncodeToString(network.Digest[:]),
		StreamID: hex.EncodeToString(stream[:]), BatchSize: DefaultBatchSize,
		Generation: hex.EncodeToString(generation[:]), K: uint16(encoder.K()),
		SymbolSize: uint16(encoder.SymbolSize()), OriginalSize: uint32(encoder.OriginalSize()),
		ContentHash: hex.EncodeToString(root[:]), PublisherKey: base64.StdEncoding.EncodeToString(publisher),
		ObjectSignature: base64.StdEncoding.EncodeToString(objectSignature),
		DKGCertificate: certificate, MixRounds: rounds,
	}
	descriptor, err = SignDescriptor(descriptor, authority)
	if err != nil {
		return Generated{}, err
	}
	shares := make([]ShareFile, len(memberSecrets))
	for index, secret := range memberSecrets {
		operator, _ := network.Operator(uint16(index))
		shares[index] = ShareToFile(secret, operator, network)
	}
	return Generated{Descriptor: descriptor, Bundle: seed, Shares: shares}, nil
}

func chooseSymbolSize(contentSize, batchSize int) (int, error) {
	const packetPayloadCapacity = rlnc.PacketSize - rlnc.PacketHeaderSize
	for symbolSize := packetPayloadCapacity - 1; symbolSize > 0; symbolSize-- {
		k := (contentSize + symbolSize - 1) / symbolSize
		if k <= batchSize && k+symbolSize <= packetPayloadCapacity {
			return symbolSize, nil
		}
	}
	return 0, errors.New("object is too large for the live single-generation profile")
}

func strictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
