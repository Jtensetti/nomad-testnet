package batch

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	ShareVersion   = committee.ShareVersion
	PartialVersion = "nomad-partial-decryption-v1"
)

type ShareFile = committee.ShareFile

type PartialFile struct {
	Version     string   `json:"version"`
	StreamID    string   `json:"stream_id"`
	CommitteeID string   `json:"committee_id"`
	Epoch       uint64   `json:"epoch"`
	MemberIndex uint32   `json:"member_index"`
	BatchDigest string   `json:"batch_digest"`
	Points      []string `json:"points"`
	Proof       string   `json:"proof"`
}

func ShareToFile(secret mix.MemberSecret, operator topology.Operator, network topology.Verified) ShareFile {
	return committee.ShareFromSecret(secret, operator, network)
}

func EncodeShare(file ShareFile) ([]byte, error) { return committee.EncodeShare(file) }

func LoadShare(path string, descriptor VerifiedDescriptor, network topology.Verified) (mix.MemberSecret, error) {
	return committee.LoadShare(path, descriptor.Certificate, network)
}

func VerifyShare(encoded []byte, descriptor VerifiedDescriptor, network topology.Verified) (mix.MemberSecret, error) {
	return committee.VerifyShare(encoded, descriptor.Certificate, network)
}

func PartialToFile(stream string, partial *mix.PartialDecryption) (PartialFile, error) {
	if partial == nil {
		return PartialFile{}, errors.New("partial decryption is required")
	}
	points := make([]string, len(partial.Points))
	for index, point := range partial.Points {
		points[index] = base64.StdEncoding.EncodeToString(point[:])
	}
	return PartialFile{
		Version: PartialVersion, StreamID: stream,
		CommitteeID: hex.EncodeToString(partial.CommitteeID[:]), Epoch: partial.Epoch,
		MemberIndex: partial.MemberIndex, BatchDigest: hex.EncodeToString(partial.BatchDigest[:]),
		Points: points, Proof: base64.StdEncoding.EncodeToString(partial.Proof),
	}, nil
}

func EncodePartial(file PartialFile) ([]byte, error) { return json.MarshalIndent(file, "", "  ") }

func DecodePartial(encoded []byte, descriptor VerifiedDescriptor) (*mix.PartialDecryption, error) {
	var file PartialFile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode partial decryption: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing partial-decryption data")
	}
	if file.Version != PartialVersion || file.StreamID != descriptor.Descriptor.StreamID || file.CommitteeID != hex.EncodeToString(descriptor.Committee.ID[:]) || file.Epoch != descriptor.Committee.Epoch {
		return nil, errors.New("partial decryption context mismatch")
	}
	if int(file.MemberIndex) >= len(descriptor.Committee.Members) {
		return nil, errors.New("partial decryption member is outside committee")
	}
	batchDigest, err := decodeHex(file.BatchDigest, 32)
	if err != nil {
		return nil, errors.New("invalid partial batch digest")
	}
	proof, err := decodeBase64(file.Proof, -1)
	if err != nil || len(proof) == 0 || len(proof) > 4<<20 {
		return nil, errors.New("invalid partial proof")
	}
	partial := &mix.PartialDecryption{
		Epoch: file.Epoch, MemberIndex: file.MemberIndex, Points: make([][32]byte, len(file.Points)), Proof: proof,
	}
	copy(partial.CommitteeID[:], descriptor.Committee.ID[:])
	copy(partial.BatchDigest[:], batchDigest)
	for index, encodedPoint := range file.Points {
		point, err := decodeBase64(encodedPoint, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid partial point %d", index)
		}
		copy(partial.Points[index][:], point)
	}
	return partial, nil
}
