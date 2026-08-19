package batch

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	ShareVersion   = "nomad-threshold-share-v1"
	PartialVersion = "nomad-partial-decryption-v1"
)

type ShareFile struct {
	Version        string `json:"version"`
	NetworkID      string `json:"network_id"`
	TopologyDigest string `json:"topology_digest"`
	OperatorID     string `json:"operator_id"`
	CommitteeID    string `json:"committee_id"`
	Epoch          uint64 `json:"epoch"`
	Index          uint32 `json:"index"`
	Secret         string `json:"secret"`
	Public         string `json:"public"`
}

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
	return ShareFile{
		Version: ShareVersion, NetworkID: network.Document.NetworkID,
		TopologyDigest: hex.EncodeToString(network.Digest[:]), OperatorID: operator.ID,
		CommitteeID: hex.EncodeToString(secret.CommitteeID[:]), Epoch: secret.Epoch, Index: secret.Index,
		Secret: base64.StdEncoding.EncodeToString(secret.Secret[:]),
		Public: base64.StdEncoding.EncodeToString(secret.Public[:]),
	}
}

func EncodeShare(file ShareFile) ([]byte, error) { return json.MarshalIndent(file, "", "  ") }

func LoadShare(path string, descriptor VerifiedDescriptor, network topology.Verified) (mix.MemberSecret, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return mix.MemberSecret{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return mix.MemberSecret{}, errors.New("threshold share must be a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return mix.MemberSecret{}, errors.New("threshold share permissions must be 0600 or stricter")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return mix.MemberSecret{}, err
	}
	return VerifyShare(encoded, descriptor, network)
}

func VerifyShare(encoded []byte, descriptor VerifiedDescriptor, network topology.Verified) (mix.MemberSecret, error) {
	var file ShareFile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return mix.MemberSecret{}, fmt.Errorf("decode threshold share: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return mix.MemberSecret{}, errors.New("trailing threshold share data")
	}
	if file.Version != ShareVersion || file.NetworkID != network.Document.NetworkID || file.TopologyDigest != hex.EncodeToString(network.Digest[:]) {
		return mix.MemberSecret{}, errors.New("threshold share belongs to a different topology")
	}
	operator, err := network.OperatorByID(file.OperatorID)
	if err != nil || file.Index != uint32(operator.Index) {
		return mix.MemberSecret{}, errors.New("threshold share operator binding mismatch")
	}
	committeeID, err := decodeHex(file.CommitteeID, len(mix.CommitteeID{}))
	if err != nil || file.CommitteeID != hex.EncodeToString(descriptor.Committee.ID[:]) || file.Epoch != descriptor.Committee.Epoch {
		return mix.MemberSecret{}, errors.New("threshold share committee binding mismatch")
	}
	secretBytes, err := decodeBase64(file.Secret, len(mix.PrivateShare{}))
	if err != nil {
		return mix.MemberSecret{}, errors.New("invalid private threshold share")
	}
	publicBytes, err := decodeBase64(file.Public, len(mix.SharePublicKey{}))
	if err != nil || !bytes.Equal(publicBytes, descriptor.Committee.Members[file.Index].Share[:]) {
		return mix.MemberSecret{}, errors.New("threshold share public commitment mismatch")
	}
	secret := mix.MemberSecret{Epoch: file.Epoch, Index: file.Index}
	copy(secret.CommitteeID[:], committeeID)
	copy(secret.Secret[:], secretBytes)
	copy(secret.Public[:], publicBytes)
	return secret, nil
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
