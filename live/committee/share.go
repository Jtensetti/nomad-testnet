package committee

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

const ShareVersion = "nomad-threshold-share-v2"

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

func ShareFromSecret(secret mix.MemberSecret, operator topology.Operator, network topology.Verified) ShareFile {
	return ShareFile{
		Version: ShareVersion, NetworkID: network.Document.NetworkID,
		TopologyDigest: hex.EncodeToString(network.Digest[:]), OperatorID: operator.ID,
		CommitteeID: hex.EncodeToString(secret.CommitteeID[:]), Epoch: secret.Epoch, Index: secret.Index,
		Secret: base64.StdEncoding.EncodeToString(secret.Secret[:]), Public: base64.StdEncoding.EncodeToString(secret.Public[:]),
	}
}

func EncodeShare(file ShareFile) ([]byte, error) {
	return json.MarshalIndent(file, "", "  ")
}

func LoadShare(path string, certificate Verified, network topology.Verified) (mix.MemberSecret, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return mix.MemberSecret{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumFileBytes {
		return mix.MemberSecret{}, errors.New("threshold share must be a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return mix.MemberSecret{}, errors.New("threshold share permissions must be 0600 or stricter")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return mix.MemberSecret{}, err
	}
	return VerifyShare(encoded, certificate, network)
}

func VerifyShare(encoded []byte, certificate Verified, network topology.Verified) (mix.MemberSecret, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return mix.MemberSecret{}, errors.New("threshold share is empty or too large")
	}
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
	if file.CommitteeID != hex.EncodeToString(certificate.Committee.ID[:]) || file.Epoch != certificate.Committee.Epoch || int(file.Index) >= len(certificate.Committee.Members) {
		return mix.MemberSecret{}, errors.New("threshold share committee binding mismatch")
	}
	secretBytes, err := decodeBase64(file.Secret, len(mix.PrivateShare{}))
	if err != nil {
		return mix.MemberSecret{}, errors.New("invalid private threshold share")
	}
	publicBytes, err := decodeBase64(file.Public, len(mix.SharePublicKey{}))
	if err != nil || !bytes.Equal(publicBytes, certificate.Committee.Members[file.Index].Share[:]) {
		return mix.MemberSecret{}, errors.New("threshold share public commitment mismatch")
	}
	secret := mix.MemberSecret{CommitteeID: certificate.Committee.ID, Epoch: file.Epoch, Index: file.Index}
	copy(secret.Secret[:], secretBytes)
	copy(secret.Public[:], publicBytes)
	if err := mix.ValidateMemberSecret(certificate.Committee, secret); err != nil {
		return mix.MemberSecret{}, fmt.Errorf("invalid private threshold share: %w", err)
	}
	return secret, nil
}
