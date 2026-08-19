package topology

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

const SecretVersion = "nomad-operator-secrets-v1"

type Secrets struct {
	Version         string            `json:"version"`
	OperatorID      string            `json:"operator_id"`
	IdentityPrivate string            `json:"identity_private"`
	OutboundKeys    map[string]string `json:"outbound_keys"`
	InboundKeys     map[string]string `json:"inbound_keys"`
}

type VerifiedSecrets struct {
	Operator     Operator
	Identity     ed25519.PrivateKey
	OutboundKeys map[uint16][32]byte
	InboundKeys  map[uint16][32]byte
}

func LoadSecrets(path string, verified Verified) (VerifiedSecrets, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return VerifiedSecrets{}, errors.New("operator secrets must be a bounded regular file")
	}
	// Unix secret files must not be readable or writable by group/other. Docker
	// secrets mounted as 0400 satisfy this. Windows relies on its ACL model.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return VerifiedSecrets{}, errors.New("operator secret permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	return VerifySecrets(data, verified)
}

func VerifySecrets(encoded []byte, verified Verified) (VerifiedSecrets, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return VerifiedSecrets{}, errors.New("operator secrets are empty or too large")
	}
	var secrets Secrets
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&secrets); err != nil {
		return VerifiedSecrets{}, fmt.Errorf("decode operator secrets: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerifiedSecrets{}, errors.New("trailing operator secret data")
	}
	if secrets.Version != SecretVersion {
		return VerifiedSecrets{}, errors.New("unsupported operator secret version")
	}
	operator, err := verified.OperatorByID(secrets.OperatorID)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	identity, err := decodeFixed(secrets.IdentityPrivate, ed25519.PrivateKeySize)
	if err != nil {
		return VerifiedSecrets{}, errors.New("invalid operator identity private key")
	}
	privateKey := ed25519.PrivateKey(append([]byte(nil), identity...))
	configuredPublic, _ := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), configuredPublic) {
		return VerifiedSecrets{}, errors.New("operator identity private key does not match signed topology")
	}

	outbound := make(map[uint16][32]byte)
	for _, peerIndex := range operator.PeerPlan {
		peer, _ := verified.Operator(peerIndex)
		key, err := decodeMACKey(secrets.OutboundKeys[peer.ID])
		if err != nil {
			return VerifiedSecrets{}, fmt.Errorf("outbound key for %s: %w", peer.ID, err)
		}
		outbound[peerIndex] = key
	}
	inbound := make(map[uint16][32]byte)
	for _, peer := range verified.IncomingPeers(operator.Index) {
		key, err := decodeMACKey(secrets.InboundKeys[peer.ID])
		if err != nil {
			return VerifiedSecrets{}, fmt.Errorf("inbound key for %s: %w", peer.ID, err)
		}
		inbound[peer.Index] = key
	}
	if len(secrets.OutboundKeys) != len(outbound) || len(secrets.InboundKeys) != len(inbound) {
		return VerifiedSecrets{}, errors.New("operator secrets contain an unknown or unused peer key")
	}
	return VerifiedSecrets{
		Operator: operator, Identity: privateKey, OutboundKeys: outbound, InboundKeys: inbound,
	}, nil
}

func EncodeSecrets(secrets Secrets) ([]byte, error) {
	return json.MarshalIndent(secrets, "", "  ")
}

func decodeMACKey(encoded string) ([32]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, errors.New("key must be 32 strict-base64 bytes")
	}
	var key [32]byte
	copy(key[:], decoded)
	if key == ([32]byte{}) {
		return [32]byte{}, errors.New("all-zero peer key is forbidden")
	}
	return key, nil
}
