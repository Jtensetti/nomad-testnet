package topology

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

const SecretVersion = "nomad-operator-secrets-v2"

type Secrets struct {
	Version         string `json:"version"`
	OperatorID      string `json:"operator_id"`
	IdentityPrivate string `json:"identity_private"`
	KEXPrivate      string `json:"kex_private"`
}

type PrivateKeys struct {
	OperatorID string
	Identity   ed25519.PrivateKey
	KEX        *ecdh.PrivateKey
}

type VerifiedSecrets struct {
	Operator     Operator
	Identity     ed25519.PrivateKey
	OutboundKeys map[uint16][32]byte
	InboundKeys  map[uint16][32]byte
}

func LoadSecrets(path string, verified Verified) (VerifiedSecrets, error) {
	encoded, err := loadSecretFile(path)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	return VerifySecrets(encoded, verified)
}

// LoadPrivateKeys is used by an operator during an offline topology ceremony.
// It performs the same regular-file and permission checks as the live node but
// does not require an authority-signed topology yet.
func LoadPrivateKeys(path string) (PrivateKeys, error) {
	encoded, err := loadSecretFile(path)
	if err != nil {
		return PrivateKeys{}, err
	}
	return DecodePrivateKeys(encoded)
}

func loadSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return nil, errors.New("operator secrets must be a bounded regular file")
	}
	// Unix secret files must not be readable or writable by group/other. Docker
	// secrets mounted as 0400 satisfy this. Windows relies on its ACL model.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("operator secret permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func VerifySecrets(encoded []byte, verified Verified) (VerifiedSecrets, error) {
	private, err := DecodePrivateKeys(encoded)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	operator, err := verified.OperatorByID(private.OperatorID)
	if err != nil {
		return VerifiedSecrets{}, err
	}
	configuredIdentity, _ := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize)
	if !bytes.Equal(private.Identity.Public().(ed25519.PublicKey), configuredIdentity) {
		return VerifiedSecrets{}, errors.New("operator identity private key does not match signed topology")
	}
	configuredKEX, _ := decodeFixed(operator.KEXKey, 32)
	if !bytes.Equal(private.KEX.PublicKey().Bytes(), configuredKEX) {
		return VerifiedSecrets{}, errors.New("operator key-agreement private key does not match signed topology")
	}

	outbound := make(map[uint16][32]byte)
	for _, peerIndex := range operator.PeerPlan {
		peer, _ := verified.Operator(peerIndex)
		key, err := deriveMACKey(verified, private.KEX, operator, peer)
		if err != nil {
			return VerifiedSecrets{}, fmt.Errorf("outbound key for %s: %w", peer.ID, err)
		}
		outbound[peerIndex] = key
	}
	inbound := make(map[uint16][32]byte)
	for _, peer := range verified.IncomingPeers(operator.Index) {
		key, err := deriveMACKey(verified, private.KEX, peer, operator)
		if err != nil {
			return VerifiedSecrets{}, fmt.Errorf("inbound key for %s: %w", peer.ID, err)
		}
		inbound[peer.Index] = key
	}
	return VerifiedSecrets{
		Operator: operator, Identity: private.Identity, OutboundKeys: outbound, InboundKeys: inbound,
	}, nil
}

func DecodePrivateKeys(encoded []byte) (PrivateKeys, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return PrivateKeys{}, errors.New("operator secrets are empty or too large")
	}
	var secrets Secrets
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&secrets); err != nil {
		return PrivateKeys{}, fmt.Errorf("decode operator secrets: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PrivateKeys{}, errors.New("trailing operator secret data")
	}
	if secrets.Version != SecretVersion {
		return PrivateKeys{}, errors.New("unsupported operator secret version")
	}
	if !operatorIDPattern.MatchString(secrets.OperatorID) {
		return PrivateKeys{}, errors.New("invalid operator ID in secrets")
	}
	identity, err := decodeFixed(secrets.IdentityPrivate, ed25519.PrivateKeySize)
	if err != nil {
		return PrivateKeys{}, errors.New("invalid operator identity private key")
	}
	privateKey := ed25519.PrivateKey(append([]byte(nil), identity...))
	if !bytes.Equal(privateKey, ed25519.NewKeyFromSeed(privateKey.Seed())) {
		return PrivateKeys{}, errors.New("operator identity private key is not canonical")
	}
	kexBytes, err := decodeFixed(secrets.KEXPrivate, 32)
	if err != nil {
		return PrivateKeys{}, errors.New("invalid operator key-agreement private key")
	}
	kex, err := ecdh.X25519().NewPrivateKey(kexBytes)
	if err != nil {
		return PrivateKeys{}, errors.New("invalid operator key-agreement private key")
	}
	return PrivateKeys{OperatorID: secrets.OperatorID, Identity: privateKey, KEX: kex}, nil
}

func GenerateSecrets(operatorID string) (Secrets, error) {
	if !operatorIDPattern.MatchString(operatorID) {
		return Secrets{}, errors.New("invalid operator ID")
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Secrets{}, err
	}
	kex, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Secrets{}, err
	}
	return Secrets{
		Version: SecretVersion, OperatorID: operatorID,
		IdentityPrivate: base64.StdEncoding.EncodeToString(identity),
		KEXPrivate:      base64.StdEncoding.EncodeToString(kex.Bytes()),
	}, nil
}

func EncodeSecrets(secrets Secrets) ([]byte, error) {
	return json.MarshalIndent(secrets, "", "  ")
}

func deriveMACKey(network Verified, ownPrivate *ecdh.PrivateKey, sender, receiver Operator) ([32]byte, error) {
	if ownPrivate == nil {
		return [32]byte{}, errors.New("key-agreement private key is required")
	}
	ownPublic := ownPrivate.PublicKey().Bytes()
	senderPublic, err := decodeFixed(sender.KEXKey, 32)
	if err != nil {
		return [32]byte{}, errors.New("sender key-agreement key is invalid")
	}
	receiverPublic, err := decodeFixed(receiver.KEXKey, 32)
	if err != nil {
		return [32]byte{}, errors.New("receiver key-agreement key is invalid")
	}
	var peerBytes []byte
	switch {
	case bytes.Equal(ownPublic, senderPublic):
		peerBytes = receiverPublic
	case bytes.Equal(ownPublic, receiverPublic):
		peerBytes = senderPublic
	default:
		return [32]byte{}, errors.New("private key is not a participant in directed hop")
	}
	peerPublic, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return [32]byte{}, errors.New("peer key-agreement key is invalid")
	}
	shared, err := ownPrivate.ECDH(peerPublic)
	if err != nil {
		return [32]byte{}, errors.New("peer key agreement failed")
	}
	info := make([]byte, 0, 64+len(network.Document.NetworkID))
	info = append(info, []byte("nomad-hop-mac-kdf-v2")...)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(len(network.Document.NetworkID)))
	info = append(info, integer[:]...)
	info = append(info, network.Document.NetworkID...)
	binary.BigEndian.PutUint64(integer[:], network.Document.Epoch)
	info = append(info, integer[:]...)
	binary.BigEndian.PutUint64(integer[:], uint64(sender.Index))
	info = append(info, integer[:]...)
	binary.BigEndian.PutUint64(integer[:], uint64(receiver.Index))
	info = append(info, integer[:]...)
	reader := hkdf.New(sha256.New, shared, network.Digest[:], info)
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}
