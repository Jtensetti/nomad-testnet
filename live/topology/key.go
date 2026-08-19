package topology

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
)

func LoadAuthorityKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024 {
		return nil, errors.New("authority key must be a bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("authority key must contain one strict-base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}
