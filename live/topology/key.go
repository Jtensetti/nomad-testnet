package topology

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"runtime"

	"github.com/Jtensetti/nomad-testnet/live/strictjson"
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
	decoded, err := strictjson.DecodeBase64(string(bytes.TrimSpace(encoded)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("authority key must contain one strict-base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func LoadAuthorityPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1024 {
		return nil, errors.New("authority private key must be a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("authority private key permissions must be 0600 or stricter")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := strictjson.DecodeBase64(string(bytes.TrimSpace(encoded)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("authority private key must contain one strict-base64 Ed25519 private key")
	}
	private := ed25519.PrivateKey(append([]byte(nil), decoded...))
	if !bytes.Equal(private, ed25519.NewKeyFromSeed(private.Seed())) {
		return nil, errors.New("authority private key is not canonical")
	}
	return private, nil
}
