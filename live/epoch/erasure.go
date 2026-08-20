package epoch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	ErasureVersion = "nomad-epoch-erasure-v1"
	erasureDomain  = "nomad-epoch-erasure-v1"

	// erasurePasses is the number of overwrite passes before unlinking.
	// More passes do not defeat wear levelling or copy-on-write, so this is
	// deliberately small; the real control is full-disk encryption, stated
	// in the limitations of every statement this package produces.
	erasurePasses = 1
)

// ErasedFile records one destroyed artifact.
type ErasedFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest_before_erasure"`
}

// ErasureStatement is an operator's signed assertion that it destroyed its
// private material for a retired epoch. It records exactly what was done and
// what that does and does not guarantee, so the claim cannot be read as
// stronger than the storage substrate allows.
type ErasureStatement struct {
	Version          string       `json:"version"`
	NetworkID        string       `json:"network_id"`
	OperatorID       string       `json:"operator_id"`
	Epoch            uint64       `json:"epoch"`
	DescriptorDigest string       `json:"descriptor_digest"`
	Files            []ErasedFile `json:"files"`
	Method           string       `json:"method"`
	Filesystem       string       `json:"filesystem"`
	ErasedAt         string       `json:"erased_at"`
	Limitations      string       `json:"limitations"`
	Signature        string       `json:"signature"`
}

// ErasureLimitations is recorded verbatim in every statement. Overwriting a
// file does not guarantee physical destruction on a journaling filesystem,
// on flash with wear levelling, or where snapshots or backups exist.
const ErasureLimitations = "Overwrite-then-unlink destroys the file as visible to the filesystem. " +
	"It does not guarantee physical destruction on journaling filesystems, on flash with wear levelling, " +
	"or where snapshots, backups or copy-on-write clones exist. The operative guarantee is destruction of " +
	"the file within an encrypted volume; deployments must use full-disk encryption and must not back up " +
	"the share directory."

func erasureCanonicalBytes(statement ErasureStatement) ([]byte, error) {
	if statement.Version != ErasureVersion {
		return nil, errors.New("unsupported erasure statement version")
	}
	if !networkIDPattern.MatchString(statement.NetworkID) {
		return nil, errors.New("invalid erasure network ID")
	}
	if !networkIDPattern.MatchString(statement.OperatorID) {
		return nil, errors.New("invalid erasure operator ID")
	}
	if statement.Epoch == 0 {
		return nil, errors.New("erasure statement must name an epoch")
	}
	digest, err := decodeHex(statement.DescriptorDigest, 32)
	if err != nil {
		return nil, errors.New("invalid erasure descriptor digest")
	}
	if err := validateCanonicalTime(statement.ErasedAt); err != nil {
		return nil, fmt.Errorf("erased_at: %w", err)
	}
	if statement.Limitations != ErasureLimitations {
		return nil, errors.New("erasure statement must carry the standard limitations text")
	}
	canonical := make([]byte, 0, 256)
	canonical = appendString(canonical, statement.Version)
	canonical = appendString(canonical, statement.NetworkID)
	canonical = appendString(canonical, statement.OperatorID)
	canonical = appendUint64(canonical, statement.Epoch)
	canonical = append(canonical, digest...)
	canonical = appendUint64(canonical, uint64(len(statement.Files)))
	for _, file := range statement.Files {
		fileDigest, err := decodeHex(file.Digest, 32)
		if err != nil {
			return nil, errors.New("invalid erased-file digest")
		}
		canonical = appendString(canonical, file.Path)
		canonical = appendUint64(canonical, uint64(file.SizeBytes))
		canonical = append(canonical, fileDigest...)
	}
	canonical = appendString(canonical, statement.Method)
	canonical = appendString(canonical, statement.Filesystem)
	canonical = appendString(canonical, statement.ErasedAt)
	canonical = appendString(canonical, statement.Limitations)
	return canonical, nil
}

// ErasureMessage is the exact signing message for an erasure statement.
func ErasureMessage(statement ErasementInput) ([]byte, error) {
	canonical, err := erasureCanonicalBytes(ErasureStatement(statement))
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(erasureDomain)+32)
	message = append(message, erasureDomain...)
	digest := sha256.Sum256(canonical)
	message = append(message, digest[:]...)
	return message, nil
}

// ErasementInput is an unsigned erasure statement.
type ErasementInput ErasureStatement

// EraseEpochMaterial destroys the listed private artifacts and returns a
// signed statement of what was destroyed. Each file is overwritten with
// random bytes, synced and unlinked. A file that is already absent is
// reported rather than treated as an error, so re-running the procedure is
// safe.
func EraseEpochMaterial(networkID, operatorID string, retired Verified, paths []string, filesystem string, identity ed25519.PrivateKey, now time.Time) (ErasureStatement, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return ErasureStatement{}, errors.New("operator identity is required to sign an erasure statement")
	}
	if len(paths) == 0 {
		return ErasureStatement{}, errors.New("erasure requires at least one path")
	}
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)

	files := make([]ErasedFile, 0, len(ordered))
	for _, path := range ordered {
		record, err := eraseOne(path)
		if err != nil {
			return ErasureStatement{}, fmt.Errorf("erase %s: %w", path, err)
		}
		files = append(files, record)
	}

	statement := ErasureStatement{
		Version: ErasureVersion, NetworkID: networkID, OperatorID: operatorID,
		Epoch: retired.Epoch, DescriptorDigest: hex.EncodeToString(retired.Digest[:]),
		Files: files, Method: "overwrite-random-then-unlink", Filesystem: filesystem,
		ErasedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), Limitations: ErasureLimitations,
	}
	message, err := ErasureMessage(ErasementInput(statement))
	if err != nil {
		return ErasureStatement{}, err
	}
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	return statement, nil
}

// eraseOne overwrites and removes a single file, recording what it was.
func eraseOne(path string) (ErasedFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErasedFile{Path: filepath.Base(path), SizeBytes: 0, Digest: hex.EncodeToString(make([]byte, 32))}, nil
	}
	if err != nil {
		return ErasedFile{}, err
	}
	if !info.Mode().IsRegular() {
		return ErasedFile{}, errors.New("refusing to erase a non-regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ErasedFile{}, err
	}
	digest := sha256.Sum256(contents)

	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return ErasedFile{}, err
	}
	for pass := 0; pass < erasurePasses; pass++ {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return ErasedFile{}, err
		}
		noise := make([]byte, info.Size())
		if _, err := rand.Read(noise); err != nil {
			_ = file.Close()
			return ErasedFile{}, err
		}
		if _, err := file.Write(noise); err != nil {
			_ = file.Close()
			return ErasedFile{}, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return ErasedFile{}, err
		}
	}
	if err := file.Close(); err != nil {
		return ErasedFile{}, err
	}
	if err := os.Remove(path); err != nil {
		return ErasedFile{}, err
	}
	return ErasedFile{Path: filepath.Base(path), SizeBytes: info.Size(), Digest: hex.EncodeToString(digest[:])}, nil
}

// VerifyErasureStatement checks the signature against the operator's
// identity in the retired epoch.
func VerifyErasureStatement(statement ErasureStatement, retired Verified) error {
	if statement.NetworkID != retired.NetworkID || statement.Epoch != retired.Epoch {
		return errors.New("erasure statement belongs to a different epoch")
	}
	if statement.DescriptorDigest != hex.EncodeToString(retired.Digest[:]) {
		return errors.New("erasure statement does not match the retired descriptor")
	}
	operator, err := retired.Topology.OperatorByID(statement.OperatorID)
	if err != nil {
		return fmt.Errorf("erasure operator %q is not in the retired epoch", statement.OperatorID)
	}
	public, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return errors.New("invalid operator identity key")
	}
	message, err := ErasureMessage(ErasementInput(statement))
	if err != nil {
		return err
	}
	signature, err := decodeBase64(statement.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return errors.New("erasure statement signature verification failed")
	}
	return nil
}

func EncodeErasureStatement(statement ErasureStatement) ([]byte, error) {
	return json.MarshalIndent(statement, "", "  ")
}
