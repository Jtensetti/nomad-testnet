package epoch

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
	"path/filepath"
	"sort"
	"time"
)

const (
	ErasureIntentVersion = "nomad-epoch-erasure-intent-v1"
	erasureIntentDomain  = "nomad-epoch-erasure-intent-v1"
)

// ErasureIntentFile pins the pre-erasure state of one local private artifact.
// Absolute paths are local-only metadata and the intent file must remain 0600.
type ErasureIntentFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest_before_erasure"`
	Absent    bool   `json:"absent"`
}

// ErasureIntent is a signed, local crash-recovery record written before any
// destructive step. If the process dies after unlinking some files but before
// the public erasure statement is durable, the intent preserves the original
// digests so a retry can finish without inventing replacement evidence.
type ErasureIntent struct {
	Version          string              `json:"version"`
	NetworkID        string              `json:"network_id"`
	OperatorID       string              `json:"operator_id"`
	Epoch            uint64              `json:"epoch"`
	DescriptorDigest string              `json:"descriptor_digest"`
	Filesystem       string              `json:"filesystem"`
	PreparedAt       string              `json:"prepared_at"`
	Files            []ErasureIntentFile `json:"files"`
	Signature        string              `json:"signature"`
}

func erasureIntentMessage(intent ErasureIntent) ([]byte, error) {
	if intent.Version != ErasureIntentVersion || intent.NetworkID == "" || intent.OperatorID == "" || intent.Epoch == 0 {
		return nil, errors.New("invalid erasure intent identity")
	}
	if _, err := decodeHex(intent.DescriptorDigest, 32); err != nil {
		return nil, errors.New("invalid erasure intent descriptor digest")
	}
	if intent.Filesystem == "" || len(intent.Files) == 0 {
		return nil, errors.New("erasure intent requires filesystem and files")
	}
	if err := validateCanonicalTime(intent.PreparedAt); err != nil {
		return nil, fmt.Errorf("prepared_at: %w", err)
	}
	unsigned := intent
	unsigned.Signature = ""
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	message := make([]byte, 0, len(erasureIntentDomain)+len(digest))
	message = append(message, erasureIntentDomain...)
	message = append(message, digest[:]...)
	return message, nil
}

// NewErasureIntent snapshots and signs the pre-erasure state. No file is
// modified by this function.
func NewErasureIntent(retired Verified, operatorID string, paths []string, filesystem string, identity ed25519.PrivateKey, now time.Time) (ErasureIntent, error) {
	operator, found := operatorByID(retired.Topology, operatorID)
	if !found {
		return ErasureIntent{}, fmt.Errorf("operator %q is not in epoch %d", operatorID, retired.Epoch)
	}
	if len(identity) != ed25519.PrivateKeySize {
		return ErasureIntent{}, errors.New("operator identity is required")
	}
	expected, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(expected, identity.Public().(ed25519.PublicKey)) {
		return ErasureIntent{}, errors.New("operator identity does not match retired epoch")
	}
	if filesystem == "" || len(paths) == 0 {
		return ErasureIntent{}, errors.New("filesystem and at least one erasure path are required")
	}
	absolute := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		value, err := filepath.Abs(path)
		if err != nil {
			return ErasureIntent{}, err
		}
		value = filepath.Clean(value)
		if _, duplicate := seen[value]; duplicate {
			return ErasureIntent{}, fmt.Errorf("duplicate erasure path %q", path)
		}
		seen[value] = struct{}{}
		absolute = append(absolute, value)
	}
	sort.Strings(absolute)
	files := make([]ErasureIntentFile, 0, len(absolute))
	for _, path := range absolute {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			files = append(files, ErasureIntentFile{Path: path, Digest: hex.EncodeToString(make([]byte, 32)), Absent: true})
			continue
		}
		if err != nil {
			return ErasureIntent{}, err
		}
		if !info.Mode().IsRegular() {
			return ErasureIntent{}, fmt.Errorf("refusing to erase non-regular path %s", path)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return ErasureIntent{}, err
		}
		digest := sha256.Sum256(contents)
		files = append(files, ErasureIntentFile{Path: path, SizeBytes: info.Size(), Digest: hex.EncodeToString(digest[:])})
	}
	intent := ErasureIntent{
		Version: ErasureIntentVersion, NetworkID: retired.NetworkID, OperatorID: operatorID,
		Epoch: retired.Epoch, DescriptorDigest: hex.EncodeToString(retired.Digest[:]),
		Filesystem: filesystem, PreparedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), Files: files,
	}
	message, err := erasureIntentMessage(intent)
	if err != nil {
		return ErasureIntent{}, err
	}
	intent.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	return intent, nil
}

func VerifyErasureIntent(intent ErasureIntent, retired Verified) error {
	if intent.NetworkID != retired.NetworkID || intent.Epoch != retired.Epoch || intent.DescriptorDigest != hex.EncodeToString(retired.Digest[:]) {
		return errors.New("erasure intent belongs to a different epoch")
	}
	operator, found := operatorByID(retired.Topology, intent.OperatorID)
	if !found {
		return errors.New("erasure intent operator is not in the epoch")
	}
	message, err := erasureIntentMessage(intent)
	if err != nil {
		return err
	}
	public, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	signature, err := decodeBase64(intent.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return errors.New("erasure intent signature verification failed")
	}
	previous := ""
	for _, file := range intent.Files {
		if file.Path == "" || !filepath.IsAbs(file.Path) || (previous != "" && file.Path <= previous) {
			return errors.New("erasure intent paths must be absolute, unique and sorted")
		}
		previous = file.Path
		if _, err := decodeHex(file.Digest, 32); err != nil || file.SizeBytes < 0 {
			return errors.New("erasure intent contains invalid file metadata")
		}
		if file.Absent && (file.SizeBytes != 0 || file.Digest != hex.EncodeToString(make([]byte, 32))) {
			return errors.New("absent erasure intent file must carry zero size and digest")
		}
	}
	return nil
}

func EncodeErasureIntent(intent ErasureIntent) ([]byte, error) {
	if _, err := erasureIntentMessage(intent); err != nil {
		return nil, err
	}
	return json.MarshalIndent(intent, "", "  ")
}

func DecodeErasureIntent(encoded []byte) (ErasureIntent, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return ErasureIntent{}, errors.New("erasure intent is empty or too large")
	}
	var intent ErasureIntent
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return ErasureIntent{}, fmt.Errorf("decode erasure intent: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErasureIntent{}, errors.New("trailing erasure intent data")
	}
	return intent, nil
}

// ExecuteErasureIntent completes or resumes the destructive phase. A present
// file must still match the pre-erasure digest; an already-absent file that
// was present at preparation is treated as a completed step from a previous
// interrupted attempt. A path that was absent at preparation must remain
// absent, preventing an unrelated later file from being silently destroyed.
func ExecuteErasureIntent(intent ErasureIntent, retired Verified, identity ed25519.PrivateKey, now time.Time) (ErasureStatement, error) {
	if err := VerifyErasureIntent(intent, retired); err != nil {
		return ErasureStatement{}, err
	}
	operator, _ := operatorByID(retired.Topology, intent.OperatorID)
	expected, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil || len(identity) != ed25519.PrivateKeySize || !bytes.Equal(expected, identity.Public().(ed25519.PublicKey)) {
		return ErasureStatement{}, errors.New("operator identity does not match erasure intent")
	}
	directories := make(map[string]struct{}, len(intent.Files))
	records := make([]ErasedFile, 0, len(intent.Files))
	for _, planned := range intent.Files {
		directories[filepath.Dir(planned.Path)] = struct{}{}
		info, err := os.Lstat(planned.Path)
		if errors.Is(err, os.ErrNotExist) {
			if planned.Absent {
				records = append(records, ErasedFile{Path: planned.Path, SizeBytes: 0, Digest: planned.Digest})
			} else {
				records = append(records, ErasedFile{Path: planned.Path, SizeBytes: planned.SizeBytes, Digest: planned.Digest})
			}
			continue
		}
		if err != nil {
			return ErasureStatement{}, err
		}
		if planned.Absent {
			return ErasureStatement{}, fmt.Errorf("path %s appeared after erasure intent was prepared", planned.Path)
		}
		if !info.Mode().IsRegular() || info.Size() != planned.SizeBytes {
			return ErasureStatement{}, fmt.Errorf("path %s changed after erasure intent was prepared", planned.Path)
		}
		contents, err := os.ReadFile(planned.Path)
		if err != nil {
			return ErasureStatement{}, err
		}
		digest := sha256.Sum256(contents)
		if hex.EncodeToString(digest[:]) != planned.Digest {
			return ErasureStatement{}, fmt.Errorf("path %s changed after erasure intent was prepared", planned.Path)
		}
		record, err := eraseOne(planned.Path)
		if err != nil {
			return ErasureStatement{}, err
		}
		if record.SizeBytes != planned.SizeBytes || record.Digest != planned.Digest {
			return ErasureStatement{}, errors.New("erased file no longer matches prepared metadata")
		}
		record.Path = planned.Path
		records = append(records, record)
	}
	orderedDirectories := make([]string, 0, len(directories))
	for directory := range directories {
		orderedDirectories = append(orderedDirectories, directory)
	}
	sort.Strings(orderedDirectories)
	for _, directory := range orderedDirectories {
		if err := syncDir(directory); err != nil {
			return ErasureStatement{}, fmt.Errorf("persist erasure in %s: %w", directory, err)
		}
	}
	statement := ErasureStatement{
		Version: ErasureVersion, NetworkID: intent.NetworkID, OperatorID: intent.OperatorID,
		Epoch: intent.Epoch, DescriptorDigest: intent.DescriptorDigest, Files: records,
		Method: "prepared-digest-overwrite-random-then-unlink", Filesystem: intent.Filesystem,
		ErasedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), Limitations: ErasureLimitations,
	}
	message, err := ErasureMessage(ErasementInput(statement))
	if err != nil {
		return ErasureStatement{}, err
	}
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	return statement, nil
}
