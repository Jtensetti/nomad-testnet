package rotation

import (
	"bytes"
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
	"time"
)

const (
	DiscardVersion = "nomad-dkg-discard-v1"
	discardDomain  = "nomad-dkg-discard-v1"
)

const DiscardLimitations = "Overwrite-then-unlink destroys the failed DKG share as visible to the filesystem. " +
	"It does not guarantee physical destruction on journaling filesystems, flash with wear levelling, snapshots, backups or copy-on-write clones. " +
	"Operators must use encrypted storage and must not back up failed DKG share directories."

type DiscardStatement struct {
	Version        string `json:"version"`
	NetworkID      string `json:"network_id"`
	Epoch          uint64 `json:"epoch"`
	Attempt        int    `json:"attempt"`
	TopologyDigest string `json:"topology_digest"`
	OperatorID     string `json:"operator_id"`
	File           string `json:"file"`
	SizeBytes      int64  `json:"size_bytes"`
	FileSHA256     string `json:"file_sha256"`
	DiscardedAt    string `json:"discarded_at"`
	Method         string `json:"method"`
	Limitations    string `json:"limitations"`
	Signature      string `json:"signature"`
}

func discardMessage(statement DiscardStatement) ([]byte, error) {
	if statement.Version != DiscardVersion || statement.NetworkID == "" || statement.OperatorID == "" || statement.Epoch == 0 || statement.Attempt < 1 {
		return nil, errors.New("invalid failed-DKG discard identity")
	}
	if _, err := hex.DecodeString(statement.TopologyDigest); err != nil || len(statement.TopologyDigest) != 64 {
		return nil, errors.New("invalid failed-DKG topology digest")
	}
	if _, err := hex.DecodeString(statement.FileSHA256); err != nil || len(statement.FileSHA256) != 64 {
		return nil, errors.New("invalid failed-DKG file digest")
	}
	if statement.File == "" || filepath.Base(statement.File) != statement.File || statement.SizeBytes <= 0 {
		return nil, errors.New("invalid failed-DKG discarded file metadata")
	}
	if statement.Method != "overwrite-random-then-unlink" || statement.Limitations != DiscardLimitations {
		return nil, errors.New("invalid failed-DKG discard method or limitations")
	}
	parsed, err := time.Parse(time.RFC3339, statement.DiscardedAt)
	if err != nil || parsed.UTC().Format(time.RFC3339) != statement.DiscardedAt {
		return nil, errors.New("invalid failed-DKG discard time")
	}
	unsigned := statement
	unsigned.Signature = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	message := append([]byte(discardDomain), digest[:]...)
	return message, nil
}

func VerifyDiscard(statement DiscardStatement, expectedOperatorID string, identity ed25519.PublicKey) error {
	if statement.OperatorID != expectedOperatorID || len(identity) != ed25519.PublicKeySize {
		return errors.New("failed-DKG discard signer mismatch")
	}
	message, err := discardMessage(statement)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(statement.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(identity, message, signature) {
		return errors.New("failed-DKG discard signature verification failed")
	}
	return nil
}

// DiscardFailedShare destroys private share output from a failed, never-
// activated DKG attempt and persists a signed statement. The DKG journal and
// public certificate (if any) are deliberately retained as failure evidence.
// Re-running after a successful discard is idempotent and verifies the stored
// statement instead of inventing new file metadata.
func DiscardFailedShare(networkID string, epochNumber uint64, attempt int, topologyDigest, operatorID, sharePath, statementPath string, identity ed25519.PrivateKey, now time.Time) (DiscardStatement, error) {
	if len(identity) != ed25519.PrivateKeySize || networkID == "" || operatorID == "" || epochNumber == 0 || attempt < 1 {
		return DiscardStatement{}, errors.New("complete failed-DKG discard context is required")
	}
	public := identity.Public().(ed25519.PublicKey)
	if encoded, err := os.ReadFile(statementPath); err == nil {
		statement, err := decodeDiscard(encoded)
		if err != nil {
			return DiscardStatement{}, err
		}
		if statement.NetworkID != networkID || statement.Epoch != epochNumber || statement.Attempt != attempt || statement.TopologyDigest != topologyDigest || statement.File != filepath.Base(sharePath) {
			return DiscardStatement{}, errors.New("stored failed-DKG discard statement conflicts with requested attempt")
		}
		if err := VerifyDiscard(statement, operatorID, public); err != nil {
			return DiscardStatement{}, err
		}
		if _, err := os.Lstat(sharePath); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return DiscardStatement{}, errors.New("failed DKG share exists despite a completed discard statement")
			}
			return DiscardStatement{}, err
		}
		return statement, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DiscardStatement{}, err
	}

	info, err := os.Lstat(sharePath)
	if err != nil {
		return DiscardStatement{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8<<20 {
		return DiscardStatement{}, errors.New("failed DKG share must be a non-empty bounded regular file")
	}
	contents, err := os.ReadFile(sharePath)
	if err != nil {
		return DiscardStatement{}, err
	}
	digest := sha256.Sum256(contents)
	statement := DiscardStatement{
		Version: DiscardVersion, NetworkID: networkID, Epoch: epochNumber, Attempt: attempt,
		TopologyDigest: topologyDigest, OperatorID: operatorID, File: filepath.Base(sharePath),
		SizeBytes: info.Size(), FileSHA256: hex.EncodeToString(digest[:]),
		DiscardedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Method: "overwrite-random-then-unlink", Limitations: DiscardLimitations,
	}
	message, err := discardMessage(statement)
	if err != nil {
		return DiscardStatement{}, err
	}
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))

	file, err := os.OpenFile(sharePath, os.O_WRONLY, 0o600)
	if err != nil {
		return DiscardStatement{}, err
	}
	noise := make([]byte, info.Size())
	if _, err := rand.Read(noise); err != nil {
		_ = file.Close()
		return DiscardStatement{}, err
	}
	if _, err := file.WriteAt(noise, 0); err != nil {
		_ = file.Close()
		return DiscardStatement{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return DiscardStatement{}, err
	}
	if err := file.Close(); err != nil {
		return DiscardStatement{}, err
	}
	if err := os.Remove(sharePath); err != nil {
		return DiscardStatement{}, err
	}
	if err := syncDirectory(filepath.Dir(sharePath)); err != nil {
		return DiscardStatement{}, err
	}
	encoded, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return DiscardStatement{}, err
	}
	if err := writeExclusive(statementPath, encoded, 0o600); err != nil {
		return DiscardStatement{}, err
	}
	return statement, nil
}

func decodeDiscard(encoded []byte) (DiscardStatement, error) {
	if len(encoded) == 0 || len(encoded) > 32<<10 {
		return DiscardStatement{}, errors.New("failed-DKG discard statement is empty or too large")
	}
	var statement DiscardStatement
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statement); err != nil {
		return DiscardStatement{}, fmt.Errorf("decode failed-DKG discard statement: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return DiscardStatement{}, errors.New("trailing failed-DKG discard statement data")
	}
	return statement, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if err := ensureRealDirectory(parent); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	ok = true
	return nil
}
