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
	if decoded, err := hex.DecodeString(statement.TopologyDigest); err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != statement.TopologyDigest {
		return nil, errors.New("invalid failed-DKG topology digest")
	}
	if decoded, err := hex.DecodeString(statement.FileSHA256); err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != statement.FileSHA256 {
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
	message := make([]byte, 0, len(discardDomain)+len(digest))
	message = append(message, discardDomain...)
	message = append(message, digest[:]...)
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
// activated DKG attempt. It persists the signed original-file metadata in a
// .pending file before destruction; after overwrite/unlink it atomically
// renames that intent to the final evidence path. Therefore a crash at any
// point can resume without inventing a new pre-erasure digest.
func DiscardFailedShare(networkID string, epochNumber uint64, attempt int, topologyDigest, operatorID, sharePath, statementPath string, identity ed25519.PrivateKey, now time.Time) (DiscardStatement, error) {
	if len(identity) != ed25519.PrivateKeySize || networkID == "" || operatorID == "" || epochNumber == 0 || attempt < 1 {
		return DiscardStatement{}, errors.New("complete failed-DKG discard context is required")
	}
	public := identity.Public().(ed25519.PublicKey)
	pendingPath := statementPath + ".pending"
	finalExists, err := regularFileExists(statementPath)
	if err != nil {
		return DiscardStatement{}, err
	}
	pendingExists, err := regularFileExists(pendingPath)
	if err != nil {
		return DiscardStatement{}, err
	}
	if finalExists && pendingExists {
		return DiscardStatement{}, errors.New("both pending and final failed-DKG discard evidence exist")
	}
	if finalExists {
		statement, err := loadAndVerifyDiscard(statementPath, networkID, epochNumber, attempt, topologyDigest, operatorID, filepath.Base(sharePath), public)
		if err != nil {
			return DiscardStatement{}, err
		}
		if exists, err := pathExists(sharePath); err != nil {
			return DiscardStatement{}, err
		} else if exists {
			return DiscardStatement{}, errors.New("failed DKG share exists despite completed discard evidence")
		}
		return statement, nil
	}

	var statement DiscardStatement
	if pendingExists {
		statement, err = loadAndVerifyDiscard(pendingPath, networkID, epochNumber, attempt, topologyDigest, operatorID, filepath.Base(sharePath), public)
		if err != nil {
			return DiscardStatement{}, err
		}
	} else {
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
		statement = DiscardStatement{
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
		encoded, err := json.MarshalIndent(statement, "", "  ")
		if err != nil {
			return DiscardStatement{}, err
		}
		if err := writeExclusive(pendingPath, encoded, 0o600); err != nil {
			return DiscardStatement{}, err
		}
	}

	shareExists, err := pathExists(sharePath)
	if err != nil {
		return DiscardStatement{}, err
	}
	if shareExists {
		if err := verifyCurrentShareMatchesStatement(sharePath, statement); err != nil {
			return DiscardStatement{}, err
		}
		if err := overwriteAndUnlink(sharePath, statement.SizeBytes); err != nil {
			return DiscardStatement{}, err
		}
	}
	if err := os.Rename(pendingPath, statementPath); err != nil {
		return DiscardStatement{}, err
	}
	if err := syncDirectory(filepath.Dir(statementPath)); err != nil {
		return DiscardStatement{}, err
	}
	return statement, nil
}

func loadAndVerifyDiscard(path, networkID string, epochNumber uint64, attempt int, topologyDigest, operatorID, file string, public ed25519.PublicKey) (DiscardStatement, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return DiscardStatement{}, err
	}
	statement, err := decodeDiscard(encoded)
	if err != nil {
		return DiscardStatement{}, err
	}
	if statement.NetworkID != networkID || statement.Epoch != epochNumber || statement.Attempt != attempt ||
		statement.TopologyDigest != topologyDigest || statement.OperatorID != operatorID || statement.File != file {
		return DiscardStatement{}, errors.New("stored failed-DKG discard statement conflicts with requested attempt")
	}
	if err := VerifyDiscard(statement, operatorID, public); err != nil {
		return DiscardStatement{}, err
	}
	return statement, nil
}

func verifyCurrentShareMatchesStatement(path string, statement DiscardStatement) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != statement.SizeBytes {
		return errors.New("failed DKG share changed after discard intent was persisted")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != statement.FileSHA256 {
		return errors.New("failed DKG share digest changed after discard intent was persisted")
	}
	return nil
}

func overwriteAndUnlink(path string, size int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	noise := make([]byte, size)
	if _, err := rand.Read(noise); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteAt(noise, 0); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
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

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("discard evidence path exists but is not a regular file")
	}
	return true, nil
}
