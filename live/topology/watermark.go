package topology

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrTopologyRollback reports a topology older than one this node has already
// accepted for this network.
var ErrTopologyRollback = errors.New("topology epoch is older than the highest accepted")

// ErrTopologyEquivocation reports two different topologies claiming the same
// network and epoch.
var ErrTopologyEquivocation = errors.New("two topologies signed for the same network epoch")

// WatermarkVersion is the on-disk format tag.
const WatermarkVersion = "nomad-topology-watermark-v1"

type watermarkFile struct {
	Version   string `json:"version"`
	NetworkID string `json:"network_id"`
	Epoch     uint64 `json:"epoch"`
	Digest    string `json:"digest"`
}

// AcceptMonotonic records that this node is running the given topology, and
// refuses one that goes backwards.
//
// Signature and validity-window checks alone do not stop a rollback: an older
// topology that is still inside its own validity window remains perfectly
// valid to Verify. Replaying one is how an operator removed from the set, or a
// peer whose key was rotated away, is put back -- by restoring a stale
// directory rather than by forging anything. The watermark is the missing
// piece of state that makes "newer than what I have already served" a
// checkable property.
//
// Equal epoch with a different digest is equivocation and fails closed rather
// than picking a side. It records only public topology values: network, epoch
// and the topology digest, never anything about what this node carried.
func AcceptMonotonic(path string, verified Verified) error {
	if path == "" {
		return errors.New("topology watermark path is required")
	}
	previous, err := readWatermark(path)
	if err != nil {
		return err
	}
	if previous != nil && previous.NetworkID == verified.Document.NetworkID {
		switch {
		case verified.Document.Epoch < previous.Epoch:
			return fmt.Errorf("%w: offered epoch %d, already accepted %d",
				ErrTopologyRollback, verified.Document.Epoch, previous.Epoch)
		case verified.Document.Epoch == previous.Epoch &&
			previous.Digest != hex.EncodeToString(verified.Digest[:]):
			return fmt.Errorf("%w: epoch %d", ErrTopologyEquivocation, verified.Document.Epoch)
		case verified.Document.Epoch == previous.Epoch:
			return nil
		}
	}
	return writeWatermark(path, watermarkFile{
		Version: WatermarkVersion, NetworkID: verified.Document.NetworkID,
		Epoch: verified.Document.Epoch, Digest: hex.EncodeToString(verified.Digest[:]),
	})
}

func readWatermark(path string) (*watermarkFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return nil, errors.New("topology watermark must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored watermarkFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode topology watermark: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing topology watermark data")
	}
	// A watermark this node cannot interpret is not permission to proceed.
	if stored.Version != WatermarkVersion {
		return nil, errors.New("unsupported topology watermark version")
	}
	if stored.Epoch == 0 || !operatorIDPattern.MatchString(stored.NetworkID) {
		return nil, errors.New("invalid topology watermark contents")
	}
	if _, err := hex.DecodeString(stored.Digest); err != nil || len(stored.Digest) != 64 {
		return nil, errors.New("invalid topology watermark digest")
	}
	return &stored, nil
}

func writeWatermark(path string, contents watermarkFile) error {
	encoded, err := json.Marshal(contents)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".watermark-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(directory)
}

func syncDir(path string) error {
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
