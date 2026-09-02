// Package bundle is the public publication-fixture input to a network node.
// It carries already-encrypted mix ciphertext and never accepts reader state.
package bundle

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/strictjson"
)

const (
	Version          = "nomad-seed-bundle-v1"
	MaximumFileBytes = 2 << 20
)

type File struct {
	Version  string   `json:"version"`
	StreamID string   `json:"stream_id"`
	Cells    []string `json:"cells"`
}

type Verified struct {
	Stream   hop.StreamID
	Payloads [][hop.CiphertextSize]byte
}

func Load(path string) (Verified, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Verified{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return Verified{}, errors.New("seed bundle must be a bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return Verified{}, err
	}
	return Verify(encoded)
}

func Verify(encoded []byte) (Verified, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Verified{}, errors.New("seed bundle is empty or too large")
	}
	var file File
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return Verified{}, fmt.Errorf("decode seed bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verified{}, errors.New("trailing seed bundle data")
	}
	if file.Version != Version || len(file.Cells) < 2 || len(file.Cells) > hop.MaximumBatch {
		return Verified{}, errors.New("unsupported seed bundle profile")
	}
	decodedStream, err := hex.DecodeString(file.StreamID)
	if err != nil || len(decodedStream) != len(hop.StreamID{}) {
		return Verified{}, errors.New("invalid seed stream ID")
	}
	var stream hop.StreamID
	copy(stream[:], decodedStream)
	payloads := make([][hop.CiphertextSize]byte, len(file.Cells))
	for index, encodedCell := range file.Cells {
		decoded, err := strictjson.DecodeBase64(encodedCell)
		if err != nil || len(decoded) != hop.CiphertextSize {
			return Verified{}, fmt.Errorf("seed cell %d has invalid encoding or size", index)
		}
		copy(payloads[index][:], decoded)
	}
	calculated, err := hop.StreamFor(payloads)
	if err != nil {
		return Verified{}, err
	}
	if calculated != stream {
		return Verified{}, errors.New("seed stream commitment mismatch")
	}
	return Verified{Stream: stream, Payloads: payloads}, nil
}

func New(payloads [][hop.CiphertextSize]byte) (File, error) {
	stream, err := hop.StreamFor(payloads)
	if err != nil {
		return File{}, err
	}
	file := File{Version: Version, StreamID: hex.EncodeToString(stream[:]), Cells: make([]string, len(payloads))}
	for index, payload := range payloads {
		file.Cells[index] = base64.StdEncoding.EncodeToString(payload[:])
	}
	return file, nil
}

func Encode(file File) ([]byte, error) { return json.MarshalIndent(file, "", "  ") }

func (verified Verified) Cells() ([]fabric.Cell, error) {
	cells := make([]fabric.Cell, len(verified.Payloads))
	for index, payload := range verified.Payloads {
		metadata, err := hop.WorkMetadata(verified.Stream, uint16(index), uint16(len(verified.Payloads)))
		if err != nil {
			return nil, err
		}
		cell, err := hop.FromCiphertext(payload, metadata)
		if err != nil {
			return nil, err
		}
		cells[index] = cell
	}
	return cells, nil
}
