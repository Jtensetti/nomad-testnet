// Package materialize is the private-side fixed cache scanner. It imports no
// UDP or network-control package and has no API that accepts a reader query.
package materialize

import (
	"bytes"
	"context"
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
	"strings"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
)

type Materializer struct {
	Cache       *rawcache.Store
	Descriptor  batch.VerifiedDescriptor
	PartialsDir string
	OutputDir   string
	Interval    time.Duration
}

func (materializer Materializer) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if materializer.Cache == nil || materializer.PartialsDir == "" || materializer.OutputDir == "" || materializer.Interval <= 0 {
		return errors.New("materializer requires cache, partials, output and fixed interval")
	}
	if err := ensureOutputDirectory(materializer.OutputDir); err != nil {
		return err
	}
	ticker := time.NewTicker(materializer.Interval)
	defer ticker.Stop()
	for {
		if _, err := materializer.ProcessOnce(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (materializer Materializer) ProcessOnce() (bool, error) {
	if materializer.Cache == nil || materializer.PartialsDir == "" || materializer.OutputDir == "" {
		return false, errors.New("materializer requires cache, partials and output")
	}
	if err := ensureOutputDirectory(materializer.OutputDir); err != nil {
		return false, err
	}
	outputPath := filepath.Join(materializer.OutputDir, hex.EncodeToString(materializer.Descriptor.Root[:])+".nomadobject")
	if existing, err := os.ReadFile(outputPath); err == nil {
		if err := verifyOutput(existing, materializer.Descriptor); err != nil {
			return false, err
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	payloads, complete, err := materializer.Cache.Load(materializer.Descriptor.Stream)
	if err != nil || !complete {
		return false, err
	}
	wireCells := make([]mix.WireCell, len(payloads))
	for index, payload := range payloads {
		copy(wireCells[index][:hop.CiphertextSize], payload[:])
	}
	encrypted, err := mix.ParseWire(wireCells)
	if err != nil {
		return false, fmt.Errorf("parse cached mix batch: %w", err)
	}
	partials, err := materializer.loadPartials(encrypted)
	if err != nil {
		return false, err
	}
	if len(partials) < int(materializer.Descriptor.Committee.Threshold) {
		return false, nil
	}
	plainCells, err := mix.ThresholdDecrypt(materializer.Descriptor.Committee, encrypted, partials)
	if err != nil {
		return false, err
	}
	decoder, err := newPacketDecoder(materializer.Descriptor)
	if err != nil {
		return false, err
	}
	fragments := make([][]byte, len(plainCells))
	for index := range plainCells {
		fragments[index] = append([]byte(nil), plainCells[index][:]...)
	}
	recovered, err := reconstruct.Reconstruct(decoder, fragments, reconstruct.Verifier{
		Root: materializer.Descriptor.Root, PublicKey: materializer.Descriptor.Publisher,
		Signature: materializer.Descriptor.Signature,
	})
	if err != nil {
		return false, fmt.Errorf("local reconstruction: %w", err)
	}
	if len(recovered) != int(materializer.Descriptor.Descriptor.OriginalSize) {
		return false, errors.New("reconstructed object length mismatch")
	}
	envelope := batch.SignedEnvelope{
		Version: batch.EnvelopeVersion, Payload: base64.StdEncoding.EncodeToString(recovered),
		ContentHash:  hex.EncodeToString(materializer.Descriptor.Root[:]),
		PublisherKey: base64.StdEncoding.EncodeToString(materializer.Descriptor.Publisher),
		Signature:    base64.StdEncoding.EncodeToString(materializer.Descriptor.Signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return false, err
	}
	if err := verifyOutput(encoded, materializer.Descriptor); err != nil {
		return false, err
	}
	if err := writeImmutable(outputPath, encoded); err != nil {
		return false, err
	}
	return true, nil
}

func ensureOutputDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("materializer output must be a real directory")
	}
	return nil
}

func (materializer Materializer) loadPartials(encrypted *mix.Batch) ([]*mix.PartialDecryption, error) {
	entries, err := os.ReadDir(materializer.PartialsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	prefix := materializer.Descriptor.Descriptor.StreamID + "-"
	seen := make(map[uint32]struct{})
	partials := make([]*mix.PartialDecryption, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".partial.json") {
			continue
		}
		path := filepath.Join(materializer.PartialsDir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > batch.MaximumFileBytes {
			_ = file.Close()
			return nil, errors.New("partial file has invalid type or size")
		}
		encoded, err := io.ReadAll(io.LimitReader(file, batch.MaximumFileBytes+1))
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		partial, err := batch.DecodePartial(encoded, materializer.Descriptor)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[partial.MemberIndex]; exists {
			return nil, errors.New("duplicate threshold member partial")
		}
		if err := mix.VerifyPartialDecryption(materializer.Descriptor.Committee, encrypted, partial); err != nil {
			return nil, err
		}
		seen[partial.MemberIndex] = struct{}{}
		partials = append(partials, partial)
	}
	return partials, nil
}

type packetDecoder struct {
	expectedGeneration rlnc.GenerationID
	k                  int
	symbolSize         int
	originalSize       int
	decoder            *rlnc.Decoder
}

func newPacketDecoder(descriptor batch.VerifiedDescriptor) (*packetDecoder, error) {
	k := int(descriptor.Descriptor.K)
	symbolSize := int(descriptor.Descriptor.SymbolSize)
	originalSize := int(descriptor.Descriptor.OriginalSize)
	decoder, err := rlnc.NewDecoder(k, symbolSize, originalSize)
	if err != nil {
		return nil, err
	}
	return &packetDecoder{
		expectedGeneration: descriptor.Generation, k: k, symbolSize: symbolSize,
		originalSize: originalSize, decoder: decoder,
	}, nil
}

func (decoder *packetDecoder) Add(fragment []byte) error {
	packet, err := rlnc.ParsePacket(fragment)
	if err != nil {
		return err
	}
	if packet.Generation != decoder.expectedGeneration || packet.K != decoder.k || packet.SymbolSize != decoder.symbolSize || packet.OriginalSize != decoder.originalSize {
		return errors.New("coded packet metadata differs from signed descriptor")
	}
	_, err = decoder.decoder.Add(packet.Symbol)
	return err
}

func (decoder *packetDecoder) Ready() bool { return decoder.decoder.Ready() }

func (decoder *packetDecoder) Decode() ([]byte, error) { return decoder.decoder.Decode() }

func verifyOutput(encoded []byte, descriptor batch.VerifiedDescriptor) error {
	var envelope batch.SignedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing materialized object data")
	}
	payload, root, publisher, signature, err := batch.VerifyEnvelope(envelope)
	if err != nil {
		return err
	}
	if root != descriptor.Root || !bytes.Equal(publisher, descriptor.Publisher) || !bytes.Equal(signature, descriptor.Signature) || uint32(len(payload)) != descriptor.Descriptor.OriginalSize {
		return errors.New("materialized envelope differs from signed descriptor")
	}
	return nil
}

func writeImmutable(path string, encoded []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".object-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	// Verified objects are public, signed content. Read-only consumers such as
	// the sandboxed browser may run under a different local UID.
	if err := temporary.Chmod(0o644); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func OutputDigest(path string) ([32]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
