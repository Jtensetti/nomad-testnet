// Package share performs local threshold-share work from the raw cache. It is
// a separate process from the UDP node and exposes no network endpoint.
package share

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
)

type Service struct {
	Cache      *rawcache.Store
	Descriptor batch.VerifiedDescriptor
	Secret     mix.MemberSecret
	OutputDir  string
	Interval   time.Duration
}

func (service Service) Run(ctx context.Context) error {
	if service.Cache == nil || service.OutputDir == "" || service.Interval <= 0 {
		return errors.New("share service requires cache, output directory and fixed interval")
	}
	if err := os.MkdirAll(service.OutputDir, 0o700); err != nil {
		return err
	}
	ticker := time.NewTicker(service.Interval)
	defer ticker.Stop()
	for {
		if _, err := service.ProcessOnce(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (service Service) ProcessOnce() (bool, error) {
	payloads, complete, err := service.Cache.Load(service.Descriptor.Stream)
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
	path := filepath.Join(service.OutputDir, fmt.Sprintf("%s-%02d.partial.json", service.Descriptor.Descriptor.StreamID, service.Secret.Index))
	if existing, err := os.ReadFile(path); err == nil {
		partial, err := batch.DecodePartial(existing, service.Descriptor)
		if err != nil {
			return false, err
		}
		if partial.MemberIndex != service.Secret.Index {
			return false, errors.New("existing partial belongs to a different threshold member")
		}
		if err := mix.VerifyPartialDecryption(service.Descriptor.Committee, encrypted, partial); err != nil {
			return false, err
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	partial, err := mix.CreatePartialDecryption(service.Descriptor.Committee, service.Secret, encrypted)
	if err != nil {
		return false, err
	}
	if err := mix.VerifyPartialDecryption(service.Descriptor.Committee, encrypted, partial); err != nil {
		return false, err
	}
	file, err := batch.PartialToFile(service.Descriptor.Descriptor.StreamID, partial)
	if err != nil {
		return false, err
	}
	encoded, err := batch.EncodePartial(file)
	if err != nil {
		return false, err
	}
	return writeOrCompare(path, encoded)
}

func writeOrCompare(path string, encoded []byte) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, encoded) {
			return false, errors.New("partial-decryption output equivocation")
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".partial-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	return true, nil
}

func HealthJSON(operatorID string, complete bool) ([]byte, error) {
	return json.Marshal(struct {
		OperatorID string    `json:"operator_id"`
		Complete   bool      `json:"partial_complete"`
		UpdatedAt  time.Time `json:"updated_at"`
	}{operatorID, complete, time.Now().UTC()})
}
