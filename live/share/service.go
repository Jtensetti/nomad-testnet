// Package share performs local threshold-share work from the raw cache. It is
// a separate process from the UDP node and exposes no network endpoint.
package share

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
)

// EpochGuard reports whether an epoch may still be served. The share
// service consults it before every partial decryption and before every HTTP
// response so that a retired epoch cannot remain usable merely because a
// partial-decryption file already exists. live/epoch.FreshGuard is the
// production implementation.
type EpochGuard interface {
	ServesEpoch(epochNumber uint64, now time.Time) error
}

type Service struct {
	Cache         *rawcache.Store
	Descriptor    batch.VerifiedDescriptor
	Secret        mix.MemberSecret
	OutputDir     string
	Interval      time.Duration
	ListenAddress string
	// Guard is required. A nil guard is refused rather than treated as
	// "always allowed": retirement must fail closed.
	Guard EpochGuard
	// Now supplies the clock, injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

func (service Service) now() time.Time {
	if service.Now != nil {
		return service.Now()
	}
	return time.Now().UTC()
}

func (service Service) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if service.Cache == nil || service.OutputDir == "" || service.Interval <= 0 || service.ListenAddress == "" {
		return errors.New("share service requires cache, output directory, fixed interval and listen address")
	}
	if service.Guard == nil {
		return errors.New("share service requires an epoch guard")
	}
	// Fail before opening a network listener if the epoch is not ACTIVE.
	// This decision depends only on public epoch state and therefore may
	// deliberately change at a signed public transition boundary.
	if err := service.Guard.ServesEpoch(service.Descriptor.Committee.Epoch, service.now()); err != nil {
		return fmt.Errorf("refusing to start threshold service for epoch %d: %w", service.Descriptor.Committee.Epoch, err)
	}
	if err := ensureOutputDirectory(service.OutputDir); err != nil {
		return err
	}
	ticker := time.NewTicker(service.Interval)
	defer ticker.Stop()
	server := &http.Server{
		Addr: service.ListenAddress, Handler: service.handler(),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	for {
		if _, err := service.ProcessOnce(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-serverErrors:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
		}
	}
}

func (service Service) handler() http.Handler {
	expectedPath := "/v1/partial/" + service.Descriptor.Descriptor.StreamID + "/" + strconv.FormatUint(uint64(service.Secret.Index), 10)
	filePath := filepath.Join(service.OutputDir, fmt.Sprintf("%s-%02d.partial.json", service.Descriptor.Descriptor.StreamID, service.Secret.Index))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet || request.URL.Path != expectedPath || request.URL.RawQuery != "" {
			http.NotFound(response, request)
			return
		}
		if service.Guard == nil {
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
			return
		}
		// Existing partials are still epoch-scoped outputs. Do not serve one
		// after retirement merely because its file remains on disk.
		if err := service.Guard.ServesEpoch(service.Descriptor.Committee.Epoch, service.now()); err != nil {
			http.Error(response, "retired", http.StatusGone)
			return
		}
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > batch.MaximumFileBytes {
			http.NotFound(response, request)
			return
		}
		encoded, err := os.ReadFile(filePath)
		if err != nil || len(encoded) > batch.MaximumFileBytes {
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/vnd.nomad.partial+json")
		response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(encoded)
	})
}

func (service Service) ProcessOnce() (bool, error) {
	if service.Cache == nil || service.OutputDir == "" {
		return false, errors.New("share service requires cache and output directory")
	}
	if service.Guard == nil {
		return false, errors.New("share service requires an epoch guard")
	}
	if err := service.Guard.ServesEpoch(service.Descriptor.Committee.Epoch, service.now()); err != nil {
		return false, fmt.Errorf("refusing threshold work for epoch %d: %w", service.Descriptor.Committee.Epoch, err)
	}
	if err := ensureOutputDirectory(service.OutputDir); err != nil {
		return false, err
	}
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

func ensureOutputDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("share output must be a real directory")
	}
	return nil
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
