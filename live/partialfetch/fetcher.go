// Package partialfetch is a public, fixed-cadence control-plane process. It
// fetches opaque threshold proofs into a local directory. It cannot reconstruct
// content and has no reader-query API.
package partialfetch

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const MaximumPartialBytes = 4 << 20

type Fetcher struct {
	Topology topology.Verified
	StreamID string
	OutputDir string
	Interval time.Duration
	Client *http.Client
}

func New(network topology.Verified, streamID, outputDirectory string, interval time.Duration) (*Fetcher, error) {
	decoded, err := hex.DecodeString(streamID)
	if err != nil || len(decoded) != len(hop.StreamID{}) || streamID != hex.EncodeToString(decoded) {
		return nil, errors.New("partial fetcher stream ID is invalid")
	}
	if outputDirectory == "" || interval < 100*time.Millisecond || interval > time.Minute {
		return nil, errors.New("partial fetcher output or public interval is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.MaxIdleConns = len(network.Document.Operators)
	transport.MaxIdleConnsPerHost = 1
	transport.MaxConnsPerHost = 1
	client := &http.Client{
		Transport: transport,
		Timeout: interval * 3 / 4,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("partial endpoint redirects are forbidden")
		},
	}
	return &Fetcher{Topology: network, StreamID: streamID, OutputDir: outputDirectory, Interval: interval, Client: client}, nil
}

func (fetcher *Fetcher) Run(ctx context.Context) error {
	if fetcher == nil || fetcher.Client == nil {
		return errors.New("partial fetcher is not initialized")
	}
	if err := os.MkdirAll(fetcher.OutputDir, 0o700); err != nil {
		return err
	}
	next := time.Now()
	for {
		if err := waitUntil(ctx, next); err != nil {
			return err
		}
		if err := fetcher.PollOnce(ctx); err != nil {
			return err
		}
		next = next.Add(fetcher.Interval)
		if !time.Now().Before(next) {
			return errors.New("partial fetch cycle missed its public cadence")
		}
	}
}

func (fetcher *Fetcher) PollOnce(ctx context.Context) error {
	if fetcher == nil || fetcher.Client == nil {
		return errors.New("partial fetcher is not initialized")
	}
	type result struct {
		operator uint16
		encoded []byte
		available bool
		err error
	}
	results := make(chan result, len(fetcher.Topology.Document.Operators))
	for _, operator := range fetcher.Topology.Document.Operators {
		operator := operator
		go func() {
			encoded, available, err := fetcher.fetch(ctx, operator)
			results <- result{operator: operator.Index, encoded: encoded, available: available, err: err}
		}()
	}
	var localError error
	for range fetcher.Topology.Document.Operators {
		result := <-results
		if result.err != nil || !result.available {
			// Reachability and 404 are public availability state. Retrying on the
			// next fixed slot does not depend on private reader activity.
			continue
		}
		path := filepath.Join(fetcher.OutputDir, fmt.Sprintf("%s-%02d.partial.json", fetcher.StreamID, result.operator))
		if err := writeOrCompare(path, result.encoded); err != nil {
			localError = err
		}
	}
	return localError
}

func (fetcher *Fetcher) fetch(ctx context.Context, operator topology.Operator) ([]byte, bool, error) {
	base, err := url.Parse(operator.PartialEndpoint)
	if err != nil {
		return nil, false, err
	}
	base.Path = "/v1/partial/" + fetcher.StreamID + "/" + strconv.FormatUint(uint64(operator.Index), 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Accept", "application/vnd.nomad.partial+json")
	response, err := fetcher.Client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 || response.ContentLength > MaximumPartialBytes {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, false, errors.New("partial endpoint returned an invalid status or length")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, MaximumPartialBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumPartialBytes {
		return nil, false, errors.New("partial endpoint body is invalid")
	}
	return encoded, true, nil
}

func writeOrCompare(path string, encoded []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, encoded) {
			return errors.New("partial fetch equivocation")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".fetch-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
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
	return os.Rename(temporaryPath, path)
}

func waitUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
