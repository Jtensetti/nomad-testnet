package rotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	artifactCertificate = "certificate"
	artifactDraft       = "draft"
	artifactDescriptor  = "descriptor"
	artifactApproval    = "approval"
	artifactActivation  = "activation"
)

var controlOperatorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Exchange is the public epoch-control mailbox. Operators write only their
// own verified, signed artifacts to the local side; peers can only GET exact
// immutable names. There is deliberately no remote write or listing API.
type Exchange struct {
	root   string
	client *http.Client
}

func OpenExchange(root string) (*Exchange, error) {
	return openExchange(root, nil)
}

// openExchange accepts a transport only for same-package boundary tests. The
// production constructor deliberately fixes the HTTP behavior: callers must
// not be able to install a redirecting or retrying transport that turns one
// aligned public fetch into a private-state-dependent request sequence.
func openExchange(root string, client *http.Client) (*Exchange, error) {
	if root == "" {
		return nil, errors.New("epoch exchange root is required")
	}
	if err := ensureRealDirectory(root); err != nil {
		return nil, err
	}
	if client == nil {
		transport := &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13},
			DisableKeepAlives: true,
		}
		client = &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Exchange{root: root, client: client}, nil
}

// ControlEndpoint derives the lifecycle service from the signed DKG endpoint.
// The immediately following TCP port is reserved for this public service, so
// no unsigned discovery document or fallback address can redirect it.
func ControlEndpoint(dkgEndpoint string) (string, error) {
	return topology.EpochControlEndpoint(dkgEndpoint)
}

func (exchange *Exchange) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/v1/epoch/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		epochNumber, kind, operatorID, err := parseControlPath(request.URL.EscapedPath())
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		path, err := exchange.path(epochNumber, kind, operatorID)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		encoded, err := readBoundedRegular(path, epoch.MaximumFileBytes)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(encoded)
	})
	return mux
}

func parseControlPath(escaped string) (uint64, string, string, error) {
	if strings.Contains(escaped, "%") || strings.Contains(escaped, "//") {
		return 0, "", "", errors.New("non-canonical control path")
	}
	parts := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "epoch" || len(parts[2]) != 20 {
		return 0, "", "", errors.New("invalid control path")
	}
	epochNumber, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || epochNumber == 0 || fmt.Sprintf("%020d", epochNumber) != parts[2] {
		return 0, "", "", errors.New("invalid control epoch")
	}
	switch {
	case len(parts) == 4 && (parts[3] == artifactCertificate || parts[3] == artifactDraft || parts[3] == artifactDescriptor):
		return epochNumber, parts[3], "", nil
	case len(parts) == 5 && (parts[3] == artifactApproval || parts[3] == artifactActivation) && controlOperatorPattern.MatchString(parts[4]):
		return epochNumber, parts[3], parts[4], nil
	default:
		return 0, "", "", errors.New("invalid control artifact")
	}
}

func (exchange *Exchange) path(epochNumber uint64, kind, operatorID string) (string, error) {
	if exchange == nil || epochNumber == 0 {
		return "", errors.New("complete epoch exchange path is required")
	}
	directory := filepath.Join(exchange.root, fmt.Sprintf("epoch-%020d", epochNumber))
	var name string
	switch kind {
	case artifactCertificate, artifactDraft, artifactDescriptor:
		if operatorID != "" {
			return "", errors.New("operator ID is not valid for singleton artifact")
		}
		name = kind + ".json"
	case artifactApproval, artifactActivation:
		if !controlOperatorPattern.MatchString(operatorID) {
			return "", errors.New("invalid control artifact operator")
		}
		name = kind + "-" + operatorID + ".json"
	default:
		return "", errors.New("unknown epoch control artifact")
	}
	return filepath.Join(directory, name), nil
}

func (exchange *Exchange) Publish(epochNumber uint64, kind, operatorID string, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > epoch.MaximumFileBytes {
		return errors.New("epoch control artifact is empty or too large")
	}
	path, err := exchange.path(epochNumber, kind, operatorID)
	if err != nil {
		return err
	}
	if err := ensureRealDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	existing, err := readBoundedRegular(path, epoch.MaximumFileBytes)
	if err == nil {
		if !bytes.Equal(existing, encoded) {
			return errors.New("published epoch control artifact conflicts with immutable local state")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeExclusive(path, encoded, 0o644)
}

// Fetch performs exactly one request. The aligned public controller loop, not
// this method, decides if another request is due; there is no immediate retry
// or catch-up path after timeout, refusal or malformed input.
func (exchange *Exchange) Fetch(ctx context.Context, operator topology.Operator, epochNumber uint64, kind, operatorID string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("epoch exchange fetch requires context")
	}
	if _, err := exchange.path(epochNumber, kind, operatorID); err != nil {
		return nil, err
	}
	base, err := ControlEndpoint(operator.DKGEndpoint)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/epoch/%020d/%s", epochNumber, kind)
	if operatorID != "" {
		path += "/" + operatorID
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := exchange.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return nil, fmt.Errorf("epoch control endpoint returned %s", response.Status)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("epoch control endpoint returned an unexpected content type")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, epoch.MaximumFileBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > epoch.MaximumFileBytes {
		return nil, errors.New("epoch control endpoint returned an invalid bounded artifact")
	}
	return encoded, nil
}
