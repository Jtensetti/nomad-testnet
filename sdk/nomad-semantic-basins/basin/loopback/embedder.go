// Package loopback holds the embedder that speaks to a local embedding
// service over HTTP.
//
// It is a separate package for one reason: importing it links net, net/http
// and crypto/tls, and the package that handles a user's query text must not
// drag a TLS stack and a full HTTP client into every binary that reads a
// query. The browser core's architecture rests on the statement that the
// process cannot open a socket, and a socket-capable transitive dependency
// inside basin made that statement false for anything importing basin --
// including github.com/Jtensetti/nomad-browser/selector, which is the private
// selection side.
//
// Nothing in the Nomad tree constructed the model server; this package is the
// integration point for a deployment that runs one, and Service is the shim
// that stands in front of it. Keeping both here means a deployment opts into
// the dependency explicitly, and that basin itself is socket-free by
// construction rather than by review.
//
// The wire format between HTTPEmbedder and Service is sealed under a shared
// service key; seal.go explains why the query is encrypted to the service
// rather than merely gated on proof that the service exists.
package loopback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

// HTTPEmbedder sends a sealed embedding request to a local Service. It accepts
// only literal loopback IPs, disables proxy use and rejects redirects, so
// private query text cannot leave the host through normal HTTP client
// configuration, and it seals the request so that being on the host is not
// enough to read it.
type HTTPEmbedder struct {
	BaseURL string
	Model   string

	// ServiceKey is shared with the embedding service and nothing else. It
	// authenticates both directions: only its holder can read the query, and
	// only its holder can produce a vector this client will accept.
	//
	// There is no unauthenticated mode. A client that would send the query
	// anyway when the key is missing is the silent fallback this design
	// exists to remove, so an absent key is refused rather than treated as
	// "no authentication required".
	ServiceKey []byte

	Timeout          time.Duration
	MaxInputBytes    int
	MaxDimensions    int
	MaxResponseBytes int
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (e HTTPEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, errors.New("text must not be empty")
	}
	maxInput, err := basin.BoundedInt(e.MaxInputBytes, basin.DefaultMaxInputBytes, basin.HardMaxInputBytes, "maximum input size")
	if err != nil {
		return nil, err
	}
	if len(trimmed) > maxInput {
		return nil, errors.New("text exceeds maximum input size")
	}
	maxDimensions, err := basin.BoundedInt(e.MaxDimensions, basin.DefaultMaxEmbeddingDims, basin.HardMaxEmbeddingDims, "maximum dimensions")
	if err != nil {
		return nil, err
	}
	maxResponse, err := basin.BoundedInt(e.MaxResponseBytes, basin.DefaultMaxEmbeddingResponse, basin.HardMaxEmbeddingResponse, "maximum response size")
	if err != nil {
		return nil, err
	}
	if e.BaseURL == "" || e.Model == "" {
		return nil, errors.New("base URL and model are required")
	}
	if err := checkServiceKey(e.ServiceKey); err != nil {
		return nil, err
	}
	if err := checkLoopbackBase(e.BaseURL); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(embeddingRequest{Model: e.Model, Input: trimmed})
	if err != nil {
		return nil, err
	}
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	sealed, err := seal(e.ServiceKey, salt, requestInfo, "request", payload)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 1+len(salt)+len(sealed))
	body = append(body, sealVersion)
	body = append(body, salt...)
	body = append(body, sealed...)

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("embedding endpoint redirects are disabled")
		},
	}

	endpoint := strings.TrimRight(e.BaseURL, "/") + SealedPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("embedding service returned %s", resp.Status)
	}
	sealedResponse, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	if err != nil {
		return nil, err
	}
	if len(sealedResponse) > maxResponse {
		return nil, errors.New("embedding response exceeds maximum size")
	}
	// The response opens only under a key derived from this request's salt,
	// so a vector reaches the caller only if it came from the key holder and
	// only if it answers this request rather than an earlier one.
	plaintext, err := unseal(e.ServiceKey, salt, responseInfo, "response", sealedResponse)
	if err != nil {
		return nil, fmt.Errorf("%w; the process listening on the embedding endpoint "+
			"does not hold the service key", err)
	}
	var out embeddingResponse
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return nil, err
	}
	if len(out.Data) != 1 || len(out.Data[0].Embedding) == 0 {
		return nil, errors.New("embedding response must contain exactly one non-empty vector")
	}
	if len(out.Data[0].Embedding) > maxDimensions {
		return nil, errors.New("embedding response exceeds maximum dimensions")
	}
	if !basin.Normalize(out.Data[0].Embedding) {
		return nil, errors.New("embedding response was the zero vector")
	}
	return out.Data[0].Embedding, nil
}
