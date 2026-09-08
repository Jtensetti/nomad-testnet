package loopback

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

// Service is the shim a deployment runs in front of its model server. It is
// the only process that sees a reader's query in the clear, and it holds the
// key that says so.
//
// It is deliberately not a proxy for anything else: one path, one method, one
// payload shape, and an upstream it will only reach over loopback. A shim that
// could be talked into forwarding elsewhere would be a hole straight through
// the property the browser core is built on.
type Service struct {
	// ServiceKey is shared with the clients allowed to use this service.
	ServiceKey []byte
	// Upstream computes the vector. A deployment normally uses
	// OpenAIUpstream pointed at its local model server.
	Upstream Upstream
	// MaxInputBytes bounds the query the service will accept. The client
	// bounds it too; neither side trusts the other's bound.
	MaxInputBytes int
	// MaxDimensions bounds the vector the service will return.
	MaxDimensions int
}

// Upstream produces an embedding for one input under one model.
type Upstream interface {
	Embed(ctx context.Context, model, input string) ([]float32, error)
}

// NewServiceKey draws a fresh service key. Deployments generate one, give it
// to the client and to the service, and to nothing else.
func NewServiceKey() ([]byte, error) {
	key := make([]byte, MinimumServiceKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// refuse answers without saying why.
//
// Every failure below is a client that could not produce a valid sealed
// request, and a client that cannot do that is not owed a description of which
// check it failed. The detail goes to the service's own logs, or nowhere; it
// does not go on the wire.
func refuse(w http.ResponseWriter, status int) {
	http.Error(w, "sealed embedding request refused", status)
}

func (s Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != SealedPath {
		refuse(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed)
		return
	}
	if err := checkServiceKey(s.ServiceKey); err != nil || s.Upstream == nil {
		refuse(w, http.StatusInternalServerError)
		return
	}
	maxInput, err := basin.BoundedInt(s.MaxInputBytes, basin.DefaultMaxInputBytes, basin.HardMaxInputBytes, "maximum input size")
	if err != nil {
		refuse(w, http.StatusInternalServerError)
		return
	}
	maxDimensions, err := basin.BoundedInt(s.MaxDimensions, basin.DefaultMaxEmbeddingDims, basin.HardMaxEmbeddingDims, "maximum dimensions")
	if err != nil {
		refuse(w, http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxSealedBytes+1))
	if err != nil || len(body) > maxSealedBytes {
		refuse(w, http.StatusBadRequest)
		return
	}
	if len(body) < 1+saltBytes || body[0] != sealVersion {
		refuse(w, http.StatusBadRequest)
		return
	}
	salt := body[1 : 1+saltBytes]
	payload, err := unseal(s.ServiceKey, salt, requestInfo, "request", body[1+saltBytes:])
	if err != nil {
		refuse(w, http.StatusBadRequest)
		return
	}

	var request embeddingRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		refuse(w, http.StatusBadRequest)
		return
	}
	input := strings.TrimSpace(request.Input)
	if request.Model == "" || input == "" || len(input) > maxInput {
		refuse(w, http.StatusBadRequest)
		return
	}

	vector, err := s.Upstream.Embed(r.Context(), request.Model, input)
	if err != nil {
		refuse(w, http.StatusBadGateway)
		return
	}
	if len(vector) == 0 || len(vector) > maxDimensions {
		refuse(w, http.StatusBadGateway)
		return
	}

	var response embeddingResponse
	response.Data = append(response.Data, struct {
		Embedding []float32 `json:"embedding"`
	}{Embedding: vector})
	plaintext, err := json.Marshal(response)
	if err != nil {
		refuse(w, http.StatusInternalServerError)
		return
	}
	sealed, err := seal(s.ServiceKey, salt, responseInfo, "response", plaintext)
	if err != nil {
		refuse(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// OpenAIUpstream speaks the common OpenAI-compatible /v1/embeddings shape to a
// model server on loopback. It is the last hop, and it is still constrained to
// loopback: the shim exists to hold a key, not to gain the ability to send a
// query somewhere the client could not.
type OpenAIUpstream struct {
	BaseURL string
	// APIKey is whatever the local model server wants, if anything. It never
	// leaves this process for anywhere but that server, and it is not what
	// authenticates a Nomad client.
	APIKey           string
	Timeout          time.Duration
	MaxResponseBytes int
}

// checkLoopbackBase rejects any base URL that could take query text off the
// host. It is shared by the client and the shim so both reach the same answer
// on the same string.
func checkLoopbackBase(raw string) error {
	if raw == "" {
		return errors.New("base URL is required")
	}
	base, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse base URL: %w", err)
	}
	if base.Scheme != "http" {
		return errors.New("loopback embedding endpoint must use http")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("embedding base URL must not contain user info, query or fragment")
	}
	ip := net.ParseIP(base.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("embedding endpoint host must be a literal loopback IP")
	}
	return nil
}

func (u OpenAIUpstream) Embed(ctx context.Context, model, input string) ([]float32, error) {
	if err := checkLoopbackBase(u.BaseURL); err != nil {
		return nil, err
	}
	maxResponse, err := basin.BoundedInt(u.MaxResponseBytes, basin.DefaultMaxEmbeddingResponse, basin.HardMaxEmbeddingResponse, "maximum response size")
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(embeddingRequest{Model: model, Input: input})
	if err != nil {
		return nil, err
	}
	timeout := u.Timeout
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
	endpoint := strings.TrimRight(u.BaseURL, "/") + "/v1/embeddings"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if u.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+u.APIKey)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("model server returned %s", response.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponse)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxResponse {
		return nil, errors.New("model server response exceeds maximum size")
	}
	var out embeddingResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	if len(out.Data) != 1 || len(out.Data[0].Embedding) == 0 {
		return nil, errors.New("model server response must contain exactly one non-empty vector")
	}
	return out.Data[0].Embedding, nil
}
