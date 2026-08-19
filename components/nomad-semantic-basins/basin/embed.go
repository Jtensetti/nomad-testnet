package basin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultMaxInputBytes         = 64 << 10
	DefaultMaxEmbeddingDims      = 8192
	DefaultMaxEmbeddingResponse = 8 << 20
	HardMaxInputBytes            = 1 << 20
	HardMaxEmbeddingDims         = 1 << 16
	HardMaxEmbeddingResponse     = 32 << 20
)

type Embedder interface {
	Embed(context.Context, string) ([]float32, error)
}

// LexicalHashEmbedder is a deterministic bag-of-words/character-ngram
// baseline. It is useful for tests and lexical similarity only; it is not a
// semantic model.
type LexicalHashEmbedder struct {
	Dims          int
	MaxInputBytes int
}

func (h LexicalHashEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	if h.Dims <= 0 || h.Dims > HardMaxEmbeddingDims {
		return nil, errors.New("dims are outside the allowed range")
	}
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return nil, errors.New("text must not be empty")
	}
	maxInput, err := boundedInt(h.MaxInputBytes, DefaultMaxInputBytes, HardMaxInputBytes, "maximum input size")
	if err != nil {
		return nil, err
	}
	if len(s) > maxInput {
		return nil, errors.New("text exceeds maximum input size")
	}
	v := make([]float32, h.Dims)
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		tok := strings.TrimFunc(scanner.Text(), func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSpace(r) })
		if tok == "" {
			continue
		}
		f := fnv.New64a()
		_, _ = f.Write([]byte(tok))
		x := f.Sum64()
		idx := int(x % uint64(h.Dims))
		sign := float32(1)
		if (x>>63)&1 == 1 {
			sign = -1
		}
		v[idx] += sign

		rs := []rune(tok)
		for i := 0; i+2 < len(rs); i++ {
			f.Reset()
			_, _ = f.Write([]byte("3:" + string(rs[i:i+3])))
			y := f.Sum64()
			j := int(y % uint64(h.Dims))
			sg := float32(0.35)
			if (y>>63)&1 == 1 {
				sg = -sg
			}
			v[j] += sg
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !normalize(v) {
		return nil, errors.New("text produced an empty lexical vector")
	}
	return v, nil
}

// LoopbackHTTPEmbedder speaks the common OpenAI-compatible /v1/embeddings
// request shape. It accepts only literal loopback IPs, disables proxy use and
// rejects redirects so private query text cannot leave the host through normal
// HTTP client configuration.
type LoopbackHTTPEmbedder struct {
	BaseURL         string
	Model           string
	APIKey          string
	Timeout         time.Duration
	MaxInputBytes   int
	MaxDimensions   int
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

func (e LoopbackHTTPEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, errors.New("text must not be empty")
	}
	maxInput, err := boundedInt(e.MaxInputBytes, DefaultMaxInputBytes, HardMaxInputBytes, "maximum input size")
	if err != nil {
		return nil, err
	}
	if len(trimmed) > maxInput {
		return nil, errors.New("text exceeds maximum input size")
	}
	maxDimensions, err := boundedInt(e.MaxDimensions, DefaultMaxEmbeddingDims, HardMaxEmbeddingDims, "maximum dimensions")
	if err != nil {
		return nil, err
	}
	maxResponse, err := boundedInt(e.MaxResponseBytes, DefaultMaxEmbeddingResponse, HardMaxEmbeddingResponse, "maximum response size")
	if err != nil {
		return nil, err
	}
	if e.BaseURL == "" || e.Model == "" {
		return nil, errors.New("base URL and model are required")
	}
	base, err := url.Parse(e.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if base.Scheme != "http" {
		return nil, errors.New("loopback embedding endpoint must use http")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("embedding base URL must not contain user info, query or fragment")
	}
	ip := net.ParseIP(base.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("embedding endpoint host must be a literal loopback IP")
	}

	body, err := json.Marshal(embeddingRequest{Model: e.Model, Input: trimmed})
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(e.BaseURL, "/") + "/v1/embeddings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.APIKey)
	}

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
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("embedding service returned %s", resp.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxResponse {
		return nil, errors.New("embedding response exceeds maximum size")
	}
	var out embeddingResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	if len(out.Data) != 1 || len(out.Data[0].Embedding) == 0 {
		return nil, errors.New("embedding response must contain exactly one non-empty vector")
	}
	if len(out.Data[0].Embedding) > maxDimensions {
		return nil, errors.New("embedding response exceeds maximum dimensions")
	}
	if !normalize(out.Data[0].Embedding) {
		return nil, errors.New("embedding response was the zero vector")
	}
	return out.Data[0].Embedding, nil
}

func boundedInt(value, defaultValue, hardMaximum int, name string) (int, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < 0 || value > hardMaximum {
		return 0, fmt.Errorf("%s is outside the allowed range", name)
	}
	return value, nil
}

func normalize(v []float32) bool {
	var ss float64
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return false
		}
		ss += float64(x) * float64(x)
	}
	if ss == 0 {
		return false
	}
	inv := float32(1 / math.Sqrt(ss))
	for i := range v {
		v[i] *= inv
	}
	return true
}

// Quantizer implements a 64-bit random-hyperplane (SimHash-style) signature.
// Hyperplane coefficients are deterministic standard-normal values derived
// from Seed, bit index and vector dimension. Basin IDs are similarity metadata,
// not secrecy primitives.
type Quantizer struct{ Seed [32]byte }

func (q Quantizer) Basin(v []float32) (uint64, error) {
	if len(v) == 0 {
		return 0, errors.New("empty vector")
	}
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return 0, errors.New("vector contains non-finite value")
		}
	}

	var id uint64
	for bit := 0; bit < 64; bit++ {
		var dot float64
		for i, x := range v {
			dot += gaussianCoefficient(q.Seed, uint64(bit), uint64(i)) * float64(x)
		}
		if dot >= 0 {
			id |= 1 << uint(bit)
		}
	}
	return id, nil
}

func gaussianCoefficient(seed [32]byte, bit, dimension uint64) float64 {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-basin-hyperplane-v1"))
	_, _ = h.Write(seed[:])
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], bit)
	binary.BigEndian.PutUint64(b[8:], dimension)
	_, _ = h.Write(b[:])
	sum := h.Sum(nil)

	// Convert to open (0,1) intervals before Box-Muller so log(0) is impossible.
	u1 := (float64(binary.BigEndian.Uint64(sum[:8])) + 0.5) / (float64(^uint64(0)) + 1)
	u2 := (float64(binary.BigEndian.Uint64(sum[8:16])) + 0.5) / (float64(^uint64(0)) + 1)
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func HammingDistance(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}
