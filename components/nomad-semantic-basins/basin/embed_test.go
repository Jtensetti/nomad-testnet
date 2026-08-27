package basin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLexicalHashEmbedderDeterministic(t *testing.T) {
	e := LexicalHashEmbedder{Dims: 256}
	a, err := e.Embed(context.Background(), "Iran military systems")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Embed(context.Background(), "Iran military systems")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatal("length mismatch")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d", i)
		}
	}
}

func TestHyperplaneQuantizerIdenticalAndOppositeVectors(t *testing.T) {
	q := Quantizer{Seed: sha256.Sum256([]byte("test-seed"))}
	v := []float32{0.3, -0.7, 0.2, 0.6}
	opposite := []float32{-0.3, 0.7, -0.2, -0.6}
	a, err := q.Basin(v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := q.Basin(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Basin(opposite)
	if err != nil {
		t.Fatal(err)
	}
	if a != again {
		t.Fatal("same vector and seed produced different basin")
	}
	if got := HammingDistance(a, b); got != 64 {
		t.Fatalf("opposite vectors differed in %d bits, want 64", got)
	}
}

func TestHyperplaneDistanceTracksAngularDistanceAcrossSeeds(t *testing.T) {
	nearA := []float32{1, 0, 0, 0}
	nearB := []float32{0.98, 0.2, 0, 0}
	orthogonal := []float32{0, 1, 0, 0}
	var nearTotal, orthogonalTotal int
	const seeds = 64
	for i := 0; i < seeds; i++ {
		seed := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		q := Quantizer{Seed: seed}
		a, err := q.Basin(nearA)
		if err != nil {
			t.Fatal(err)
		}
		b, err := q.Basin(nearB)
		if err != nil {
			t.Fatal(err)
		}
		c, err := q.Basin(orthogonal)
		if err != nil {
			t.Fatal(err)
		}
		nearTotal += HammingDistance(a, b)
		orthogonalTotal += HammingDistance(a, c)
	}
	if nearTotal >= orthogonalTotal/2 {
		t.Fatalf("nearby vectors were not materially closer: near=%d orthogonal=%d", nearTotal, orthogonalTotal)
	}
}

func TestQuantizerRejectsNonFiniteVector(t *testing.T) {
	if _, err := (Quantizer{}).Basin([]float32{1, float32(math.NaN())}); err == nil {
		t.Fatal("expected NaN to be rejected")
	}
}

func TestEmbeddersRejectOversizedInputsAndDimensions(t *testing.T) {
	if _, err := (LexicalHashEmbedder{Dims: HardMaxEmbeddingDims + 1}).Embed(context.Background(), "query"); err == nil {
		t.Fatal("lexical embedder accepted excessive dimensions")
	}
	if _, err := (LexicalHashEmbedder{Dims: 8, MaxInputBytes: 4}).Embed(context.Background(), "private query"); err == nil {
		t.Fatal("lexical embedder accepted oversized input")
	}
	e := LoopbackHTTPEmbedder{
		BaseURL: "http://127.0.0.1:9", Model: "local", MaxInputBytes: 4,
	}
	if _, err := e.Embed(context.Background(), "private query"); err == nil {
		t.Fatal("loopback embedder accepted oversized input")
	}
}

func TestLoopbackHTTPEmbedderRejectsRemoteHost(t *testing.T) {
	e := LoopbackHTTPEmbedder{BaseURL: "http://example.com", Model: "test"}
	if _, err := e.Embed(context.Background(), "private query"); err == nil {
		t.Fatal("expected non-loopback endpoint to be rejected")
	}
}

func TestLoopbackHTTPEmbedderRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	e := LoopbackHTTPEmbedder{BaseURL: server.URL, Model: "local-model"}
	if _, err := e.Embed(context.Background(), "private query"); err == nil {
		t.Fatal("expected redirect to be rejected")
	}
}

func TestLoopbackHTTPEmbedderRequestAndNormalization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var req embeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model != "local-model" || req.Input != "private query" {
			t.Fatalf("unexpected request: %#v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": []float32{3, 4}}},
		})
	}))
	defer server.Close()

	e := LoopbackHTTPEmbedder{BaseURL: server.URL, Model: "local-model"}
	v, err := e.Embed(context.Background(), "private query")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 2 || math.Abs(float64(v[0]-.6)) > 1e-6 || math.Abs(float64(v[1]-.8)) > 1e-6 {
		t.Fatalf("unexpected normalized vector: %#v", v)
	}
}

func TestLoopbackHTTPEmbedderBoundsResponseAndDimensions(t *testing.T) {
	t.Run("response bytes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 1024))
		}))
		defer server.Close()
		e := LoopbackHTTPEmbedder{
			BaseURL: server.URL, Model: "local", MaxResponseBytes: 64,
		}
		if _, err := e.Embed(context.Background(), "query"); err == nil {
			t.Fatal("accepted oversized embedding response")
		}
	})

	t.Run("vector dimensions", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"embedding": []float32{1, 2, 3}}},
			})
		}))
		defer server.Close()
		e := LoopbackHTTPEmbedder{
			BaseURL: server.URL, Model: "local", MaxDimensions: 2,
		}
		if _, err := e.Embed(context.Background(), "query"); err == nil {
			t.Fatal("accepted excessive embedding dimensions")
		}
	})

	t.Run("multiple vectors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"embedding": []float32{1, 2}},
					{"embedding": []float32{3, 4}},
				},
			})
		}))
		defer server.Close()
		e := LoopbackHTTPEmbedder{BaseURL: server.URL, Model: "local"}
		if _, err := e.Embed(context.Background(), "query"); err == nil {
			t.Fatal("accepted multiple embedding vectors")
		}
	})
}
