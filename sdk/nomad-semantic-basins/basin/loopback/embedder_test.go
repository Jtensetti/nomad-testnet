package loopback

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The half of TestEmbeddersRejectOversizedInputsAndDimensions that belongs to
// this embedder. The bound comes from basin.BoundedInt, so the point is that
// an embedder in another package reaches the same limit rather than its own.
func TestHTTPEmbedderRejectsOversizedInput(t *testing.T) {
	embedder := HTTPEmbedder{
		BaseURL: "http://127.0.0.1:9", Model: "local",
		ServiceKey: testServiceKey(), MaxInputBytes: 4,
	}
	_, err := embedder.Embed(context.Background(), "private query")
	if err == nil {
		t.Fatal("loopback embedder accepted oversized input")
	}
	if !strings.Contains(err.Error(), "maximum input size") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// The endpoint check is what stops private query text leaving the host. It is
// the reason this package can exist at all, so it is checked against more than
// one way of not being loopback.
func TestHTTPEmbedderAcceptsOnlyALiteralLoopbackAddress(t *testing.T) {
	// The reason matters as much as the refusal: every address below also
	// fails to connect, so asserting only that an error came back would pass
	// with the address check removed.
	for base, reason := range badLoopbackBases() {
		embedder := HTTPEmbedder{BaseURL: base, Model: "test", ServiceKey: testServiceKey()}
		_, err := embedder.Embed(context.Background(), "private query")
		if err == nil {
			t.Errorf("%s was accepted as a loopback embedding endpoint", base)
			continue
		}
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%s was refused for the wrong reason: %v", base, err)
		}
	}
	// And the addresses that are loopback are not rejected for being so: this
	// one fails to connect, which is a different error from being refused.
	for _, base := range []string{"http://127.0.0.1:9", "http://[::1]:9"} {
		embedder := HTTPEmbedder{
			BaseURL: base, Model: "test", ServiceKey: testServiceKey(),
			Timeout: 250 * time.Millisecond,
		}
		_, err := embedder.Embed(context.Background(), "private query")
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "literal loopback IP") {
			t.Errorf("%s was refused as non-loopback", base)
		}
	}
}

func TestHTTPEmbedderRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	embedder := HTTPEmbedder{
		BaseURL: server.URL, Model: "local-model", ServiceKey: testServiceKey(),
	}
	_, err := embedder.Embed(context.Background(), "private query")
	if err == nil {
		t.Fatal("expected redirect to be rejected")
	}
	if !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// A service that holds the key is still not trusted with the shape of what it
// returns. These bounds are the client's, and they apply to a correctly sealed
// response.
func TestHTTPEmbedderBoundsAKeyHoldersResponse(t *testing.T) {
	key := testServiceKey()

	t.Run("response bytes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 1024))
		}))
		defer server.Close()
		embedder := HTTPEmbedder{
			BaseURL: server.URL, Model: "local", ServiceKey: key, MaxResponseBytes: 64,
		}
		_, err := embedder.Embed(context.Background(), "query")
		if err == nil {
			t.Fatal("accepted oversized embedding response")
		}
		if !strings.Contains(err.Error(), "maximum size") {
			t.Fatalf("rejected for the wrong reason: %v", err)
		}
	})

	t.Run("vector dimensions", func(t *testing.T) {
		server := httptest.NewServer(sealWith(t, key, func([]byte) []byte {
			return oneVector([]float32{1, 2, 3})
		}))
		defer server.Close()
		embedder := HTTPEmbedder{
			BaseURL: server.URL, Model: "local", ServiceKey: key, MaxDimensions: 2,
		}
		_, err := embedder.Embed(context.Background(), "query")
		if err == nil {
			t.Fatal("accepted excessive embedding dimensions")
		}
		if !strings.Contains(err.Error(), "maximum dimensions") {
			t.Fatalf("rejected for the wrong reason: %v", err)
		}
	})

	t.Run("multiple vectors", func(t *testing.T) {
		server := httptest.NewServer(sealWith(t, key, func([]byte) []byte {
			payload, _ := json.Marshal(map[string]any{
				"data": []map[string]any{
					{"embedding": []float32{1, 2}},
					{"embedding": []float32{3, 4}},
				},
			})
			return payload
		}))
		defer server.Close()
		embedder := HTTPEmbedder{BaseURL: server.URL, Model: "local", ServiceKey: key}
		if _, err := embedder.Embed(context.Background(), "query"); err == nil {
			t.Fatal("accepted multiple embedding vectors")
		}
	})

	t.Run("zero vector", func(t *testing.T) {
		server := httptest.NewServer(sealWith(t, key, func([]byte) []byte {
			return oneVector([]float32{0, 0})
		}))
		defer server.Close()
		embedder := HTTPEmbedder{BaseURL: server.URL, Model: "local", ServiceKey: key}
		_, err := embedder.Embed(context.Background(), "query")
		if err == nil {
			t.Fatal("accepted the zero vector")
		}
		if !strings.Contains(err.Error(), "zero vector") {
			t.Fatalf("rejected for the wrong reason: %v", err)
		}
	})

	t.Run("not JSON at all", func(t *testing.T) {
		server := httptest.NewServer(sealWith(t, key, func([]byte) []byte {
			return []byte("this is not a vector")
		}))
		defer server.Close()
		embedder := HTTPEmbedder{BaseURL: server.URL, Model: "local", ServiceKey: key}
		if _, err := embedder.Embed(context.Background(), "query"); err == nil {
			t.Fatal("accepted a sealed non-JSON response")
		}
	})
}

// The service receives exactly the model and the query, and the request
// carries nothing else that identifies the reader.
func TestServiceReceivesTheRequestAndNothingElse(t *testing.T) {
	upstream := &stubUpstream{vector: []float32{3, 4}}
	server := httptest.NewServer(Service{ServiceKey: testServiceKey(), Upstream: upstream})
	defer server.Close()

	embedder := HTTPEmbedder{
		BaseURL: server.URL, Model: "local-model", ServiceKey: testServiceKey(),
	}
	if _, err := embedder.Embed(context.Background(), "  private query  "); err != nil {
		t.Fatal(err)
	}
	called := upstream.called()
	if len(called) != 1 || called[0] != "local-model|private query" {
		t.Fatalf("the shim passed %v upstream", called)
	}
}

func TestServiceRefusesWhenUpstreamFails(t *testing.T) {
	for name, upstream := range map[string]*stubUpstream{
		"upstream error": {err: context.DeadlineExceeded},
		"empty vector":   {vector: nil},
		"too many dims":  {vector: make([]float32, 5)},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(Service{
				ServiceKey: testServiceKey(), Upstream: upstream, MaxDimensions: 4,
			})
			defer server.Close()
			embedder := HTTPEmbedder{
				BaseURL: server.URL, Model: "local-model", ServiceKey: testServiceKey(),
			}
			if _, err := embedder.Embed(context.Background(), "private query"); err == nil {
				t.Fatal("the client accepted a vector the shim should have refused")
			}
		})
	}
}

func TestServiceRefusesWithoutAKeyOrUpstream(t *testing.T) {
	for name, service := range map[string]Service{
		"no key":      {Upstream: &stubUpstream{vector: []float32{3, 4}}},
		"short key":   {ServiceKey: []byte{1, 2, 3}, Upstream: &stubUpstream{vector: []float32{3, 4}}},
		"no upstream": {ServiceKey: testServiceKey()},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(service)
			defer server.Close()
			embedder := HTTPEmbedder{
				BaseURL: server.URL, Model: "local-model", ServiceKey: testServiceKey(),
			}
			if _, err := embedder.Embed(context.Background(), "private query"); err == nil {
				t.Fatal("a misconfigured shim served a request")
			}
		})
	}
}
