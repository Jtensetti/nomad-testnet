package loopback

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"
)

const privateQuery = "how do I appeal an eviction notice in this municipality"

func testServiceKey() []byte  { return bytes.Repeat([]byte{0x5a}, MinimumServiceKeyBytes) }
func otherServiceKey() []byte { return bytes.Repeat([]byte{0xa5}, MinimumServiceKeyBytes) }

type stubUpstream struct {
	mu     sync.Mutex
	calls  []string
	vector []float32
	err    error
}

func (u *stubUpstream) Embed(_ context.Context, model, input string) ([]float32, error) {
	u.mu.Lock()
	u.calls = append(u.calls, model+"|"+input)
	u.mu.Unlock()
	if u.err != nil {
		return nil, u.err
	}
	return append([]float32(nil), u.vector...), nil
}

func (u *stubUpstream) called() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.calls...)
}

// recorder keeps every byte of every request, headers and body alike, so a
// test can assert what a listening process did and did not receive.
type recorder struct {
	mu      sync.Mutex
	seen    [][]byte
	handler http.HandlerFunc
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, "dump failed", http.StatusInternalServerError)
		return
	}
	rec.mu.Lock()
	rec.seen = append(rec.seen, dump)
	rec.mu.Unlock()
	if rec.handler == nil {
		http.Error(w, "no", http.StatusNotFound)
		return
	}
	rec.handler(w, r)
}

func (rec *recorder) requests() [][]byte {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([][]byte(nil), rec.seen...)
}

func (rec *recorder) everything() []byte {
	return bytes.Join(rec.requests(), []byte("\n"))
}

// sealWith answers a sealed request by sealing plaintext under sealKey, bound
// to the salt the client chose. Passing a key the client does not hold is how
// an impostor is built.
func sealWith(t *testing.T, sealKey []byte, plaintext func(salt []byte) []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readAllBody(r)
		if err != nil || len(body) < 1+saltBytes {
			http.Error(w, "short", http.StatusBadRequest)
			return
		}
		salt := body[1 : 1+saltBytes]
		sealed, err := seal(sealKey, salt, responseInfo, "response", plaintext(salt))
		if err != nil {
			http.Error(w, "seal", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(sealed)
	}
}

func readAllBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(r.Body); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func oneVector(vector []float32) []byte {
	payload, _ := json.Marshal(map[string]any{
		"data": []map[string]any{{"embedding": vector}},
	})
	return payload
}

// The claim this whole file exists to support: a process that does not hold
// the service key never receives the query text, even though it is the process
// the client connected to and talked to.
func TestQueryIsNotDisclosedToAProcessWithoutTheServiceKey(t *testing.T) {
	impostor := &recorder{handler: sealWith(t, otherServiceKey(), func([]byte) []byte {
		return oneVector([]float32{3, 4})
	})}
	server := httptest.NewServer(impostor)
	defer server.Close()

	key := testServiceKey()
	embedder := HTTPEmbedder{BaseURL: server.URL, Model: "local-model", ServiceKey: key}
	if _, err := embedder.Embed(context.Background(), privateQuery); err == nil {
		t.Fatal("the client accepted a vector from a process without the service key")
	}

	received := impostor.everything()
	if len(impostor.requests()) != 1 {
		t.Fatalf("expected the client to have contacted the impostor once, got %d requests",
			len(impostor.requests()))
	}
	if bytes.Contains(received, []byte(privateQuery)) {
		t.Fatal("the query text reached a process that does not hold the service key")
	}
	for _, fragment := range []string{"eviction", "municipality", "appeal"} {
		if bytes.Contains(bytes.ToLower(received), []byte(fragment)) {
			t.Fatalf("query fragment %q reached a process without the service key", fragment)
		}
	}
	if bytes.Contains(received, key) {
		t.Fatal("the service key itself was sent to the process on the endpoint")
	}
	if bytes.Contains(bytes.ToLower(received), []byte("authorization")) {
		t.Fatal("a credential header was sent to a process that was never authenticated")
	}
}

// The other direction. An impostor that answers with a chosen vector chooses
// the reader's basin, and so chooses which part of the catalogue they fetch.
func TestVectorFromAProcessWithoutTheServiceKeyIsRefused(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"sealed under the wrong key": sealWith(t, otherServiceKey(), func([]byte) []byte {
			return oneVector([]float32{3, 4})
		}),
		"plain OpenAI-shaped JSON": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(oneVector([]float32{3, 4}))
		},
		"empty body": func(http.ResponseWriter, *http.Request) {},
		"random bytes": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte{0x41}, 512))
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			embedder := HTTPEmbedder{
				BaseURL: server.URL, Model: "local-model", ServiceKey: testServiceKey(),
			}
			vector, err := embedder.Embed(context.Background(), privateQuery)
			if err == nil {
				t.Fatalf("accepted a vector %v from an unauthenticated responder", vector)
			}
		})
	}
}

// A response is bound to the salt of the request it answers, so a genuine
// response captured once cannot be replayed to pin a reader on a stale vector.
func TestResponseFromAnEarlierRequestIsRefused(t *testing.T) {
	key := testServiceKey()
	var mu sync.Mutex
	var firstResponse []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readAllBody(r)
		if err != nil || len(body) < 1+saltBytes {
			http.Error(w, "short", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if firstResponse != nil {
			_, _ = w.Write(firstResponse)
			return
		}
		sealed, err := seal(key, body[1:1+saltBytes], responseInfo, "response",
			oneVector([]float32{3, 4}))
		if err != nil {
			http.Error(w, "seal", http.StatusInternalServerError)
			return
		}
		firstResponse = sealed
		_, _ = w.Write(sealed)
	}))
	defer server.Close()

	embedder := HTTPEmbedder{BaseURL: server.URL, Model: "local-model", ServiceKey: key}
	if _, err := embedder.Embed(context.Background(), privateQuery); err != nil {
		t.Fatalf("the genuine first response was refused: %v", err)
	}
	if _, err := embedder.Embed(context.Background(), privateQuery); err == nil {
		t.Fatal("a response sealed for an earlier request was accepted")
	}
}

// An absent or short key is refused before anything is sent, not treated as
// "no authentication required".
func TestEmbedderRefusesWithoutAUsableServiceKeyAndSendsNothing(t *testing.T) {
	for name, key := range map[string][]byte{
		"absent":     nil,
		"empty":      {},
		"one byte":   {0x01},
		"one short":  bytes.Repeat([]byte{0x5a}, MinimumServiceKeyBytes-1),
		"just right": testServiceKey(),
	} {
		t.Run(name, func(t *testing.T) {
			listener := &recorder{handler: sealWith(t, testServiceKey(), func([]byte) []byte {
				return oneVector([]float32{3, 4})
			})}
			server := httptest.NewServer(listener)
			defer server.Close()

			embedder := HTTPEmbedder{
				BaseURL: server.URL, Model: "local-model", ServiceKey: key,
			}
			_, err := embedder.Embed(context.Background(), privateQuery)
			usable := len(key) >= MinimumServiceKeyBytes
			if usable {
				if err != nil {
					t.Fatalf("a usable key was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a client with no usable service key embedded anyway")
			}
			if got := len(listener.requests()); got != 0 {
				t.Fatalf("a client with no usable service key opened %d requests", got)
			}
			if !strings.Contains(err.Error(), "service key") {
				t.Fatalf("refusal did not name the missing key: %v", err)
			}
		})
	}
}

// The full three-process chain: client, shim, model server. This is the
// positive control for every refusal above -- without it they could all be a
// client that refuses everything.
func TestSealedRoundTripThroughTheShimToAModelServer(t *testing.T) {
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("model server saw unexpected path %s", r.URL.Path)
		}
		var request embeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("model server could not decode request: %v", err)
		}
		if request.Model != "local-model" || request.Input != privateQuery {
			t.Errorf("model server saw unexpected request %#v", request)
		}
		_, _ = w.Write(oneVector([]float32{3, 4}))
	}))
	defer modelServer.Close()

	shim := httptest.NewServer(Service{
		ServiceKey: testServiceKey(),
		Upstream:   OpenAIUpstream{BaseURL: modelServer.URL},
	})
	defer shim.Close()

	embedder := HTTPEmbedder{
		BaseURL: shim.URL, Model: "local-model", ServiceKey: testServiceKey(),
	}
	vector, err := embedder.Embed(context.Background(), privateQuery)
	if err != nil {
		t.Fatal(err)
	}
	if len(vector) != 2 ||
		math.Abs(float64(vector[0]-.6)) > 1e-6 || math.Abs(float64(vector[1]-.8)) > 1e-6 {
		t.Fatalf("unexpected normalized vector: %#v", vector)
	}
}

// The shim must not pass anything upstream that it could not authenticate: the
// model server is the process that would see the query in the clear.
func TestServiceRefusesUnauthenticatedRequestsWithoutReachingUpstream(t *testing.T) {
	key := testServiceKey()
	sealedBody := func(t *testing.T, sealKey []byte) []byte {
		t.Helper()
		salt, err := newSalt()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(embeddingRequest{Model: "local-model", Input: privateQuery})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := seal(sealKey, salt, requestInfo, "request", payload)
		if err != nil {
			t.Fatal(err)
		}
		return append(append([]byte{sealVersion}, salt...), sealed...)
	}

	good := sealedBody(t, key)
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		status int
	}{
		{"sealed under another key", http.MethodPost, SealedPath, sealedBody(t, otherServiceKey()), http.StatusBadRequest},
		{"plain JSON", http.MethodPost, SealedPath, []byte(`{"model":"local-model","input":"` + privateQuery + `"}`), http.StatusBadRequest},
		{"truncated", http.MethodPost, SealedPath, good[:len(good)-1], http.StatusBadRequest},
		{"flipped ciphertext bit", http.MethodPost, SealedPath, flipLast(good), http.StatusBadRequest},
		{"flipped salt bit", http.MethodPost, SealedPath, flipSalt(good), http.StatusBadRequest},
		{"wrong version", http.MethodPost, SealedPath, append([]byte{0x02}, good[1:]...), http.StatusBadRequest},
		{"header only", http.MethodPost, SealedPath, good[:1+saltBytes], http.StatusBadRequest},
		{"empty", http.MethodPost, SealedPath, nil, http.StatusBadRequest},
		{"wrong method", http.MethodGet, SealedPath, nil, http.StatusMethodNotAllowed},
		{"wrong path", http.MethodPost, "/v1/embeddings", good, http.StatusNotFound},
	}

	var refusalBodies []string
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := &stubUpstream{vector: []float32{3, 4}}
			server := httptest.NewServer(Service{ServiceKey: key, Upstream: upstream})
			defer server.Close()

			request, err := http.NewRequest(testCase.method, server.URL+testCase.path,
				bytes.NewReader(testCase.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			answer, err := readAllResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != testCase.status {
				t.Fatalf("expected %d, got %s (%s)", testCase.status, response.Status, answer)
			}
			if called := upstream.called(); len(called) != 0 {
				t.Fatalf("the shim reached the model server with %v", called)
			}
			if strings.Contains(answer, privateQuery) {
				t.Fatal("the refusal echoed the request back")
			}
			refusalBodies = append(refusalBodies, answer)
		})
	}

	// One message for every cause. A shim that says which check failed tells
	// whoever is probing it how to get closer.
	for _, body := range refusalBodies {
		if body != refusalBodies[0] {
			t.Fatalf("refusals differ and so distinguish causes: %q vs %q",
				refusalBodies[0], body)
		}
	}
}

func readAllResponse(response *http.Response) (string, error) {
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func flipLast(body []byte) []byte {
	flipped := append([]byte(nil), body...)
	flipped[len(flipped)-1] ^= 0x01
	return flipped
}

func flipSalt(body []byte) []byte {
	flipped := append([]byte(nil), body...)
	flipped[1] ^= 0x01
	return flipped
}

// The shim holds a key; it does not gain the ability to send a query where the
// client could not.
//
// Each case asserts the reason it was refused, not merely that it failed.
// Every address here also fails to connect, so a test that only checked for an
// error would pass with the address check deleted -- which is exactly the
// mutation that has to fail.
func TestUpstreamMustBeLoopback(t *testing.T) {
	for base, reason := range badLoopbackBases() {
		upstream := OpenAIUpstream{BaseURL: base}
		_, err := upstream.Embed(context.Background(), "local-model", privateQuery)
		if err == nil {
			t.Errorf("%q was accepted as a model server address", base)
			continue
		}
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%q was refused for the wrong reason: %v", base, err)
		}
	}
}

// badLoopbackBases maps a base URL that must be refused to the words the
// refusal has to contain.
func badLoopbackBases() map[string]string {
	const notLoopback = "literal loopback IP"
	return map[string]string{
		"http://example.com":           notLoopback,
		"http://localhost:9":           notLoopback,
		"http://0.0.0.0:9":             notLoopback,
		"http://169.254.169.254":       notLoopback,
		"http://10.0.0.1:9":            notLoopback,
		"http://[fe80::1]:9":           notLoopback,
		"https://127.0.0.1:9":          "must use http",
		"http://user:pass@127.0.0.1:9": "user info, query or fragment",
		"http://127.0.0.1:9?to=away":   "user info, query or fragment",
		"http://127.0.0.1:9#away":      "user info, query or fragment",
		"":                             "required",
	}
}

func TestNewServiceKeyIsFreshAndLongEnough(t *testing.T) {
	first, err := NewServiceKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewServiceKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < MinimumServiceKeyBytes {
		t.Fatalf("NewServiceKey returned %d bytes", len(first))
	}
	if bytes.Equal(first, second) {
		t.Fatal("NewServiceKey returned the same key twice")
	}
	if err := checkServiceKey(first); err != nil {
		t.Fatalf("NewServiceKey produced a key its own check rejects: %v", err)
	}
}
