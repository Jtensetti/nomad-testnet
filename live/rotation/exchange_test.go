package rotation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestControlEndpointIsDerivedWithoutDiscoveryFallback(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "http://127.0.0.1:6100/", want: "http://127.0.0.1:6101"},
		{input: "https://operator.example:443", want: "https://operator.example:444"},
		{input: "https://[2001:db8::1]:6200", want: "https://[2001:db8::1]:6201"},
	} {
		got, err := ControlEndpoint(test.input)
		if err != nil {
			t.Fatalf("derive %q: %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("derive %q = %q, want %q", test.input, got, test.want)
		}
	}
	for _, invalid := range []string{
		"http://operator.example:6100", // cleartext is loopback-only
		"ftp://127.0.0.1:6100",
		"http://127.0.0.1:65535",
		"http://127.0.0.1:6100/path",
		"http://user@127.0.0.1:6100",
		"http://127.0.0.1:6100?fallback=other",
	} {
		if _, err := ControlEndpoint(invalid); err == nil {
			t.Fatalf("invalid DKG endpoint %q derived a lifecycle address", invalid)
		}
	}
}

func TestLifecycleEndpointReservationRejectsSocketCollisions(t *testing.T) {
	network := topology.Verified{Document: topology.Document{Operators: []topology.Operator{
		{ID: "op-a", PartialEndpoint: "http://127.0.0.1:6101", DKGEndpoint: "http://127.0.0.1:6100"},
		{ID: "op-b", PartialEndpoint: "http://127.0.0.1:6200", DKGEndpoint: "http://127.0.0.1:6201"},
	}}}
	if err := topology.ValidateEpochControlEndpoints(network); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("derived lifecycle/partial collision was accepted: %v", err)
	}
	network.Document.Operators[0].PartialEndpoint = "http://127.0.0.1:6110"
	if err := topology.ValidateEpochControlEndpoints(network); err != nil {
		t.Fatalf("disjoint lifecycle endpoints were rejected: %v", err)
	}
	network.Document.Operators[1].DKGEndpoint = "http://127.0.0.1:65535"
	if err := topology.ValidateEpochControlEndpoints(network); err == nil {
		t.Fatal("DKG port 65535 was accepted despite having no lifecycle successor port")
	}
}

func TestExchangePublishesImmutableArtifacts(t *testing.T) {
	exchange, err := OpenExchange(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte("{\"certificate\":true}\n")
	if err := exchange.Publish(2, artifactCertificate, "", encoded); err != nil {
		t.Fatal(err)
	}
	if err := exchange.Publish(2, artifactCertificate, "", encoded); err != nil {
		t.Fatalf("idempotent publication failed: %v", err)
	}
	if err := exchange.Publish(2, artifactCertificate, "", []byte("{\"certificate\":false}\n")); err == nil {
		t.Fatal("conflicting singleton artifact replaced immutable state")
	}
	if err := exchange.Publish(2, artifactApproval, "../op-a", encoded); err == nil {
		t.Fatal("path-bearing operator ID was accepted")
	}
	path, err := exchange.path(2, artifactCertificate, "")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(encoded) {
		t.Fatal("immutable publication changed after conflicting write")
	}
	if info, err := os.Lstat(filepath.Dir(path)); err != nil || !info.IsDir() {
		t.Fatalf("exchange epoch directory is invalid: %v", err)
	}
}

func TestExchangeHandlerHasOnlyCanonicalReadEndpoints(t *testing.T) {
	exchange, err := OpenExchange(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte("{\"certificate\":true}\n")
	if err := exchange.Publish(2, artifactCertificate, "", encoded); err != nil {
		t.Fatal(err)
	}
	handler := exchange.Handler()
	validPath := "/v1/epoch/00000000000000000002/certificate"
	request := httptest.NewRequest(http.MethodGet, validPath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != string(encoded) {
		t.Fatalf("canonical GET = %d %q", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("artifact response is not immutable: %q", got)
	}

	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: validPath},
		{method: http.MethodPut, path: validPath},
		{method: http.MethodGet, path: validPath + "?retry=1"},
		{method: http.MethodGet, path: "/v1/epoch/2/certificate"},
		{method: http.MethodGet, path: "/v1/epoch/00000000000000000002/%63ertificate"},
		{method: http.MethodGet, path: "/v1/epoch/00000000000000000002/approval/../certificate"},
		{method: http.MethodGet, path: "/v1/epoch/00000000000000000002//certificate"},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatalf("non-canonical or mutating request %s %s succeeded", test.method, test.path)
		}
	}
}

type countingRoundTripper struct {
	calls atomic.Int32
}

func (transport *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("synthetic refusal")
}

func TestFetchMakesExactlyOneRequest(t *testing.T) {
	transport := &countingRoundTripper{}
	exchange, err := openExchange(t.TempDir(), &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	operator := topology.Operator{ID: "op-a", DKGEndpoint: "http://127.0.0.1:6100"}
	if _, err := exchange.Fetch(context.Background(), operator, 2, artifactCertificate, ""); err == nil {
		t.Fatal("synthetic refusal unexpectedly succeeded")
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("one aligned fetch generated %d HTTP requests", got)
	}
	if _, err := exchange.Fetch(context.Background(), operator, 2, "../certificate", ""); err == nil {
		t.Fatal("invalid artifact path reached the transport")
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("invalid artifact path generated a network request; calls = %d", got)
	}
}

func TestProductionFetchDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, "{}")
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	controlPort, err := strconv.Atoi(parsed.Port())
	if err != nil || controlPort <= 1 {
		t.Fatalf("invalid test listener port %q", parsed.Port())
	}
	exchange, err := OpenExchange(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	operator := topology.Operator{ID: "op-a", DKGEndpoint: "http://127.0.0.1:" + strconv.Itoa(controlPort-1)}
	if _, err := exchange.Fetch(context.Background(), operator, 2, artifactCertificate, ""); err == nil {
		t.Fatal("redirect response was accepted as an artifact")
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("production fetch followed redirect %d time(s)", got)
	}
}
