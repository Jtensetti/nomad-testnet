package adapter

import (
	"crypto/sha256"
	"os/exec"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/egress"
	"github.com/Jtensetti/nomad-browser/localcache"
)

// A gate that skips has not passed. These resolve the package graph with
// go/build, a library call over source that is present whenever tests run
// at all, so a failure here means the capability boundary was not checked
// rather than that this environment is unusual -- and an unchecked boundary
// on the emission path is exactly what must not pass quietly.

// What is needed is evidence that a failed load never reaches ordinary
// networking. There was no fallback code path, and now there is a test that
// says so: every way a load can fail is walked, and each must end in a local
// status with nothing in the response that could move the renderer somewhere
// else. A redirect header is the specific shape this failure would take --
// a 404 that carries a Location is a fallback whatever the code intended.
func TestEveryFailedLoadEndsLocallyWithNoRedirect(t *testing.T) {
	store := newFallbackStore()
	present := store.put([]byte("<h1>local</h1>"))
	missing := sha256.Sum256([]byte("this object was never stored"))

	bundleBytes, err := EncodeBundle([]Entry{
		{Path: "/index.html", ObjectID: present, MediaType: "text/html"},
		{Path: "/gone.css", ObjectID: missing, MediaType: "text/css"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleID := store.put(bundleBytes)
	adapter, err := New(store, bundleID)
	if err != nil {
		t.Fatal(err)
	}

	failures := []struct {
		name    string
		request Request
	}{
		{"unknown resource", Request{Method: "GET", Path: "/nope.html"}},
		{"object missing from the verified store", Request{Method: "GET", Path: "/gone.css"}},
		{"traversal", Request{Method: "GET", Path: "/../../etc/passwd"}},
		{"backslash separator", Request{Method: "GET", Path: "/a\\..\\b"}},
		{"non-canonical path", Request{Method: "GET", Path: "/./index.html"}},
		{"query syntax in the path", Request{Method: "GET", Path: "/index.html?x=1"}},
		{"fragment syntax in the path", Request{Method: "GET", Path: "/index.html#top"}},
		{"NUL in the path", Request{Method: "GET", Path: "/index.html\x00.png"}},
		{"relative path", Request{Method: "GET", Path: "index.html"}},
		{"empty path", Request{Method: "GET", Path: ""}},
		{"oversized path", Request{Method: "GET", Path: "/" + strings.Repeat("a", 4096)}},
		{"write method", Request{Method: "POST", Path: "/index.html"}},
		{"connect method", Request{Method: "CONNECT", Path: "/index.html"}},
	}

	redirectHeaders := []string{"Location", "Refresh", "Link", "Content-Location"}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			response, err := adapter.Handle(failure.request)
			if err != nil {
				t.Fatalf("failed load returned a transport-level error: %v", err)
			}
			if response.Status == 200 {
				t.Fatalf("a failing request was served: status %d", response.Status)
			}
			if response.Status < 400 || response.Status > 499 {
				t.Errorf("status %d is not a local client-error status", response.Status)
			}
			if len(response.Body) != 0 {
				t.Errorf("a failed load carried a %d-byte body", len(response.Body))
			}
			for _, header := range redirectHeaders {
				if value, present := response.Headers[header]; present {
					t.Errorf("a failed load carried %s: %q, which is a navigation away "+
						"from the verified local store", header, value)
				}
			}
			policy := response.Headers["Content-Security-Policy"]
			for _, directive := range []string{"default-src 'none'", "connect-src 'none'"} {
				if !strings.Contains(policy, directive) {
					t.Errorf("a failed load dropped %q from its CSP: %q", directive, policy)
				}
			}
		})
	}
}

// The adapter resolves requests from a verified local store. If it could
// reach a socket, "no fallback code path" would be a claim about the current
// code rather than about the capability it holds.
func TestAdapterHasNoNetworkCapability(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps",
		"github.com/Jtensetti/nomad-browser/adapter").Output()
	if err != nil {
		t.Fatalf("cannot resolve the package graph, so the capability boundary went "+
			"unchecked: %v", err)
	}
	forbidden := map[string]struct{}{
		"net": {}, "net/http": {}, "os/exec": {},
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if _, banned := forbidden[dependency]; banned {
			t.Errorf("the local adapter reaches %q; a failed load having no fallback would "+
				"then be a property of the current code rather than of its capability",
				dependency)
		}
	}
	if err := (egress.Policy{}).Authorize(egress.HTTP); err == nil {
		t.Error("the egress policy authorised HTTP")
	}
}

type fallbackStore struct {
	objects map[[32]byte][]byte
}

func newFallbackStore() *fallbackStore {
	return &fallbackStore{objects: map[[32]byte][]byte{}}
}

func (store *fallbackStore) put(data []byte) [32]byte {
	id := sha256.Sum256(data)
	store.objects[id] = append([]byte(nil), data...)
	return id
}

func (store *fallbackStore) Get(id [32]byte) (localcache.Object, error) {
	data, found := store.objects[id]
	if !found {
		return localcache.Object{}, localcache.ErrNotFound
	}
	return localcache.Object{Bytes: append([]byte(nil), data...)}, nil
}
