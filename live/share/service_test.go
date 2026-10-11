package share

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
)

// The share service performs threshold work on cached ciphertext and serves
// the resulting partial decryption over HTTP. It is the only process in this
// repository that both holds a threshold secret and answers a socket, and its
// network-facing half had no tests at all: Run, handler, ensureOutputDirectory
// and writeOrCompare all measured 0.0%, and ProcessOnce 4.9%, which is the
// worse number of the two because a summary reading "some coverage" hides it.
//
// What follows covers the request surface and the retirement path. The
// cryptographic path is exercised by the Compose gate, which runs three of
// these services against a real committee.

const testStream = "0123456789abcdef0123456789abcdef"

type refusingGuard struct {
	retireAt time.Time
	epoch    uint64
}

func (guard refusingGuard) ServesEpoch(epochNumber uint64, now time.Time) error {
	if epochNumber != guard.epoch {
		return errors.New("not this operator's epoch")
	}
	if !now.Before(guard.retireAt) {
		return errors.New("epoch is retired")
	}
	return nil
}

func testService(t *testing.T, index uint32) (Service, string) {
	t.Helper()
	output := t.TempDir()
	// A real but empty cache: Load on a stream it does not hold returns no
	// payloads and no error, so ProcessOnce reaches its guard check and stops
	// there rather than failing the configuration check that precedes it.
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := batch.VerifiedDescriptor{}
	descriptor.Descriptor.StreamID = testStream
	descriptor.Committee.Epoch = 7
	return Service{
		Cache:         cache,
		Descriptor:    descriptor,
		Secret:        mix.MemberSecret{Index: index},
		OutputDir:     output,
		Interval:      10 * time.Millisecond,
		ListenAddress: "127.0.0.1:0",
		Guard:         refusingGuard{retireAt: time.Unix(1<<40, 0), epoch: 7},
		Now:           func() time.Time { return time.Unix(1000, 0).UTC() },
	}, output
}

func partialPath(output string, index uint32) string {
	return filepath.Join(output, testStream+"-0"+string(rune('0'+index))+".partial.json")
}

// The endpoint answers exactly one request and refuses everything else. A
// share service that served a partial under a path an attacker could vary is
// one whose threshold material is reachable by guessing.
func TestTheEndpointServesOnlyItsOwnPartial(t *testing.T) {
	service, output := testService(t, 1)
	body := []byte(`{"partial":"content"}`)
	if err := os.WriteFile(partialPath(output, 1), body, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := service.handler()
	expected := "/v1/partial/" + testStream + "/1"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, expected, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("the correct request was refused with %d", response.Code)
	}
	if response.Body.String() != string(body) {
		t.Fatalf("served %q, want %q", response.Body.String(), body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("a threshold partial was served with Cache-Control %q", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("served without nosniff: %q", got)
	}

	for _, refused := range []struct {
		name   string
		method string
		target string
	}{
		{"another member's index", http.MethodGet, "/v1/partial/" + testStream + "/2"},
		{"another stream", http.MethodGet, "/v1/partial/" + strings.Repeat("f", 32) + "/1"},
		{"a query string", http.MethodGet, expected + "?x=1"},
		{"a POST", http.MethodPost, expected},
		{"a HEAD", http.MethodHead, expected},
		{"the collection", http.MethodGet, "/v1/partial/"},
		{"a traversal", http.MethodGet, "/v1/partial/" + testStream + "/1/../1"},
		{"the root", http.MethodGet, "/"},
	} {
		t.Run(refused.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(refused.method, refused.target, nil))
			if response.Code == http.StatusOK {
				t.Fatalf("%s was served", refused.name)
			}
		})
	}
}

// Nothing to serve is a 404, not an empty 200. A zero-length body accepted as
// a partial would be assembled by a collector as though it were one.
func TestTheEndpointRefusesWhatIsNotAPartial(t *testing.T) {
	service, output := testService(t, 1)
	handler := service.handler()
	target := "/v1/partial/" + testStream + "/1"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("a missing partial answered %d", response.Code)
	}

	if err := os.WriteFile(partialPath(output, 1), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("an empty file was served as a partial with %d", response.Code)
	}

	// A directory where the partial should be is not a partial either.
	if err := os.Remove(partialPath(output, 1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(partialPath(output, 1), 0o700); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("a directory was served as a partial with %d", response.Code)
	}
}

// Retirement must fail closed. A share that stayed usable past its epoch is
// the whole reason the guard exists, and a nil guard must be refused rather
// than read as "no restriction".
func TestThresholdWorkStopsWhenTheEpochRetires(t *testing.T) {
	service, _ := testService(t, 1)
	service.Guard = refusingGuard{retireAt: time.Unix(2000, 0), epoch: 7}

	service.Now = func() time.Time { return time.Unix(2001, 0).UTC() }
	_, err := service.ProcessOnce()
	if err == nil {
		t.Fatal("threshold work was performed for a retired epoch")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("the refusal does not say the epoch is retired: %v", err)
	}

	service.Guard = refusingGuard{retireAt: time.Unix(2000, 0), epoch: 9}
	service.Now = func() time.Time { return time.Unix(1000, 0).UTC() }
	if _, err := service.ProcessOnce(); err == nil {
		t.Fatal("threshold work was performed for another operator's epoch")
	}

	service.Guard = nil
	if _, err := service.ProcessOnce(); err == nil {
		t.Fatal("a service with no guard performed threshold work")
	}
	if _, err := (Service{OutputDir: "x"}).ProcessOnce(); err == nil {
		t.Fatal("a service with no cache performed threshold work")
	}
}

// Run must stop rather than keep serving once its epoch retires, and the
// endpoint must go with it. This is the property that bounds how long a
// retired epoch's partial stays reachable, and nothing measured it.
func TestRunStopsServingOnceTheEpochRetires(t *testing.T) {
	service, output := testService(t, 1)
	if err := os.WriteFile(partialPath(output, 1), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retire := time.Unix(2000, 0)
	service.Guard = refusingGuard{retireAt: retire, epoch: 7}
	service.Now = func() time.Time { return retire.Add(time.Second).UTC() }

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := service.Run(ctx)
	if err == nil {
		t.Fatal("Run returned no error for a retired epoch")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Run kept running with a retired epoch until the test timed out")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("Run stopped for some other reason: %v", err)
	}
}

func TestRunRefusesAnIncompleteConfiguration(t *testing.T) {
	base, _ := testService(t, 1)
	for _, scenario := range []struct {
		name   string
		change func(*Service)
	}{
		{"no output directory", func(s *Service) { s.OutputDir = "" }},
		{"no interval", func(s *Service) { s.Interval = 0 }},
		{"no listen address", func(s *Service) { s.ListenAddress = "" }},
		{"no guard", func(s *Service) { s.Guard = nil }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			service := base
			scenario.change(&service)
			if err := service.Run(t.Context()); err == nil {
				t.Fatalf("a service with %s started", scenario.name)
			}
		})
	}
	// Run guards against a nil context and the guard had no test, here or in
	// the two other packages that carry the same one. Passing the nil through
	// a typed variable rather than as a literal keeps staticcheck's SA1012 --
	// which exists to stop production callers passing nil -- from flagging the
	// one call that has to.
	var absent context.Context
	if err := base.Run(absent); err == nil {
		t.Fatal("a service ran with no context")
	}
}

// A service refused for its configuration must not have touched anything
// first. Run checks its arguments, then the guard, and only then creates the
// output directory and binds the socket -- so a rejected service leaves no
// directory behind and never listens.
//
// This is what makes Run's own nil-guard check worth having: ProcessOnce
// refuses a nil guard too, with the same message, so a test that only asked
// whether Run returned an error passed with Run's check deleted. It passed
// after the socket had been bound and the endpoint had briefly served.
func TestARefusedServiceNeverReachesTheFilesystemOrTheSocket(t *testing.T) {
	base, _ := testService(t, 1)
	base.OutputDir = filepath.Join(t.TempDir(), "never-created")

	service := base
	service.Guard = nil
	if err := service.Run(t.Context()); err == nil {
		t.Fatal("a service with no guard started")
	}
	if _, err := os.Stat(base.OutputDir); !os.IsNotExist(err) {
		t.Fatalf("a refused service created its output directory: %v", err)
	}

	// Vacuity: an accepted service does create it, so the assertion above is
	// about the refusal and not about the directory never being created.
	accepted := base
	accepted.Guard = refusingGuard{retireAt: time.Unix(1, 0), epoch: 7}
	accepted.Now = func() time.Time { return time.Unix(1000, 0).UTC() }
	if err := accepted.Run(t.Context()); err == nil {
		t.Fatal("the retired-epoch service did not stop")
	}
	if _, err := os.Stat(base.OutputDir); err != nil {
		t.Fatalf("a service that got past its configuration did not create its "+
			"output directory, so the refusal check above proves nothing: %v", err)
	}
}

// writeOrCompare is how a restarted service reconciles with what it already
// wrote. Two different partials at one path is either a bug or a compromised
// member, and either way it must not be overwritten silently.
func TestAConflictingPartialIsRefusedRatherThanOverwritten(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "p.json")
	created, err := writeOrCompare(path, []byte("first"))
	if err != nil || !created {
		t.Fatalf("the first write failed: created=%v err=%v", created, err)
	}
	created, err = writeOrCompare(path, []byte("first"))
	if err != nil {
		t.Fatalf("rewriting identical content failed: %v", err)
	}
	if created {
		t.Fatal("rewriting identical content reported a creation")
	}
	if _, err := writeOrCompare(path, []byte("second")); err == nil {
		t.Fatal("a conflicting partial overwrote the one already published")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "first" {
		t.Fatalf("the original was disturbed: %q %v", content, err)
	}
}
