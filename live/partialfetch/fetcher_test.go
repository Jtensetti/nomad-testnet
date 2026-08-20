package partialfetch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestPollOnceUsesPublicPlanAndRejectsEquivocation(t *testing.T) {
	const streamID = "0102030405060708090a0b0c0d0e0f10"
	bodies := [][]byte{[]byte(`{"operator":0}`), []byte(`{"operator":1}`), []byte(`{"operator":2}`)}
	var requests [3]atomic.Uint32
	servers := make([]*httptest.Server, 3)
	operators := make([]topology.Operator, 3)
	for index := range servers {
		index := index
		servers[index] = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			expected := fmt.Sprintf("/v1/partial/%s/%d", streamID, index)
			if request.Method != http.MethodGet || request.URL.Path != expected || request.URL.RawQuery != "" ||
				request.Header.Get("Accept") != "application/vnd.nomad.partial+json" {
				http.Error(response, "bad request", http.StatusBadRequest)
				return
			}
			requests[index].Add(1)
			response.Header().Set("Content-Type", "application/vnd.nomad.partial+json")
			response.Header().Set("Content-Length", fmt.Sprintf("%d", len(bodies[index])))
			_, _ = response.Write(bodies[index])
		}))
		defer servers[index].Close()
		operators[index] = topology.Operator{Index: uint16(index), PartialEndpoint: servers[index].URL}
	}
	output := filepath.Join(t.TempDir(), "partials")
	fetcher, err := New(topology.Verified{Document: topology.Document{Operators: operators}}, streamID, output, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetcher.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := range servers {
		if requests[index].Load() != 1 {
			t.Fatalf("operator %d received %d requests", index, requests[index].Load())
		}
		path := filepath.Join(output, fmt.Sprintf("%s-%02d.partial.json", streamID, index))
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != string(bodies[index]) {
			t.Fatalf("operator %d cache differs from response", index)
		}
	}

	bodies[1] = []byte(`{"operator":1,"changed":true}`)
	if err := fetcher.PollOnce(context.Background()); err == nil || err.Error() != "partial fetch equivocation" {
		t.Fatalf("expected immutable partial equivocation, got %v", err)
	}
}
