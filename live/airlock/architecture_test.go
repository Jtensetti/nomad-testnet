package airlock

import (
	"go/build"
	"strings"
	"testing"
)

// The CI workflow runs the same check over the transitive graph. This one
// runs in `go test` so the boundary fails at the point of change rather than
// on a push, and states which imports are the problem.
func TestAirlockHasNoNetworkOrSchedulingCapability(t *testing.T) {
	forbidden := []string{
		"net", "net/http", "net/url", "os/exec",
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
		"github.com/Jtensetti/nomad-selection-firewall/firewall",
		"github.com/Jtensetti/nomad-testnet/live/node",
		"github.com/Jtensetti/nomad-testnet/live/hop",
		"github.com/Jtensetti/nomad-testnet/live/uplink",
		"github.com/Jtensetti/nomad-testnet/live/fetchplan",
		"github.com/Jtensetti/nomad-testnet/live/partialfetch",
	}
	visited := map[string]bool{}
	var walk func(path, from string)
	walk = func(path, from string) {
		if visited[path] || path == "C" {
			return
		}
		visited[path] = true
		for _, banned := range forbidden {
			if path == banned {
				t.Errorf("live/airlock reaches %q via %s: the release boundary must have "+
					"no path to a socket, a scheduler or peer selection", path, from)
				return
			}
		}
		pkg, err := build.Import(path, "", 0)
		if err != nil {
			return
		}
		if pkg.Goroot {
			return
		}
		for _, next := range pkg.Imports {
			walk(next, from+" -> "+path)
		}
	}
	root := "github.com/Jtensetti/nomad-testnet/live/airlock"
	pkg, err := build.Import(root, "", 0)
	if err != nil {
		t.Skipf("cannot resolve the package graph in this environment: %v", err)
	}
	for _, next := range pkg.Imports {
		if strings.HasPrefix(next, "golang.org/x/") {
			continue
		}
		walk(next, root)
	}
}
