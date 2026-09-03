package publish

import (
	"go/build"
	"strings"
	"testing"
)

// The queue is the API a publishing application holds. Submit puts an object's
// encrypted fragments on disk and returns; nothing about that call reaches the
// network, and the whole airlock rests on it staying that way.
//
// live/deposit and live/airlock each state their capability boundary as a test.
// This package -- the one furthest from the wire and closest to the caller --
// did not, and was clean only by not having been given a reason to change. A
// separation that holds because nobody has needed to break it yet is not a
// separation; the day someone adds a "confirm the deposit landed" call here,
// publishing becomes an observable network event caused by private activity,
// and this is what has to fail then.
//
// A gate that skips has not passed, so these resolve the graph with go/build --
// a library call over source, present whenever tests run at all. A failure here
// means the boundary went unchecked rather than that this environment is
// unusual.

func TestPublishingCannotReachTheNetwork(t *testing.T) {
	forbiddenDirect := []string{"net", "net/http", "net/url", "os/exec"}
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("cannot read this package, so the direct-import boundary went "+
			"unchecked: %v", err)
	}
	imports := append(pkg.Imports, pkg.TestImports...)
	if len(imports) == 0 {
		t.Fatal("this package resolved to no imports at all, so nothing was checked")
	}
	for _, imported := range imports {
		for _, banned := range forbiddenDirect {
			if imported == banned {
				t.Errorf("live/publish imports %q directly: submitting an object must "+
					"not be able to emit anything, or the existence of a network "+
					"event becomes a fact about what the user published", imported)
			}
		}
	}
}

// Transitively, what must stay unreachable is everything that could turn a
// submission into an emission or make one depend on the other: the fabric's
// scheduler and transport, the uplink session that seals cells, the drain that
// bridges the two, peer selection, hop routing and basin classification.
//
// Unlike live/deposit, this package has no legitimate reason to reach any of
// them even indirectly -- it hands fragments to a directory, and something else
// entirely reads that directory on a clock.
func TestPublishingCannotReachEmissionOrSelection(t *testing.T) {
	forbidden := []string{
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
		"github.com/Jtensetti/nomad-selection-firewall/firewall",
		"github.com/Jtensetti/nomad-semantic-basins/basin",
		"github.com/Jtensetti/nomad-testnet/live/deposit",
		"github.com/Jtensetti/nomad-testnet/live/fetchplan",
		"github.com/Jtensetti/nomad-testnet/live/hop",
		"github.com/Jtensetti/nomad-testnet/live/node",
		"github.com/Jtensetti/nomad-testnet/live/partialfetch",
		"github.com/Jtensetti/nomad-testnet/live/uplink",
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
				t.Errorf("live/publish reaches %q via %s: a queue that can reach the "+
					"emission path can make a submission cause a packet", path, from)
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
	root := "github.com/Jtensetti/nomad-testnet/live/publish"
	pkg, err := build.Import(root, "", 0)
	if err != nil {
		t.Fatalf("cannot resolve the package graph, so the capability boundary went "+
			"unchecked: %v", err)
	}
	for _, next := range pkg.Imports {
		if strings.HasPrefix(next, "golang.org/x/") {
			continue
		}
		walk(next, root)
	}
	if len(visited) == 0 {
		t.Fatal("the walk visited no packages, so this check proved nothing")
	}
}
