package deposit

import (
	"go/build"
	"strings"
	"testing"
)

// A gate that skips has not passed. These resolve the package graph with
// go/build, a library call over source that is present whenever tests run
// at all, so a failure here means the capability boundary was not checked
// rather than that this environment is unusual -- and an unchecked boundary
// on the emission path is exactly what must not pass quietly.

// The drain bridges the publication queue and the uplink, which makes it the
// one package that legitimately touches both. That is exactly why it must not
// also own a socket: a component that can read the queue and write to the
// network is a component that can decide *when* to write based on what it
// read, and the whole design rests on that decision belonging to the clock.
//
// Emission is handed back to the caller as a cell. The scheduler that ticks,
// and the transport that sends, are somebody else's.
// Direct imports are checked separately from the transitive graph, because
// the two answer different questions and only one of them can be absolute
// here. The cell type lives in the fabric package alongside the UDP
// transport, so anything that produces a cell -- uplink included -- reaches
// "net" transitively and always will. That says nothing about whether this
// code can open a socket; what would say so is this package importing net
// itself, which is checked below and forbidden.
//
// Transitively, what must stay unreachable is the machinery that could make
// the drain's behaviour depend on something other than the clock: peer
// selection, the node's scheduler, hop routing, basin classification.
func TestDepositPathDoesNotImportTheNetworkItself(t *testing.T) {
	forbiddenDirect := []string{"net", "net/http", "net/url", "os/exec"}
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("cannot read this package, so the direct-import boundary went "+
			"unchecked: %v", err)
	}
	for _, imported := range append(pkg.Imports, pkg.TestImports...) {
		for _, banned := range forbiddenDirect {
			if imported == banned {
				t.Errorf("live/deposit imports %q directly: emission is the caller's, "+
					"and a package that can both read the queue and write to the "+
					"network can decide when to write from what it read", imported)
			}
		}
	}
}

func TestDepositPathCannotReachSelectionOrScheduling(t *testing.T) {
	forbidden := []string{
		"github.com/Jtensetti/nomad-selection-firewall/firewall",
		"github.com/Jtensetti/nomad-testnet/live/node",
		"github.com/Jtensetti/nomad-testnet/live/hop",
		"github.com/Jtensetti/nomad-semantic-basins/basin",
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
				t.Errorf("live/deposit reaches %q via %s: the drain must not be able to "+
					"make its behaviour depend on peer selection, routing or "+
					"classification", path, from)
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
	root := "github.com/Jtensetti/nomad-testnet/live/deposit"
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
}
