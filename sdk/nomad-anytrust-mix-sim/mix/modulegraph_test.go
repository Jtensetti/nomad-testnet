package mix

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// Two different sets, pinned separately because they mean different things.
//
// compiledModules is code that runs: modules providing packages this one's
// build or tests actually import. A new name here is new third-party code
// executing inside a process that mixes other people's traffic.
//
// Only two of them are chosen -- go.dedis.ch/kyber/v4 for the group
// operations and the Pedersen DKG, and golang.org/x/crypto. fixbuf and x/sys
// arrive through kyber, which is exactly why the list is written out: a
// transitive addition is the one nobody notices.
var compiledModules = []string{
	"go.dedis.ch/fixbuf",
	"go.dedis.ch/kyber/v4",
	"golang.org/x/crypto",
	"golang.org/x/sys",
}

// graphModules is the whole module graph -- what go.sum pins and what a
// vulnerability scan walks. Thirteen of these compile into nothing here; they
// are reachable only through dependencies' own tests and tools. Pinned anyway
// because a name arriving in this list is a name one import away from the
// list above, and go.sum growing is not otherwise visible in review.
var graphModules = []string{
	"github.com/bits-and-blooms/bitset",
	"github.com/cloudflare/circl",
	"github.com/consensys/gnark-crypto",
	"github.com/davecgh/go-spew",
	"github.com/kilic/bls12-381",
	"github.com/kr/text",
	"github.com/pmezard/go-difflib",
	"github.com/rogpeppe/go-internal",
	"github.com/stretchr/testify",
	"go.dedis.ch/fixbuf",
	"go.dedis.ch/kyber/v4",
	"golang.org/x/crypto",
	"golang.org/x/net",
	"golang.org/x/sys",
	"golang.org/x/term",
	"golang.org/x/text",
	"gopkg.in/yaml.v3",
}

func goList(t *testing.T, arguments ...string) []string {
	t.Helper()
	out, err := exec.Command("go", arguments...).Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(arguments, " "), err)
	}
	seen := map[string]bool{}
	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		module, _, _ := strings.Cut(line, " ")
		if module == "" || strings.HasPrefix(module, "github.com/Jtensetti/") || seen[module] {
			continue
		}
		seen[module] = true
		found = append(found, module)
	}
	sort.Strings(found)
	return found
}

func compiledExternalModules(t *testing.T) []string {
	t.Helper()
	return goList(t, "list", "-deps", "-test", "-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./...")
}

func graphExternalModules(t *testing.T) []string {
	t.Helper()
	return goList(t, "list", "-m", "all")
}

func compareModuleSets(t *testing.T, what string, expected, found []string) {
	t.Helper()
	remaining := map[string]bool{}
	for _, module := range expected {
		remaining[module] = true
	}
	var added []string
	for _, module := range found {
		if !remaining[module] {
			added = append(added, module)
		}
		delete(remaining, module)
	}
	var gone []string
	for module := range remaining {
		gone = append(gone, module)
	}
	sort.Strings(gone)

	if len(added) > 0 {
		t.Errorf("modules %s that are not in the reviewed set:\n  %s\n\n"+
			"Add them here deliberately, and say in the commit what they are and who "+
			"looked at them. A transitive addition is the one nobody notices.",
			what, strings.Join(added, "\n  "))
	}
	if len(gone) > 0 {
		t.Errorf("the reviewed set names modules that are not %s:\n  %s\n\n"+
			"Remove them here, so the list stays a description of this build rather "+
			"than of an older one.", what, strings.Join(gone, "\n  "))
	}
}

func TestTheCompiledModulesAreTheOnesThatWereReviewed(t *testing.T) {
	compareModuleSets(t, "compiled into this module", compiledModules, compiledExternalModules(t))
}

func TestTheModuleGraphIsTheOneThatWasReviewed(t *testing.T) {
	compareModuleSets(t, "in this module's graph", graphModules, graphExternalModules(t))
}

// The two scans measure different things, and a change that quietly made them
// measure the same thing would leave the distinction above stated but not
// enforced. The graph is a strict superset here: it holds names nothing
// imports.
func TestTheGraphHoldsModulesNothingCompilesAgainst(t *testing.T) {
	compiled := map[string]bool{}
	for _, module := range compiledExternalModules(t) {
		compiled[module] = true
	}
	graph := graphExternalModules(t)
	var uncompiled []string
	for _, module := range graph {
		if !compiled[module] {
			uncompiled = append(uncompiled, module)
		}
	}
	if len(uncompiled) == 0 {
		t.Fatalf("every module in the graph now compiles into this one, so the two "+
			"scans no longer measure different things; graph was %v", graph)
	}
	for module := range compiled {
		var inGraph bool
		for _, candidate := range graph {
			if candidate == module {
				inGraph = true
			}
		}
		if !inGraph {
			t.Fatalf("%s compiles into this module but is absent from its graph, so "+
				"one of the two scans is wrong", module)
		}
	}
}

// The control. A scan that returned nothing would pass both gates above by
// reporting no additions, so each must find what is plainly there.
func TestTheModuleScansSeeTheDependencyThisModuleHas(t *testing.T) {
	for name, found := range map[string][]string{
		"compiled": compiledExternalModules(t),
		"graph":    graphExternalModules(t),
	} {
		if len(found) == 0 {
			t.Fatalf("the %s scan found no external modules in a module that requires kyber", name)
		}
		var hasKyber bool
		for _, module := range found {
			if module == "go.dedis.ch/kyber/v4" {
				hasKyber = true
			}
		}
		if !hasKyber {
			t.Fatalf("the %s scan did not report kyber, which this module plainly "+
				"imports: %v", name, found)
		}
	}
}
