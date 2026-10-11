package nomadbrowser_test

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func dependencies(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	deps := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(string(out)))
	for s.Scan() {
		deps[s.Text()] = true
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	return deps
}

func TestSelectorDependencyGraphHasNoNetworkPlanner(t *testing.T) {
	deps := dependencies(t, "./selector")
	for _, forbidden := range []string{
		"github.com/Jtensetti/nomad-selection-firewall/firewall",
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
	} {
		if deps[forbidden] {
			t.Fatalf("selector depends on network package %s", forbidden)
		}
	}
}

func TestPlannerDependencyGraphHasNoPrivateSelectionPackages(t *testing.T) {
	deps := dependencies(t, "./planner")
	for _, forbidden := range []string{
		"github.com/Jtensetti/nomad-semantic-basins/basin",
		"github.com/Jtensetti/nomad-local-reconstruction/reconstruct",
	} {
		if deps[forbidden] {
			t.Fatalf("planner depends on private-selection package %s", forbidden)
		}
	}
}

func TestVerifiedResourcePathHasNoNetworkPlannerOrSemanticQuery(t *testing.T) {
	for _, pkg := range []string{"./adapter", "./localcache"} {
		deps := dependencies(t, pkg)
		for _, forbidden := range []string{
			"github.com/Jtensetti/nomad-selection-firewall/firewall",
			"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
			"github.com/Jtensetti/nomad-semantic-basins/basin",
		} {
			if deps[forbidden] {
				t.Fatalf("%s depends on forbidden package %s", pkg, forbidden)
			}
		}
	}
}

// An updater that fetches is a network client inside the binary that is
// supposed to have none, and every guarantee downstream of "this process
// cannot open a socket" would then rest on that one component behaving.
//
// So the update package verifies bytes the user already has and downloads
// nothing. That division is enforced here:
// the package must not be able to reach a socket, launch a process, or read
// the private selection side.
// The browser core's guarantees rest on the release process being unable to
// open a socket. That was asserted for exactly one package, the update
// verifier, and it was false for another: ./selector transitively linked net,
// net/http and crypto/tls, because github.com/Jtensetti/nomad-semantic-basins
// shipped a loopback HTTP embedder in the same package as the query handling.
// Nothing constructed it; the dependency arrived by import alone, which is
// precisely what a dependency gate is for and this one did not look. The
// embedder now lives in basin/loopback, which a deployment opts into.
//
// So the check covers every package that can end up in a Nomad process,
// rather than the one somebody remembered to name.
func TestNoBrowserCorePackageCanReachASocket(t *testing.T) {
	// Socket and process capability only. net/url is deliberately absent: it
	// parses strings and cannot open anything, and ./egress exists precisely
	// to decide which URLs a renderer may ask for. Forbidding it there would
	// be a gate against the package doing its job. Where handling a URL at
	// all is out of character -- the update verifier -- it stays forbidden,
	// in the test below.
	forbidden := []string{
		"net",
		"net/http",
		"crypto/tls",
		"os/exec",
		"github.com/Jtensetti/nomad-semantic-basins/basin/loopback",
	}
	for _, pkg := range []string{
		"./adapter", "./egress", "./localcache", "./planner", "./selector",
		"./update", "./cmd/nomad-browser-verify",
	} {
		deps := dependencies(t, pkg)
		for _, banned := range forbidden {
			if deps[banned] {
				t.Errorf("%s links %s, so a Nomad process built from it can open a "+
					"socket or launch a process", pkg, banned)
			}
		}
	}
}

func TestUpdateVerifierHasNoNetworkOrProcessCapability(t *testing.T) {
	deps := dependencies(t, "./update")
	for _, forbidden := range []string{
		"net",
		"net/http",
		"net/url",
		"os/exec",
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
		"github.com/Jtensetti/nomad-semantic-basins/basin",
	} {
		if deps[forbidden] {
			t.Errorf("the update verifier reaches %s, so it could fetch a release "+
				"rather than only checking one", forbidden)
		}
	}
}

// The Linux client's claim is that it cannot reach the network. The launcher
// in linux/ enforces that with a network namespace, but the strongest form of
// the claim is that there is nothing in the binary to enforce it against: no
// networking package is linked into it at all.
//
// go list -deps is the whole transitive graph, so this covers packages pulled
// in indirectly as well as those imported here.
func TestTheLinuxClientLinksNoNetworkingPackage(t *testing.T) {
	deps := dependencies(t, "./cmd/nomad-browser")
	for _, forbidden := range []string{
		"net",
		"net/http",
		"net/url",
		"crypto/tls",
		"os/exec",
	} {
		if deps[forbidden] {
			t.Fatalf("the Linux client links %s; a reader of local objects has "+
				"no use for it, and its presence makes the networkless claim "+
				"depend on the program's behaviour rather than on its contents",
				forbidden)
		}
	}
}

// The private selection side must not acquire a socket-capable dependency
// either, since it is the package that handles query text.
func TestTheSearchIndexLinksNoNetworkingPackage(t *testing.T) {
	deps := dependencies(t, "./search")
	for _, forbidden := range []string{"net", "net/http", "crypto/tls"} {
		if deps[forbidden] {
			t.Fatalf("search links %s, so the package holding query text can open a socket", forbidden)
		}
	}
}

// Verifying a model pack is hashing files and reading a manifest. Neither
// needs an inference runtime, so the tool that does it links none -- and keeps
// the same guarantee as the client it reports for.
//
// This matters because the obvious way to run a real model is the sealed
// loopback service, and that would put a socket in whatever links it. Keeping
// verification separate from inference is what lets a reader check a pack
// without giving the checker a network stack.
func TestTheModelToolLinksNoNetworkingPackage(t *testing.T) {
	deps := dependencies(t, "./cmd/nomad-model")
	for _, forbidden := range []string{"net", "net/http", "net/url", "crypto/tls", "os/exec"} {
		if deps[forbidden] {
			t.Fatalf("the model tool links %s", forbidden)
		}
	}
}

// The semantic model machinery is reachable from the client -- the client has
// to know a fingerprint to pick an index -- so it must not drag a socket in
// behind it. basin/model describes and verifies models; it does not run them.
func TestTheModelPackageDoesNotPutASocketInTheClient(t *testing.T) {
	deps := dependencies(t, "github.com/Jtensetti/nomad-semantic-basins/basin/model")
	for _, forbidden := range []string{"net", "net/http", "crypto/tls", "os/exec"} {
		if deps[forbidden] {
			t.Fatalf("basin/model links %s; a model pack may open a socket, the "+
				"package that describes models may not", forbidden)
		}
	}
}

// The browser links no third-party code at all.
//
// Every dependency-graph test above bans a particular capability -- a socket,
// a process, a private-selection package. This one bans the category those
// bans are trying to reason about: code nobody here reviewed. A vulnerability
// gate scans what is there, and a digest pins what is there; neither says
// anything about a module arriving. This does.
//
// It is worth asserting rather than noticing because the current answer is
// zero. A module graph at zero is a claim a reader can check in one line; one
// at four is a list somebody has to keep reviewing, and the difference between
// them should be a decision.
// thirdPartyModules is the scan itself, factored out so the control below runs
// this code rather than a second copy of it. `go list -m all` prints the main
// module first; everything after it is a dependency.
func thirdPartyModules(t *testing.T, directory string, environment []string) []string {
	t.Helper()
	command := exec.Command("go", "list", "-m", "all")
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	out, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("go list -m all in %s: %v\n%s", directory, err, exit.Stderr)
		}
		t.Fatalf("go list -m all in %s: %v", directory, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("go list -m all named no main module in %s", directory)
	}
	var third []string
	for _, line := range lines[1:] {
		module, _, _ := strings.Cut(line, " ")
		if module == "" {
			continue
		}
		third = append(third, module)
	}
	return third
}

// The browser links no third-party code, and couples to exactly these three
// sibling repositories. Both halves are decisions rather than facts to notice:
// a third-party module here is code no one in this project reviewed, running
// inside the binary whose whole claim is what it cannot do, and a fourth
// sibling is a repository this one now cannot ship without.
var expectedSiblings = []string{
	"github.com/Jtensetti/nomad-local-reconstruction",
	"github.com/Jtensetti/nomad-selection-firewall",
	"github.com/Jtensetti/nomad-semantic-basins",
}

func TestTheModuleGraphHasNoThirdPartyCode(t *testing.T) {
	const own = "github.com/Jtensetti/"
	expected := map[string]bool{}
	for _, module := range expectedSiblings {
		expected[module] = true
	}
	var third, siblings []string
	for _, module := range thirdPartyModules(t, ".", nil) {
		if strings.HasPrefix(module, own) {
			siblings = append(siblings, module)
			continue
		}
		third = append(third, module)
	}
	if len(third) > 0 {
		t.Errorf("the browser's module graph now contains code from outside this "+
			"project:\n  %s\n\nThat is not forbidden, but it is a decision: a "+
			"module here is code no one in this project reviewed, running inside "+
			"the binary whose whole claim is what it cannot do. Update this test "+
			"deliberately, and say in the commit who reviewed what.",
			strings.Join(third, "\n  "))
	}

	sort.Strings(siblings)
	var added []string
	for _, module := range siblings {
		if !expected[module] {
			added = append(added, module)
		}
		delete(expected, module)
	}
	var gone []string
	for module := range expected {
		gone = append(gone, module)
	}
	sort.Strings(gone)
	if len(added) > 0 {
		t.Errorf("the browser now depends on sibling repositories it did not:\n  %s\n\n"+
			"Each is a repository this one cannot ship without. Add them here "+
			"deliberately.", strings.Join(added, "\n  "))
	}
	if len(gone) > 0 {
		t.Errorf("this test names sibling repositories the browser no longer "+
			"depends on:\n  %s\n\nRemove them, so the list describes this build.",
			strings.Join(gone, "\n  "))
	}
}

// The control for the test above: the same scan, run against a module graph
// that does contain a dependency, must report it. A scan that always found
// nothing would pass the zero case perfectly.
//
// The fixture requires a second module and replaces it with a local directory,
// so it resolves under GOPROXY=off. The first version named a real dependency
// and skipped when the module cache could not resolve it -- which made the
// control disappear in exactly the environments that need it.
func TestTheThirdPartyScanReportsWhatIsThere(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "dep"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod": "module example.test\n\ngo 1.25.0\n\n" +
			"require example.test/dep v1.0.0\n\nreplace example.test/dep => ./dep\n",
		"use.go":     "package use\n",
		"dep/go.mod": "module example.test/dep\n\ngo 1.25.0\n",
		"dep/dep.go": "package dep\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found := thirdPartyModules(t, directory, []string{"GOFLAGS=-mod=mod", "GOPROXY=off"})
	if len(found) != 1 || found[0] != "example.test/dep" {
		t.Fatalf("the scan did not report the one dependency that is plainly there: %v", found)
	}
}
