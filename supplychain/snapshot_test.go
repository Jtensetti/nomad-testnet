package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// components/* are byte-for-byte snapshots of six separate repositories,
// wired in by replace directives. COMPONENTS.sha256 is what pins them: without
// it, an edit to a vendored file is indistinguishable from the upstream code
// it claims to be.
//
// CI verifies the manifest with `sha256sum --check`, which answers only "does
// every listed file still hash to what it says". It cannot answer the question
// that actually matters, "is every shipped file listed", because a file absent
// from the manifest is a file sha256sum never looks at. Seventeen of
// forty-six vendored files were unlisted when this test was written, including
// two production files: mix/blame.go, and rlnc/bounded.go, which is the budget
// enforcement the materializer relies on to bound a pollution attack. Either
// could have been edited in place with the supply-chain gate still green.
//
// So this test checks both halves, and checks them here rather than in the
// workflow so that a developer adding a vendored file finds out at `go test`
// instead of at review.
const manifest = "../COMPONENTS.sha256"

func TestSnapshotManifestPinsEveryVendoredFile(t *testing.T) {
	pinned := readManifest(t)
	shipped := walkComponents(t)

	var unpinned, missing []string
	for _, path := range shipped {
		if _, listed := pinned[path]; !listed {
			unpinned = append(unpinned, path)
		}
	}
	present := map[string]struct{}{}
	for _, path := range shipped {
		present[path] = struct{}{}
	}
	for path := range pinned {
		if _, exists := present[path]; !exists {
			missing = append(missing, path)
		}
	}
	sort.Strings(unpinned)
	sort.Strings(missing)

	if len(unpinned) > 0 {
		t.Errorf("%d vendored file(s) ship unpinned, so an edit to them passes the "+
			"supply-chain check:\n  %s", len(unpinned), strings.Join(unpinned, "\n  "))
	}
	if len(missing) > 0 {
		t.Errorf("%d manifest entr(ies) name a file that no longer ships:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

func TestSnapshotManifestDigestsMatchWhatShips(t *testing.T) {
	pinned := readManifest(t)
	for _, path := range walkComponents(t) {
		expected, listed := pinned[path]
		if !listed {
			continue // reported by the completeness test
		}
		content, err := os.ReadFile(filepath.Join("..", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		actual := sha256.Sum256(content)
		if hex.EncodeToString(actual[:]) != expected {
			t.Errorf("%s: ships as %x, manifest pins %s", path, actual[:8], expected[:16])
		}
	}
}

func readManifest(t *testing.T) map[string]string {
	t.Helper()
	encoded, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{}
	for number, line := range strings.Split(strings.TrimSpace(string(encoded)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("%s line %d is not a sha256sum entry: %q", manifest, number+1, line)
		}
		digest, path := fields[0], fields[1]
		if len(digest) != 2*sha256.Size {
			t.Fatalf("%s line %d does not carry a sha256 digest", manifest, number+1)
		}
		if previous, repeated := pinned[path]; repeated {
			// A repeated path lets one entry satisfy the checker while the
			// other silently disagrees about what ships.
			t.Fatalf("%s pins %s twice (%s and %s)", manifest, path, previous[:16], digest[:16])
		}
		pinned[path] = digest
	}
	return pinned
}

func walkComponents(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var shipped []string
	err = filepath.WalkDir(filepath.Join(root, "components"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		shipped = append(shipped, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(shipped) < 40 {
		t.Fatalf("found only %d vendored files, so the tree was not walked as expected", len(shipped))
	}
	sort.Strings(shipped)
	return shipped
}

// The manifest is only as good as the checker's willingness to fail. This
// proves the completeness half actually rejects an unlisted file rather than
// passing vacuously.
func TestAnUnlistedVendoredFileIsRejected(t *testing.T) {
	pinned := readManifest(t)
	shipped := walkComponents(t)
	intruder := "components/nomad-rlnc/rlnc/injected.go"
	if _, exists := pinned[intruder]; exists {
		t.Fatalf("%s is genuinely pinned, so this case proves nothing", intruder)
	}
	shipped = append(shipped, intruder)

	var unpinned []string
	for _, path := range shipped {
		if _, listed := pinned[path]; !listed {
			unpinned = append(unpinned, path)
		}
	}
	if len(unpinned) != 1 || unpinned[0] != intruder {
		t.Fatalf("an unlisted file was not detected: %v", unpinned)
	}
}

// COMPONENTS.lock says which upstream commit each vendored tree came from.
// Nothing checked it, and it drifted: the lock pinned a fabric commit whose
// scheduler had no ErrCellDropped while the vendored tree had one, so anyone
// auditing which fabric this integration carries would have checked out the
// wrong code and read the wrong behaviour. `sha256sum --check` cannot catch
// that, because the lock is not a list of file digests.
//
// A commit ID cannot be verified from inside this repository without fetching
// the upstream. What can be verified is that the lock was updated when the
// vendored code was: each line carries the digest of that component's lines in
// COMPONENTS.sha256, so moving a vendored file and leaving the lock alone
// fails here rather than in an audit.
func TestSnapshotLockTracksTheVendoredTrees(t *testing.T) {
	pinned := readManifest(t)
	byComponent := map[string][]string{}
	for path, digest := range pinned {
		parts := strings.Split(path, "/")
		if len(parts) < 2 {
			t.Fatalf("manifest entry %q is not under components/", path)
		}
		byComponent[parts[1]] = append(byComponent[parts[1]], digest+"  "+path)
	}

	locked := readLock(t)
	if len(locked) != len(byComponent) {
		t.Errorf("the lock names %d components and %d ship", len(locked), len(byComponent))
	}
	for component, lines := range byComponent {
		module := "github.com/Jtensetti/" + component
		entry, listed := locked[module]
		if !listed {
			t.Errorf("%s ships but COMPONENTS.lock does not name it", module)
			continue
		}
		sort.Strings(lines)
		sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
		if actual := hex.EncodeToString(sum[:]); actual != entry.tree {
			t.Errorf("%s: the vendored tree hashes to %s but the lock records %s. The "+
				"vendored code moved and the lock did not, so the commit it names is "+
				"no longer the code that ships.", module, actual[:16], entry.tree[:16])
		}
	}
	for module := range locked {
		component := strings.TrimPrefix(module, "github.com/Jtensetti/")
		if _, ships := byComponent[component]; !ships {
			t.Errorf("COMPONENTS.lock names %s, which does not ship", module)
		}
	}
}

type lockEntry struct {
	commit string
	branch string
	tree   string
}

func readLock(t *testing.T) map[string]lockEntry {
	t.Helper()
	encoded, err := os.ReadFile("../COMPONENTS.lock")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]lockEntry{}
	for index, line := range strings.Split(string(encoded), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("COMPONENTS.lock line %d has %d fields, want module, commit, "+
				"branch and tree digest: %q", index+1, len(fields), line)
		}
		if _, exists := entries[fields[0]]; exists {
			t.Fatalf("COMPONENTS.lock names %s twice", fields[0])
		}
		entries[fields[0]] = lockEntry{commit: fields[1], branch: fields[2], tree: fields[3]}
	}
	return entries
}
