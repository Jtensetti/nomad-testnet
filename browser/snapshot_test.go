package nomadbrowser_test

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

// COMPONENTS.sha256 pins the vendored snapshots. CI checks it with
// `sha256sum --check`, which answers only "does every listed file still hash
// to what it says" -- never "is every shipped file listed", because a file
// absent from the manifest is a file sha256sum never looks at.
//
// nomad-testnet had exactly this gap: seventeen of forty-six vendored files
// were unlisted, including the RLNC budget enforcement its materializer relies
// on. This repository's manifest happens to be complete today. Nothing was
// keeping it that way.
const componentManifest = "COMPONENTS.sha256"

func TestSnapshotManifestPinsEveryVendoredFile(t *testing.T) {
	pinned := readComponentManifest(t)
	shipped := walkComponents(t)

	present := map[string]struct{}{}
	var unpinned []string
	for _, path := range shipped {
		present[path] = struct{}{}
		if _, listed := pinned[path]; !listed {
			unpinned = append(unpinned, path)
		}
	}
	var missing []string
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
	pinned := readComponentManifest(t)
	for _, path := range walkComponents(t) {
		expected, listed := pinned[path]
		if !listed {
			continue // reported by the completeness test
		}
		content, err := os.ReadFile(path)
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

func readComponentManifest(t *testing.T) map[string]string {
	t.Helper()
	encoded, err := os.ReadFile(componentManifest)
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{}
	for number, line := range strings.Split(strings.TrimSpace(string(encoded)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 2*sha256.Size {
			t.Fatalf("%s line %d is not a sha256sum entry: %q", componentManifest, number+1, line)
		}
		if previous, repeated := pinned[fields[1]]; repeated {
			// A repeated path lets one entry satisfy the checker while the
			// other silently disagrees about what ships.
			t.Fatalf("%s pins %s twice (%s and %s)",
				componentManifest, fields[1], previous[:16], fields[0][:16])
		}
		pinned[fields[1]] = fields[0]
	}
	return pinned
}

func walkComponents(t *testing.T) []string {
	t.Helper()
	var shipped []string
	err := filepath.WalkDir("components", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			shipped = append(shipped, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(shipped) < 10 {
		t.Fatalf("found only %d vendored files, so the tree was not walked as expected",
			len(shipped))
	}
	sort.Strings(shipped)
	return shipped
}

// COMPONENTS.sha256 and COMPONENTS.lock pin different things, and only one of
// them was checked.
//
// The digest manifest pins the bytes that ship. The lock records which upstream
// commit those bytes came from, which is what anyone auditing this integration
// follows to read the component's history. Nothing compared them, so all three
// lock entries had gone stale while the manifest stayed correct and every gate
// stayed green -- and an auditor checking out the recorded commit would have
// read code this repository does not carry.
//
// nomad-testnet hit exactly this and answered it in its own lock v2; this is
// the same check, and the reason the lock here now carries a tree digest.
func TestTheSnapshotLockTracksTheVendoredTrees(t *testing.T) {
	manifest, err := os.ReadFile("COMPONENTS.sha256")
	if err != nil {
		t.Fatal(err)
	}
	byComponent := map[string][]string{}
	for _, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("COMPONENTS.sha256 entry %q is not a digest and a path", line)
		}
		parts := strings.Split(fields[1], "/")
		if len(parts) < 2 || parts[0] != "components" {
			t.Fatalf("COMPONENTS.sha256 entry %q is not under components/", fields[1])
		}
		byComponent[parts[1]] = append(byComponent[parts[1]], fields[0]+"  "+fields[1])
	}
	if len(byComponent) == 0 {
		t.Fatal("no components ship, so this proves nothing")
	}

	locked := readSnapshotLock(t)
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
		if _, ships := byComponent[strings.TrimPrefix(module, "github.com/Jtensetti/")]; !ships {
			t.Errorf("COMPONENTS.lock names %s, which does not ship", module)
		}
	}
}

type snapshotLockEntry struct{ commit, branch, tree string }

func readSnapshotLock(t *testing.T) map[string]snapshotLockEntry {
	t.Helper()
	encoded, err := os.ReadFile("COMPONENTS.lock")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]snapshotLockEntry{}
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
		entries[fields[0]] = snapshotLockEntry{fields[1], fields[2], fields[3]}
	}
	return entries
}
