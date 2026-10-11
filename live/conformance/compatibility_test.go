package conformance_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// versionConstant matches the version strings the protocol puts on the wire.
var versionConstant = regexp.MustCompile(`"(nomad-[a-z0-9-]+-v\d+)"`)

// The compatibility matrix must name every versioned format the code knows
// about. A matrix that silently falls behind the source is worse than none: it
// reads as a complete statement of what a release accepts while omitting the
// format someone is about to get wrong.
func TestCompatibilityMatrixCoversEveryWireVersion(t *testing.T) {
	root := filepath.Join("..", "..")
	matrix, err := os.ReadFile(filepath.Join(root, "conformance", "COMPATIBILITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := string(matrix)

	found := map[string][]string{}
	for _, tree := range []string{"live", "cmd", "components"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			// Test files name versions they are deliberately refusing.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, match := range versionConstant.FindAllStringSubmatch(string(source), -1) {
				found[match[1]] = append(found[match[1]], path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) < 15 {
		t.Fatalf("only %d version constants found; the scan is not working", len(found))
	}

	var missing []string
	for version, paths := range found {
		if !strings.Contains(documented, "`"+version+"`") {
			missing = append(missing, version+" (in "+paths[0]+")")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the compatibility matrix omits %d wire version(s):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
