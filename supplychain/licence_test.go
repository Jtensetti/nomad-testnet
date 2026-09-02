package supplychain_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A vendored tree carries its upstream's licence, and upstream can change it.
// That arrives here as one line in a snapshot diff, in a file nobody re-reads,
// and this repository ships the result. So a licence that differs from this
// repository's own has to be written down in COMPONENT_LICENSES.md, which
// turns it from a diff into an entry somebody had to make.
//
// This checks that the difference is acknowledged. It does not judge whether
// the combination is permissible, which is not a thing a test can decide.

const componentLicences = "COMPONENT_LICENSES.md"

// licenceName is the first non-empty line of a LICENSE file, which is where
// all of these put their title.
func licenceName(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	t.Fatalf("%s is empty, so this repository ships code under no stated licence", path)
	return ""
}

func TestEveryVendoredLicenceMatchesOrIsAcknowledged(t *testing.T) {
	root := filepath.Join("..")
	own := licenceName(t, filepath.Join(root, "LICENSE"))
	record, err := os.ReadFile(filepath.Join(root, componentLicences))
	if err != nil {
		t.Fatalf("reading %s: %v", componentLicences, err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "components"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, "components", entry.Name(), "LICENSE")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s has no LICENSE, so this repository ships its code under "+
				"nothing anybody stated", entry.Name())
			continue
		}
		checked++
		name := licenceName(t, path)
		if name == own {
			continue
		}
		written := strings.ToLower(string(record))
		if !strings.Contains(written, strings.ToLower(entry.Name())) {
			t.Errorf("%s is licensed %q and this repository is %q, and %s does not "+
				"mention it. A licence changing under a vendored tree arrives as one "+
				"line in a snapshot diff; write down what happened.",
				entry.Name(), name, own, componentLicences)
			continue
		}
		if !strings.Contains(written, strings.ToLower(name)) {
			t.Errorf("%s is mentioned in %s but %q is not, so the record does not say "+
				"which licence it acquired", entry.Name(), componentLicences, name)
		}
	}
	if checked < 5 {
		t.Fatalf("only %d vendored licences were examined; this repository vendors "+
			"six components, so the check is too narrow to mean anything", checked)
	}
}
