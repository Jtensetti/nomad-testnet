package supplychain_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// PROD-25 asks about malicious dependencies as well as vulnerable ones.
// govulncheck answers a different question: whether a *known advisory* is
// reachable. It says nothing about a module that is exactly what its author
// intended and hostile, or about one that arrived without anybody deciding it
// should.
//
// The second of those is the part a repository can control, and it is the way
// this class of attack usually lands: not by compromising a module somebody
// chose, but by an update quietly adding a transitive one nobody looked at.
// So the set of external modules is closed and reviewed. A requirement that is
// not in DEPENDENCY_POLICY.json fails here, which makes adding a dependency an
// edit to a file with a reviewer rather than a line in a diff nobody reads.
//
// What this does not establish, stated here as well as in the policy file: that
// a listed module is benign. Nothing here reads upstream source.

type dependencyPolicy struct {
	Allowed []struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		Why     string `json:"why"`
	} `json:"allowed"`
	AllowedOlderInComponents []struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		Why     string `json:"why"`
	} `json:"allowed_older_in_components"`
}

var requirePattern = regexp.MustCompile(`^\s*([a-zA-Z0-9._~+-]+(?:\.[a-zA-Z0-9._~+-]+)*\/[^\s]+)\s+(v[^\s]+)`)

// moduleFiles is every go.mod this repository owns: the integration root and
// each vendored component, which are separate modules behind replace
// directives and therefore carry their own requirements.
func moduleFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..")
	files := []string{filepath.Join(root, "go.mod")}
	entries, err := os.ReadDir(filepath.Join(root, "components"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, "components", entry.Name(), "go.mod")
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	if len(files) < 4 {
		t.Fatalf("found only %d go.mod files; the check is too narrow to mean anything",
			len(files))
	}
	return files
}

// requirements reads the module paths and versions a go.mod requires,
// ignoring the ones this repository replaces with its own vendored trees.
func requirements(t *testing.T, path string) map[string]string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaced := map[string]struct{}{}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "replace ") {
			continue
		}
		parts := strings.Fields(strings.TrimPrefix(trimmed, "replace "))
		if len(parts) >= 1 {
			replaced[parts[0]] = struct{}{}
		}
	}

	found := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "require (":
			inBlock = true
			continue
		case inBlock && trimmed == ")":
			inBlock = false
			continue
		case strings.HasPrefix(trimmed, "require ") && !inBlock:
			trimmed = strings.TrimPrefix(trimmed, "require ")
		case !inBlock:
			continue
		}
		match := requirePattern.FindStringSubmatch(trimmed)
		if match == nil {
			continue
		}
		if _, isReplaced := replaced[match[1]]; isReplaced {
			continue
		}
		found[match[1]] = match[2]
	}
	return found
}

func loadPolicy(t *testing.T) dependencyPolicy {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "DEPENDENCY_POLICY.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy dependencyPolicy
	if err := json.Unmarshal(content, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Allowed) == 0 {
		t.Fatal("the dependency policy allows nothing, so every build would fail; this is " +
			"a broken policy rather than a strict one")
	}
	return policy
}

func TestEveryExternalDependencyIsInThePolicy(t *testing.T) {
	policy := loadPolicy(t)
	allowed := map[string]map[string]struct{}{}
	for _, entry := range policy.Allowed {
		if allowed[entry.Module] == nil {
			allowed[entry.Module] = map[string]struct{}{}
		}
		allowed[entry.Module][entry.Version] = struct{}{}
	}
	for _, entry := range policy.AllowedOlderInComponents {
		if allowed[entry.Module] == nil {
			allowed[entry.Module] = map[string]struct{}{}
		}
		allowed[entry.Module][entry.Version] = struct{}{}
	}

	seen := map[string]struct{}{}
	for _, path := range moduleFiles(t) {
		for module, version := range requirements(t, path) {
			seen[module] = struct{}{}
			versions, listed := allowed[module]
			if !listed {
				t.Errorf("%s requires %s %s, which no reviewer has approved. Add it to "+
					"DEPENDENCY_POLICY.json with a reason, or remove the requirement.",
					path, module, version)
				continue
			}
			if _, ok := versions[version]; !ok {
				want := make([]string, 0, len(versions))
				for candidate := range versions {
					want = append(want, candidate)
				}
				sort.Strings(want)
				t.Errorf("%s requires %s %s; the policy approves %s. A version bump is a "+
					"new review, because the bytes are different.",
					path, module, version, strings.Join(want, ", "))
			}
		}
	}

	// An entry nobody requires any more is a reviewer's attention spent on
	// something that is not there, and it makes the list look larger than the
	// surface it describes.
	for _, entry := range policy.Allowed {
		if _, required := seen[entry.Module]; !required {
			t.Errorf("the policy approves %s and nothing requires it", entry.Module)
		}
	}
}

// A replace that points outside the repository substitutes code with no trace
// in go.sum and no entry in the snapshot manifest: the module resolves to
// whatever is at that path on the machine doing the build. Every replace here
// must point at a vendored tree this repository pins by content.
func TestEveryReplacementPointsInsideThisRepository(t *testing.T) {
	checked := 0
	for _, path := range moduleFiles(t) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "replace ") {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) < 4 {
				t.Errorf("%s: cannot read replacement %q", path, trimmed)
				continue
			}
			target := parts[len(parts)-1]
			checked++
			if !strings.HasPrefix(target, "./") && !strings.HasPrefix(target, "../") {
				t.Errorf("%s replaces %s with %s, which is not a path in this repository, "+
					"so the module that ships is whatever is there at build time",
					path, parts[1], target)
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), target)
			if _, err := os.Stat(filepath.Join(resolved, "go.mod")); err != nil {
				t.Errorf("%s replaces %s with %s, which has no go.mod: %v",
					path, parts[1], target, err)
				continue
			}
			relative, err := filepath.Rel(filepath.Join(".."), resolved)
			if err != nil || strings.HasPrefix(relative, "..") {
				t.Errorf("%s replaces %s with %s, which resolves outside the repository",
					path, parts[1], target)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no replacements were examined; this repository is built on vendored " +
			"components and finding none means the check did not run")
	}
}

// Every approved module must be content-addressed. A requirement with no
// go.sum entry is a module the toolchain would fetch and accept on whatever
// the proxy served that day.
func TestEveryApprovedDependencyIsPinnedByContent(t *testing.T) {
	sum, err := os.ReadFile(filepath.Join("..", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	lines := string(sum)
	policy := loadPolicy(t)
	for _, entry := range policy.Allowed {
		if !strings.Contains(lines, entry.Module+" "+entry.Version+"/go.mod ") {
			t.Errorf("go.sum has no go.mod hash for %s %s", entry.Module, entry.Version)
		}
		if !strings.Contains(lines, entry.Module+" "+entry.Version+" h1:") {
			t.Errorf("go.sum has no module hash for %s %s, so its content is not pinned",
				entry.Module, entry.Version)
		}
	}
}

// The checksum database is what makes go.sum's hashes mean something the first
// time a module is fetched. Turning it off for a Nomad module would let a
// substituted module be recorded as legitimate.
func TestNothingDisablesTheChecksumDatabase(t *testing.T) {
	for _, variable := range []string{"GONOSUMDB", "GONOSUMCHECK", "GOFLAGS", "GOPRIVATE", "GONOSUMVERIFY"} {
		value := os.Getenv(variable)
		if value == "" {
			continue
		}
		if strings.Contains(value, "Jtensetti") || strings.Contains(value, "*") ||
			strings.Contains(value, "insecure") || strings.Contains(value, "mod=mod") {
			t.Errorf("%s is %q, which relaxes module verification for this build", variable, value)
		}
	}
	if value := os.Getenv("GONOSUMDB"); value != "" {
		t.Errorf("GONOSUMDB is set to %q", value)
	}
	if value := os.Getenv("GOSUMDB"); value == "off" {
		t.Error("GOSUMDB is off, so a substituted module would be recorded as legitimate " +
			"the first time it is fetched")
	}
}
