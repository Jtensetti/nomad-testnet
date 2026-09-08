package nomadbrowser_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Linux client writes nothing to disk.
//
// That is the reason its uninstall story is one line -- there is no private
// state to remove, because none is created -- and the reason
// linux/run-sandboxed.sh can bind the object directory read-only. Both of
// those rest on the property, so the property is asserted here rather than
// left to hold by accident.
//
// An index derived from a reader's corpus is private: which objects were
// materialised for this reader, and what they are near. Persisting one would
// put that on disk and would need every uninstall path, retention document and
// sandbox binding updated with it. This test is what makes that a decision
// rather than an oversight.

// writeCalls are the standard-library entry points that create or modify a
// path. An allowlist would be wrong here -- this is a denylist, and it is
// checked against a planted write so it cannot silently list nothing.
var writeCalls = map[string]map[string]bool{
	"os": {
		"Create": true, "CreateTemp": true, "OpenFile": true, "WriteFile": true,
		"Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "Rename": true,
		"Remove": true, "RemoveAll": true, "Symlink": true, "Link": true,
		"Chmod": true, "Chown": true, "Truncate": true, "WriteString": true,
	},
	"ioutil": {"WriteFile": true, "TempFile": true, "TempDir": true},
}

func clientPackages(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "./cmd/nomad-browser").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const prefix = "github.com/Jtensetti/nomad-browser/"
	var directories []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		directories = append(directories, strings.TrimPrefix(line, prefix))
	}
	if len(directories) == 0 {
		t.Fatal("the client resolved to no in-module packages, so this test reads nothing")
	}
	return directories
}

// findWrites reports every write-capable call in the non-test sources of the
// given directories, as "package.Function at file:line".
func findWrites(t *testing.T, directories []string) []string {
	t.Helper()
	var found []string
	for _, directory := range directories {
		fileSet := token.NewFileSet()
		packages, err := parser.ParseDir(fileSet, directory, func(info os.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", directory, err)
		}
		for _, parsed := range packages {
			for path, file := range parsed.Files {
				ast.Inspect(file, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := selector.X.(*ast.Ident)
					if !ok {
						return true
					}
					if writeCalls[pkg.Name][selector.Sel.Name] {
						found = append(found, pkg.Name+"."+selector.Sel.Name+" at "+
							filepath.Base(path)+":"+
							fileSetPosition(fileSet, call.Pos()))
					}
					return true
				})
			}
		}
	}
	return found
}

func fileSetPosition(fileSet *token.FileSet, pos token.Pos) string {
	return strings.TrimPrefix(fileSet.Position(pos).String(),
		fileSet.Position(pos).Filename+":")
}

func TestTheLinuxClientWritesNothingToDisk(t *testing.T) {
	if writes := findWrites(t, clientPackages(t)); len(writes) > 0 {
		t.Fatalf("the Linux client can write to disk:\n  %s\n\nA client that "+
			"writes creates private state a reader has to be able to remove, so "+
			"linux/README.md's uninstall section, the retention documentation and "+
			"run-sandboxed.sh's read-only bind all have to change with it.",
			strings.Join(writes, "\n  "))
	}
}

// The control. A detector that listed nothing would pass the test above
// perfectly, so it is pointed at a package that does write and must find it.
func TestTheWriteDetectorFindsAWriteWhenThereIsOne(t *testing.T) {
	planted := t.TempDir()
	source := `package planted

import "os"

func Save(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
`
	if err := os.WriteFile(filepath.Join(planted, "planted.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	writes := findWrites(t, []string{planted})
	if len(writes) != 1 || !strings.Contains(writes[0], "os.WriteFile") {
		t.Fatalf("the detector found %v in a package that writes once", writes)
	}
}
