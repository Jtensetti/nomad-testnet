package durable

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryAcceptsADirectory(t *testing.T) {
	if err := Directory(t.TempDir()); err != nil {
		t.Fatalf("a real directory was refused: %v", err)
	}
}

// The flush differs between platforms and these do not: a path that names a
// file, or nothing, must fail the same way everywhere. A Windows build that
// accepted what a unix build rejects would turn a portability difference into
// a difference in what the code validates.
func TestDirectoryRefusesAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Directory(path)
	if err == nil {
		t.Fatal("a regular file was accepted as a directory to flush")
	}
	if !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("a regular file was refused for %q rather than for not being a directory", err)
	}
}

func TestDirectoryRefusesAMissingPath(t *testing.T) {
	err := Directory(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("a path that does not exist was accepted")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing path was refused for %q rather than for not existing", err)
	}
}

// keepsItsOwnFlush reports functions that both open a path for reading and
// call Sync on something. Writing a file uses os.Create or os.OpenFile, so
// os.Open together with Sync is specifically the shape of a directory flush --
// which is the thing this package exists to be the only copy of.
func keepsItsOwnFlush(t *testing.T, file string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var found []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		var opens, syncs bool
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if identifier, ok := selector.X.(*ast.Ident); ok &&
				identifier.Name == "os" && selector.Sel.Name == "Open" {
				opens = true
			}
			if selector.Sel.Name == "Sync" {
				syncs = true
			}
			return true
		})
		if opens && syncs {
			found = append(found, function.Name.Name)
		}
	}
	return found
}

func TestNoOtherPackageKeepsItsOwnDirectoryFlush(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "components", "durable", "runtime", "deploy":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		for _, function := range keepsItsOwnFlush(t, path) {
			offenders = append(offenders, path+": "+function)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("these open a directory and flush it themselves:\n  %s\n\n"+
			"Call live/durable.Directory instead. Five packages had their own "+
			"copy, no two the same, and all five were broken on Windows in the "+
			"same way -- which is what made finding it cost five fixes rather "+
			"than one.", strings.Join(offenders, "\n  "))
	}
}

// The control. The scan above passes by finding nothing, so it must find the
// one that is there: this package's own unix implementation, parsed directly
// so the result does not depend on which platform the test runs on.
func TestTheFlushScanFindsTheOneThatIsThere(t *testing.T) {
	found := keepsItsOwnFlush(t, "directory_unix.go")
	if len(found) != 1 || found[0] != "Directory" {
		t.Fatalf("the scan did not find this package's own directory flush: %v", found)
	}
}
