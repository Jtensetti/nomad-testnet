package supplychain_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A checkout has to be the commit, byte for byte, because several things here
// are sealed by content: conformance/wire-vectors.json by a digest,
// COMPONENTS.sha256 by hashes of vendored trees, live/epoch/testdata by a
// direct comparison against its encoder.
//
// Git's default on Windows is core.autocrlf=true, which rewrites LF to CRLF on
// checkout. The first Windows CI run found it: the epoch vector comparison
// failed on bytes that were identical in the repository, which means a second
// implementer verifying the conformance corpus on Windows would have computed
// a different digest for it and had no way to tell why. .gitattributes now
// turns the translation off for every file.

// carriageReturns reports whether a text file contains one. Binary files are
// exempt and say so: git only translates what it judges to be text, using the
// presence of a NUL byte to decide, and a carriage return inside a compiled
// artefact or a packet capture is data rather than a line ending.
func carriageReturns(t *testing.T, path string) (found, isText bool) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	head := content
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false, false
	}
	return bytes.ContainsRune(content, '\r'), true
}

func TestLineEndingTranslationIsOffForEveryFile(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", ".gitattributes"))
	if err != nil {
		t.Fatalf("there is no .gitattributes, so a Windows checkout rewrites line "+
			"endings and stops being the commit: %v", err)
	}
	var found bool
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Fields(line) != nil && len(strings.Fields(line)) == 2 &&
			strings.Fields(line)[0] == "*" && strings.Fields(line)[1] == "-text" {
			found = true
		}
	}
	if !found {
		t.Fatalf(".gitattributes does not contain the rule `* -text`, so line-ending "+
			"translation is on for files it does not name:\n%s", content)
	}
}

// The paths whose bytes are the evidence. A carriage return in any of them
// means the working tree and the repository disagree.
var byteExact = []string{
	filepath.Join("..", "conformance"),
	filepath.Join("..", "live", "epoch", "testdata"),
	filepath.Join("..", "COMPONENTS.sha256"),
}

func TestTheSealedArtefactsHaveNoCarriageReturns(t *testing.T) {
	checked := 0
	for _, root := range byteExact {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("%s is named as byte-exact evidence and is not there: %v", root, err)
		}
		if !info.IsDir() {
			if found, isText := carriageReturns(t, root); isText {
				checked++
				if found {
					t.Errorf("%s contains a carriage return", root)
				}
			}
			continue
		}
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				// Build output that git ignores is not part of the commit, so
				// what it contains says nothing about the checkout.
				if entry.Name() == "__pycache__" {
					return fs.SkipDir
				}
				return nil
			}
			found, isText := carriageReturns(t, path)
			if !isText {
				return nil
			}
			checked++
			if found {
				t.Errorf("%s contains a carriage return, so this checkout is not the commit", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d files were examined; the list of byte-exact evidence has "+
			"gone stale and the check is too narrow to mean anything", checked)
	}
}

// The control: the scan passes by finding nothing, so it must find one that is
// there.
func TestTheCarriageReturnScanFindsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "windows.json")
	if err := os.WriteFile(path, []byte("{\r\n}\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, isText := carriageReturns(t, path); !found || !isText {
		t.Fatal("the scan did not find a carriage return in a text file full of them")
	}
	clean := filepath.Join(t.TempDir(), "unix.json")
	if err := os.WriteFile(clean, []byte("{\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, _ := carriageReturns(t, clean); found {
		t.Fatal("the scan reported a carriage return in a file that has none")
	}

	// The binary exemption must be an exemption and not a hole: a file with a
	// NUL byte is skipped, and the scan has to say that rather than say clean.
	binary := filepath.Join(t.TempDir(), "capture.bin")
	if err := os.WriteFile(binary, []byte{0x00, 0x0d, 0x0a}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, isText := carriageReturns(t, binary); isText {
		t.Fatal("a file with a NUL byte was treated as text")
	}
}
