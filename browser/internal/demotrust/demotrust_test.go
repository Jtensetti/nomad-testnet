package demotrust

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This used to check that the Swift client compiled in the same publisher key
// as the Go tests. The client stopped compiling one in: it verifies a signed
// SiteID descriptor instead, which is a stronger property than a key baked
// into a binary, and the old check failed rather than passing quietly because
// it refused to compare against a marker that was no longer there.
//
// The property worth keeping is the new one. A hardcoded trusted publisher
// reappearing in the client would be a regression back to trust that cannot be
// rotated, revoked or transitioned, and it would not announce itself.

var swiftSourceRoot = filepath.Join("..", "..", "macos", "Sources", "NomadBrowser")

// base64Ed25519 matches a 32-byte key written as base64, which is what an
// anchored publisher looks like in source.
var base64Ed25519 = regexp.MustCompile(`"[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}"`)

func swiftSources(t *testing.T) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(swiftSourceRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".swift") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatalf("found no Swift sources under %s, so this check read nothing", swiftSourceRoot)
	}
	return found
}

func TestTheSwiftClientAnchorsNoPublisherKey(t *testing.T) {
	for _, source := range swiftSources(t) {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range base64Ed25519.FindAllString(string(content), -1) {
			t.Errorf("%s contains %s, which is the shape of a compiled-in "+
				"publisher key. The client verifies a signed SiteID descriptor so "+
				"that trust can be rotated, revoked and transitioned; a key in the "+
				"source is trust that cannot be. If this is not a key, give it a "+
				"shape that is not one.", source, match)
		}
	}
}

// The control: the scan passes by finding nothing, so it must find a key that
// is there. The Go fixture key is exactly the shape it is looking for.
func TestTheKeyScanFindsAKeyThatIsThere(t *testing.T) {
	if !base64Ed25519.MatchString(`"` + PublisherKey + `"`) {
		t.Fatalf("the scan does not recognise %s, which is a base64 Ed25519 key, so "+
			"it would not recognise one in the Swift sources either", PublisherKey)
	}
	if base64Ed25519.MatchString(`"not a key"`) {
		t.Fatal("the scan matches text that is not a key")
	}
}
