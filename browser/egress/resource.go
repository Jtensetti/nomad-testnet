package egress

import (
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"unicode/utf8"
)

// MaxResourcePath bounds a renderer-local resource path.
const MaxResourcePath = 2048

// CanonicalResourcePath is the single definition of what a Nomad renderer may
// ask for.
//
// It lives here, in the package with no dependencies, because two gates check
// it: the renderer URL policy before scheme dispatch, and the local adapter
// before a bundle lookup. When each carried its own rule they disagreed --
// the URL policy accepted "nomad:/../../etc/passwd" and the adapter refused
// it -- which was not exploitable, since nothing reached the filesystem
// without passing the adapter, but two gates that disagree are how a bypass
// arrives later, as soon as something else is wired to the looser one.
// Sharing the rule makes them agree by construction rather than by review.
func CanonicalResourcePath(resourcePath string) error {
	if resourcePath == "" {
		return errors.New("resource path is empty")
	}
	if len(resourcePath) > MaxResourcePath {
		return fmt.Errorf("resource path exceeds %d bytes", MaxResourcePath)
	}
	if !utf8.ValidString(resourcePath) {
		return errors.New("resource path is not valid UTF-8")
	}
	if resourcePath[0] != '/' {
		return errors.New("resource path must be absolute")
	}
	// Backslash is rejected because platforms disagree about whether it is a
	// separator, and a rule that means different things on different
	// platforms is not a rule. The rest is URL syntax that has no place in a
	// resolved path.
	if strings.ContainsAny(resourcePath, "\\?#\x00") {
		return errors.New("resource path contains URL syntax or a path separator alias")
	}
	for _, character := range resourcePath {
		if character < 0x20 || character == 0x7f {
			return errors.New("resource path contains a control character")
		}
	}
	// Canonical after cleaning, so no "..", no ".", and no empty segments
	// survive. Percent-encoded traversal decodes before this point and is
	// caught here.
	if pathpkg.Clean(resourcePath) != resourcePath {
		return errors.New("resource path is not canonical")
	}
	return nil
}
