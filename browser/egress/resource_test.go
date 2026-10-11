package egress

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalResourcePathRejectsEscapes(t *testing.T) {
	denied := []string{
		"",
		"index.html",
		"/../../etc/passwd",
		"/a/../../../etc/passwd",
		"/./index.html",
		"/a//b",
		"/a/b/",
		"/a/..",
		"/index.html\\..\\..\\x",
		"/index.html?x=1",
		"/index.html#frag",
		"/index.html\x00.png",
		"/index\x01.html",
		"/index\x7f.html",
		"/" + strings.Repeat("a", MaxResourcePath),
		"/\xff\xfe",
	}
	for _, path := range denied {
		if err := CanonicalResourcePath(path); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	allowed := []string{"/", "/index.html", "/a/b/c.css", "/a b.png", "/dot.file.js"}
	for _, path := range allowed {
		if err := CanonicalResourcePath(path); err != nil {
			t.Errorf("rejected %q: %v", path, err)
		}
	}
}

// The renderer URL gate and the local adapter must agree on every path. When
// they disagreed, the URL gate was the lenient one.
func TestRendererGateAgreesWithTheResourceRule(t *testing.T) {
	paths := []string{
		"/index.html", "/a/b.css", "/", "/../../etc/passwd", "/./x", "/a//b",
		"/x\\y", "/x?y", "/x#y", "/%2e%2e/%2e%2e/etc/passwd",
	}
	for _, path := range paths {
		urlErr := (Policy{}).CheckRendererURL("nomad:" + path)
		// Percent-encoding decodes during URL parsing, so compare the rule
		// against the decoded form the adapter would receive.
		decoded := strings.ReplaceAll(strings.ReplaceAll(path, "%2e", "."), "%2E", ".")
		ruleErr := CanonicalResourcePath(decoded)
		if (urlErr == nil) != (ruleErr == nil) {
			t.Errorf("%q: URL gate err=%v but the resource rule err=%v", path, urlErr, ruleErr)
		}
	}
}

func TestDataURLsAreLimitedToNonScriptableTypes(t *testing.T) {
	denied := []string{
		"data:text/html,<script>fetch('https://evil.example')</script>",
		"data:text/html;base64,PHNjcmlwdD4=",
		"data:application/xhtml+xml,<html/>",
		"data:image/svg+xml,<svg onload='fetch(1)'/>",
		"data:text/javascript,fetch('https://evil.example')",
		"data:application/javascript,x",
		"data:application/octet-stream,x",
		"data:TEXT/HTML,<script>",
		"data:text/html",
	}
	for _, raw := range denied {
		if err := (Policy{}).CheckRendererURL(raw); !errors.Is(err, ErrDenied) {
			t.Errorf("%q was not denied: %v", raw, err)
		}
	}
	allowed := []string{
		"data:,plain",
		"data:text/plain,hello",
		"data:text/plain;charset=utf-8,hello",
		"data:image/png;base64,iVBORw0KGgo=",
		"data:font/woff2;base64,d09GMg==",
		"data:TEXT/PLAIN,hello",
	}
	for _, raw := range allowed {
		if err := (Policy{}).CheckRendererURL(raw); err != nil {
			t.Errorf("%q was denied: %v", raw, err)
		}
	}
	// The allowlist must stay an allowlist: nothing scriptable in it.
	for _, mediaType := range AllowedDataMediaTypes() {
		switch mediaType {
		case "text/html", "image/svg+xml", "application/xhtml+xml",
			"text/javascript", "application/javascript", "application/ecmascript":
			t.Errorf("allowlist contains the scriptable type %q", mediaType)
		}
	}
}
