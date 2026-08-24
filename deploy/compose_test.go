package deploy

import (
	"os"
	"strings"
	"testing"
)

// Every service must set GOTRACEBACK=none. A panic otherwise prints goroutine
// stacks whose frame arguments are raw machine words, which for these
// processes can be key material, and the runtime keeps whatever a crashing
// service wrote. The Go runtime reads the variable at startup, so no
// in-process call can substitute for it -- debug.SetTraceback("none") looks
// like it does and does not.
//
// This is checked here rather than trusted to the YAML anchor because a merge
// key replaces a mapping instead of deep-merging it: the three DKG services
// set SSL_CERT_FILE and thereby dropped the anchor's GOTRACEBACK entirely,
// which is how this test came to exist.
func TestEveryComposeServiceSuppressesCrashDumps(t *testing.T) {
	encoded, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	services := serviceNames(t, text)
	if len(services) < 10 {
		t.Fatalf("found only %d services, so the file was not parsed as expected", len(services))
	}
	for _, name := range services {
		block := serviceBlock(text, name)
		if !strings.Contains(block, "GOTRACEBACK: none") &&
			!strings.Contains(block, "<<: *locked-service") {
			t.Fatalf("service %q neither sets GOTRACEBACK: none nor inherits it", name)
		}
		// Inheriting is not enough when the service also declares its own
		// environment, because the merge replaces the mapping.
		if strings.Contains(block, "environment:") && !strings.Contains(block, "GOTRACEBACK: none") {
			t.Fatalf("service %q declares its own environment and so loses the "+
				"inherited GOTRACEBACK; set it explicitly", name)
		}
	}
}

func serviceNames(t *testing.T, text string) []string {
	t.Helper()
	inServices := false
	var names []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "services:") {
			inServices = true
			continue
		}
		if inServices && len(line) > 0 && !strings.HasPrefix(line, " ") {
			break
		}
		if inServices && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			strings.HasSuffix(strings.TrimSpace(line), ":") {
			names = append(names, strings.TrimSuffix(strings.TrimSpace(line), ":"))
		}
	}
	return names
}

func serviceBlock(text, name string) string {
	start := strings.Index(text, "\n  "+name+":\n")
	if start < 0 {
		return ""
	}
	rest := text[start+1:]
	for offset := 1; offset < len(rest); offset++ {
		if rest[offset-1] == '\n' && strings.HasPrefix(rest[offset:], "  ") &&
			!strings.HasPrefix(rest[offset:], "   ") &&
			strings.HasSuffix(strings.TrimSpace(strings.SplitN(rest[offset:], "\n", 2)[0]), ":") &&
			offset > 4 {
			return rest[:offset]
		}
	}
	return rest
}
