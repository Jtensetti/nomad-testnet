package nomadbrowser_test

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The release bundle's declared capabilities are the outermost guarantee this
// project makes: everything else in the browser is defence in depth behind
// "the binary cannot open a socket". Until now that guarantee was checked by
// macos/scripts/security_gate.sh, which uses PlistBuddy and swift and
// therefore runs only on a macOS runner -- and the only macOS workflow is
// gated on `branches: [agent/macos-browser]`. On every other branch, including
// the one this work happens on, nothing checked the entitlements at all. A
// gate that does not run is not a gate.
//
// These tests parse the plists directly so the checks run wherever Go runs, on
// every push. They are deliberately allowlists rather than denylists: a
// denylist answers "did someone add the one key we thought of", and the
// interesting failure is always the key nobody thought of.

const (
	entitlementsPath = "macos/NomadBrowser.entitlements"
	infoPlistPath    = "macos/Info.plist"
	swiftSourceRoot  = "macos/Sources/NomadBrowser"
)

// justifiedEntitlements is every entitlement the release bundle may declare,
// with the reason it is there. Adding a key here is a deliberate act that
// leaves a written reason behind; adding one to the plist without touching
// this map fails the build.
var justifiedEntitlements = map[string]string{
	"com.apple.security.app-sandbox": "the sandbox is what denies network, and " +
		"under it every capability is refused unless separately granted",
	"com.apple.security.application-groups": "the browser reads verified objects " +
		"from a Team-scoped shared container rather than from a path it is told, " +
		"which is what makes the materializer the only bridge into it. Exactly one " +
		"group, <TeamID>.nomad.browser-cache, and the browser is on the reading " +
		"side of it: the network domain uses a separate fabric-cache group it " +
		"cannot see, and macos/scripts/security_gate.sh fails the build on a " +
		"second group, on a group that is not Team-scoped, or on a write capability " +
		"appearing in the browser sources. A shared container is a real widening of " +
		"the sandbox and it is here because the alternative -- the browser reaching " +
		"a path outside its container -- is worse",
}

// forbiddenEntitlements are keys whose presence is a specific, named defeat of
// the networkless guarantee. The allowlist above already refuses them; these
// exist so the failure message says what was actually broken rather than
// "unexpected key".
var forbiddenEntitlements = map[string]string{
	"com.apple.security.network.client":                              "outbound sockets",
	"com.apple.security.network.server":                              "inbound sockets",
	"com.apple.security.temporary-exception.mach-lookup.global-name": "reaching a system service that can",
	"com.apple.security.cs.allow-unsigned-executable-memory":         "loading code the signature does not cover",
	"com.apple.security.cs.disable-library-validation":               "loading libraries the signature does not cover",
	"com.apple.security.get-task-allow":                              "letting another process inspect this one's memory",
	"com.apple.security.automation.apple-events":                     "driving other applications, including a networked browser",
}

type plistDict struct {
	Keys []string `xml:"key"`
}

func readPlistKeys(t *testing.T, path string) []string {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Dict plistDict `xml:"dict"`
	}
	if err := xml.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return document.Dict.Keys
}

func TestTheReleaseBundleDeclaresOnlyJustifiedEntitlements(t *testing.T) {
	keys := readPlistKeys(t, entitlementsPath)
	if len(keys) == 0 {
		t.Fatalf("%s declares no entitlements at all, so this test read the wrong "+
			"thing or the file lost its sandbox declaration", entitlementsPath)
	}

	declared := map[string]struct{}{}
	for _, key := range keys {
		declared[key] = struct{}{}
		if reason, forbidden := forbiddenEntitlements[key]; forbidden {
			t.Errorf("%s declares %s, which grants %s", entitlementsPath, key, reason)
			continue
		}
		if _, justified := justifiedEntitlements[key]; !justified {
			t.Errorf("%s declares %s, which nobody has written down a reason for. "+
				"Add it to justifiedEntitlements with that reason, or remove it",
				entitlementsPath, key)
		}
	}
	if _, sandboxed := declared["com.apple.security.app-sandbox"]; !sandboxed {
		t.Errorf("%s does not declare the app sandbox, which is what denies network "+
			"by default; without it every other check here is decoration", entitlementsPath)
	}
}

// The sandbox denies network by default, so the entitlements above are the
// control. Info.plist is where a bundle can quietly ask for the opposite, or
// declare that it wants to be launchable by other applications.
func TestTheInfoPlistAsksForNoNetworkAndNoDiagnosticUpload(t *testing.T) {
	encoded, err := os.ReadFile(infoPlistPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	keys := readPlistKeys(t, infoPlistPath)

	// A URL scheme or document type makes the bundle a target another
	// application can hand arbitrary input to.
	for _, key := range []string{"CFBundleURLTypes", "CFBundleDocumentTypes", "NSExtension"} {
		for _, declared := range keys {
			if declared == key {
				t.Errorf("%s declares %s, which lets another application drive this one",
					infoPlistPath, key)
			}
		}
	}

	// App Transport Security exceptions are how a bundle re-permits the
	// loads the platform would otherwise refuse.
	for _, exception := range []string{
		"NSAllowsArbitraryLoadsInWebContent",
		"NSAllowsArbitraryLoadsForMedia",
		"NSExceptionDomains",
		"NSExceptionAllowsInsecureHTTPLoads",
	} {
		if strings.Contains(text, exception) {
			t.Errorf("%s carries the App Transport Security exception %s",
				infoPlistPath, exception)
		}
	}

	// Both ATS switches this bundle does declare must be false. Reading them
	// as adjacent key/value pairs is enough for a file this shape, and the
	// assertion below fails loudly if the shape changes.
	for _, switched := range []string{"NSAllowsArbitraryLoads", "NSAllowsLocalNetworking"} {
		pattern := regexp.MustCompile(`<key>` + switched + `</key>\s*<(true|false)/>`)
		match := pattern.FindStringSubmatch(text)
		if match == nil {
			t.Errorf("%s does not declare %s as a plain boolean; this check needs to be "+
				"rewritten rather than silently skipped", infoPlistPath, switched)
			continue
		}
		if match[1] != "false" {
			t.Errorf("%s sets %s to true", infoPlistPath, switched)
		}
	}
}

// forbiddenSwiftSymbol is the same scan macos/scripts/security_gate.sh runs,
// moved somewhere it executes. Each entry names what the symbol would give a
// process that is supposed to have no network and no way to launch another
// application.
var forbiddenSwiftSymbols = []struct {
	pattern *regexp.Regexp
	grants  string
}{
	{regexp.MustCompile(`import\s+(WebKit|Network|FoundationNetworking|Darwin)\b`), "a networking or raw-syscall framework"},
	{regexp.MustCompile(`\bURLSession\b`), "HTTP requests"},
	{regexp.MustCompile(`\bWK(WebView|URLSchemeHandler)\b`), "an engine that fetches on its own"},
	{regexp.MustCompile(`\bNW(Connection|Browser|Listener)\b`), "sockets"},
	// No trailing \b: these are prefixes of longer symbols such as
	// CFNetworkCopySystemProxySettings, which a word boundary would miss.
	{regexp.MustCompile(`\b(CFNetwork|CFStream|NSStream)`), "lower-level networking"},
	{regexp.MustCompile(`\b(NSAppleScript|SFSafariApplication)\b`), "driving another application"},
	{regexp.MustCompile(`NSWorkspace\.shared\.open|\bopenURL\(`), "handing a URL to a networked browser"},
	{regexp.MustCompile(`\bProcess\s*\(`), "launching a subprocess that has none of these limits"},
	{regexp.MustCompile(`(^|[^\w.])(socket|connect|sendto|recvfrom|getaddrinfo|dlopen|dlsym)\s*\(`), "a raw syscall"},
}

// swiftSources lists every .swift file under root, failing if there are none:
// a scan over an empty set passes without checking anything.
func swiftSources(t *testing.T, root string) []string {
	t.Helper()
	var sources []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".swift") {
			sources = append(sources, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) == 0 {
		t.Fatalf("no Swift sources found under %s, so this checked nothing", root)
	}
	sort.Strings(sources)
	return sources
}

func TestNoSwiftSourceReachesTheNetworkOrAnotherApplication(t *testing.T) {
	for _, source := range swiftSources(t, swiftSourceRoot) {
		encoded, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(encoded), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, forbidden := range forbiddenSwiftSymbols {
				if forbidden.pattern.MatchString(line) {
					t.Errorf("%s:%d reaches %s: %s",
						source, number+1, forbidden.grants, trimmed)
				}
			}
		}
	}
}

// The scan is only worth having if it fires. This runs it over text that
// contains each forbidden construct, so a pattern that stopped matching --
// after a rename, or a regexp edit -- is caught rather than passing quietly
// over sources that happen to be clean.
func TestTheSwiftScanStillDetectsEachForbiddenConstruct(t *testing.T) {
	samples := []string{
		"import WebKit",
		"import Network",
		"import FoundationNetworking",
		"import Darwin",
		"let task = URLSession.shared.dataTask(with: url)",
		"let view = WKWebView(frame: .zero)",
		"let handler: WKURLSchemeHandler = local",
		"let connection = NWConnection(to: endpoint, using: .tcp)",
		"let listener = NWListener(using: .tcp)",
		"let stream = NSStream()",
		"CFNetworkCopySystemProxySettings()",
		"let script = NSAppleScript(source: text)",
		"NSWorkspace.shared.open(url)",
		"UIApplication.shared.openURL(url)",
		"let child = Process()",
		"let fd = socket(AF_INET, SOCK_STREAM, 0)",
		"getaddrinfo(host, nil, &hints, &result)",
		"dlopen(path, RTLD_NOW)",
	}
	for _, sample := range samples {
		matched := false
		for _, forbidden := range forbiddenSwiftSymbols {
			if forbidden.pattern.MatchString(sample) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("the scan no longer detects %q", sample)
		}
	}

	// And it must not fire on ordinary local code, or it will be disabled.
	for _, benign := range []string{
		"let manager = FileManager.default",
		"documents = accepted.values.sorted { $0.title < $1.title }",
		"try JSONDecoder().decode(SignedEnvelope.self, from: data)",
		"let url = URL(fileURLWithPath: path)",
		"processed(objects)",
	} {
		for _, forbidden := range forbiddenSwiftSymbols {
			if forbidden.pattern.MatchString(benign) {
				t.Errorf("the scan fires on ordinary local code %q via %v",
					benign, forbidden.pattern)
			}
		}
	}
}

// The shell gate still exists and still runs on macOS, where it can also run
// `swift test`. It must not drift into checking something weaker than this
// file does, because the two are read as one guarantee.
func TestTheMacOSShellGateStillChecksTheEntitlements(t *testing.T) {
	encoded, err := os.ReadFile("macos/scripts/security_gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(encoded)
	// The script writes the network key as a grep regexp with escaped dots, so
	// these are matched as patterns rather than as literal substrings. An
	// earlier version of this test searched for the literal and failed against
	// a script that was in fact checking the right thing.
	for _, required := range []*regexp.Regexp{
		regexp.MustCompile(`com\.apple\.security\.app-sandbox`),
		regexp.MustCompile(`com\\?\.apple\\?\.security\\?\.network`),
		regexp.MustCompile(`swift test`),
	} {
		if !required.MatchString(script) {
			t.Errorf("macos/scripts/security_gate.sh no longer matches %v", required)
		}
	}
}
