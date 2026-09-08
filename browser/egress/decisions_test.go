package egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The requirement is that executable-content decisions are pinned by a corpus rather
// than by the tests of the code that makes them. The difference is not
// pedantry: a test describes what this implementation does, and changes when
// it does, so a rule that quietly loosens takes its own test with it. A corpus
// is data. Loosening the rule then fails against a file somebody has to edit
// deliberately, and a second implementation can check itself against the same
// file without reading any Go.
//
// testdata/url-decisions.json is that file. Every entry carries the reason the
// case matters, because a decision table nobody can read is a decision table
// nobody will maintain.
type urlDecision struct {
	URL   string `json:"url"`
	Allow bool   `json:"allow"`
	Why   string `json:"why"`
}

type decisionCorpus struct {
	Version     string        `json:"version"`
	Description string        `json:"description"`
	Cases       []urlDecision `json:"cases"`
}

const decisionCorpusVersion = "nomad-browser-url-decisions-v1"

func loadDecisions(t *testing.T) decisionCorpus {
	t.Helper()
	encoded, err := os.ReadFile("testdata/url-decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus decisionCorpus
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != decisionCorpusVersion {
		t.Fatalf("corpus version %q, want %q: an unrecognised version is refused "+
			"rather than read as if it were this one", corpus.Version, decisionCorpusVersion)
	}
	return corpus
}

func TestTheRendererGateMatchesTheFrozenDecisions(t *testing.T) {
	corpus := loadDecisions(t)
	var policy Policy
	allowed, refused := 0, 0
	for _, decision := range corpus.Cases {
		err := policy.CheckRendererURL(decision.URL)
		switch {
		case decision.Allow && err != nil:
			t.Errorf("%q was refused (%v) but the corpus allows it: %s",
				decision.URL, err, decision.Why)
		case !decision.Allow && err == nil:
			t.Errorf("%q was allowed but the corpus refuses it: %s",
				decision.URL, decision.Why)
		case !decision.Allow && !errors.Is(err, ErrDenied):
			t.Errorf("%q was refused with %v, which does not carry ErrDenied, so a "+
				"caller cannot tell a policy refusal from a bug", decision.URL, err)
		}
		if decision.Allow {
			allowed++
		} else {
			refused++
		}
	}

	// A corpus that only refuses would pass against a gate that refuses
	// everything, and a corpus that only allows would pass against one that
	// allows everything. Both directions have to be represented.
	if allowed < 10 || refused < 20 {
		t.Fatalf("the corpus has %d allowed and %d refused cases; it must exercise "+
			"both directions to mean anything", allowed, refused)
	}
	t.Logf("%d frozen decisions: %d allowed, %d refused", len(corpus.Cases), allowed, refused)
}

// The allowlist and the corpus have to agree, or one of them is stale. This
// catches a media type added to the code and not to the corpus, which is
// exactly how a scriptable type would arrive unnoticed.
func TestEveryAllowedMediaTypeIsInTheFrozenDecisions(t *testing.T) {
	corpus := loadDecisions(t)
	covered := map[string]bool{}
	for _, decision := range corpus.Cases {
		if !decision.Allow || !strings.HasPrefix(decision.URL, "data:") {
			continue
		}
		body := strings.TrimPrefix(decision.URL, "data:")
		mediaType, _, _ := strings.Cut(body, ",")
		mediaType, _, _ = strings.Cut(mediaType, ";")
		covered[strings.ToLower(mediaType)] = true
	}
	for _, mediaType := range AllowedDataMediaTypes() {
		if !covered[strings.ToLower(mediaType)] {
			t.Errorf("%s is allowed by the code and has no case in the frozen "+
				"decisions: a media type can be added without anyone deciding it "+
				"is non-scriptable", mediaType)
		}
	}
}

// And the reverse: a case in the corpus naming a type the code no longer
// allows means the corpus is describing a policy that is gone.
func TestTheFrozenDecisionsNameNoMediaTypeTheCodeDropped(t *testing.T) {
	corpus := loadDecisions(t)
	known := map[string]bool{}
	for _, mediaType := range AllowedDataMediaTypes() {
		known[strings.ToLower(mediaType)] = true
	}
	for _, decision := range corpus.Cases {
		if !decision.Allow || !strings.HasPrefix(decision.URL, "data:") {
			continue
		}
		body := strings.TrimPrefix(decision.URL, "data:")
		mediaType, _, _ := strings.Cut(body, ",")
		mediaType, _, _ = strings.Cut(mediaType, ";")
		if mediaType == "" {
			continue
		}
		if !known[strings.ToLower(mediaType)] {
			t.Errorf("the frozen decisions allow %s, which the code no longer does",
				mediaType)
		}
	}
}

// Every case must carry its reason. A decision table without them is one
// nobody can review, and reviewing it is the only way a wrong entry is caught.
func TestEveryFrozenDecisionSaysWhyItMatters(t *testing.T) {
	corpus := loadDecisions(t)
	seen := map[string]bool{}
	for _, decision := range corpus.Cases {
		if strings.TrimSpace(decision.Why) == "" {
			t.Errorf("%q has no reason recorded", decision.URL)
		}
		if seen[decision.URL] {
			t.Errorf("%q appears twice; one of the two entries is unreachable", decision.URL)
		}
		seen[decision.URL] = true
	}
}

// What is needed is parser-differential evidence at the renderer boundary. The
// corpus is that evidence only if something other than the encoder that wrote
// it reads it: a corpus checked by its own producer is a self-consistency check
// wearing an interoperability claim.
//
// conformance/reference/nomadegress.py decides the same URLs with Python's own
// URL parser and path handling, sharing no code with this package. It is run
// here rather than only in CI, so a change to the policy that the corpus does
// not cover fails in the same command that made it.
//
// On its first run it disagreed twice, and both disagreements were bugs in the
// second implementation rather than in this one -- which is what makes them
// worth keeping: they are the mistakes a third implementer makes. It denied
// "nomad:/" for having an empty segment, and it *allowed*
// "data:text/plain;base64;charset=x,y" by treating the text before the first
// semicolon as the media type. The second is a prefix match, and a prefix match
// is exactly how a scriptable type gets past an allowlist.
// requireCapabilityGates reports whether this environment has declared that a
// named gate -- one depending on an external tool or a kernel capability -- can
// run here.
//
// A skip is green, so a gate that quietly stopped running is indistinguishable
// from one that passed, and where the environment has promised the capability
// its absence has to be a failure.
//
// Two ways to promise. NOMAD_REQUIRE_CAPABILITY_GATES=1 means everything, which
// is what the Linux job says. NOMAD_REQUIRE_CAPABILITIES is a comma-separated
// list, which is what a platform with some of the tools and not others needs:
// the macOS runner has python3 and no strace, and under the all-or-nothing
// version it could declare neither -- so the parser-differential gate would
// have become a silent skip on the platform the browser actually ships to.
func requireCapabilityGates(capability string) bool {
	if os.Getenv("NOMAD_REQUIRE_CAPABILITY_GATES") == "1" {
		return true
	}
	for _, declared := range strings.Split(os.Getenv("NOMAD_REQUIRE_CAPABILITIES"), ",") {
		if strings.TrimSpace(declared) == capability && capability != "" {
			return true
		}
	}
	return false
}

func pythonForTheSecondImplementation(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err == nil {
		return python
	}
	if requireCapabilityGates("python3") {
		t.Fatal("python3 is unavailable, and this environment declared the python3 " +
			"capability, so it is supposed to run the second implementation")
	}
	t.Skip("python3 is unavailable, so the second implementation cannot be run; " +
		"an environment limit and not a pass")
	return ""
}

func TestTheDecisionCorpusAgreesWithASecondImplementation(t *testing.T) {
	python := pythonForTheSecondImplementation(t)
	script := filepath.Join("..", "conformance", "reference", "crosscheck_egress.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the second implementation is missing: %v", err)
	}
	corpus := filepath.Join("testdata", "url-decisions.json")

	command := exec.Command(python, script, corpus)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the second implementation disagrees with the published decisions:\n%s",
			output)
	}
	if !bytes.Contains(output, []byte("cases agree")) {
		t.Fatalf("the second implementation did not report a verdict:\n%s", output)
	}
	t.Logf("%s", bytes.TrimSpace(output))
}

// The cross-check is worth nothing if it would pass on a corpus the second
// implementation never read. This gives it a corpus with one decision inverted
// and requires it to fail.
func TestTheCrossCheckNoticesAChangedDecision(t *testing.T) {
	python := pythonForTheSecondImplementation(t)
	script := filepath.Join("..", "conformance", "reference", "crosscheck_egress.py")
	original, err := os.ReadFile(filepath.Join("testdata", "url-decisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version     string `json:"version"`
		Description string `json:"description"`
		Cases       []struct {
			URL   string `json:"url"`
			Allow bool   `json:"allow"`
			Why   string `json:"why"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(original, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("the corpus is empty")
	}
	corpus.Cases[0].Allow = !corpus.Cases[0].Allow

	altered, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "altered.json")
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(python, script, path)
	output, _ := command.CombinedOutput()
	if command.ProcessState.ExitCode() == 0 {
		t.Fatalf("the cross-check passed on a corpus with an inverted decision, so it "+
			"would pass on anything:\n%s", output)
	}
	if !bytes.Contains(output, []byte(corpus.Cases[0].URL)) {
		t.Errorf("the failure does not name the URL that disagreed:\n%s", output)
	}
}
