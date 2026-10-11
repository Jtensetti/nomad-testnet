package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/internal/demotrust"
)

// corpusDirectory materializes the same catalog the Swift client ships, so the
// client is exercised against real signed objects rather than fixtures written
// to match it.
func corpusDirectory(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "macos", "Sources",
		"NomadBrowser", "Resources", "demo-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []json.RawMessage
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for index, envelope := range envelopes {
		name := filepath.Join(directory, "object-"+string(rune('a'+index))+".nomadobject")
		if err := os.WriteFile(name, envelope, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func drive(t *testing.T, directory string, commands ...string) string {
	t.Helper()
	var out strings.Builder
	err := run([]string{"-objects", directory, "-trust", demotrust.PublisherKey},
		strings.NewReader(strings.Join(append(commands, "quit"), "\n")+"\n"), &out)
	if err != nil {
		t.Fatalf("client failed: %v\n%s", err, out.String())
	}
	return out.String()
}

func TestTheClientListsSearchesAndRendersTheCorpus(t *testing.T) {
	directory := corpusDirectory(t)
	output := drive(t, directory, "list", "search nomad")

	if !strings.Contains(output, "3 verified objects, 3 searchable") {
		t.Fatalf("the corpus did not load:\n%s", output)
	}
	if !strings.Contains(output, "Välkommen till Nomad") {
		t.Fatalf("list did not show the corpus:\n%s", output)
	}
	// A ranking must say which embedder produced it.
	if !strings.Contains(output, "lexical ranking") {
		t.Fatalf("the ranking did not name its provenance:\n%s", output)
	}
}

func TestReadRendersOneObjectByIDPrefix(t *testing.T) {
	directory := corpusDirectory(t)
	listing := drive(t, directory, "list")
	var id string
	for _, line := range strings.Split(listing, "\n") {
		if strings.Contains(line, "Välkommen till Nomad") {
			id = strings.Fields(line)[0]
			break
		}
	}
	if id == "" {
		t.Fatalf("no object id in the listing:\n%s", listing)
	}
	output := drive(t, directory, "read "+id)
	if !strings.Contains(output, "Nomad Demo Publisher") {
		t.Fatalf("read did not render the object:\n%s", output)
	}
}

// A client with no anchored publisher refuses to start. Starting would mean
// choosing between rendering everything and rendering nothing, and both are
// worse than saying what is missing.
func TestTheClientRefusesToStartWithoutATrustAnchor(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-objects", corpusDirectory(t)}, strings.NewReader("quit\n"), &out)
	if err == nil {
		t.Fatal("the client started with no anchored publisher key")
	}
	if !strings.Contains(err.Error(), "-trust is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Objects signed by a key this client does not anchor are counted as rejected
// and are not listed. The corpus here is real and correctly signed: the only
// thing wrong with it is that this client does not trust its publisher.
func TestObjectsFromAnUnanchoredPublisherAreRejectedNotRendered(t *testing.T) {
	directory := corpusDirectory(t)
	var out strings.Builder
	stranger := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := run([]string{"-objects", directory, "-trust", stranger},
		strings.NewReader("list\nquit\n"), &out); err != nil {
		t.Fatalf("client failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "0 verified objects") {
		t.Fatalf("objects from an unanchored publisher were accepted:\n%s", output)
	}
	if !strings.Contains(output, "3 files in the object directory did not verify") {
		t.Fatalf("rejections were not reported:\n%s", output)
	}
	if strings.Contains(output, "Välkommen") {
		t.Fatalf("an unanchored object was listed:\n%s", output)
	}
}

// An ambiguous id prefix renders nothing. Rendering the first match would mean
// a reader could ask for one object and be shown another.
func TestAnAmbiguousIDPrefixRendersNothing(t *testing.T) {
	directory := corpusDirectory(t)
	output := drive(t, directory, "read ")
	if !strings.Contains(output, "read needs an object id") {
		t.Fatalf("an empty id was accepted:\n%s", output)
	}
	// "" would match everything; the single hex character below matches
	// whatever share of the corpus starts with it, and the client must either
	// find exactly one or list the candidates without rendering.
	for _, prefix := range []string{"0", "1", "2", "5", "a", "f"} {
		out := drive(t, directory, "read "+prefix)
		if strings.Contains(out, "matches") && strings.Contains(out, "publisher ") {
			t.Fatalf("an ambiguous prefix %q both listed candidates and rendered:\n%s", prefix, out)
		}
	}
}

// The client says which ranking it is using, in the banner and not only in the
// search results.
//
// A word match presented without qualification reads as an understanding of
// meaning, and a reader who believes the search is semantic will conclude an
// object is absent when it was only worded differently. This build has no
// semantic model, and says so.
func TestTheClientStatesThatItsRankingIsLexical(t *testing.T) {
	output := drive(t, corpusDirectory(t), "list")
	if !strings.Contains(output, "ranking: lexical") {
		t.Fatalf("the banner does not name the ranking:\n%s", output)
	}
	if !strings.Contains(output, "no semantic model") {
		t.Fatalf("the banner does not say a semantic model is absent, so a lexical "+
			"ranking could be read as a semantic one:\n%s", output)
	}
}
