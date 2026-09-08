package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// notShipped names every command that must NOT reach the container image,
// with the reason, because an exclusion nobody can see is an exclusion that
// gets reversed.
var notShipped = map[string]string{
	"nomad-load": "a flood generator; the load gate runs it from the host, and a " +
		"release image has no business carrying one",
	"nomad-testnet":     "a developer harness, not a deployed service",
	"nomad-conformance": "generates and checks conformance vectors; not a service",
	"nomad-publish":     "the publisher half, run by a publisher rather than an operator",
	"nomad-entry":       "the entry operator service, not part of the relay fabric image",
}

// The image's contents, checked in both directions. A command missing from the
// Dockerfile is a service the deployment cannot run; one that should not ship
// but does is quieter and worse, since nothing fails at all.
//
// This lives here because nomad-load is the reason it exists.
func TestTheImageBuildsEveryCommandThatShouldShipAndNoneThatShouldNot(t *testing.T) {
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read the image definition: %v", err)
	}
	recipe := string(dockerfile)

	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, err := os.Stat(filepath.Join("..", name, "main.go")); err != nil {
			continue
		}
		built := strings.Contains(recipe, "./cmd/"+name)
		reason, excluded := notShipped[name]
		switch {
		case built && excluded:
			t.Errorf("the Dockerfile builds %s into the image, and it is listed as "+
				"not shipped because it is %s. Either the exclusion is wrong or the "+
				"image now carries something it should not", name, reason)
		case !built && !excluded:
			t.Errorf("the Dockerfile does not build %s and notShipped does not list "+
				"it. A deployment that needs it gets a container that exits with "+
				"\"executable file not found\"; if it should not ship, say so with "+
				"the reason", name)
		}
	}

	// A stale exclusion is its own defect: it documents a decision about a
	// command that no longer exists, and reads as coverage.
	for name := range notShipped {
		if _, err := os.Stat(filepath.Join("..", name, "main.go")); err != nil {
			t.Errorf("notShipped names %s, which is not a command in this tree", name)
		}
	}
}
