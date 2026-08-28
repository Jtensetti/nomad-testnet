package main

import (
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// The Compose gate checks wire versions by string literal, and a literal in a
// shell script cannot be refactored by the compiler.
//
// It drifted. `nomad-batch-descriptor` went to v3 on 2026-08-24 and the gate
// kept asserting v2, so every live run failed on a version check rather than
// on the thing it gates. Nobody saw it for four days, because CI was not
// running -- but a gate that pins a version this way would have drifted again
// regardless. This test is what makes the literal a reference.
//
// It asserts the exact set of versions the script mentions for each object,
// not merely that the current one appears. After a bump, an added `-v4` next
// to a left-behind `-v3` is still a stale gate, and only comparing the whole
// set catches that.
//
// It lives here rather than beside the script because this package already
// imports all three constants; nothing about the choice is deeper.
func TestTheComposeGateChecksTheVersionsThisCodeWrites(t *testing.T) {
	const path = "../../scripts/compose-e2e.sh"
	script, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the live Compose gate: %v", err)
	}
	for name, version := range map[string]string{
		"batch descriptor": batch.DescriptorVersion,
		"DKG certificate":  committee.CertificateVersion,
		"operator secrets": topology.SecretVersion,
	} {
		prefix := regexp.MustCompile(`-v\d+$`).ReplaceAllString(version, "")
		if prefix == version {
			t.Fatalf("%s: %q does not end in a version suffix, so this test "+
				"cannot tell drift from a rename", name, version)
		}
		pattern := regexp.MustCompile(regexp.QuoteMeta(prefix) + `-v\d+`)
		seen := map[string]bool{}
		for _, match := range pattern.FindAllString(string(script), -1) {
			seen[match] = true
		}
		found := make([]string, 0, len(seen))
		for value := range seen {
			found = append(found, value)
		}
		sort.Strings(found)
		if len(found) == 0 {
			t.Errorf("%s: %s does not mention %s at all; the live gate checks "+
				"no version for this object", path, name, version)
			continue
		}
		if len(found) != 1 || found[0] != version {
			t.Errorf("%s: %s mentions %v, but this code writes %q.\n"+
				"The gate asserts a version string that is not the one produced, so "+
				"a live run fails on the check instead of on what it gates.",
				path, name, found, version)
		}
	}
}
