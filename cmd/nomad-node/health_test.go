package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/node"
)

// A node that no longer stops on a local failure needs an alarm that a node
// which did stop got for free. These cases are the ones that used to be
// indistinguishable from a working node once "is the process up" stopped
// answering the question.
func TestTheLivenessGateSeparatesAWorkingNodeFromASilentOne(t *testing.T) {
	now := time.Now().UTC()
	const limit = 30 * time.Second

	cases := []struct {
		name  string
		stats node.Stats
		// want is a fragment of the required failure message, or "" for a
		// node that must pass.
		want string
	}{
		{
			name: "emitting on cadence",
			stats: node.Stats{
				StartedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Second),
				LastSentAt: now.Add(-100 * time.Millisecond), Sent: 72000,
			},
		},
		{
			name: "up, on cadence, emitting nothing",
			stats: node.Stats{
				StartedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Second),
				LastSentAt: now.Add(-20 * time.Minute), SendDropped: 24000,
			},
			want: "last emitted",
		},
		{
			name: "never emitted at all",
			stats: node.Stats{
				StartedAt: now.Add(-5 * time.Minute), UpdatedAt: now.Add(-time.Second),
				SendDropped: 6000,
			},
			want: "emitted nothing since it started",
		},
		{
			name: "maintain loop died, file frozen",
			stats: node.Stats{
				StartedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-10 * time.Minute),
				LastSentAt: now.Add(-10 * time.Minute),
			},
			want: "stopped reporting",
		},
		{
			// The file exists and is non-empty, which is all the healthcheck
			// used to ask for.
			name:  "empty stats",
			stats: node.Stats{},
			want:  "no update time",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "health.json")
			encoded, err := json.Marshal(testCase.stats)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			err = checkNodeIsEmitting(path, limit, now)
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("a node emitting on cadence was reported unhealthy: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a %s node passed the liveness gate", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("gate said %q, which does not mention %q", err, testCase.want)
			}
		})
	}
}

// The gate reads a file a supervisor points it at, so it has to fail closed on
// a file that is missing, unparseable, or not a health file at all. Reporting
// a node healthy because its status could not be read is the failure mode that
// makes a healthcheck worse than none.
func TestTheLivenessGateFailsClosedOnAnUnreadableFile(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC()

	if err := checkNodeIsEmitting(filepath.Join(directory, "absent.json"), time.Minute, now); err == nil {
		t.Error("a missing health file passed the gate")
	}
	garbage := filepath.Join(directory, "garbage.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNodeIsEmitting(garbage, time.Minute, now); err == nil {
		t.Error("an unparseable health file passed the gate")
	}
	empty := filepath.Join(directory, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNodeIsEmitting(empty, time.Minute, now); err == nil {
		t.Error("an empty health file passed the gate")
	}
	usable := filepath.Join(directory, "usable.json")
	encoded, err := json.Marshal(node.Stats{
		StartedAt: now.Add(-time.Hour), UpdatedAt: now, LastSentAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(usable, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNodeIsEmitting(usable, 0, now); err == nil {
		t.Error("a zero silence limit was accepted; it would pass everything or nothing")
	}
}
