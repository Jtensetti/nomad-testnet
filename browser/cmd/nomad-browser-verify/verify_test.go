package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/update"
)

// This binary decides whether a release may be installed over what is
// installed now, and had no test of any kind: run and trustedKeys were both at
// zero coverage. The update package underneath is well covered; what was not
// covered is the wrapper that chooses which keys the rule is applied against,
// which is where a build with no release key must refuse rather than proceed
// with an empty trust set.

type world struct {
	directory string
	manifest  string
	artifact  string
	watermark string
	approvers []ed25519.PrivateKey
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{directory: t.TempDir()}
	w.manifest = filepath.Join(w.directory, "release.json")
	w.artifact = filepath.Join(w.directory, "installer.dmg")
	w.watermark = filepath.Join(w.directory, "watermark")
	for i := 0; i < 2; i++ {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		w.approvers = append(w.approvers, private)
	}
	return w
}

func (w *world) keyList() string {
	fields := make([]string, len(w.approvers))
	for index, key := range w.approvers {
		fields[index] = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	return strings.Join(fields, ",")
}

// publish writes an artifact and a manifest approved by every approver.
func (w *world) publish(t *testing.T, release string) {
	t.Helper()
	payload := []byte("installer bytes for " + release)
	if err := os.WriteFile(w.artifact, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	manifest := update.Prepare(update.Manifest{
		Release: release, Channel: "alpha", ArtifactName: "installer.dmg",
		ArtifactDigest: hex.EncodeToString(digest[:]), ArtifactBytes: int64(len(payload)),
	})
	var err error
	for _, key := range w.approvers {
		manifest, err = update.Approve(manifest, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.manifest, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A build with no compiled-in release key must say so, not proceed with an
// empty trust set. An empty set is a set every signature is outside, but a
// wrapper that returned one and let Decode decide would be one refactor away
// from a rule satisfied by nobody.
func TestABuildWithNoReleaseKeyRefusesRatherThanTrustingNothing(t *testing.T) {
	if releaseKeys != "" {
		t.Skip("this build has compiled-in release keys, so the empty case is not reachable")
	}
	_, err := trustedKeys("")
	if err == nil {
		t.Fatal("a build with no release keys returned a trust set")
	}
	for _, expected := range []string{"no compiled-in release keys", "EB-7"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("the refusal does not mention %q: %v", expected, err)
		}
	}
}

func TestAnApprovedReleaseIsAcceptedAndRecorded(t *testing.T) {
	w := newWorld(t)
	w.publish(t, "1.2.0")
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), false); err != nil {
		t.Fatalf("an approved release was refused: %v", err)
	}
	installed, err := update.InstalledVersion(w.watermark)
	if err != nil {
		t.Fatal(err)
	}
	if installed == nil || installed.String() != "1.2.0" {
		t.Fatalf("the watermark records %v after accepting 1.2.0", installed)
	}
}

// The property H-08 names: a release older than what is installed is refused,
// and the watermark is left where it was.
func TestAnOlderReleaseIsRefusedAndTheWatermarkStands(t *testing.T) {
	w := newWorld(t)
	w.publish(t, "2.0.0")
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), false); err != nil {
		t.Fatal(err)
	}
	w.publish(t, "1.9.0")
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), false); err == nil {
		t.Fatal("a release older than the installed one was accepted")
	}
	installed, err := update.InstalledVersion(w.watermark)
	if err != nil {
		t.Fatal(err)
	}
	if installed == nil || installed.String() != "2.0.0" {
		t.Fatalf("the watermark moved to %v after a refused rollback", installed)
	}
}

// A dry run verifies and records nothing. A dry run that advanced the
// watermark would mark a release installed that nobody installed, and the next
// real release would be refused as a rollback.
func TestADryRunDoesNotAdvanceTheWatermark(t *testing.T) {
	w := newWorld(t)
	w.publish(t, "1.2.0")
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), true); err != nil {
		t.Fatalf("a dry run of an approved release failed: %v", err)
	}
	installed, err := update.InstalledVersion(w.watermark)
	if err != nil {
		t.Fatal(err)
	}
	if installed != nil {
		t.Fatalf("a dry run recorded %v as installed", installed)
	}
}

func TestAnArtifactThatDoesNotMatchTheManifestIsRefused(t *testing.T) {
	w := newWorld(t)
	w.publish(t, "1.2.0")
	if err := os.WriteFile(w.artifact, []byte("different installer bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), false); err == nil {
		t.Fatal("an artifact whose digest does not match its manifest was accepted")
	}
}

func TestAManifestApprovedByOnlyOnePersonIsRefused(t *testing.T) {
	w := newWorld(t)
	only := w.approvers[:1]
	all := w.approvers
	w.approvers = only
	w.publish(t, "1.2.0")
	w.approvers = all
	if err := run(w.manifest, w.artifact, w.watermark, w.keyList(), false); err == nil {
		t.Fatal("a release with one approval was accepted")
	}
}

func TestMissingPathsAreRefused(t *testing.T) {
	w := newWorld(t)
	for name, call := range map[string]func() error{
		"no manifest":  func() error { return run("", w.artifact, w.watermark, w.keyList(), false) },
		"no artifact":  func() error { return run(w.manifest, "", w.watermark, w.keyList(), false) },
		"no watermark": func() error { return run(w.manifest, w.artifact, "", w.keyList(), false) },
	} {
		if err := call(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
