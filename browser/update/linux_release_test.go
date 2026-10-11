package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A manifest names an artifact, a digest and a byte count. Nothing in this
// package mentions macOS, a disk image or an application bundle, so the
// mechanism is platform-neutral by construction -- and every test drove it
// with a .dmg, so the neutrality was true and unexercised. A property that
// holds by construction and is never exercised is one a refactor can remove
// without anything failing.
//
// The Linux client is not offered as a release because the process does not
// cover it. This is the mechanism half of covering it:
// the same two-approval path, the same verifier, driven by a real gzipped
// tarball of the shape linux-release.yml produces.

// linuxTarball writes a real .tar.gz and returns its path and bytes, so the
// digest and length are over a genuine archive rather than a random blob.
func linuxTarball(t *testing.T, directory, name, architecture string) (string, []byte) {
	t.Helper()
	path := filepath.Join(directory, name)
	handle, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	compressor := gzip.NewWriter(handle)
	archive := tar.NewWriter(compressor)
	body := []byte("#!/bin/sh\n# " + architecture + "\nexec nomad-browser \"$@\"\n")
	if err := archive.WriteHeader(&tar.Header{
		Name: "nomad-browser-" + architecture + "/bin/nomad-browser",
		Mode: 0o755, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{archive.Close(), compressor.Close(), handle.Close()} {
		if err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, content
}

type linuxRelease struct {
	trusted   []ed25519.PublicKey
	keys      []ed25519.PrivateKey
	directory string
	path      string
	content   []byte
	name      string
}

func newLinuxRelease(t *testing.T) *linuxRelease {
	t.Helper()
	release := &linuxRelease{directory: t.TempDir(), name: "nomad-browser-linux-amd64.tar.gz"}
	for approver := 0; approver < MinimumApprovals; approver++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		release.trusted = append(release.trusted, public)
		release.keys = append(release.keys, private)
	}
	release.path, release.content = linuxTarball(t, release.directory, release.name, "amd64")
	return release
}

// manifest builds one approved by the named approvers, so a test can ask for
// too few approvals or the same approver twice.
func (r *linuxRelease) manifest(t *testing.T, version string, approvers ...int) []byte {
	t.Helper()
	digest := sha256.Sum256(r.content)
	manifest := Prepare(Manifest{
		Release: version, Channel: "stable",
		ArtifactName:   r.name,
		ArtifactDigest: hex.EncodeToString(digest[:]),
		ArtifactBytes:  int64(len(r.content)),
	})
	for _, approver := range approvers {
		approved, err := Approve(manifest, r.keys[approver])
		if err != nil {
			t.Fatal(err)
		}
		manifest = approved
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestALinuxTarballTakesTheSameTwoApprovalPath(t *testing.T) {
	r := newLinuxRelease(t)
	verified, err := Decode(r.manifest(t, "1.0.0", 0, 1), r.trusted)
	if err != nil {
		t.Fatalf("a properly approved Linux release did not decode: %v", err)
	}
	if verified.Release.String() != "1.0.0" {
		t.Fatalf("decoded %+v", verified)
	}
	if err := VerifyArtifact(r.path, verified); err != nil {
		t.Fatalf("a genuine tarball did not verify: %v", err)
	}
	watermark := filepath.Join(r.directory, "installed.json")
	if err := AcceptMonotonic(watermark, verified); err != nil {
		t.Fatalf("a first Linux install was refused: %v", err)
	}
	installed, err := InstalledVersion(watermark)
	if err != nil || installed == nil || installed.String() != "1.0.0" {
		t.Fatalf("watermark records %v (%v)", installed, err)
	}
}

// The two-person rule is the reason this process exists, so it has to hold for
// a tarball exactly as it does for a disk image.
func TestALinuxTarballNeedsTwoDistinctApprovers(t *testing.T) {
	r := newLinuxRelease(t)
	for name, approvers := range map[string][]int{
		"no approvals":               {},
		"one approval":               {0},
		"one approver signing twice": {0, 0},
	} {
		if _, err := Decode(r.manifest(t, "1.0.0", approvers...), r.trusted); err == nil {
			t.Errorf("a Linux release with %s was accepted", name)
		}
	}
}

// Size is checked before the hash, so a padded artefact fails on length. Worth
// asserting for the tarball because gzip ignores trailing bytes: a reader that
// checked only that the archive extracts would accept this.
func TestAPaddedLinuxTarballIsRefused(t *testing.T) {
	r := newLinuxRelease(t)
	verified, err := Decode(r.manifest(t, "1.0.0", 0, 1), r.trusted)
	if err != nil {
		t.Fatal(err)
	}
	padded := filepath.Join(r.directory, "padded.tar.gz")
	if err := os.WriteFile(padded, append(append([]byte{}, r.content...), 0, 0, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyArtifact(padded, verified)
	if err == nil {
		t.Fatal("a tarball with three bytes appended verified")
	}
	if !strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("a padded tarball was refused for %q rather than for its length", err)
	}
}

// A manifest is for one artifact. The Linux and macOS artifacts of one release
// carry different digests, and a manifest naming one must not authorise the
// other -- which is what would let a build for one platform be installed as
// the other.
func TestALinuxManifestDoesNotAuthoriseADifferentArtifact(t *testing.T) {
	r := newLinuxRelease(t)
	verified, err := Decode(r.manifest(t, "1.0.0", 0, 1), r.trusted)
	if err != nil {
		t.Fatal(err)
	}
	other, content := linuxTarball(t, r.directory, "nomad-browser-linux-arm64.tar.gz", "arm64")
	// The first version of this built both archives from the same bytes, so
	// they had one digest and the refusal below could not happen. Assert they
	// actually differ before asserting anything about refusing one.
	if bytes.Equal(content, r.content) {
		t.Fatal("the two architectures produced identical archives, so this test " +
			"would pass whatever VerifyArtifact did")
	}
	if err := VerifyArtifact(other, verified); err == nil {
		t.Fatal("a manifest for the amd64 tarball verified the arm64 one")
	}
}
