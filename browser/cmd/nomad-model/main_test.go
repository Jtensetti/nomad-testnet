package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-semantic-basins/basin/model"
)

// writePack builds a pack whose digests match its files, so a negative case
// can break exactly one thing about a pack that would otherwise verify.
func writePack(t *testing.T, directory string, adjust func(*model.Manifest)) model.Manifest {
	t.Helper()
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	weights := []byte("fixture weights")
	tokenizer := []byte(`{"tokenizer":"fixture"}`)
	weightsDigest := sha256.Sum256(weights)
	tokenizerDigest := sha256.Sum256(tokenizer)

	manifest := model.Manifest{
		Schema: model.SchemaVersion, ID: "embeddinggemma-300m", Version: "1.0.0",
		Revision: 1, Runtime: model.RuntimeGGUF, Quantization: "q8_0",
		Adapter: "gemma", AdapterVersion: 1,
		Dimensions: 256, NativeDimensions: 768,
		SupportedDims: []int{768, 512, 256, 128},
		Normalize:     true, MaxInputTokens: 2048,
		InferenceSettings: map[string]string{"pooling": "mean"},
		WeightsSHA256:     hex.EncodeToString(weightsDigest[:]),
		TokenizerSHA256:   hex.EncodeToString(tokenizerDigest[:]),
		WeightsBytes:      int64(len(weights)),
		License:           "Gemma Terms of Use", NoticeRequired: true,
		Source:       "https://example.invalid/pack",
		Requirements: model.Requirements{MinimumRAMBytes: 1 << 28, Threads: 2},
	}
	if adjust != nil {
		adjust(&manifest)
	}
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("weights."+string(manifest.Runtime), weights)
	write("tokenizer.json", tokenizer)
	write(model.LicenseFile, []byte("the model's own license"))
	if manifest.NoticeRequired {
		write(model.NoticeFile, []byte("NOTICE"))
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write(model.ManifestFile, encoded)
	return manifest
}

func drive(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := run(args, &out)
	return out.String(), err
}

func TestThePackReportNamesTheFingerprintAndItsIndex(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gemma")
	manifest := writePack(t, directory, nil)

	output, err := drive(t, "-pack", directory, "-index-root", "/var/lib/nomad")
	if err != nil {
		t.Fatalf("a verifying pack was not described: %v\n%s", err, output)
	}
	fingerprint := manifest.Fingerprint()
	if !strings.Contains(output, fingerprint) {
		t.Fatalf("the report does not name the fingerprint:\n%s", output)
	}
	if !strings.Contains(output, filepath.Join("/var/lib/nomad", "semantic-index", fingerprint)) {
		t.Fatalf("the report does not name the index directory:\n%s", output)
	}
	// The truncation is worth saying out loud: a 256-wide index from a
	// 768-wide model is not a bug report waiting to happen if it is stated.
	if !strings.Contains(output, "truncated from 768") {
		t.Fatalf("the report does not mention truncation:\n%s", output)
	}
	if !strings.Contains(output, "requires carrying a NOTICE") {
		t.Fatalf("the report does not state the redistribution obligation:\n%s", output)
	}
}

// A pack that does not verify is not described as though it might be fine.
func TestAPackThatDoesNotVerifyIsRefusedRatherThanDescribed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tampered")
	writePack(t, directory, nil)
	if err := os.WriteFile(filepath.Join(directory, "weights.gguf"),
		[]byte("different weights"), 0o640); err != nil {
		t.Fatal(err)
	}
	output, err := drive(t, "-pack", directory)
	if err == nil {
		t.Fatalf("a pack whose weights do not match its manifest was described:\n%s", output)
	}
	if strings.Contains(output, "fingerprint") {
		t.Fatalf("a fingerprint was printed for an unverified pack:\n%s", output)
	}
}

// The catalogue is offered without any claim to have measured a file.
func TestTheCatalogueListsTheThreeModelsAndTheirTerms(t *testing.T) {
	output, err := drive(t, "-catalogue")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"EmbeddingGemma 300M", "multilingual-e5-small", "Qwen3 Embedding 0.6B",
		"Gemma Terms of Use", "MIT", "Apache-2.0",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("the catalogue does not mention %q", expected)
		}
	}
	if !strings.Contains(output, "not a pack") {
		t.Error("the catalogue does not say that an entry is not a verified pack")
	}
}

// One unverifiable pack costs itself, and the count is reported rather than
// swallowed.
func TestARegistryReportsWhatItRejected(t *testing.T) {
	root := t.TempDir()
	writePack(t, filepath.Join(root, "good"), nil)
	writePack(t, filepath.Join(root, "broken"), nil)
	if err := os.Remove(filepath.Join(root, "broken", model.NoticeFile)); err != nil {
		t.Fatal(err)
	}
	output, err := drive(t, "-registry", root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "1 verified packs") {
		t.Fatalf("the report does not say how many verified:\n%s", output)
	}
	if !strings.Contains(output, "1 directories did not verify") {
		t.Fatalf("the rejected pack was not reported:\n%s", output)
	}
}

// With no arguments the tool does nothing and says so, rather than picking a
// default directory to go looking in.
func TestNoArgumentsIsAnErrorRatherThanAGuess(t *testing.T) {
	if _, err := drive(t); err == nil {
		t.Fatal("the tool ran with no arguments")
	}
}
