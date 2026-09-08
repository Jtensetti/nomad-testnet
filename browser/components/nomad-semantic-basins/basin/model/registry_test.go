package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// writePack builds a pack on disk whose digests actually match its files, so a
// negative case can break exactly one thing about a pack that would otherwise
// load.
func writePack(t *testing.T, directory string, adjust func(*Manifest)) Manifest {
	t.Helper()
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	weights := []byte("weights for a model that does not exist")
	tokenizer := []byte(`{"tokenizer":"fixture"}`)

	weightsDigest := sha256.Sum256(weights)
	tokenizerDigest := sha256.Sum256(tokenizer)

	manifest := validManifest()
	manifest.WeightsSHA256 = hex.EncodeToString(weightsDigest[:])
	manifest.TokenizerSHA256 = hex.EncodeToString(tokenizerDigest[:])
	manifest.WeightsBytes = int64(len(weights))
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
	write(LicenseFile, []byte("the model's own license, which is not Nomad's"))
	if manifest.NoticeRequired {
		write(NoticeFile, []byte("NOTICE carried forward as the terms require"))
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(ManifestFile, encoded)
	return manifest
}

func TestAWellFormedPackLoads(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gemma")
	manifest := writePack(t, directory, nil)

	pack, err := LoadPack(directory)
	if err != nil {
		t.Fatalf("a pack whose digests match was refused: %v", err)
	}
	if pack.Fingerprint() != manifest.Fingerprint() {
		t.Fatal("the loaded pack reports a different fingerprint than its manifest")
	}
}

// The manifest is the only thing that says what the weights are. A manifest
// describing different bytes is a label on the wrong thing, so it is refused
// rather than trusted.
func TestAPackWhoseWeightsDoNotMatchIsRefused(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tampered")
	writePack(t, directory, nil)

	weights := filepath.Join(directory, "weights.gguf")
	original, err := os.ReadFile(weights)
	if err != nil {
		t.Fatal(err)
	}
	// One flipped byte, same length, so the size check cannot be what catches it.
	tampered := append([]byte(nil), original...)
	tampered[0] ^= 0x01
	if err := os.WriteFile(weights, tampered, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a pack whose weights differ from its manifest by one byte loaded")
	}
}

func TestAPackWhoseTokenizerDoesNotMatchIsRefused(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tampered")
	writePack(t, directory, nil)
	if err := os.WriteFile(filepath.Join(directory, "tokenizer.json"),
		[]byte(`{"tokenizer":"other"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a pack with a substituted tokenizer loaded; the same weights with a " +
			"different tokenizer produce different vectors")
	}
}

// A redistribution obligation, enforced rather than documented.
func TestAPackUnderTermsRequiringANoticeIsRefusedWithoutOne(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gemma")
	writePack(t, directory, func(m *Manifest) { m.NoticeRequired = true })

	if _, err := LoadPack(directory); err != nil {
		t.Fatalf("the pack with its NOTICE was refused: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, NoticeFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a pack whose terms require a NOTICE loaded without one")
	}
}

// The control for the case above: a pack that needs no NOTICE is not refused
// for lacking one, so the check is about the obligation rather than about a
// file always having to be there.
func TestAPackUnderMITIsNotRefusedForLackingANotice(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "e5")
	writePack(t, directory, func(m *Manifest) {
		m.License = "MIT"
		m.NoticeRequired = false
	})
	if _, err := os.Stat(filepath.Join(directory, NoticeFile)); !os.IsNotExist(err) {
		t.Fatal("the fixture wrote a NOTICE, so this proves nothing")
	}
	if _, err := LoadPack(directory); err != nil {
		t.Fatalf("an MIT pack was refused for lacking a NOTICE it does not need: %v", err)
	}
}

// Every pack carries its own LICENSE, because the model's terms are not Nomad's.
func TestAPackWithoutItsOwnLicenseIsRefused(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gemma")
	writePack(t, directory, nil)
	if err := os.Remove(filepath.Join(directory, LicenseFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a pack loaded without carrying the model's own license")
	}
}

// A setting this build does not understand is a setting that is not in the
// fingerprint, so a manifest carrying one is refused rather than partly read.
func TestAManifestWithAnUnknownFieldIsRefused(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "future")
	writePack(t, directory, nil)

	path := filepath.Join(directory, ManifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["poolingStrategy"] = "cls"
	rewritten, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rewritten, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a manifest carrying a field this build ignores was accepted; the " +
			"setting would have changed the vectors and not the fingerprint")
	}
}

func TestAManifestWithATrailingValueIsRefused(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "double")
	writePack(t, directory, nil)
	path := filepath.Join(directory, ManifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("\n{}")...), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(directory); err == nil {
		t.Fatal("a manifest carrying two JSON values was accepted")
	}
}

// One unverifiable pack costs exactly itself, and is counted rather than
// swallowed: a registry that silently offers fewer models than are installed
// looks the same as one with fewer models installed.
func TestOneBadPackDoesNotHideTheOthers(t *testing.T) {
	root := t.TempDir()
	writePack(t, filepath.Join(root, "good"), nil)
	writePack(t, filepath.Join(root, "broken"), nil)
	if err := os.Remove(filepath.Join(root, "broken", LicenseFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}

	registry, rejected, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if rejected != 2 {
		t.Fatalf("rejected %d packs, want 2", rejected)
	}
	if got := len(registry.Installed()); got != 1 {
		t.Fatalf("registry holds %d packs, want 1", got)
	}
}

// Lookup is by fingerprint, because an id does not identify what an index was
// built with.
func TestLookupIsByFingerprintRatherThanByName(t *testing.T) {
	root := t.TempDir()
	first := writePack(t, filepath.Join(root, "a"), nil)
	second := writePack(t, filepath.Join(root, "b"), func(m *Manifest) {
		m.Dimensions = 128 // same id, same weights, incomparable output
	})
	if first.ID != second.ID {
		t.Fatal("the fixtures no longer share an id")
	}

	registry, rejected, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if rejected != 0 {
		t.Fatalf("%d packs were rejected", rejected)
	}
	if len(registry.Installed()) != 2 {
		t.Fatalf("two packs sharing an id collapsed into %d", len(registry.Installed()))
	}
	if _, ok := registry.ByFingerprint(first.Fingerprint()); !ok {
		t.Fatal("the first pack is not reachable by its fingerprint")
	}
	if _, ok := registry.ByFingerprint(second.Fingerprint()); !ok {
		t.Fatal("the second pack is not reachable by its fingerprint")
	}
}

// An unreadable registry root is not an empty one.
func TestAMissingRegistryRootIsAnErrorNotAnEmptyRegistry(t *testing.T) {
	if _, _, err := OpenRegistry(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing registry root opened as an empty registry")
	}
}

// The catalogue describes models; it carries nothing it has not been told.
//
// It has no digest, size or memory fields, and no method that turns an entry
// into a manifest. Writing plausible digests for weights nobody measured would
// give a registry that verifies packs against invented numbers, which is worse
// than no verification because it looks verified -- and an approximate size is
// the same claim in a smaller font. A pack builder measures the files it
// shipped and writes the manifest from those.
func TestTheCatalogueOffersTheThreeModelsAndAssertsNothingUnmeasured(t *testing.T) {
	entries := Catalogue()
	if len(entries) != 3 {
		t.Fatalf("the catalogue offers %d models, want the three recommended", len(entries))
	}
	fields := map[string]bool{}
	structType := reflect.TypeOf(CatalogueEntry{})
	for index := 0; index < structType.NumField(); index++ {
		fields[structType.Field(index).Name] = true
	}
	for _, unmeasured := range []string{
		"WeightsSHA256", "TokenizerSHA256", "WeightsBytes",
		"ApproximateDiskBytes", "ApproximateResidentKB",
	} {
		if fields[unmeasured] {
			t.Errorf("CatalogueEntry carries %s, a value this build cannot have "+
				"measured; a pack builder supplies it from the files that shipped",
				unmeasured)
		}
	}
	for _, entry := range entries {
		t.Run(entry.ID, func(t *testing.T) {
			if _, err := BuiltinAdapter(Manifest{
				Adapter:           entry.Adapter,
				InferenceSettings: map[string]string{},
			}); err != nil {
				t.Fatalf("the catalogue names an adapter this build does not have: %v", err)
			}
			if !slices.Contains(entry.SupportedDims, entry.RecommendedDimensions) {
				t.Fatalf("recommended width %d is not among the supported %v",
					entry.RecommendedDimensions, entry.SupportedDims)
			}
			if entry.RecommendedDimensions > entry.NativeDimensions {
				t.Fatalf("recommended width %d exceeds native %d",
					entry.RecommendedDimensions, entry.NativeDimensions)
			}
			if strings.TrimSpace(entry.License) == "" {
				t.Fatal("a catalogue entry must name its license")
			}
		})
	}
}

// Gemma is the one of the three whose terms oblige a NOTICE, and the catalogue
// has to say so or the registry check never fires for it.
func TestTheCatalogueMarksTheLicenceThatObligesANotice(t *testing.T) {
	notices := map[string]bool{}
	for _, entry := range Catalogue() {
		notices[entry.ID] = entry.NoticeRequired
	}
	if !notices["embeddinggemma-300m"] {
		t.Error("EmbeddingGemma is under Google's Gemma Terms, which oblige a " +
			"redistributor to carry a NOTICE; the catalogue does not say so, so " +
			"LoadPack would never require one")
	}
	if notices["multilingual-e5-small"] {
		t.Error("multilingual-e5-small is MIT and needs no NOTICE; requiring one " +
			"would refuse a pack that is fine")
	}
}
