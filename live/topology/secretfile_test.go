package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The permission checks on the operator's secret files, the authority's
// private key and the threshold share are the whole of "no plaintext secrets
// readable by anyone else" on the operator side. None of the loaders that
// carry them had a test: LoadSecrets, LoadPrivateKeys, LoadAuthorityKey and
// LoadAuthorityPrivateKey were all at zero coverage across the repository, so
// deleting a mode check broke nothing.

func writeSecretFile(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask, so the mode is set explicitly: a test that
	// meant to write 0644 and got 0600 would pass for the wrong reason.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func generatedSecrets(t *testing.T) []byte {
	t.Helper()
	secrets, err := GenerateSecrets("operator-a")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestOperatorSecretsAreRefusedWhenOthersCanReadThem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permission check is not applied on Windows, which uses its ACL model")
	}
	encoded := generatedSecrets(t)

	if _, err := LoadPrivateKeys(writeSecretFile(t, "secrets.json", encoded, 0o600)); err != nil {
		t.Fatalf("a 0600 secret file was refused: %v", err)
	}
	// 0400 is what a Docker secret is mounted as, and it is stricter, so it
	// must load: a check written as an equality rather than a mask would
	// refuse the one deployment shape this is meant to accommodate.
	if _, err := LoadPrivateKeys(writeSecretFile(t, "secrets.json", encoded, 0o400)); err != nil {
		t.Fatalf("a 0400 secret file was refused: %v", err)
	}

	for name, mode := range map[string]os.FileMode{
		"group readable": 0o640,
		"world readable": 0o604,
		"world writable": 0o602,
	} {
		_, err := LoadPrivateKeys(writeSecretFile(t, "secrets.json", encoded, mode))
		if err == nil {
			t.Fatalf("a %s secret file was accepted", name)
		}
		if !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("a %s secret file was refused for %q rather than its permissions", name, err)
		}
	}
}

// The message has to name the regular-file rule. A directory fails ReadFile
// anyway and a symlink fails the permission check on its 0777 link mode, so
// asserting only that an error came back leaves the check under test unproven
// -- removing it kept the first version of this test green.
func TestOperatorSecretsMustBeARegularFile(t *testing.T) {
	_, err := LoadPrivateKeys(t.TempDir())
	if err == nil {
		t.Fatal("a directory was accepted as a secret file")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a directory was refused for %q rather than for not being a regular file", err)
	}

	// A named pipe is the case the check exists for: it is not a directory, so
	// ReadFile does not refuse it -- it blocks, or returns whatever a writer
	// puts there, which is a secret file an attacker supplies the contents of.
	pipe := filepath.Join(t.TempDir(), "secrets.json")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("FIFOs are unavailable here: %v", err)
	}
	if _, err := LoadPrivateKeys(pipe); err == nil {
		t.Fatal("a FIFO was accepted as a secret file")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a FIFO was refused for %q rather than for not being a regular file", err)
	}
}

// A symlink is refused on its own mode rather than followed. Following one
// would let anything that can write the directory point the loader at a file
// whose permissions it does not control.
func TestASymlinkToASecretFileIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permission check is not applied on Windows, which uses its ACL model")
	}
	target := writeSecretFile(t, "real.json", generatedSecrets(t), 0o600)
	link := filepath.Join(filepath.Dir(target), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	if _, err := LoadPrivateKeys(link); err == nil {
		t.Fatal("a symlink to a secret file was followed")
	}
}

func TestAMissingSecretFileIsReportedRatherThanTreatedAsEmpty(t *testing.T) {
	_, err := LoadPrivateKeys(filepath.Join(t.TempDir(), "absent.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing secret file reported %v, want a not-exist error", err)
	}
}

func TestTheAuthorityPrivateKeyIsRefusedWhenOthersCanReadIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permission check is not applied on Windows, which uses its ACL model")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivate := []byte(base64.StdEncoding.EncodeToString(private))

	if _, err := LoadAuthorityPrivateKey(
		writeSecretFile(t, "authority.key", encodedPrivate, 0o600)); err != nil {
		t.Fatalf("a 0600 authority private key was refused: %v", err)
	}
	_, err = LoadAuthorityPrivateKey(writeSecretFile(t, "authority.key", encodedPrivate, 0o644))
	if err == nil {
		t.Fatal("a world-readable authority private key was accepted")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("refused for %q rather than its permissions", err)
	}

	// The public half deliberately has no permission check: a public key is
	// public, and refusing a readable one would only teach operators to widen
	// the mode on the private one too. Asserted so the asymmetry is deliberate
	// rather than an oversight either way.
	encodedPublic := []byte(base64.StdEncoding.EncodeToString(public))
	if _, err := LoadAuthorityKey(
		writeSecretFile(t, "authority.pub", encodedPublic, 0o644)); err != nil {
		t.Fatalf("a world-readable authority public key was refused: %v", err)
	}
}

// A private key whose scalar half does not match its seed is not a key this
// implementation produced, and signing with one produces signatures that do
// not verify under the public key it advertises.
func TestANonCanonicalAuthorityPrivateKeyIsRefused(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), private...)
	tampered[ed25519.SeedSize] ^= 0xff
	_, err = LoadAuthorityPrivateKey(writeSecretFile(t, "authority.key",
		[]byte(base64.StdEncoding.EncodeToString(tampered)), 0o600))
	if err == nil {
		t.Fatal("a non-canonical authority private key was accepted")
	}
	if !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("refused for %q rather than for not being canonical", err)
	}
}

func TestAnAuthorityKeyThatIsNotStrictBase64IsRefused(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Standard base64 with the padding replaced by characters a lenient
	// decoder would drop. Two encodings that decode to one key is a place two
	// implementations disagree about what was pinned.
	lenient := base64.StdEncoding.EncodeToString(public)
	lenient = strings.TrimRight(lenient, "=") + "\n\n"
	if _, err := LoadAuthorityKey(writeSecretFile(t, "authority.pub",
		[]byte(lenient), 0o644)); err == nil {
		t.Fatal("an authority key missing its base64 padding was accepted")
	}
}
