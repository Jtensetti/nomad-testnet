package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-semantic-basins/basin/loopback"
)

// A key file another account can read is a key that account holds, which
// defeats the point of the key.
func TestKeyFileMustNotBeReadableByOtherAccounts(t *testing.T) {
	key := strings.Repeat("5a", loopback.MinimumServiceKeyBytes)
	for mode, allowed := range map[os.FileMode]bool{
		0o600: true,
		0o400: true,
		0o640: false,
		0o644: false,
		0o604: false,
		0o666: false,
	} {
		path := filepath.Join(t.TempDir(), "service.key")
		if err := os.WriteFile(path, []byte(key), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := readKeyFile(path)
		if allowed && err != nil {
			t.Errorf("mode %04o was refused: %v", mode, err)
		}
		if !allowed {
			if err == nil {
				t.Errorf("mode %04o was accepted", mode)
				continue
			}
			if !strings.Contains(err.Error(), "0600") {
				t.Errorf("mode %04o was refused for the wrong reason: %v", mode, err)
			}
		}
	}
}

func TestGenerateKeyRefusesToOverwriteAnExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.key")
	if err := generateKey(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := generateKey(path); err == nil {
		t.Fatal("generate-key overwrote an existing service key")
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the existing service key was changed by a refused generate")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("a generated key file is mode %04o", info.Mode().Perm())
	}
}

// The bytes an operator generates on the service side have to be the bytes the
// client seals with. A mismatch here would look like a wrong key at runtime and
// send whoever hit it hunting in the wrong place.
func TestGeneratedKeyWorksEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.key")
	if err := generateKey(path); err != nil {
		t.Fatal(err)
	}
	key, err := readKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}

	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": []float32{3, 4}}},
		})
	}))
	defer modelServer.Close()

	shim := httptest.NewServer(loopback.Service{
		ServiceKey: key,
		Upstream:   loopback.OpenAIUpstream{BaseURL: modelServer.URL},
	})
	defer shim.Close()

	embedder := loopback.HTTPEmbedder{
		BaseURL: shim.URL, Model: "local-model", ServiceKey: key,
	}
	vector, err := embedder.Embed(context.Background(), "private query")
	if err != nil {
		t.Fatalf("a freshly generated key did not work end to end: %v", err)
	}
	if len(vector) != 2 {
		t.Fatalf("unexpected vector %v", vector)
	}

	// And a different generated key does not.
	otherPath := filepath.Join(t.TempDir(), "other.key")
	if err := generateKey(otherPath); err != nil {
		t.Fatal(err)
	}
	otherKey, err := readKeyFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	embedder.ServiceKey = otherKey
	if _, err := embedder.Embed(context.Background(), "private query"); err == nil {
		t.Fatal("a client holding a different key was served")
	}
}

func TestListenAddressMustBeLoopback(t *testing.T) {
	for address, allowed := range map[string]bool{
		"127.0.0.1:8779": true,
		"[::1]:8779":     true,
		"0.0.0.0:8779":   false,
		"10.0.0.1:8779":  false,
		"localhost:8779": false,
		":8779":          false,
		"127.0.0.1":      false,
		"":               false,
	} {
		err := checkListenAddress(address)
		if allowed && err != nil {
			t.Errorf("%q was refused: %v", address, err)
		}
		if !allowed && err == nil {
			t.Errorf("%q was accepted as a listen address", address)
		}
	}
}

func TestDecodeKeyAcceptsHexAndRawAndRefusesShort(t *testing.T) {
	full := strings.Repeat("ab", loopback.MinimumServiceKeyBytes)
	decoded, err := decodeKey(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != loopback.MinimumServiceKeyBytes {
		t.Fatalf("hex key decoded to %d bytes", len(decoded))
	}
	for _, b := range decoded {
		if b != 0xab {
			t.Fatalf("hex key decoded to %#x", decoded)
		}
	}

	raw := strings.Repeat("z", loopback.MinimumServiceKeyBytes)
	if decoded, err := decodeKey(raw); err != nil || len(decoded) != len(raw) {
		t.Fatalf("raw key of %d bytes was not accepted: %v", len(raw), err)
	}

	for _, short := range []string{"", "ab", strings.Repeat("ab", loopback.MinimumServiceKeyBytes/2-1)} {
		if _, err := decodeKey(short); err == nil {
			t.Errorf("%q was accepted as a service key", short)
		}
	}
}
