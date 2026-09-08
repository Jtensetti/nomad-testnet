package localcache

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

func TestCacheAcceptsOnlyVerifiedImmutableObjects(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("verified local browser resource")
	manifest, err := reconstruct.NewManifest(data, 1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewMemory()
	if err := cache.Put(manifest, data); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get(manifest.Root)
	if err != nil {
		t.Fatal(err)
	}
	got.Bytes[0] ^= 1
	again, err := cache.Get(manifest.Root)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Bytes) != string(data) {
		t.Fatal("caller mutated cached bytes")
	}

	tampered := append([]byte(nil), data...)
	tampered[0] ^= 1
	if err := cache.Put(manifest, tampered); err == nil {
		t.Fatal("cache accepted bytes that do not match the commitment")
	}
}
