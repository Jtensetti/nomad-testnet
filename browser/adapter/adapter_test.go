package adapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/localcache"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

func TestAdapterServesOnlyBundleBoundVerifiedLocalResource(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := localcache.NewMemory()
	html := []byte("<!doctype html><title>Nomad local object</title>")
	htmlManifest, err := reconstruct.NewManifest(html, 1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(htmlManifest, html); err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := EncodeBundle([]Entry{{
		Path: "/", ObjectID: htmlManifest.Root, MediaType: "text/html; charset=utf-8",
	}})
	if err != nil {
		t.Fatal(err)
	}
	bundleManifest, err := reconstruct.NewManifest(bundleBytes, 1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(bundleManifest, bundleBytes); err != nil {
		t.Fatal(err)
	}
	browser, err := New(store, bundleManifest.Root)
	if err != nil {
		t.Fatal(err)
	}
	response, err := browser.Handle(Request{Method: "GET", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 200 || response.MediaType != "text/html; charset=utf-8" || string(response.Body) != string(html) {
		t.Fatalf("unexpected response: %#v", response)
	}
	if !strings.Contains(response.Headers["Content-Security-Policy"], "connect-src 'none'") {
		t.Fatal("response did not deny renderer network connections")
	}
	head, err := browser.Handle(Request{Method: "HEAD", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if head.Status != 200 || len(head.Body) != 0 {
		t.Fatal("HEAD returned an unexpected body")
	}
	missing, err := browser.Handle(Request{Method: "GET", Path: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	if missing.Status != 404 {
		t.Fatalf("missing status = %d", missing.Status)
	}
}

func TestBundleRejectsNonCanonicalAndDuplicatePaths(t *testing.T) {
	var id [32]byte
	if _, err := EncodeBundle([]Entry{{Path: "/a/../b", ObjectID: id, MediaType: "text/plain"}}); err == nil {
		t.Fatal("accepted non-canonical path")
	}
	if _, err := EncodeBundle([]Entry{
		{Path: "/same", ObjectID: id, MediaType: "text/plain"},
		{Path: "/same", ObjectID: id, MediaType: "text/plain"},
	}); err == nil {
		t.Fatal("accepted duplicate path")
	}
}
