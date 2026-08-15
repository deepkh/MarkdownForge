package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeHTTPSOrigin(t *testing.T) {
	valid := map[string]string{
		"https://LOCALDRAFT.ai/":    "https://localdraft.ai",
		"https://localdraft.ai:443": "https://localdraft.ai",
		"https://example.com:8443":  "https://example.com:8443",
	}
	for input, expected := range valid {
		actual, err := NormalizeHTTPSOrigin(input)
		if err != nil || actual != expected {
			t.Fatalf("NormalizeHTTPSOrigin(%q) = %q, %v", input, actual, err)
		}
	}
	for _, input := range []string{"*", "https://*.example.com", "http://localdraft.ai", "https://localdraft.ai/path", "https://user@example.com", "https://localdraft.ai?x=1", "https://localdraft.ai/#x"} {
		if _, err := NormalizeHTTPSOrigin(input); err == nil {
			t.Fatalf("invalid origin %q was accepted", input)
		}
	}
}

func TestSecurityStoreSeedsAndPersistsAllowedOrigins(t *testing.T) {
	directory := t.TempDir()
	paths := Paths{Directory: directory, SecurityFile: filepath.Join(directory, "bridge-settings.json")}
	store := NewSecurityStore(paths)
	origins, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 1 || origins[0] != DefaultAllowedOrigin {
		t.Fatalf("first-run origins = %#v", origins)
	}
	origins, err = store.Add("https://DEV.localdraft.ai/")
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 {
		t.Fatalf("origins after add = %#v", origins)
	}
	origins, err = store.Add("https://dev.localdraft.ai")
	if err != nil || len(origins) != 2 {
		t.Fatalf("duplicate add = %#v, %v", origins, err)
	}
	origins, removed, err := store.Remove(DefaultAllowedOrigin)
	if err != nil || !removed || len(origins) != 1 {
		t.Fatalf("remove = %#v, %v, %v", origins, removed, err)
	}
	info, err := os.Stat(paths.SecurityFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("security file permissions = %o", info.Mode().Perm())
	}
	reloaded, err := NewSecurityStore(paths).List()
	if err != nil || len(reloaded) != 1 || reloaded[0] != "https://dev.localdraft.ai" {
		t.Fatalf("reloaded origins = %#v, %v", reloaded, err)
	}
}

func TestPairedClientStoreBindsClientToOrigin(t *testing.T) {
	directory := t.TempDir()
	paths := Paths{Directory: directory, PairedClientsFile: filepath.Join(directory, "paired-clients.json")}
	store := NewPairedClientStore(paths)
	client, err := store.Upsert(PairedClient{
		ID: "client-1", Name: "Chrome", Origin: "https://localdraft.ai/",
		PublicKey: PublicKeyJWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.Origin != "https://localdraft.ai" {
		t.Fatalf("origin = %q", client.Origin)
	}
	if _, found, _ := store.Get("client-1", "https://evil.example"); found {
		t.Fatal("client authenticated on a different origin")
	}
	if _, found, _ := store.Get("client-1", "https://localdraft.ai"); !found {
		t.Fatal("paired client was not found")
	}
	removed, err := store.Remove("client-1")
	if err != nil || !removed {
		t.Fatalf("remove = %v, %v", removed, err)
	}
}
