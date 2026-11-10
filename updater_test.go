package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := updatePublicKey
	updatePublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updatePublicKey = old })
	return priv
}

func serveManifest(t *testing.T, manifest, sig string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + updateManifestName:
			w.Write([]byte(manifest))
		case "/" + updateManifestName + ".sig":
			w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

func TestUpdateManifestSignature(t *testing.T) {
	priv := withTestKey(t)
	manifest := `{"version":"9.1.0","notesUrl":"https://example.com/n","assets":{"darwin/arm64":{"url":"https://example.com/a.zip","sha256":"ab"}}}`
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest)))

	_, _, m, err := fetchUpdateManifest(context.Background(), serveManifest(t, manifest, sig+"\n"))
	if err != nil || m.Version != "9.1.0" || m.Assets["darwin/arm64"].SHA256 != "ab" {
		t.Fatalf("valid manifest: %+v %v", m, err)
	}

	// One byte changed (a different download URL): rejected.
	tampered := strings.Replace(manifest, "a.zip", "b.zip", 1)
	if _, _, _, err := fetchUpdateManifest(context.Background(), serveManifest(t, tampered, sig)); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	// Signed by another key: rejected.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSig := base64.StdEncoding.EncodeToString(ed25519.Sign(other, []byte(manifest)))
	if _, _, _, err := fetchUpdateManifest(context.Background(), serveManifest(t, manifest, otherSig)); err == nil {
		t.Fatal("foreign signature accepted")
	}
	// No signature at all: rejected.
	if _, _, _, err := fetchUpdateManifest(context.Background(), serveManifest(t, manifest, "")); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
}

func TestCompiledInKeyIsValid(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(updatePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("updatePublicKey is not a base64 ed25519 key: %v", err)
	}
}

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.1.0", "2.0.0", true},
		{"2.0.10", "2.0.9", true},
		{"v3.0.0", "2.9.9", true},
		{"2.0.0", "2.0.0", false},
		{"1.9.9", "2.0.0", false},
		{"2.1", "2.0.0", false},
		{"2.1.0-beta", "2.0.0", false},
	}
	for _, c := range cases {
		if got := versionNewer(c.a, c.b); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestNoManifestIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, _, _, err := fetchUpdateManifest(context.Background(), srv.URL+"/"); !errors.Is(err, errNoManifest) {
		t.Fatalf("404 should mean no manifest, got %v", err)
	}
}
