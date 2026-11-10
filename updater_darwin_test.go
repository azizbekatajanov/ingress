package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeBundle builds a tiny ad-hoc signed Ingress.app of the given version.
func makeBundle(t *testing.T, dir, version, marker string) string {
	t.Helper()
	app := filepath.Join(dir, "Ingress.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ingress</string>
<key>CFBundleIdentifier</key><string>com.example.ingress-test</string>
<key>CFBundleShortVersionString</key><string>` + version + `</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "ingress"), []byte("#!/bin/sh\necho "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", app).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v %s", err, out)
	}
	return app
}

func zipBundle(t *testing.T, app, dest string) {
	t.Helper()
	if out, err := exec.Command("/usr/bin/ditto", "-c", "-k", "--keepParent", app, dest).CombinedOutput(); err != nil {
		t.Fatalf("ditto: %v %s", err, out)
	}
}

func TestReplaceAppBundle(t *testing.T) {
	installed := makeBundle(t, filepath.Join(t.TempDir(), "Applications"), "2.0.0", "old")
	src := makeBundle(t, t.TempDir(), "2.1.0", "new")
	archive := filepath.Join(t.TempDir(), "Ingress.zip")
	zipBundle(t, src, archive)

	if err := replaceAppBundle(archive, "2.1.0", installed); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(filepath.Join(installed, "Contents", "MacOS", "ingress")).Output()
	if string(out) != "new\n" {
		t.Fatalf("installed app runs %q", out)
	}
	if entries, _ := os.ReadDir(filepath.Dir(installed)); len(entries) != 1 {
		t.Errorf("leftovers next to the app: %v", entries)
	}
}

func TestReplaceAppBundleRejectsWrongVersion(t *testing.T) {
	installed := makeBundle(t, filepath.Join(t.TempDir(), "Applications"), "2.0.0", "old")
	src := makeBundle(t, t.TempDir(), "2.0.5", "new")
	archive := filepath.Join(t.TempDir(), "Ingress.zip")
	zipBundle(t, src, archive)

	// The manifest promised 2.1.0; the archive holds 2.0.5.
	if err := replaceAppBundle(archive, "2.1.0", installed); err == nil {
		t.Fatal("version mismatch accepted")
	}
	out, _ := exec.Command(filepath.Join(installed, "Contents", "MacOS", "ingress")).Output()
	if string(out) != "old\n" {
		t.Fatalf("old app was replaced anyway: %q", out)
	}
}

func TestReplaceAppBundleRejectsBrokenSignature(t *testing.T) {
	installed := makeBundle(t, filepath.Join(t.TempDir(), "Applications"), "2.0.0", "old")
	src := makeBundle(t, t.TempDir(), "2.1.0", "new")
	// Modify the binary after signing.
	os.WriteFile(filepath.Join(src, "Contents", "MacOS", "ingress"), []byte("#!/bin/sh\necho evil\n"), 0o755)
	archive := filepath.Join(t.TempDir(), "Ingress.zip")
	zipBundle(t, src, archive)

	if err := replaceAppBundle(archive, "2.1.0", installed); err == nil {
		t.Fatal("bundle with a broken code signature accepted")
	}
}
