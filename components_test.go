package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name     string
	typ      byte
	mode     int64
	body     string
	linkname string
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Size: int64(len(e.body)), Linkname: e.linkname}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractTarGzLayoutAndModes(t *testing.T) {
	data := makeTarGz(t, []tarEntry{
		{name: "./bin/", typ: tar.TypeDir, mode: 0o777},
		{name: "./bin/openfortivpn", typ: tar.TypeReg, mode: 0o777, body: "#!/bin/sh\n"},
		{name: "LICENSES/GPL-3.0.txt", typ: tar.TypeReg, mode: 0o666, body: "license"},
	})
	dest := t.TempDir()
	if err := extractTarGz(data, dest); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "bin", "openfortivpn"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 != 0 || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("binary mode = %v, want executable and not group/other-writable", fi.Mode().Perm())
	}
	fi, err = os.Stat(filepath.Join(dest, "LICENSES", "GPL-3.0.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o133 != 0 {
		t.Errorf("license mode = %v, want 0644-ish", fi.Mode().Perm())
	}
}

func TestExtractTarGzRejectsUnsafeEntries(t *testing.T) {
	cases := map[string][]tarEntry{
		"parent traversal": {{name: "../evil", typ: tar.TypeReg, mode: 0o644, body: "x"}},
		"nested traversal": {{name: "bin/../../evil", typ: tar.TypeReg, mode: 0o644, body: "x"}},
		"absolute path":    {{name: "/etc/evil", typ: tar.TypeReg, mode: 0o644, body: "x"}},
		"symlink":          {{name: "bin/openfortivpn", typ: tar.TypeSymlink, linkname: "/bin/sh"}},
		"hardlink":         {{name: "bin/openfortivpn", typ: tar.TypeLink, linkname: "/bin/sh"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			os.Mkdir(dest, 0o755)
			if err := extractTarGz(makeTarGz(t, entries), dest); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := os.Lstat(filepath.Join(parent, "evil")); err == nil {
				t.Fatal("file escaped the destination")
			}
		})
	}
}

func TestParseRootResult(t *testing.T) {
	if err := parseRootResult("noise\n"+rootOKMarker+"\n", nil); err != nil {
		t.Errorf("OK marker: got %v", err)
	}
	if err := parseRootResult(rootErrPrefix+"bad sum\n", errors.New("exit 1")); err == nil || err.Error() != "bad sum" {
		t.Errorf("error marker: got %v", err)
	}
	cancelled := errors.New("запрос прав администратора отменён")
	if err := parseRootResult("", cancelled); err != cancelled {
		t.Errorf("no output + run error: got %v", err)
	}
	if err := parseRootResult("garbage", nil); err == nil {
		t.Error("no marker should be an error")
	}
}

func TestDownloadVerified(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.tar.gz")
	payload := []byte("archive bytes")
	os.WriteFile(src, payload, 0o644)
	sum := sha256.Sum256(payload)
	good := ComponentBuild{Version: "1", URL: "file://" + src, SHA256: hex.EncodeToString(sum[:])}

	var lastDone int64
	if err := downloadVerified(context.Background(), good, filepath.Join(dir, "ok"), func(d, _ int64) { lastDone = d }); err != nil {
		t.Fatal(err)
	}
	if lastDone != int64(len(payload)) {
		t.Errorf("progress done = %d, want %d", lastDone, len(payload))
	}

	bad := good
	bad.SHA256 = strings.Repeat("0", 64)
	err := downloadVerified(context.Background(), bad, filepath.Join(dir, "bad"), func(int64, int64) {})
	if err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Errorf("mismatched sum: got %v", err)
	}

	insecure := good
	insecure.URL = "http://example.com/a.tar.gz"
	if err := downloadVerified(context.Background(), insecure, filepath.Join(dir, "http"), func(int64, int64) {}); err == nil {
		t.Error("plain http must be refused")
	}
}

func TestVerifyRootOwnedRejectsUserOwned(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	dir := t.TempDir()
	if err := verifyRootOwned([]string{dir}); err == nil {
		t.Error("a user-owned directory must fail the check")
	}
	if err := verifyRootOwned([]string{"/usr/bin", "/usr/bin/true"}); err != nil {
		t.Errorf("system paths should pass: %v", err)
	}
}

func TestResolvePrefersOverrideThenSystem(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	store := &ProfileStore{path: filepath.Join(t.TempDir(), "profiles.json")}
	cm := NewComponentManager(store)

	bin := filepath.Join(t.TempDir(), "openfortivpn")
	os.WriteFile(bin, []byte("#!/bin/sh\necho 1.20.5\n"), 0o755)

	t.Setenv("PATH", filepath.Dir(bin))
	path, source, err := cm.resolve("openfortivpn")
	if _, statErr := os.Lstat(managedBinary("openfortivpn")); statErr == nil {
		t.Skip("a managed openfortivpn is installed on this machine")
	}
	if err != nil || source != "system" || path != bin {
		t.Fatalf("system fallback: got %q %q %v", path, source, err)
	}

	override := filepath.Join(t.TempDir(), "my-openfortivpn")
	os.WriteFile(override, []byte("#!/bin/sh\n"), 0o755)
	if err := cm.SetOverride("openfortivpn", override); err != nil {
		t.Fatal(err)
	}
	if path, source, _ := cm.resolve("openfortivpn"); source != "override" || path != override {
		t.Fatalf("override: got %q %q", path, source)
	}
	if err := cm.SetOverride("openfortivpn", "relative/path"); err == nil {
		t.Error("relative override must be rejected")
	}

	t.Setenv("PATH", t.TempDir())
	cm.SetOverride("openfortivpn", "")
	if _, _, err := cm.resolve("openfortivpn"); err == nil {
		t.Error("nothing installed should be an error")
	}
}

func TestInstallArchiveReplacesAtomically(t *testing.T) {
	comps := t.TempDir()
	build := ComponentBuild{Version: "1.20.5-ingress.1", SHA256: "ABC"}
	v1 := makeTarGz(t, []tarEntry{
		{name: "bin/openfortivpn", typ: tar.TypeReg, mode: 0o755, body: "v1"},
		{name: "SOURCES.txt", typ: tar.TypeReg, mode: 0o644, body: "src"},
	})
	if err := installArchive(v1, "openfortivpn", build, comps, false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(comps, "openfortivpn", "bin", "openfortivpn"))
	if string(got) != "v1" {
		t.Fatalf("binary = %q", got)
	}
	info, _ := os.ReadFile(filepath.Join(comps, "openfortivpn", installedInfoFile))
	if !strings.Contains(string(info), "1.20.5-ingress.1") || !strings.Contains(string(info), `"abc"`) {
		t.Errorf("installed.json = %s", info)
	}

	// A broken archive (no bin/<name>) must leave the previous install intact.
	broken := makeTarGz(t, []tarEntry{{name: "README", typ: tar.TypeReg, mode: 0o644, body: "x"}})
	if err := installArchive(broken, "openfortivpn", build, comps, false); err == nil {
		t.Fatal("expected an error for an archive without the binary")
	}
	got, _ = os.ReadFile(filepath.Join(comps, "openfortivpn", "bin", "openfortivpn"))
	if string(got) != "v1" {
		t.Fatalf("previous install damaged: %q", got)
	}

	v2 := makeTarGz(t, []tarEntry{{name: "bin/openfortivpn", typ: tar.TypeReg, mode: 0o755, body: "v2"}})
	if err := installArchive(v2, "openfortivpn", build, comps, false); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(filepath.Join(comps, "openfortivpn", "bin", "openfortivpn"))
	if string(got) != "v2" {
		t.Fatalf("binary after upgrade = %q", got)
	}
	if _, err := os.Stat(filepath.Join(comps, "openfortivpn", "SOURCES.txt")); err == nil {
		t.Error("files from the old version must not survive an upgrade")
	}
	entries, _ := os.ReadDir(comps)
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("leftover staging/old dirs: %v", names)
	}
}

func TestRootInstallRefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if err := rootInstall([]string{"openfortivpn", "/nonexistent"}); err == nil {
		t.Fatal("must refuse without root")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24.1", "1.21", 1}, {"1.21", "1.21", 0}, {"1.21.0", "1.21", 0},
		{"1.20.5", "1.21", -1}, {"1.3", "1.21", -1}, {"2.0", "1.21", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
