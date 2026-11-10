package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Self-install on macOS. The release archive is a zip of Ingress.app made
// with `ditto -c -k --keepParent` (ditto keeps everything a bundle needs);
// it's unpacked with ditto next to the running app, checked, and swapped
// in with two renames. If the app's folder isn't writable by the user,
// the same steps run as root through `ingress --install-update`, which
// verifies the signature and hash again itself — it never trusts what the
// unprivileged side checked.

const rootUpdateFlag = "--install-update"

// runningAppBundle returns the .app the running binary belongs to.
func runningAppBundle() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	// …/Ingress.app/Contents/MacOS/ingress
	app := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if !strings.HasSuffix(app, ".app") {
		return "", errors.New(T("update.err.not_bundle"))
	}
	return app, nil
}

// selfUpdateBlocker says why Ingress can't replace itself here ("" = it can).
func selfUpdateBlocker(hasAsset bool) string {
	if !hasAsset {
		return T("update.block.no_build")
	}
	app, err := runningAppBundle()
	if err != nil {
		return T("update.block.not_bundle")
	}
	// Gatekeeper's App Translocation runs a quarantined app from a random
	// read-only copy; replacing that copy changes nothing.
	if strings.Contains(app, "/AppTranslocation/") {
		return T("update.block.translocated")
	}
	if strings.HasPrefix(app, "/Volumes/") {
		return T("update.block.dmg")
	}
	return ""
}

func installUpdate(ctx context.Context, manifest, sig []byte, m updateManifest, progress func(done, total int64), installing func()) error {
	app, err := runningAppBundle()
	if err != nil {
		return err
	}
	asset, ok := m.Assets[platformKey()]
	if !ok {
		return errors.New(T("update.block.no_build"))
	}
	work, err := os.MkdirTemp("", "ingress-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	archive := filepath.Join(work, "Ingress.zip")
	if err := downloadVerified(ctx, ComponentBuild{Version: m.Version, URL: asset.URL, SHA256: asset.SHA256}, archive, progress); err != nil {
		return err
	}
	installing()

	if unix.Access(filepath.Dir(app), unix.W_OK) == nil && unix.Access(app, unix.W_OK) == nil {
		return replaceAppBundle(archive, m.Version, app)
	}
	// Not ours to write: do it as root, handing over everything it needs
	// to check for itself.
	manifestPath := filepath.Join(work, updateManifestName)
	sigPath := manifestPath + ".sig"
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		return err
	}
	out, err := elevatedRun(rootUpdateFlag, manifestPath, sigPath, archive, app, langArg())
	return parseRootResult(out, err)
}

// replaceAppBundle unpacks archive next to app, checks the new bundle and
// swaps it in. On any failure the old app stays where it was.
func replaceAppBundle(archive, version, app string) error {
	parent := filepath.Dir(app)
	stage, err := os.MkdirTemp(parent, ".ingress-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	if out, err := exec.Command("/usr/bin/ditto", "-x", "-k", archive, stage).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v %s", T("update.err.unpack"), err, bytes.TrimSpace(out))
	}
	fresh := filepath.Join(stage, "Ingress.app")
	if err := checkNewBundle(fresh, version); err != nil {
		return err
	}
	old := filepath.Join(stage, "Ingress.old.app")
	if err := os.Rename(app, old); err != nil {
		return err
	}
	if err := os.Rename(fresh, app); err != nil {
		_ = os.Rename(old, app) // put the old one back
		return err
	}
	return nil // stage (with the old app) is removed by the defer
}

// checkNewBundle makes sure the unpacked bundle is the version the signed
// manifest promised and that its code signature is intact.
func checkNewBundle(bundle, version string) error {
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", filepath.Join(bundle, "Contents", "Info.plist")).Output()
	if err != nil {
		return errors.New(T("update.err.bad_bundle", err))
	}
	if got := strings.TrimSpace(string(out)); got != version {
		return errors.New(T("update.err.version_mismatch", got, version))
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", bundle).CombinedOutput(); err != nil {
		return errors.New(T("update.err.bad_bundle", strings.TrimSpace(string(out))))
	}
	return nil
}

// relaunchSelf starts the (new) bundle once this process has exited.
func relaunchSelf() error {
	app, err := runningAppBundle()
	if err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open "$2"`, "sh", fmt.Sprint(os.Getpid()), app)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// --- root side: `ingress --install-update <manifest> <sig> <archive> <app>` ---

func isRootUpdateCommand(arg string) bool { return arg == rootUpdateFlag }

func runRootUpdateCommand(args []string) int {
	err := rootInstallUpdate(args)
	if err != nil {
		fmt.Println(rootErrPrefix + err.Error())
		return 1
	}
	fmt.Println(rootOKMarker)
	return 0
}

func rootInstallUpdate(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New(T("update.err.not_root"))
	}
	if len(args) != 4 {
		return errors.New("usage: --install-update <manifest> <sig> <archive> <app>")
	}
	manifest, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	rawSig, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	if _, err := verifyUpdateManifest(manifest, rawSig); err != nil {
		return err
	}
	var m updateManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return errors.New(T("update.err.bad_manifest"))
	}
	asset, ok := m.Assets[platformKey()]
	if !ok {
		return errors.New(T("update.block.no_build"))
	}
	archive, app := args[2], args[3]
	if filepath.Base(app) != "Ingress.app" || !filepath.IsAbs(app) {
		return errors.New(T("update.err.not_bundle"))
	}
	// Copy the archive somewhere the user can't touch before hashing it,
	// so it can't be swapped between the check and the unpack.
	data, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	if len(data) > maxUpdateArchive {
		return errors.New(T("comp.err.too_big"))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, asset.SHA256) {
		return errors.New(T("root.err.checksum", got))
	}
	private, err := os.MkdirTemp("/var/root", "ingress-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(private)
	safe := filepath.Join(private, "Ingress.zip")
	if err := os.WriteFile(safe, data, 0o600); err != nil {
		return err
	}
	return replaceAppBundle(safe, m.Version, app)
}
