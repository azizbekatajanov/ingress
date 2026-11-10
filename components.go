package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Components are the external VPN binaries Ingress drives (openfortivpn for
// Fortinet, openconnect for GlobalProtect). Since v2 they're no longer
// installed through Homebrew: Ingress downloads its own pinned builds (see
// components_manifest.go), verifies their sha256, and installs them as root
// into a root-owned directory (components_root.go) — root-owned because the
// binaries are later executed as root, so a user-writable location would be
// a privilege-escalation path.
//
// Which binary actually runs is decided by ResolvePath, in this order:
//  1. a per-component override path the user set (Компоненты screen, or the
//     "use the system one" choice in the migration banner),
//  2. Ingress' own managed install,
//  3. a system binary found on PATH (e.g. a brew install left over from
//     1.0.x) — so upgrading never blocks connecting while the user hasn't
//     picked one of the two options above yet.

type componentInfo struct {
	Name  string
	Title string
	VPN   string
}

var knownComponents = []componentInfo{
	{Name: "openfortivpn", Title: "openfortivpn", VPN: "Fortinet SSL-VPN"},
	{Name: "openconnect", Title: "OpenConnect", VPN: "GlobalProtect, Cisco"},
	{Name: "sstpc", Title: "sstpc", VPN: "SSTP"},
}

func lookupComponent(name string) (componentInfo, bool) {
	for _, c := range knownComponents {
		if c.Name == name {
			return c, true
		}
	}
	return componentInfo{}, false
}

// componentForProfileType is the binary a profile of that type runs.
func componentForProfileType(profileType string) string {
	if profileType == ProfileTypeGlobalProtect || profileType == ProfileTypeCisco {
		return "openconnect"
	}
	if profileType == ProfileTypeSSTP {
		return "sstpc"
	}
	return "openfortivpn"
}

func platformKey() string { return runtime.GOOS + "/" + runtime.GOARCH }

func componentsDir() string           { return filepath.Join(componentsBaseDir(), "components") }
func componentDir(name string) string { return filepath.Join(componentsDir(), name) }
func managedBinary(name string) string {
	return filepath.Join(componentDir(name), "bin", name)
}

// installedInfoFile is written by the root installer next to bin/ so the
// unprivileged side can show the installed version without executing the
// binary.
const installedInfoFile = "installed.json"

type installedInfo struct {
	Component   string    `json:"component"`
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installedAt"`
}

func readInstalledInfo(name string) (installedInfo, bool) {
	data, err := os.ReadFile(filepath.Join(componentDir(name), installedInfoFile))
	if err != nil {
		return installedInfo{}, false
	}
	var info installedInfo
	if json.Unmarshal(data, &info) != nil {
		return installedInfo{}, false
	}
	return info, true
}

// ComponentStatus is what the frontend renders (install banner, migration
// banner, Компоненты screen).
type ComponentStatus struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	VPN   string `json:"vpn"`

	// Available: the compiled-in manifest has a build for this OS/arch.
	Available     bool   `json:"available"`
	LatestVersion string `json:"latestVersion"`

	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installedVersion"`
	InstalledPath    string `json:"installedPath"`
	UpdateAvailable  bool   `json:"updateAvailable"`
	// Broken is set when a managed install exists but fails the root-owned
	// integrity check — it won't be executed until reinstalled.
	Broken string `json:"broken"`

	Override        string `json:"override"`
	OverrideVersion string `json:"overrideVersion"`
	OverrideError   string `json:"overrideError"`

	SystemPath    string `json:"systemPath"`
	SystemVersion string `json:"systemVersion"`

	// ActivePath/ActiveSource: what Connect would run right now.
	// ActiveSource is "override", "managed", "system", or "" (nothing usable).
	ActivePath   string `json:"activePath"`
	ActiveSource string `json:"activeSource"`
	// Warning flags a known-broken version of a non-managed binary in use.
	Warning string `json:"warning"`

	Installing bool `json:"installing"`
}

// ComponentProgress is emitted as the "component:progress" event.
type ComponentProgress struct {
	Name  string `json:"name"`
	Phase string `json:"phase"` // "download" | "install"
	Done  int64  `json:"done"`
	Total int64  `json:"total"` // -1 if unknown
}

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// knownBadVersions lists version ranges (>= minVersion) known to be broken,
// per component. Only applied to binaries Ingress didn't install itself
// (managed builds are pinned).
var knownBadVersions = map[string][]struct {
	minVersion string
	warning    string // i18n key
}{
	"openfortivpn": {{
		// openfortivpn 1.21+ fails to bring the tunnel up on macOS Sonoma
		// and later — adrienverge/openfortivpn#1165, marked wontfix upstream.
		// (1.0.x matched this by string prefix "1.21", which silently let
		// 1.22+ through.)
		minVersion: "1.21",
		warning:    "comp.warn.ofv121",
	}},
}

func badVersionWarning(name, version string) string {
	if version == "" || runtime.GOOS != "darwin" {
		return ""
	}
	for _, bad := range knownBadVersions[name] {
		if compareVersions(version, bad.minVersion) >= 0 {
			return T(bad.warning)
		}
	}
	return ""
}

// compareVersions compares dotted numeric versions ("1.24.1" vs "1.21"),
// treating missing parts as 0.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// binaryVersion runs `<path> --version` (unprivileged, short timeout) and
// extracts the first dotted version number.
func binaryVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	return versionRe.FindString(string(out))
}

func checkExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New(T("comp.err.abs_path"))
	}
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return errors.New(T("comp.err.not_found"))
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New(T("comp.err.not_file"))
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return errors.New(T("comp.err.not_exec"))
	}
	return nil
}

func managedChain(name string) []string {
	return []string{
		componentsBaseDir(),
		componentsDir(),
		componentDir(name),
		filepath.Join(componentDir(name), "bin"),
		managedBinary(name),
	}
}

// ComponentManager is the unprivileged side: status, path resolution,
// download + verification, and handing the verified archive to the root
// installer.
type ComponentManager struct {
	store *ProfileStore

	mu         sync.Mutex
	installing map[string]bool
}

func NewComponentManager(store *ProfileStore) *ComponentManager {
	return &ComponentManager{store: store, installing: make(map[string]bool)}
}

func (cm *ComponentManager) isInstalling(name string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.installing[name]
}

func (cm *ComponentManager) List() []ComponentStatus {
	out := make([]ComponentStatus, 0, len(knownComponents))
	for _, c := range knownComponents {
		out = append(out, cm.Status(c.Name))
	}
	return out
}

func (cm *ComponentManager) Status(name string) ComponentStatus {
	info, ok := lookupComponent(name)
	if !ok {
		return ComponentStatus{Name: name}
	}
	st := ComponentStatus{Name: info.Name, Title: info.Title, VPN: info.VPN, Installing: cm.isInstalling(name)}

	if build, ok := activeManifest()[name][platformKey()]; ok && build.URL != "" && build.SHA256 != "" {
		st.Available = true
		st.LatestVersion = build.Version
	}

	if inst, ok := readInstalledInfo(name); ok {
		st.Installed = true
		st.InstalledVersion = inst.Version
		st.InstalledPath = managedBinary(name)
		st.UpdateAvailable = st.Available && inst.Version != st.LatestVersion
		if err := verifyRootOwned(managedChain(name)); err != nil {
			st.Broken = err.Error()
		}
	}

	if o := cm.store.ComponentOverride(name); o != "" {
		st.Override = o
		if err := checkExecutable(o); err != nil {
			st.OverrideError = err.Error()
		} else {
			st.OverrideVersion = binaryVersion(o)
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		st.SystemPath = p
		st.SystemVersion = binaryVersion(p)
	}

	if path, source, err := cm.resolve(name); err == nil {
		st.ActivePath, st.ActiveSource = path, source
		switch source {
		case "override":
			st.Warning = badVersionWarning(name, st.OverrideVersion)
		case "system":
			st.Warning = badVersionWarning(name, st.SystemVersion)
		}
	}
	return st
}

// ResolvePath returns the absolute path of the binary to run for a
// component, or a user-facing error explaining what to do.
func (cm *ComponentManager) ResolvePath(name string) (string, error) {
	path, _, err := cm.resolve(name)
	return path, err
}

func (cm *ComponentManager) resolve(name string) (string, string, error) {
	if _, ok := lookupComponent(name); !ok {
		return "", "", errors.New(T("comp.err.unknown", name))
	}
	if o := cm.store.ComponentOverride(name); o != "" {
		if err := checkExecutable(o); err != nil {
			return "", "", errors.New(T("comp.err.override_broken", name, o, err))
		}
		return o, "override", nil
	}
	if _, err := os.Lstat(managedBinary(name)); err == nil {
		if err := verifyRootOwned(managedChain(name)); err != nil {
			return "", "", errors.New(T("comp.err.integrity", name, err))
		}
		return managedBinary(name), "managed", nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, "system", nil
	}
	return "", "", errors.New(T("comp.err.not_installed", name))
}

// SetOverride stores (or, with an empty path, clears) a custom binary path.
func (cm *ComponentManager) SetOverride(name, path string) error {
	if _, ok := lookupComponent(name); !ok {
		return errors.New(T("comp.err.unknown", name))
	}
	path = strings.TrimSpace(path)
	if path != "" {
		if err := checkExecutable(path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return cm.store.SetComponentOverride(name, path)
}

const maxArchiveSize = 100 << 20

// Install downloads, verifies and (via one admin prompt) installs the
// manifest's build of a component.
func (cm *ComponentManager) Install(ctx context.Context, name string, progress func(ComponentProgress)) error {
	if _, ok := lookupComponent(name); !ok {
		return errors.New(T("comp.err.unknown", name))
	}
	build, ok := activeManifest()[name][platformKey()]
	if !ok || build.URL == "" || build.SHA256 == "" {
		return errors.New(T("comp.err.no_build", name, platformKey()))
	}

	cm.mu.Lock()
	if cm.installing[name] {
		cm.mu.Unlock()
		return errors.New(T("comp.err.installing", name))
	}
	cm.installing[name] = true
	cm.mu.Unlock()
	defer func() {
		cm.mu.Lock()
		delete(cm.installing, name)
		cm.mu.Unlock()
	}()

	tmp, err := os.MkdirTemp("", "ingress-component-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	archive := filepath.Join(tmp, name+".tar.gz")

	err = downloadVerified(ctx, build, archive, func(done, total int64) {
		progress(ComponentProgress{Name: name, Phase: "download", Done: done, Total: total})
	})
	if err != nil {
		return err
	}

	progress(ComponentProgress{Name: name, Phase: "install", Total: -1})
	args := append(append([]string{rootInstallFlag, name, archive}, devManifestArgs()...), langArg())
	out, runErr := elevatedRun(args...)
	return parseRootResult(out, runErr)
}

// Remove deletes Ingress' managed install of a component (admin prompt).
func (cm *ComponentManager) Remove(name string) error {
	if _, ok := lookupComponent(name); !ok {
		return errors.New(T("comp.err.unknown", name))
	}
	if cm.isInstalling(name) {
		return errors.New(T("comp.err.installing_now", name))
	}
	out, err := elevatedRun(rootRemoveFlag, name, langArg())
	return parseRootResult(out, err)
}

func downloadVerified(ctx context.Context, build ComponentBuild, dest string, progress func(done, total int64)) error {
	var (
		body  io.ReadCloser
		total int64 = -1
	)
	u, err := url.Parse(build.URL)
	if err != nil {
		return fmt.Errorf("%s: %w", T("comp.err.bad_url"), err)
	}
	switch u.Scheme {
	case "https":
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, build.URL, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", T("comp.err.download"), err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return errors.New(T("comp.err.download_status", resp.Status))
		}
		body, total = resp.Body, resp.ContentLength
	case "file":
		// Only ever present in a dev manifest (-tags devmanifest); release
		// manifests are https-only.
		f, err := os.Open(u.Path)
		if err != nil {
			return err
		}
		if fi, err := f.Stat(); err == nil {
			total = fi.Size()
		}
		body = f
	default:
		return errors.New(T("comp.err.scheme", u.Scheme))
	}
	defer body.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	h := sha256.New()
	var done int64
	last := time.Time{}
	buf := make([]byte, 64<<10)
	r := io.LimitReader(body, maxArchiveSize+1)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if done > maxArchiveSize {
				return errors.New(T("comp.err.too_big"))
			}
			if time.Since(last) > 100*time.Millisecond {
				progress(done, total)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("%s: %w", T("comp.err.interrupted"), rerr)
		}
	}
	progress(done, total)

	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, build.SHA256) {
		return fmt.Errorf("%s", T("comp.err.checksum", build.SHA256, got))
	}
	return out.Close()
}

func parseRootResult(out string, runErr error) error {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == rootOKMarker {
			return nil
		}
		if msg, ok := strings.CutPrefix(line, rootErrPrefix); ok {
			return errors.New(msg)
		}
	}
	if runErr != nil {
		return runErr
	}
	tail := strings.TrimSpace(out)
	if len(tail) > 300 {
		tail = tail[len(tail)-300:]
	}
	return errors.New(T("comp.err.no_result", tail))
}
