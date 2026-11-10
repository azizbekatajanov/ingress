package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// In-app updates.
//
// Every release carries ingress-update.json (version, release notes URL and,
// per platform, the app archive's URL and sha256) plus ingress-update.json.sig:
// an ed25519 signature of the manifest's exact bytes, made with a key that
// lives only in the maintainer's keychain (see tools/updatesign). The public
// half is compiled in below. So a compromised GitHub account can't push an
// update: it can't produce a valid signature.
//
// Ingress checks at start and once a day (unless turned off in About), and
// shows a banner; nothing is installed without the user clicking "Update".
// Self-install is macOS only (updater_darwin.go): on Linux apt owns
// /usr/bin/ingress, so there the banner just links to the release.

// updatePublicKey is the ed25519 public key release manifests are signed
// with (base64). Var, not const, so tests can swap in their own.
var updatePublicKey = "FlnmGojsKodPMoHXaXAFCOU/YERkLsuG7gdeY+i5syM="

const (
	updateManifestName  = "ingress-update.json"
	updateCheckInterval = 24 * time.Hour
	updateFirstDelay    = 5 * time.Second
	maxManifestSize     = 64 << 10
	maxUpdateArchive    = 256 << 20
)

// errNoManifest: the latest release has no update manifest (releases before
// in-app updates existed) — nothing to update to, not an error.
var errNoManifest = errors.New("no update manifest")

var updateBaseURL = AppGithubURL + "/releases/latest/download/"

// devAutoInstallUpdate (dev builds only, see components_devmanifest.go)
// installs a found update without the click — for end-to-end tests.
var devAutoInstallUpdate bool

type updateManifest struct {
	Version  string                 `json:"version"`
	NotesURL string                 `json:"notesUrl"`
	Assets   map[string]updateAsset `json:"assets"` // platformKey() → archive
}

type updateAsset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// UpdateStatus is what the frontend renders (banner and About).
type UpdateStatus struct {
	Current   string `json:"current"`
	AutoCheck bool   `json:"autoCheck"`
	Checking  bool   `json:"checking"`
	LastCheck string `json:"lastCheck,omitempty"` // RFC 3339
	// Available: a newer, correctly signed release exists.
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	NotesURL  string `json:"notesUrl,omitempty"`
	// CanInstall: Ingress can replace itself here; otherwise Blocker says
	// why (an i18n'd sentence) and the banner links to the release.
	CanInstall bool   `json:"canInstall"`
	Blocker    string `json:"blocker,omitempty"`
	Dismissed  bool   `json:"dismissed"` // "Later" until the next check
	// Phase is "", "downloading" or "installing"; Done/Total the download.
	Phase string `json:"phase,omitempty"`
	Done  int64  `json:"done,omitempty"`
	Total int64  `json:"total,omitempty"`
	Error string `json:"error,omitempty"`
}

type Updater struct {
	app *App

	mu       sync.Mutex
	status   UpdateStatus
	manifest []byte // the verified manifest, as signed
	sig      []byte
	parsed   updateManifest
	kick     chan struct{}
}

func NewUpdater(app *App) *Updater {
	return &Updater{app: app, status: UpdateStatus{Current: AppVersion}, kick: make(chan struct{}, 1)}
}

// run checks after a short delay, then daily, while auto-check is on.
func (u *Updater) run(ctx context.Context) {
	timer := time.NewTimer(updateFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-u.kick:
		}
		if u.app.store.UpdateCheck() {
			u.Check(ctx)
			if devAutoInstallUpdate && u.Status().CanInstall {
				_ = u.app.InstallUpdate(false)
			}
		}
		timer.Reset(updateCheckInterval)
	}
}

func (u *Updater) Status() UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.status
	s.AutoCheck = u.app.store.UpdateCheck()
	return s
}

func (u *Updater) emit() {
	if u.app.ctx != nil {
		wailsRuntime.EventsEmit(u.app.ctx, "update:status", u.Status())
	}
}

func (u *Updater) update(fn func(s *UpdateStatus)) {
	u.mu.Lock()
	fn(&u.status)
	u.mu.Unlock()
	u.emit()
}

// Check fetches and verifies the latest manifest.
func (u *Updater) Check(ctx context.Context) {
	u.mu.Lock()
	if u.status.Checking || u.status.Phase != "" {
		u.mu.Unlock()
		return
	}
	u.status.Checking = true
	u.status.Error = ""
	u.mu.Unlock()
	u.emit()

	manifest, sig, m, err := fetchUpdateManifest(ctx, updateBaseURL)
	u.mu.Lock()
	u.status.Checking = false
	u.status.LastCheck = time.Now().Format(time.RFC3339)
	if errors.Is(err, errNoManifest) {
		u.status.Available = false
		u.mu.Unlock()
		u.emit()
		return
	}
	if err != nil {
		u.status.Error = err.Error()
		u.mu.Unlock()
		log.Printf("ingress: update check: %v", err)
		u.emit()
		return
	}
	u.manifest, u.sig, u.parsed = manifest, sig, m
	u.status.Available = versionNewer(m.Version, AppVersion)
	u.status.Version, u.status.NotesURL = m.Version, m.NotesURL
	u.status.Dismissed = false
	_, hasAsset := m.Assets[platformKey()]
	u.status.Blocker = selfUpdateBlocker(hasAsset)
	u.status.CanInstall = u.status.Available && u.status.Blocker == ""
	u.mu.Unlock()
	u.emit()
}

func (u *Updater) Dismiss() {
	u.update(func(s *UpdateStatus) { s.Dismissed = true })
}

// Install downloads, verifies and installs the checked update, then
// relaunches Ingress. Connections must already be down (the frontend asks).
func (u *Updater) Install(ctx context.Context) error {
	u.mu.Lock()
	if !u.status.CanInstall || u.status.Phase != "" {
		u.mu.Unlock()
		return errors.New(T("update.err.not_ready"))
	}
	manifest, sig, m := u.manifest, u.sig, u.parsed
	u.status.Phase, u.status.Error, u.status.Done, u.status.Total = "downloading", "", 0, 0
	u.mu.Unlock()
	u.emit()

	err := installUpdate(ctx, manifest, sig, m, func(done, total int64) {
		u.update(func(s *UpdateStatus) { s.Done, s.Total = done, total })
	}, func() {
		u.update(func(s *UpdateStatus) { s.Phase = "installing" })
	})
	if err != nil {
		u.update(func(s *UpdateStatus) { s.Phase, s.Error = "", err.Error() })
		return err
	}
	// Installed: relaunch the new copy and quit this one.
	if err := relaunchSelf(); err != nil {
		u.update(func(s *UpdateStatus) { s.Phase, s.Error = "", T("update.err.relaunch", err) })
		return err
	}
	u.app.quitConfirmed = true
	wailsRuntime.Quit(u.app.ctx)
	return nil
}

// fetchUpdateManifest downloads the manifest and its signature from base
// and verifies them. Only a verified manifest is ever parsed.
func fetchUpdateManifest(ctx context.Context, base string) (manifest, sig []byte, m updateManifest, err error) {
	if manifest, err = httpGetSmall(ctx, base+updateManifestName); err != nil {
		if errors.Is(err, errNoManifest) {
			return nil, nil, m, err
		}
		return nil, nil, m, errors.New(T("update.err.fetch", err))
	}
	rawSig, err := httpGetSmall(ctx, base+updateManifestName+".sig")
	if err != nil {
		return nil, nil, m, errors.New(T("update.err.fetch", err))
	}
	if sig, err = verifyUpdateManifest(manifest, rawSig); err != nil {
		return nil, nil, m, err
	}
	if err := json.Unmarshal(manifest, &m); err != nil || parseVersion(m.Version) == nil {
		return nil, nil, m, errors.New(T("update.err.bad_manifest"))
	}
	return manifest, sig, m, nil
}

// verifyUpdateManifest checks a base64 ed25519 signature over manifest and
// returns the decoded signature.
func verifyUpdateManifest(manifest, rawSig []byte) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(updatePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New(T("update.err.no_key"))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, sig) {
		return nil, errors.New(T("update.err.signature"))
	}
	return sig, nil
}

func httpGetSmall(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Ingress/"+AppVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoManifest
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestSize {
		return nil, errors.New("too large")
	}
	return data, nil
}

// parseVersion parses "x.y.z" (an optional leading "v"); nil if malformed.
func parseVersion(v string) []int {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

// versionNewer reports whether a is a later version than b.
func versionNewer(a, b string) bool {
	va, vb := parseVersion(a), parseVersion(b)
	if va == nil || vb == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

// --- App bindings ---

func (a *App) GetUpdateStatus() UpdateStatus { return a.updater.Status() }

func (a *App) CheckForUpdates() UpdateStatus {
	a.updater.Check(a.ctx)
	return a.updater.Status()
}

func (a *App) SetUpdateCheck(on bool) error {
	if err := a.store.SetUpdateCheck(on); err != nil {
		return err
	}
	if on {
		select {
		case a.updater.kick <- struct{}{}:
		default:
		}
	}
	a.updater.emit()
	return nil
}

func (a *App) DismissUpdate() { a.updater.Dismiss() }

// InstallUpdate disconnects every profile first if asked to (the frontend
// confirms that with the user), then installs and relaunches.
func (a *App) InstallUpdate(disconnectFirst bool) error {
	if disconnectFirst {
		a.manager.DisconnectAll(30 * time.Second)
	}
	return a.updater.Install(a.ctx)
}
