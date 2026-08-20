package main

import (
	"context"
	"log"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails-bound backend: every exported method here is callable
// from the frontend as window.go.main.App.<Method>(...).
type App struct {
	ctx           context.Context
	store         *ProfileStore
	manager       *Manager
	tray          *Tray
	quitConfirmed bool
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	store, err := NewProfileStore()
	if err != nil {
		log.Fatalf("ingress: failed to open profile store: %v", err)
	}
	a.store = store
	a.manager = NewManager(ctx, store)
	if a.tray != nil {
		a.manager.SetOnUpdate(a.tray.OnConnectionUpdate)
	}

	if len(store.List()) == 0 {
		if _, err := store.Add(); err != nil {
			log.Printf("ingress: failed to create default profile: %v", err)
		}
	}

	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}
}

// --- Profiles ---

func (a *App) GetProfiles() []Profile {
	return a.store.List()
}

func (a *App) GetSelectedProfileID() string {
	return a.store.SelectedID()
}

func (a *App) SelectProfile(id string) error {
	return a.store.SetSelectedID(id)
}

func (a *App) AddProfile() (Profile, error) {
	p, err := a.store.Add()
	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}
	return p, err
}

func (a *App) UpdateProfile(p Profile) error {
	err := a.store.Update(p)
	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}
	return err
}

func (a *App) RemoveProfile(id string) error {
	if len(a.store.List()) <= 1 {
		return nil
	}
	_ = a.manager.CancelConnect(id)
	if err := DeletePassword(id); err != nil {
		log.Printf("ingress: failed to delete keychain entry for %s: %v", id, err)
	}
	err := a.store.Remove(id)
	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}
	return err
}

// --- Credentials ---

func (a *App) GetPassword(profileID string) (string, error) {
	return LoadPassword(profileID)
}

func (a *App) SetPassword(profileID, password string) error {
	return SavePassword(profileID, password)
}

// --- Theme ---

func (a *App) GetTheme() string {
	return a.store.Theme()
}

func (a *App) SetTheme(theme string) error {
	return a.store.SetTheme(theme)
}

// --- Connections ---

func (a *App) Connect(profileID string) error {
	return a.manager.Connect(profileID)
}

func (a *App) Disconnect(profileID string) error {
	return a.manager.Disconnect(profileID)
}

func (a *App) CancelConnect(profileID string) error {
	return a.manager.CancelConnect(profileID)
}

func (a *App) SubmitOtp(profileID, code string) error {
	return a.manager.SubmitOtp(profileID, code)
}

func (a *App) GetSnapshot(profileID string) ConnectionSnapshot {
	return a.manager.Snapshot(profileID)
}

// --- openfortivpn install/version ---

func (a *App) CheckOpenfortivpn() BinaryStatus {
	return CheckOpenfortivpn()
}

func (a *App) InstallOpenfortivpn() error {
	return InstallOpenfortivpnViaBrew()
}

// --- File picker (for cert/key "Обзор…" fields) ---

func (a *App) BrowseFile(title string) (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{Title: title})
}

// --- Window controls (frameless window, custom-drawn traffic lights) ---

func (a *App) WindowMinimise() {
	wailsRuntime.WindowMinimise(a.ctx)
}

func (a *App) WindowToggleMaximise() {
	wailsRuntime.WindowToggleMaximise(a.ctx)
}

// HideWindow is what the red traffic-light dot calls — this app runs in the
// background via the tray (see tray.go), so closing the window must not exit
// the process. Only the tray's "Выход" item or Cmd+Q (native app menu, wired
// by Wails regardless of this custom frameless chrome) actually quits.
//
// Uses Minimise rather than Hide: on macOS, WindowHide maps to "hide the
// whole application" (like Cmd+H) rather than just this window, and didn't
// reliably come back via WindowShow from the tray. Minimise/Unminimise is
// the better-documented, more predictable pair for this pattern.
func (a *App) HideWindow() {
	wailsRuntime.WindowMinimise(a.ctx)
}

// --- Quit confirmation ---
//
// OnBeforeClose (wired in main.go) routes *every* quit path through
// beforeClose below — Cmd+Q, the Dock's Quit, and the tray's "Выход" item all
// call the same underlying runtime.Quit(), which Wails checks against
// OnBeforeClose before actually closing (confirmed by reading Wails' own
// darwin frontend source, not assumed) — so one hook covers all of them.

func (a *App) beforeClose(ctx context.Context) bool {
	if a.quitConfirmed || a.store.SkipQuitConfirm() {
		return false // don't prevent — let it quit
	}
	wailsRuntime.WindowShow(a.ctx)
	wailsRuntime.WindowUnminimise(a.ctx)
	wailsRuntime.EventsEmit(a.ctx, "quit:confirm")
	return true // prevent this attempt; frontend shows the confirm modal
}

// ConfirmQuit is called by the frontend's quit-confirmation modal. Calling
// runtime.Quit() again re-enters beforeClose, which now allows it through
// since quitConfirmed is set.
func (a *App) ConfirmQuit(rememberChoice bool) {
	if rememberChoice {
		if err := a.store.SetSkipQuitConfirm(true); err != nil {
			log.Printf("ingress: failed to save skip-quit-confirm preference: %v", err)
		}
	}
	a.quitConfirmed = true
	wailsRuntime.Quit(a.ctx)
}
