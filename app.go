package main

import (
	"context"
	"errors"
	"log"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails-bound backend: every exported method here is callable
// from the frontend as window.go.main.App.<Method>(...).
type App struct {
	ctx           context.Context
	store         *ProfileStore
	manager       *Manager
	components    *ComponentManager
	tray          *Tray
	updater       *Updater
	quitConfirmed bool
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// main opens the store early (the tray and language need it before
	// Wails starts); tests and other callers may not have.
	if a.store == nil {
		store, err := NewProfileStore()
		if err != nil {
			log.Fatalf("ingress: failed to open profile store: %v", err)
		}
		a.store = store
	}
	store := a.store
	a.components = NewComponentManager(store)
	a.manager = NewManager(ctx, store, a.components)
	if a.tray != nil {
		a.manager.SetOnUpdate(a.tray.OnConnectionUpdate)
	}

	if len(store.List()) == 0 {
		if _, err := store.Add(ProfileTypeFortinet); err != nil {
			log.Printf("ingress: failed to create default profile: %v", err)
		}
	}

	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}

	a.updater = NewUpdater(a)
	go a.updater.run(ctx)
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

// AddProfile creates a profile of the given type (ProfileType*); the type
// can't be changed afterwards.
func (a *App) AddProfile(profileType string) (Profile, error) {
	p, err := a.store.Add(profileType)
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
	deleteLogo(id)
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

// GetI18n returns the catalog for the language in effect.
func (a *App) GetI18n() i18nBundle {
	return bundleFor(language(), a.store.Language())
}

// SetLanguage saves the choice ("" = follow the system), switches to it and
// tells the tray; the frontend re-renders from the returned catalog.
func (a *App) SetLanguage(setting string) (i18nBundle, error) {
	if setting != "" && !isSupportedLanguage(setting) {
		return i18nBundle{}, errors.New(T("err.unknown_language", setting))
	}
	if err := a.store.SetLanguage(setting); err != nil {
		return i18nBundle{}, err
	}
	setLanguage(resolveLanguage(setting))
	if a.tray != nil {
		a.tray.OnLanguageChanged()
	}
	if a.ctx != nil {
		wailsRuntime.MenuSetApplicationMenu(a.ctx, buildAppMenu(a))
		wailsRuntime.MenuUpdateApplicationMenu(a.ctx)
	}
	return a.GetI18n(), nil
}

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

// reportConnectError surfaces a Connect error that happened outside the
// window (tray menu) — e.g. the component isn't installed — instead of it
// being silently dropped.
func (a *App) reportConnectError(profileID string, err error) {
	wailsRuntime.WindowShow(a.ctx)
	wailsRuntime.WindowUnminimise(a.ctx)
	wailsRuntime.EventsEmit(a.ctx, "connect:error", map[string]string{"profileId": profileID, "message": err.Error()})
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

// SubmitPrompt answers a pending choice (e.g. the GlobalProtect gateway).
func (a *App) SubmitPrompt(profileID, value string) error {
	return a.manager.SubmitPrompt(profileID, value)
}

func (a *App) GetSnapshot(profileID string) ConnectionSnapshot {
	return a.manager.Snapshot(profileID)
}

// --- Components (openfortivpn / openconnect binaries, see components.go) ---

func (a *App) GetComponents() []ComponentStatus {
	return a.components.List()
}

// InstallComponent downloads and installs Ingress' own build of a component.
// Progress is pushed as "component:progress" events; "components:changed"
// fires when it finishes either way so every view refreshes.
func (a *App) InstallComponent(name string) error {
	defer wailsRuntime.EventsEmit(a.ctx, "components:changed")
	return a.components.Install(a.ctx, name, func(p ComponentProgress) {
		wailsRuntime.EventsEmit(a.ctx, "component:progress", p)
	})
}

func (a *App) RemoveComponent(name string) error {
	defer wailsRuntime.EventsEmit(a.ctx, "components:changed")
	return a.components.Remove(name)
}

func (a *App) SetComponentOverride(name, path string) error {
	defer wailsRuntime.EventsEmit(a.ctx, "components:changed")
	return a.components.SetOverride(name, path)
}

// --- File picker (for cert/key "Обзор…" fields) ---

func (a *App) BrowseFile(title string) (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{Title: title})
}

// --- Window controls (frameless window, custom-drawn traffic lights) ---

func (a *App) WindowMinimise() {
	wailsRuntime.WindowMinimise(a.ctx)
}

// WindowToggleFullscreen is what the green traffic-light dot calls — real
// macOS fullscreen (its own Space, exit via Esc or clicking the dot again),
// not just WindowToggleMaximise's resize-to-screen-bounds. Needs
// enableWindowFullscreen (main.go, fullscreen_darwin.go) to have already run
// once at startup — this window is borderless under the hood (Frameless:
// true), which doesn't get AppKit's usual automatic fullscreen eligibility.
func (a *App) WindowToggleFullscreen() {
	if wailsRuntime.WindowIsFullscreen(a.ctx) {
		wailsRuntime.WindowUnfullscreen(a.ctx)
	} else {
		wailsRuntime.WindowFullscreen(a.ctx)
	}
}

// HideWindow is what the red traffic-light dot calls — this app runs in the
// background via the tray (see tray.go), so closing the window must not exit
// the process. Only the tray's "Выход" item or Cmd+Q (native app menu, wired
// by Wails regardless of this custom frameless chrome) actually quits.
//
// Uses WindowHide, not WindowMinimise: Minimise leaves a genie-effect
// thumbnail parked in the Dock, which reads as "still an open window" —
// not what clicking "hide to tray" should look like. WindowHide is the
// real per-window macOS primitive ([mainWindow orderOut:nil] on the Wails
// side) — the window fully disappears, and WindowShow (makeKeyAndOrderFront
// + activate, wired to the tray's "Открыть Ingress" and to clicking the
// Dock icon) reliably brings it back.
//
// Reported live: clicking the red dot while the window was in real macOS
// fullscreen turned the whole screen black instead of hiding it. Root
// cause — orderOut: on a window that still occupies a fullscreen Space
// doesn't animate out of that Space first; the Space is left rendering
// nothing. Native apps avoid this because AppKit coordinates "exit
// fullscreen" and "close" as one transition when you close from fullscreen
// — we don't get that for free since this window is Frameless (custom-drawn
// traffic lights, no native close button for AppKit to hook). Unfullscreen
// first and poll WindowIsFullscreen until the exit transition has actually
// finished before hiding, rather than guessing a fixed delay.
func (a *App) HideWindow() {
	if wailsRuntime.WindowIsFullscreen(a.ctx) {
		go func() {
			wailsRuntime.WindowUnfullscreen(a.ctx)
			for i := 0; i < 40 && wailsRuntime.WindowIsFullscreen(a.ctx); i++ {
				time.Sleep(25 * time.Millisecond)
			}
			wailsRuntime.WindowHide(a.ctx)
		}()
		return
	}
	wailsRuntime.WindowHide(a.ctx)
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
