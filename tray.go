package main

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/energye/systray"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed assets/tray/icon.png
var trayIconPlain []byte

//go:embed assets/tray/icon-connected.png
var trayIconConnected []byte

// Tray mirrors design screen #13 (menu bar tray icon + popover): a blue
// rounded-square icon with a green dot badge when anything is connected, and
// one menu row per profile with an inline connect/disconnect action.
//
// Built on energye/systray's RunWithExternalLoop, which is the fork of
// getlantern/systray that actually works alongside another GUI toolkit's
// main loop — the plain getlantern/systray fights Wails for the macOS main
// thread and deadlocks on startup.
type Tray struct {
	app    *App
	mu     sync.Mutex
	ready  bool
	header *systray.MenuItem
	items  map[string]*systray.MenuItem
}

func NewTray(app *App) *Tray {
	return &Tray{app: app, items: make(map[string]*systray.MenuItem)}
}

func (t *Tray) onReady() {
	systray.SetIcon(trayIconPlain)
	systray.SetTooltip("Ingress")

	t.header = systray.AddMenuItem("Не подключено", "")
	t.header.Disable()
	systray.AddSeparator()

	// app.store/app.manager aren't ready yet at this point — RunWithExternalLoop's
	// start() runs before wails.Run() calls App.startup. Profile rows get
	// populated below once t.ready flips true, or by App.startup's own
	// OnProfilesChanged() call — whichever of the two finishes last.

	systray.AddSeparator()
	openItem := systray.AddMenuItem("Открыть Ingress", "")
	openItem.Click(func() {
		wailsRuntime.WindowShow(t.app.ctx)
		wailsRuntime.WindowUnminimise(t.app.ctx)
	})
	aboutItem := systray.AddMenuItem("О программе", "")
	aboutItem.Click(func() {
		wailsRuntime.WindowShow(t.app.ctx)
		wailsRuntime.WindowUnminimise(t.app.ctx)
		wailsRuntime.EventsEmit(t.app.ctx, "about:show")
	})
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("Выход", "")
	quitItem.Click(func() {
		wailsRuntime.Quit(t.app.ctx)
	})

	// energye/systray never attaches the NSMenu to the status item's button
	// on its own on macOS (see systray_darwin.m's add_or_update_menu_item —
	// its create_menu() call is commented out) — without this, the icon
	// looks clickable but nothing happens, confirmed live via Accessibility
	// inspection (the status item reported zero attached menus). Safe to call
	// once here even though profile rows are still appended later by
	// OnProfilesChanged: those calls add items to the same underlying NSMenu
	// object, which stays attached.
	systray.CreateMenu()

	t.mu.Lock()
	t.ready = true
	t.mu.Unlock()
	// Covers the ordering where App.startup's own OnProfilesChanged() call
	// (App.startup, near the end) already ran and bailed out because onReady
	// hadn't set t.header yet — confirmed live via a debug print, this isn't
	// hypothetical: on a real launch, RunWithExternalLoop's start() (called
	// synchronously in main(), before wails.Run()) does NOT guarantee this
	// callback has finished by the time wails.Run()'s OnStartup goroutine
	// gets to calling it. Without this second call, profile rows would
	// silently never appear — there's no later trigger for a fresh launch
	// where the profile list never actually changes.
	t.OnProfilesChanged()
}

func (t *Tray) onExit() {}

func (t *Tray) toggle(profileID string) {
	if t.app.manager == nil {
		return
	}
	snap := t.app.manager.Snapshot(profileID)
	if snap.Status == StatusDisconnected {
		_ = t.app.manager.Connect(profileID)
	} else {
		_ = t.app.manager.Disconnect(profileID)
	}
}

func (t *Tray) refreshItemTitleLocked(profileID string) {
	item, ok := t.items[profileID]
	if !ok || t.app.store == nil || t.app.manager == nil {
		return
	}
	p, ok := t.app.store.Get(profileID)
	if !ok {
		return
	}
	snap := t.app.manager.Snapshot(profileID)
	title := p.Name
	switch snap.Status {
	case StatusConnected:
		title += " — подключено"
	case StatusConnecting:
		title += " — подключение…"
	case StatusOtp:
		title += " — код…"
	}
	item.SetTitle(title)
}

// OnProfilesChanged is called by App after AddProfile/RemoveProfile/UpdateProfile,
// and once at startup once app.store exists.
func (t *Tray) OnProfilesChanged() {
	t.mu.Lock()
	ready := t.ready
	t.mu.Unlock()
	if !ready || t.app.store == nil {
		return // tray not ready yet, or called before App.startup set up the store
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	seen := make(map[string]bool)
	for _, p := range t.app.store.List() {
		seen[p.ID] = true
		item, ok := t.items[p.ID]
		if !ok {
			id := p.ID
			item = systray.AddMenuItem(p.Name, "")
			// Must not call t.toggle synchronously here: a native NSMenuItem
			// click runs on the main thread, inside NSMenu's own nested
			// tracking run loop — and t.toggle can reach Manager.Connect,
			// which blocks on AuthorizationExecuteWithPrivileges (a raw
			// Security.framework cgo call that pops a native auth dialog).
			// Driving that modal prompt from inside another native run
			// loop segfaulted AppKit, confirmed live via a crash log
			// (SIGSEGV inside RunMainLoop right after a tray row's
			// "Подключение к ..." log line). The in-window Connect button
			// doesn't have this problem because it arrives via Wails' own
			// bindings goroutine, never the raw main thread.
			item.Click(func() { go t.toggle(id) })
			t.items[id] = item
		}
		item.Show()
		t.refreshItemTitleLocked(p.ID)
	}
	for id, item := range t.items {
		if !seen[id] {
			item.Hide()
		}
	}
}

// OnConnectionUpdate is wired into Manager as its update hook, called on every
// connect/disconnect/log state change for any profile.
func (t *Tray) OnConnectionUpdate(snap ConnectionSnapshot) {
	t.mu.Lock()
	ready := t.ready
	t.mu.Unlock()
	if !ready || t.app.store == nil || t.app.manager == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refreshItemTitleLocked(snap.ProfileID)

	var connectedNames []string
	for _, p := range t.app.store.List() {
		if t.app.manager.Snapshot(p.ID).Status == StatusConnected {
			connectedNames = append(connectedNames, p.Name)
		}
	}
	if len(connectedNames) > 0 {
		systray.SetIcon(trayIconConnected)
		t.header.SetTitle("Подключено: " + strings.Join(connectedNames, ", "))
	} else {
		systray.SetIcon(trayIconPlain)
		t.header.SetTitle("Не подключено")
	}
}
