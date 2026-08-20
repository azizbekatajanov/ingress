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

//go:embed assets/tray/dot-connected.png
var dotConnected []byte

//go:embed assets/tray/dot-none.png
var dotNone []byte

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

	t.mu.Lock()
	t.ready = true
	t.mu.Unlock()
	// app.store/app.manager aren't ready yet at this point — RunWithExternalLoop's
	// start() runs before wails.Run() calls App.startup, so this first build is
	// typically just the static section (profiles come from App.startup's own
	// OnProfilesChanged() call once the store exists — whichever of the two
	// finishes last is the one that actually renders the profile rows;
	// confirmed live via a debug print that this ordering isn't guaranteed).
	t.rebuildMenu()

	// energye/systray never attaches the NSMenu to the status item's button
	// on its own on macOS (see systray_darwin.m's add_or_update_menu_item —
	// its create_menu() call is commented out) — without this, the icon
	// looks clickable but nothing happens, confirmed live via Accessibility
	// inspection (the status item reported zero attached menus).
	systray.CreateMenu()
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

// rebuildMenu replaces the tray's entire menu contents in one pass: profile
// rows grouped in their own section at the top (each toggle-clickable, with
// a green dot when connected), then a separator, then the fixed
// header/Открыть/О программе/Выход section.
//
// energye/systray has no insert-before or reorder API on macOS — AddMenuItem
// only ever appends to the end of the live NSMenu — so profile rows added
// incrementally (the previous approach) always landed after Выход, wherever
// they happened to be appended, instead of grouped up top. ResetMenu() +
// rebuilding from scratch on every profile-list change is what actually
// guarantees the intended order regardless of how many times it changes.
func (t *Tray) rebuildMenu() {
	t.mu.Lock()
	defer t.mu.Unlock()

	systray.ResetMenu()
	t.items = make(map[string]*systray.MenuItem)

	if t.app.store != nil {
		profiles := t.app.store.List()
		for _, p := range profiles {
			id := p.ID
			item := systray.AddMenuItem(p.Name, "")
			// Must not call t.toggle synchronously here: a native NSMenuItem
			// click runs on the main thread, inside NSMenu's own nested
			// tracking run loop — and t.toggle can reach Manager.Connect,
			// which blocks on AuthorizationExecuteWithPrivileges (a raw
			// Security.framework cgo call that pops a native auth dialog).
			// Driving that modal prompt from inside another native run loop
			// segfaulted AppKit, confirmed live via a crash log (SIGSEGV
			// inside RunMainLoop right after a tray row's "Подключение к
			// ..." log line). The in-window Connect button doesn't have this
			// problem because it arrives via Wails' own bindings goroutine,
			// never the raw main thread.
			item.Click(func() { go t.toggle(id) })
			t.items[id] = item
		}
		if len(profiles) > 0 {
			systray.AddSeparator()
		}
	}

	t.header = systray.AddMenuItem("Не подключено", "")
	t.header.Disable()
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

	// Rebuilding wiped any previous status text/icon — restore it from
	// current connection state for every row that has one.
	for id := range t.items {
		t.refreshItemLocked(id)
	}
	t.refreshHeaderLocked()
}

// refreshItemLocked updates one profile row's title and status dot from its
// live connection state. Cheap enough to call on every connection tick
// (once a second while connected, see Manager.tick) — unlike rebuildMenu,
// it mutates the existing NSMenuItem in place rather than tearing down and
// recreating the whole menu.
func (t *Tray) refreshItemLocked(profileID string) {
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
	case StatusConnecting:
		title += " — подключение…"
	case StatusOtp:
		title += " — код…"
	}
	item.SetTitle(title)
	if snap.Status == StatusConnected {
		item.SetIcon(dotConnected)
	} else {
		item.SetIcon(dotNone)
	}
}

func (t *Tray) refreshHeaderLocked() {
	if t.header == nil || t.app.store == nil || t.app.manager == nil {
		return
	}
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

// OnProfilesChanged is called by App after AddProfile/RemoveProfile/UpdateProfile,
// and once at startup once app.store exists.
func (t *Tray) OnProfilesChanged() {
	t.mu.Lock()
	ready := t.ready
	t.mu.Unlock()
	if !ready || t.app.store == nil {
		return // tray not ready yet, or called before App.startup set up the store
	}
	t.rebuildMenu()
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
	t.refreshItemLocked(snap.ProfileID)
	t.refreshHeaderLocked()
}
