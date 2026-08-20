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
	header *systray.MenuItem
	items  map[string]*systray.MenuItem
}

func NewTray(app *App) *Tray {
	return &Tray{app: app, items: make(map[string]*systray.MenuItem)}
}

func (t *Tray) onReady() {
	systray.SetIcon(trayIconPlain)
	systray.SetTooltip("Ingress")

	t.header = systray.AddMenuItem("Ingress", "")
	t.header.Disable()
	systray.AddSeparator()

	// app.store/app.manager aren't ready yet at this point — RunWithExternalLoop's
	// start() runs before wails.Run() calls App.startup. Profile rows get
	// populated by the explicit OnProfilesChanged() call at the end of startup.

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
	if t.header == nil || t.app.store == nil {
		return // tray not ready yet, or called before onReady fired
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
			item.Click(func() { t.toggle(id) })
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
	if t.header == nil || t.app.store == nil || t.app.manager == nil {
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
