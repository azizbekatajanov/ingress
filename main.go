package main

import (
	"context"
	"embed"
	"os"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Hidden re-exec mode: `ingress --pty-exec <tool> <args...>`, used by
	// elevate_darwin.go to give the elevated openfortivpn process a real pty
	// (see ptyproxy_darwin.go for why). Must be checked before anything
	// Wails/systray-related runs, since this same .app binary gets invoked
	// again, as root, purely to proxy pty I/O — never to open a window.
	if len(os.Args) > 1 && os.Args[1] == "--pty-exec" {
		runPtyExec(os.Args[2:])
		return
	}

	app := NewApp()

	// RunWithExternalLoop (energye/systray) hands us start/end functions instead
	// of blocking in systray.Run — Wails' own window loop also wants the main
	// thread on macOS, and the two fighting over it is what makes the plain
	// getlantern/systray deadlock in a Wails app.
	tray := NewTray(app)
	app.tray = tray
	trayStart, trayEnd := systray.RunWithExternalLoop(tray.onReady, tray.onExit)
	trayStart()
	defer trayEnd()

	// Custom native app menu (top-left, next to the Apple logo) instead of
	// Wails' default menu.AppMenu() role: that role's "About" item is a
	// generic native NSAlert (see WailsMenu.m's -About), which looks jarring
	// stapled onto an otherwise fully custom-drawn UI — this "About Ingress"
	// item instead opens the same styled in-app modal as the tray's "О
	// программе" item and the sidebar's "Ingress" link. The tradeoff: the
	// AppMenu role's native "Hide Others"/"Show All" items (they invoke
	// NSApplication selectors no Wails API exposes) are dropped rather than
	// reimplemented — Hide/Quit cover the cases that matter here.
	ingressMenu := menu.NewMenu()
	ingressMenu.AddText("About Ingress", nil, func(_ *menu.CallbackData) {
		wailsRuntime.WindowShow(app.ctx)
		wailsRuntime.WindowUnminimise(app.ctx)
		wailsRuntime.EventsEmit(app.ctx, "about:show")
	})
	ingressMenu.AddSeparator()
	ingressMenu.AddText("Hide Ingress", keys.CmdOrCtrl("h"), func(_ *menu.CallbackData) {
		app.HideWindow()
	})
	ingressMenu.AddSeparator()
	ingressMenu.AddText("Quit Ingress", keys.CmdOrCtrl("q"), func(_ *menu.CallbackData) {
		wailsRuntime.Quit(app.ctx)
	})
	appMenu := menu.NewMenuFromItems(
		menu.SubMenu("Ingress", ingressMenu),
		menu.EditMenu(),
	)

	// Frameless, opaque window: the traffic-light dots and sidebar chrome are
	// drawn by the frontend CSS/JS (see frontend/src/style.css .window), not
	// native OS window chrome — the "single consistent custom look on every
	// platform" call from the design review.
	//
	// Deliberately NOT using a transparent window + CSS-rounded/shadowed
	// panel here, despite that being the design's original look: on macOS
	// that combination (WebviewIsTransparent + a smaller CSS panel centered
	// in a bigger transparent canvas) reliably produced black rendering
	// artifacts — either a solid frame (when WindowIsTranslucent was also
	// set, since that applies a dark vibrancy *material*, not plain
	// transparency) or black corner pixels where the panel's border-radius
	// clips right at the webview's own edge with no margin. Squared, opaque,
	// and exactly window-sized also happens to be what real resizing needs —
	// a fixed 1180x760 CSS panel floating in a resizable canvas doesn't grow
	// with the window.
	err := wails.Run(&options.App{
		Title:            "Ingress",
		Width:            1180,
		Height:           760,
		MinWidth:         900,
		MinHeight:        600,
		Frameless:        true,
		BackgroundColour: &options.RGBA{R: 245, G: 245, B: 247, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: app.startup,
		// See dockicon_darwin.go: must run after Wails' own launch sequence
		// has forced NSApplicationActivationPolicyRegular, which OnStartup
		// (fired from a goroutine racing that sequence) can't guarantee.
		OnDomReady:    func(ctx context.Context) { hideDockIcon() },
		OnBeforeClose: app.beforeClose,
		Bind: []interface{}{
			app,
		},
		Menu: appMenu,
		Mac: &mac.Options{
			TitleBar: mac.TitleBarHidden(),
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
