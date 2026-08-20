package main

import (
	"embed"
	"os"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
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
		OnStartup:     app.startup,
		OnBeforeClose: app.beforeClose,
		Bind: []interface{}{
			app,
		},
		Mac: &mac.Options{
			TitleBar: mac.TitleBarHidden(),
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
