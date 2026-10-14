//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// Dispatched onto the main queue: OnDomReady (main.go) fires from one of
// Wails' own background message-processing goroutines, not the main thread
// — calling into AppKit window APIs directly from there crashes with
// "NSWindow geometry should only be modified on the main thread!"
// (NSInternalInconsistencyException), confirmed live via a crash log.
//
// Applies to every window in [NSApp windows], not just windows[0] — a
// WKWebView-based app can have more than one NSWindow instance at this
// point (WebKit's own helper/utility windows), and there's no guarantee
// the visible main window is first in that array. Grabbing windows[0]
// specifically risked flagging the wrong window, leaving the real one
// still ineligible for fullscreen and the green dot silently doing
// nothing — the actual bug this was rewritten to rule out.
//
// Also sets FullScreenDisallowsTiling: macOS Split View puts this window
// side-by-side with another app's in one shared fullscreen Space, and
// exiting it — via the green dot, the only control this frameless window
// has, since it has no native titlebar for AppKit's own hover-reveal exit
// affordance — leaves it broken every time: the window shrinks to the
// middle of the still-fullscreen Space with its vacated tile slot black,
// and the other app never returns to its own normal window either.
// Confirmed live this isn't about *how* the exit call is made — a bare
// native [window toggleFullScreen:nil], bypassing Wails' own exit path
// entirely, reproduced the exact same broken state. Whatever's actually
// wrong lives deeper in how AppKit negotiates a Split View tile's exit for
// a window with no native chrome — not something worth chasing further
// here. Solo fullscreen (this app's actual use case for the green dot)
// doesn't go through any of that negotiation and is unaffected; this just
// stops macOS from offering Ingress as a tiling candidate in the first
// place, so nobody can land in the broken state.
static void grantFullScreenPrimary(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (NSWindow *win in [NSApp windows]) {
            NSWindowCollectionBehavior behaviour = [win collectionBehavior];
            behaviour |= NSWindowCollectionBehaviorFullScreenPrimary;
            behaviour |= NSWindowCollectionBehaviorFullScreenDisallowsTiling;
            [win setCollectionBehavior:behaviour];
        }
    });
}
*/
import "C"

// enableWindowFullscreen grants this app's one window
// NSWindowCollectionBehaviorFullScreenPrimary, the flag AppKit requires
// before [window toggleFullScreen:] (what wailsRuntime.WindowFullscreen
// calls under the hood) will do anything at all.
//
// A normal titled+resizable NSWindow gets this automatically; a borderless
// one — which is what this app's Frameless: true (main.go) window actually
// is under the hood, despite looking titled thanks to the CSS-drawn traffic
// lights — does not. Wails only grants it itself when options.App.StartFullscreen
// is set (AppDelegate.m's applicationDidFinishLaunching, gated on
// self.startFullscreen — confirmed by reading Wails' vendored source), which
// doesn't apply here since the window shouldn't *start* fullscreen, just be
// able to *become* fullscreen later. Without this, the green dot's fullscreen
// toggle would silently no-op — this is why "no fullscreen mode" was true
// before this fix, not just a UI omission.
//
// Wired to OnDomReady (main.go), matching dockicon_darwin.go's hideDockIcon:
// needs the window to actually exist yet, which OnStartup's racing goroutine
// doesn't guarantee.
func enableWindowFullscreen() {
	C.grantFullScreenPrimary()
}
