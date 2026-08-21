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
static void grantFullScreenPrimary(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSArray<NSWindow *> *windows = [NSApp windows];
        if (windows.count == 0) {
            return;
        }
        NSWindow *win = windows[0];
        NSWindowCollectionBehavior behaviour = [win collectionBehavior];
        behaviour |= NSWindowCollectionBehaviorFullScreenPrimary;
        [win setCollectionBehavior:behaviour];
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
