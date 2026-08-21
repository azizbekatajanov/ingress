//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// Dispatched onto the main queue for the same reason fullscreen_darwin.go's
// grantFullScreenPrimary is: OnDomReady (main.go) fires from a background
// goroutine, not the main thread, and AppKit calls that touch window/app
// UI state from off the main thread are a reliable way to crash — confirmed
// live for the fullscreen case (NSInternalInconsistencyException), so this
// one is dispatched too rather than relying on setActivationPolicy: happening
// not to hit the same assertion.
static void setAccessoryActivationPolicy(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        // Without this, the app *looks* frontmost (its name shows in the
        // menu bar, its window is key) but the native "Ingress"/"Edit" menu
        // bar items don't respond to clicks — until something else forces
        // AppKit to re-evaluate activation, e.g. toggling fullscreen.
        // Reported live: the menu was dead on launch, started working only
        // after entering and leaving fullscreen once. Switching
        // activationPolicy on an already-running, already-activated app is
        // a known rough edge — AppKit's internal notion of "the active app"
        // doesn't automatically get refreshed for the new policy, so the
        // menu bar stays wired to stale state. Re-activating right after
        // the policy change forces that refresh immediately instead of
        // waiting for an unrelated transition to trigger it.
        [NSApp activateIgnoringOtherApps:YES];
    });
}
*/
import "C"

// hideDockIcon demotes this process from a regular foreground app to a
// background/accessory one — no Dock icon, no Cmd+Tab entry, matching how
// menu-bar-only utilities behave. build/darwin/Info.plist already declares
// LSUIElement for this, but Wails ignores it: AppDelegate.m's
// applicationWillFinishLaunching unconditionally calls
// [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular] on every
// launch regardless of the bundle's own Info.plist (confirmed by reading
// Wails' vendored source, not assumed). This must run *after* that reset,
// so it's wired to OnDomReady (main.go) rather than App.startup — OnStartup
// fires from a goroutine racing the native launch sequence and can easily
// run before applicationWillFinishLaunching, which would just get
// overwritten a moment later; OnDomReady only fires once the webview has
// actually finished loading, well past Cocoa's early launch callbacks.
func hideDockIcon() {
	C.setAccessoryActivationPolicy()
}
