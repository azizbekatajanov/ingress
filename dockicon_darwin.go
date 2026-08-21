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
