//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>

// Reported live: HideWindow (app.go's red dot — plain orderOut:, not even
// via fullscreen) leaves the window hidden with no way back via the Dock
// icon — clicking it does nothing. tray.go's own "Открыть Ingress" already
// works, because that's a Go click handler explicitly calling
// wailsRuntime.WindowShow; the Dock icon goes through AppKit's own path
// instead — it asks the app delegate
// -applicationShouldHandleReopen:hasVisibleWindows: (called whenever the
// user clicks a running app's Dock icon, independent of whether the app
// is already active — confirmed this is the right hook; the real failure
// was in how it got installed, see below), and Wails' own AppDelegate
// (internal/frontend/desktop/darwin/AppDelegate.m, confirmed by reading
// Wails' vendored source) doesn't implement that selector at all.
//
// First attempt was an Objective-C Category directly on Wails'
// AppDelegate class — that failed to even link
// ("_OBJC_CLASS_$_AppDelegate" undefined), meaning that class's metadata
// isn't visible for a separately-compiled cgo translation unit to
// reference by name at compile time. Second attempt observed
// NSApplicationDidBecomeActiveNotification instead, sidestepping the
// class reference entirely — but that notification only fires on an
// actual inactive→active *transition*; clicking the Dock icon while
// Ingress hadn't lost active status (nothing else had been activated in
// between) never triggers one, reproducing the exact bug report again.
//
// This instead patches the method onto the delegate's real class at
// runtime, via [NSApp delegate] and objc/runtime.h's class_addMethod —
// no compile-time name/symbol dependency on Wails' class at all, since
// everything here is resolved dynamically off the live object Wails
// already created. Only adds it if not already present (defensive, in
// case a future Wails version implements this itself).
static BOOL reopenHiddenWindow(id self, SEL _cmd, NSApplication *sender, BOOL hasVisibleWindows) {
    if (!hasVisibleWindows) {
        for (NSWindow *win in [NSApp windows]) {
            if ([win.title isEqualToString:@"Ingress"]) {
                [win makeKeyAndOrderFront:nil];
                break;
            }
        }
    }
    [NSApp activateIgnoringOtherApps:YES];
    return YES;
}

static void installReopenHandler(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        id delegate = [NSApp delegate];
        if (delegate == nil) {
            return;
        }
        SEL sel = @selector(applicationShouldHandleReopen:hasVisibleWindows:);
        if ([delegate respondsToSelector:sel]) {
            return;
        }
        class_addMethod([delegate class], sel, (IMP)reopenHiddenWindow, "c@:@c");
    });
}
*/
import "C"

// registerReopenOnActivate is wired to OnDomReady (main.go), matching
// enableWindowFullscreen — needs Wails' own delegate to already exist,
// which OnStartup's racing goroutine doesn't guarantee.
func registerReopenOnActivate() {
	C.installReopenHandler()
}
