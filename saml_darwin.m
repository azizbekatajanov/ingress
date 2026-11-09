//go:build darwin

// SAML login window for GlobalProtect (see saml.go / saml_darwin.go).
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#include "_cgo_export.h"

// A borderless-chromed app with no main menu doesn't get the standard
// editing shortcuts, so Cmd+V into the IdP's password field would do
// nothing. Route the usual key equivalents to the first responder.
@interface SAMLWindow : NSWindow
@end

@implementation SAMLWindow
- (BOOL)performKeyEquivalent:(NSEvent *)event {
    if ((event.modifierFlags & NSEventModifierFlagDeviceIndependentFlagsMask) == NSEventModifierFlagCommand) {
        NSString *k = event.charactersIgnoringModifiers;
        SEL action = NULL;
        if ([k isEqualToString:@"x"]) action = @selector(cut:);
        else if ([k isEqualToString:@"c"]) action = @selector(copy:);
        else if ([k isEqualToString:@"v"]) action = @selector(paste:);
        else if ([k isEqualToString:@"a"]) action = @selector(selectAll:);
        else if ([k isEqualToString:@"z"]) action = @selector(undo:);
        else if ([k isEqualToString:@"w"]) { [self performClose:nil]; return YES; }
        if (action && [NSApp sendAction:action to:nil from:self]) return YES;
    }
    return [super performKeyEquivalent:event];
}
@end

@interface SAMLDelegate : NSObject <WKNavigationDelegate, NSWindowDelegate>
@end

@implementation SAMLDelegate

// Portals set to "use default browser for SAML" finish by navigating to
// globalprotectcallback:<data>; catch it instead of failing on the scheme.
- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                    decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSURL *url = navigationAction.request.URL;
    if ([[url.scheme lowercaseString] isEqualToString:@"globalprotectcallback"]) {
        decisionHandler(WKNavigationActionPolicyCancel);
        samlGotCallback((char *)[url.absoluteString UTF8String]);
        return;
    }
    decisionHandler(WKNavigationActionPolicyAllow);
}

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationResponse:(WKNavigationResponse *)navigationResponse
                      decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler {
    if ([navigationResponse.response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSDictionary *headers = ((NSHTTPURLResponse *)navigationResponse.response).allHeaderFields;
        NSMutableString *block = [NSMutableString string];
        for (id key in headers) {
            [block appendFormat:@"%@: %@\n", key, headers[key]];
        }
        samlGotHeaders((char *)[block UTF8String]);
    }
    decisionHandler(WKNavigationResponsePolicyAllow);
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    // The result can also arrive as tags inside an HTML comment on the
    // final page; outerHTML keeps comments.
    [webView evaluateJavaScript:@"document.documentElement.outerHTML"
              completionHandler:^(id result, NSError *error) {
        if ([result isKindOfClass:[NSString class]]) {
            samlGotBody((char *)[(NSString *)result UTF8String]);
        }
    }];
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    // -999 is a navigation cancelled by the next one (IdP redirects) — not a failure.
    if (error.code == NSURLErrorCancelled) return;
    // A failed load before anything was shown leaves an empty window with
    // no way forward; report it instead.
    if (webView.URL == nil || webView.backForwardList.currentItem == nil) {
        samlLoadFailed((char *)[error.localizedDescription UTF8String]);
    }
}

- (void)windowWillClose:(NSNotification *)notification {
    samlWindowClosed();
}

@end

static SAMLDelegate *samlDelegate; // the window/web view don't retain their delegates

void saml_run(const char *title, const char *url, const char *html, const char *baseURL) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        // No Dock icon of its own: it's a helper window of Ingress.
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        NSRect frame = NSMakeRect(0, 0, 520, 700);
        SAMLWindow *window = [[SAMLWindow alloc]
            initWithContentRect:frame
                      styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                 NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable)
                        backing:NSBackingStoreBuffered
                          defer:NO];
        window.title = title ? @(title) : @"Вход";
        window.releasedWhenClosed = NO;

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        // Persistent store: the IdP session survives between logins, so a
        // reconnect usually doesn't ask for the password/MFA again.
        config.websiteDataStore = [WKWebsiteDataStore defaultDataStore];
        WKWebView *webView = [[WKWebView alloc] initWithFrame:frame configuration:config];
        // Some IdPs refuse "embedded browser" user agents; present as Safari.
        webView.customUserAgent = @"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

        samlDelegate = [[SAMLDelegate alloc] init];
        webView.navigationDelegate = samlDelegate;
        window.delegate = samlDelegate;
        window.contentView = webView;

        if (url) {
            [webView loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@(url)]]];
        } else if (html) {
            [webView loadHTMLString:@(html) baseURL:(baseURL ? [NSURL URLWithString:@(baseURL)] : nil)];
        }

        [window center];
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
    }
}
