//go:build darwin || (linux && cgo)

package main

/*
#include <stdlib.h>

void saml_run(const char *title, const char *url, const char *html, const char *baseURL);
*/
import "C"

import (
	"os"
	"unsafe"
)

// The window itself is native code — saml_darwin.m (WKWebView) and
// saml_linux.c (WebKitGTK); it calls back into the exported functions
// below. The process exits from a callback once there's a result
// (or the window is closed), so saml_run never returns normally.

var samlState = newSAMLCollector()

func runSAMLWindow(req samlRequest) error {
	cstr := func(s string) *C.char {
		if s == "" {
			return nil
		}
		return C.CString(s)
	}
	title, url, html, base := cstr(req.Title), cstr(req.URL), cstr(req.HTML), cstr(req.BaseURL)
	defer func() {
		for _, p := range []*C.char{title, url, html, base} {
			if p != nil {
				C.free(unsafe.Pointer(p))
			}
		}
	}()
	C.saml_run(title, url, html, base)
	return nil
}

func samlFinishIfDone() {
	if r, done := samlState.result(); done {
		writeSAMLResult(r)
		os.Exit(0)
	}
}

//export samlGotHeaders
func samlGotHeaders(block *C.char) {
	samlState.addHeaders(C.GoString(block))
	samlFinishIfDone()
}

//export samlGotBody
func samlGotBody(html *C.char) {
	samlState.addBody(C.GoString(html))
	samlFinishIfDone()
}

//export samlGotCallback
func samlGotCallback(rawURL *C.char) {
	samlState.addCallback(C.GoString(rawURL))
	samlFinishIfDone()
}

//export samlWindowClosed
func samlWindowClosed() {
	writeSAMLResult(samlResult{Cancelled: true})
	os.Exit(0)
}

//export samlLoadFailed
func samlLoadFailed(msg *C.char) {
	writeSAMLResult(samlResult{Error: "не удалось открыть страницу входа: " + C.GoString(msg)})
	os.Exit(0)
}
