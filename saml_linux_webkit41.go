//go:build linux && cgo && webkit2_41

package main

// saml_linux.c links against the same WebKitGTK as Wails: 4.1 with the
// webkit2_41 tag (what CI builds on Ubuntu 24.04), 4.0 otherwise.

/*
#cgo pkg-config: gtk+-3.0 webkit2gtk-4.1
*/
import "C"
