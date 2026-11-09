//go:build linux && cgo && !webkit2_41

package main

// See saml_linux_webkit41.go.

/*
#cgo pkg-config: gtk+-3.0 webkit2gtk-4.0
*/
import "C"
