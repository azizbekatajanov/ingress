//go:build darwin

package main

// Link flags for saml_darwin.m.

/*
#cgo LDFLAGS: -framework Cocoa -framework WebKit
*/
import "C"
