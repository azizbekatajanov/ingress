//go:build !darwin && !(linux && cgo)

package main

import "errors"

// runSAMLWindow: no native SAML window on this platform/build (Windows, or
// a Linux build without cgo — which Wails can't produce anyway).
func runSAMLWindow(samlRequest) error {
	return errors.New(T("saml.err.unsupported"))
}
