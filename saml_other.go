//go:build !darwin

package main

import "errors"

// runSAMLWindow: the SAML login window is implemented for macOS only so far
// (saml_darwin.go). On Linux it needs a WebKitGTK window — see
// design/v2-plan.md, phase 5.
func runSAMLWindow(samlRequest) error {
	return errors.New("SAML-вход пока поддерживается только на macOS")
}
