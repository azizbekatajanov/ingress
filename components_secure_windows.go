//go:build windows

package main

import "errors"

func verifyRootOwned(paths []string) error {
	return errors.New("managed components are not supported on Windows yet")
}

// trustedExecPath: nothing runs elevated on Windows yet (see
// elevate_windows.go), so there's nothing to check.
func trustedExecPath(p string) (string, error) { return p, nil }
