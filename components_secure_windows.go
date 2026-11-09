//go:build windows

package main

import "errors"

func verifyRootOwned(paths []string) error {
	return errors.New("managed components are not supported on Windows yet")
}
