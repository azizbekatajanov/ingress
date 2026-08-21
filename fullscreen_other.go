//go:build !darwin

package main

// enableWindowFullscreen is a no-op outside macOS — Windows/Linux windows
// don't need an extra native flag before wailsRuntime.WindowFullscreen works.
func enableWindowFullscreen() {}
