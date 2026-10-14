//go:build !darwin

package main

// registerReopenOnActivate is a no-op outside macOS — Windows/Linux task
// bar icons already restore a hidden window on click without this.
func registerReopenOnActivate() {}
