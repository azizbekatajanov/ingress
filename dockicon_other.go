//go:build !darwin

package main

// hideDockIcon is a no-op outside macOS — Dock/taskbar presence isn't the
// same concept on Windows/Linux, and this app doesn't attempt to hide its
// taskbar entry there.
func hideDockIcon() {}
