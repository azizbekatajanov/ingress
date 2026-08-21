//go:build !darwin

package main

// augmentPATH is a no-op outside macOS. Linux app launchers (.desktop
// files) typically inherit a full session PATH already, and Windows has no
// Homebrew-equivalent fixed install location to guess at.
func augmentPATH() {}
