//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// homebrewPathDirs are the bin/sbin directories Homebrew installs into.
// Checking both Apple Silicon's and Intel's locations costs nothing and
// covers a Rosetta-installed Homebrew alongside a native one.
var homebrewPathDirs = []string{
	"/opt/homebrew/bin", // Apple Silicon
	"/opt/homebrew/sbin",
	"/usr/local/bin", // Intel
	"/usr/local/sbin",
}

// augmentPATH prepends Homebrew's install locations to PATH if they exist
// and aren't already on it.
//
// A GUI-launched app (double-click, Dock, `open`, or — what this was
// actually diagnosed from — a freshly DMG-installed app opened normally)
// inherits launchd's bare PATH (/usr/bin:/bin:/usr/sbin:/sbin), not the
// shell's PATH from .zshrc/.zprofile that adds Homebrew's `brew shellenv`.
// Since v2 the only exec.LookPath left is ComponentManager's fallback to a
// system (typically Homebrew) binary for users upgrading from 1.0.x — the
// managed and override binaries are absolute paths. In 1.0.x every lookup
// (the brew install button, elevatedCommand) silently failed to find
// openfortivpn/brew as a result — worked fine every time this
// was run directly from a Terminal during development (which does have that
// PATH), which is exactly why this went unnoticed until testing a real
// `open`-launched, DMG-installed copy (confirmed live: "openfortivpn не
// найден" even though it was actually installed).
func augmentPATH() {
	current := os.Getenv("PATH")
	existing := make(map[string]bool)
	for _, dir := range filepath.SplitList(current) {
		existing[dir] = true
	}

	var toAdd []string
	for _, dir := range homebrewPathDirs {
		if existing[dir] {
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		toAdd = append(toAdd, dir)
	}
	if len(toAdd) == 0 {
		return
	}
	os.Setenv("PATH", strings.Join(toAdd, string(os.PathListSeparator))+string(os.PathListSeparator)+current)
}
