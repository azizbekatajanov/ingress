//go:build !devmanifest

package main

import "fmt"

func activeManifest() componentManifest { return builtinManifest }

func devManifestArgs() []string { return nil }

// rootManifest is what the elevated installer trusts. Release builds accept
// no extra arguments at all: the expected sha256 always comes from the
// compiled-in manifest, never from the (unprivileged) caller.
func rootManifest(extra []string) (componentManifest, error) {
	if len(extra) != 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", extra)
	}
	return builtinManifest, nil
}
