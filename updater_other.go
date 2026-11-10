//go:build !darwin

package main

import (
	"context"
	"errors"
)

// Linux: apt owns /usr/bin/ingress (and the .tar.gz build is unpacked
// wherever the user chose), Windows: an installer — the banner links to
// the release instead.
func selfUpdateBlocker(hasAsset bool) string { return T("update.block.manual") }

func installUpdate(ctx context.Context, manifest, sig []byte, m updateManifest, progress func(done, total int64), installing func()) error {
	return errors.New(T("update.block.manual"))
}

func relaunchSelf() error { return errors.New(T("update.block.manual")) }

func isRootUpdateCommand(string) bool { return false }

func runRootUpdateCommand([]string) int { return 1 }
