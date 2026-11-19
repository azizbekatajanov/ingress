//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// verifyRootOwned checks every path (no symlinks, owned by uid 0, not
// writable by group/other). Run before executing a managed binary as root:
// if anything along the chain could be modified without admin rights, a
// non-admin process could swap the binary and get root on the next connect.
func verifyRootOwned(paths []string) error {
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New(T("secure.symlink", p))
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errors.New(T("secure.not_root", p))
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return errors.New(T("secure.writable", p))
		}
	}
	return nil
}

// trustedExecPath resolves symlinks in p and checks the real file and every
// directory above it, up to /, with verifyRootOwned. It returns the resolved
// path, which is what must be executed: a symlink that sits in a
// user-writable directory can then be re-pointed after the check without
// effect on this run (and the next run checks again).
//
// This is what makes it safe to run a binary Ingress didn't install itself —
// a custom path from "Components", or one found on PATH — as root. Homebrew's
// /opt/homebrew/bin, for example, belongs to the user, so any process running
// as the user could swap a binary there and get root on the next connect.
func trustedExecPath(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(real) {
		return "", errors.New(T("comp.err.abs_path"))
	}
	var chain []string
	for d := real; ; d = filepath.Dir(d) {
		chain = append(chain, d)
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	if err := verifyRootOwned(chain); err != nil {
		return "", errors.New(T("comp.err.untrusted", err))
	}
	return real, nil
}
