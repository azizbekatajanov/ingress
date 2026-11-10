//go:build !windows

package main

import (
	"errors"
	"os"
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
