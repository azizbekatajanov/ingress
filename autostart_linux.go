package main

import (
	"errors"
	"os"
	"path/filepath"
)

func autostartPath() (string, error) {
	dir, err := os.UserConfigDir() // $XDG_CONFIG_HOME or ~/.config
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autostart", autostartEntryName), nil
}

func launchAtLoginEnabled() bool {
	path, err := autostartPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func setLaunchAtLogin(on bool) error {
	path, err := autostartPath()
	if err != nil {
		return err
	}
	if !on {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, desktopEntry(exe), 0o644)
}
