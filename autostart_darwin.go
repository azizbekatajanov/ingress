package main

import (
	"errors"
	"os"
	"path/filepath"
)

// launchAgentDir is a variable for tests.
var launchAgentDir = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

func launchAgentPath() (string, error) {
	dir, err := launchAgentDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, launchAgentLabel+".plist"), nil
}

func launchAtLoginEnabled() bool {
	path, err := launchAgentPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// setLaunchAtLogin adds or removes the LaunchAgent. launchd reads it at the
// next login; nothing is started now.
func setLaunchAtLogin(on bool) error {
	path, err := launchAgentPath()
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
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return writeFileAtomic(path, launchAgentPlist(launchAgentArgs(exe)), 0o644)
}
