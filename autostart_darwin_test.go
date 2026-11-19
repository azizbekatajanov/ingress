package main

import (
	"os"
	"strings"
	"testing"
)

func TestLaunchAtLoginDarwin(t *testing.T) {
	dir := t.TempDir()
	prev := launchAgentDir
	launchAgentDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { launchAgentDir = prev })

	if launchAtLoginEnabled() {
		t.Fatal("enabled before anything was written")
	}
	if err := setLaunchAtLogin(true); err != nil {
		t.Fatal(err)
	}
	if !launchAtLoginEnabled() {
		t.Fatal("not enabled after setLaunchAtLogin(true)")
	}
	path, _ := launchAgentPath()
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), hiddenArg) || !strings.Contains(string(data), "<key>RunAtLoad</key>") {
		t.Errorf("plist = %s (%v)", data, err)
	}
	if err := setLaunchAtLogin(false); err != nil || launchAtLoginEnabled() {
		t.Errorf("disable: %v, still enabled = %v", err, launchAtLoginEnabled())
	}
	if err := setLaunchAtLogin(false); err != nil {
		t.Errorf("disabling twice: %v", err)
	}
}
