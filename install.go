package main

import (
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type BinaryStatus struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	// Warning is set when the installed version is a known-bad one (e.g.
	// openfortivpn 1.21+ fails to bring the tunnel up on macOS Sonoma —
	// see adrienverge/openfortivpn#1165, marked wontfix upstream).
	Warning string `json:"warning"`
}

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// knownBadVersions maps a version string prefix to a human warning. Checked
// with strings.HasPrefix, so "1.21" also flags "1.21.0", "1.21.1", etc.
var knownBadVersions = map[string]string{
	"1.21": "openfortivpn 1.21+ не поднимает туннель на macOS Sonoma (issue #1165, wontfix upstream). Рекомендуется откатиться на 1.20.5: brew install openfortivpn@1.20.5 (или brew install https://raw.githubusercontent.com/Homebrew/homebrew-core/<older-commit>/Formula/o/openfortivpn.rb).",
}

// CheckOpenfortivpn reports whether openfortivpn is on PATH, its version, and
// whether that version is known to be broken on this OS.
func CheckOpenfortivpn() BinaryStatus {
	path, err := exec.LookPath("openfortivpn")
	if err != nil || path == "" {
		return BinaryStatus{Installed: false}
	}
	out, _ := exec.Command("openfortivpn", "--version").CombinedOutput()
	version := versionRe.FindString(string(out))
	status := BinaryStatus{Installed: true, Version: version}
	if version != "" && runtime.GOOS == "darwin" {
		for prefix, warning := range knownBadVersions {
			if strings.HasPrefix(version, prefix) {
				status.Warning = warning
				break
			}
		}
	}
	return status
}

// InstallOpenfortivpnViaBrew runs `brew install openfortivpn` and streams
// nothing back — it's a one-shot best-effort install button per the chosen
// auto-install (not bundled-binary) strategy; the caller should re-run
// CheckOpenfortivpn afterwards to see the result.
func InstallOpenfortivpnViaBrew() error {
	cmd := exec.Command("brew", "install", "openfortivpn")
	return cmd.Run()
}
