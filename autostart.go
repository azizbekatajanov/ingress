package main

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// Launch at login. The OS's own login-item mechanism is the only record of
// the setting (no copy in profiles.json that could disagree with it):
//   - macOS: a LaunchAgent in ~/Library/LaunchAgents that runs
//     `open -g -a <Ingress.app> --args --hidden` (autostart_darwin.go);
//   - Linux: an XDG autostart entry in ~/.config/autostart;
//   - Windows: the HKCU …\CurrentVersion\Run key.
//
// The entry starts Ingress with hiddenArg: no window, just the tray icon.
// While enabled, it is rewritten on every start (refreshLaunchAtLogin), so
// it follows the app if it was moved.

const (
	hiddenArg          = "--hidden"
	launchAgentLabel   = "io.github.azizbekatajanov.ingress.login"
	autostartEntryName = "ingress.desktop"
)

// startedHidden reports whether this run was launched at login.
func startedHidden(args []string) bool {
	for _, a := range args {
		if a == hiddenArg {
			return true
		}
	}
	return false
}

// appBundle returns the .app bundle holding exe, or "" when exe isn't in
// one (a dev build).
func appBundle(exe string) string {
	dir := filepath.Dir(exe) // …/Ingress.app/Contents/MacOS
	if filepath.Base(dir) != "MacOS" || filepath.Base(filepath.Dir(dir)) != "Contents" {
		return ""
	}
	bundle := filepath.Dir(filepath.Dir(dir))
	if !strings.HasSuffix(bundle, ".app") {
		return ""
	}
	return bundle
}

// launchAgentArgs is what the LaunchAgent runs for exe.
func launchAgentArgs(exe string) []string {
	if bundle := appBundle(exe); bundle != "" {
		// Through LaunchServices, like a Dock/Finder launch.
		return []string{"/usr/bin/open", "-g", "-a", bundle, "--args", hiddenArg}
	}
	return []string{exe, hiddenArg}
}

func launchAgentPlist(args []string) []byte {
	var b bytes.Buffer
	esc := func(s string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(s))
		return e.String()
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchAgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		b.WriteString("\t\t<string>" + esc(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`)
	return b.Bytes()
}

// desktopExecQuote quotes an Exec= argument per the Desktop Entry spec.
func desktopExecQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", `$`, `\\$`)
	return `"` + r.Replace(s) + `"`
}

func desktopEntry(exe string) []byte {
	return []byte("[Desktop Entry]\nType=Application\nName=Ingress\nExec=" + desktopExecQuote(exe) + " " + hiddenArg +
		"\nTerminal=false\nX-GNOME-Autostart-enabled=true\n")
}

// writeFileAtomic writes data to path via a temp file and rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// refreshLaunchAtLogin rewrites an enabled login item for the current
// executable.
func refreshLaunchAtLogin() {
	if launchAtLoginEnabled() {
		_ = setLaunchAtLogin(true)
	}
}
