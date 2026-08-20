//go:build windows

package main

import "errors"

// elevatedCommand is not yet implemented on Windows.
//
// Unlike macOS (AuthorizationExecuteWithPrivileges) and Linux (pkexec),
// Windows UAC elevation via ShellExecute's "runas" verb starts a *new*
// process that does not inherit the caller's stdin/stdout/stderr handles —
// there is no built-in way to get live log streaming or an interactive OTP
// prompt through to an elevated child the way this app relies on. A real fix
// needs a named-pipe (or local TCP) bridge between the unelevated GUI and the
// elevated openfortivpn process, which is a separate, non-trivial piece of
// work — tracked as a follow-up, not silently faked here.
func elevatedCommand(name string, args ...string) (elevatedProc, func(), error) {
	return nil, nil, errors.New("windows privilege elevation with live stdio is not implemented yet")
}

// runPtyExec is a no-op stub here — see ptyproxy_darwin.go; this hidden
// re-exec mode is specific to a macOS AuthorizationExecuteWithPrivileges quirk.
func runPtyExec(args []string) {}
