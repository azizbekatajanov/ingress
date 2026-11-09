package main

import "fmt"

// vpnBackend adapts one VPN protocol's command-line client to Manager.
// Manager owns everything protocol-independent — elevation, reading output
// (including unterminated prompts), connection state, the OTP countdown,
// traffic stats, disconnect — and asks the backend only two things: how to
// launch the client, and what each line of its human-readable output means.
//
// Neither openfortivpn nor openconnect has machine-readable status output,
// so Parse is heuristic by nature; keeping it a pure function of the line
// (no I/O, no state) is what makes it testable against captured real output.
type vpnBackend interface {
	// Component is the binary this backend runs (see components.go).
	Component() string
	// Prepare builds the client's argv (the resolved binary path is
	// prepended by Manager) for profile p with its stored secret.
	Prepare(p Profile, secret string) (backendLaunch, error)
	// Parse interprets one output line (ANSI codes already stripped).
	Parse(line string) []lineEvent
	// SaveServerCert stores a server certificate identifier the client
	// asked to be trusted, if the profile doesn't pin one yet. Returns the
	// log message to show, or "" if nothing changed.
	SaveServerCert(p *Profile, cert string) string
	// DefaultInterface is the tunnel interface assumed when the client
	// reports an IP before naming its interface ("" for none).
	DefaultInterface() string
}

type backendLaunch struct {
	Args []string
	// Stdin is written once right after the process starts (e.g. a password
	// for openconnect's --passwd-on-stdin). Never put secrets in Args: argv
	// is world-readable via ps.
	Stdin string
	// Target is what the log shows as "Подключение к <Target>...".
	Target string
	// Cleanup removes temp files; called once the process has exited.
	Cleanup func()
}

type lineEventKind int

const (
	// evError: Value is a human-readable error, shown on the overview.
	evError lineEventKind = iota
	// evPrompt: the client is waiting for input described by Prompt.
	evPrompt
	// evAssignedIP: Value is the tunnel IP; the tunnel counts as up.
	evAssignedIP
	// evInterfaceUp: Value is the tunnel interface; the tunnel counts as up.
	evInterfaceUp
	// evServerCert: Value is a server certificate identifier to trust
	// (see vpnBackend.SaveServerCert).
	evServerCert
)

type lineEvent struct {
	Kind   lineEventKind
	Value  string
	Prompt PromptKind
}

// PromptKind is what kind of input the client is blocked on.
type PromptKind string

const (
	// PromptOTP: a one-time code (2FA). Shown as the OTP modal.
	PromptOTP PromptKind = "otp"
)

func backendFor(profileType string) (vpnBackend, error) {
	switch profileType {
	case ProfileTypeFortinet:
		return fortinetBackend{}, nil
	case ProfileTypeGlobalProtect:
		// Phase 4 of design/v2-plan.md wires GlobalProtect up to openconnect.
		return nil, fmt.Errorf("подключение GlobalProtect пока не реализовано")
	}
	return nil, fmt.Errorf("неизвестный тип профиля %q", profileType)
}
