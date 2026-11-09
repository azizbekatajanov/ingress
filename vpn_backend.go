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
	// Prepare builds the client's argv for profile p with its stored secret.
	// toolPath is the resolved binary (see ComponentManager.ResolvePath),
	// for finding helper scripts installed next to it.
	Prepare(p Profile, secret, toolPath string) (backendLaunch, error)
	// Parse interprets one output line (ANSI codes already stripped).
	// prompt is true when the line had no trailing newline and nothing
	// followed it — i.e. the client is almost certainly blocked reading
	// stdin (see Manager.pump).
	Parse(line string, prompt bool) []lineEvent
	// RememberChoice stores the answer to a PromptChoice in the profile so
	// the next connect doesn't ask again. Returns whether p changed.
	RememberChoice(p *Profile, label, choice string) bool
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
	// evReply: write Value (plus newline) to the client's stdin — for
	// prompts the backend answers itself.
	evReply
	// evFatal: the attempt can't succeed (e.g. the client re-asks for a
	// password it was already given); Value is the reason. Manager records
	// it as the error and stops the client.
	evFatal
)

type lineEvent struct {
	Kind   lineEventKind
	Value  string
	Prompt PromptKind
	// Sticky (evError only): later non-sticky errors don't replace this
	// one — for a clear explanation followed by the client's own generic
	// failure lines.
	Sticky bool
	// Label and Options describe a PromptChoice.
	Label   string
	Options []string
}

// PromptKind is what kind of input the client is blocked on.
type PromptKind string

const (
	// PromptOTP: a one-time code (2FA). Shown as the OTP modal.
	PromptOTP PromptKind = "otp"
	// PromptChoice: pick one of Options (e.g. a GlobalProtect gateway).
	PromptChoice PromptKind = "choice"
)

func backendFor(profileType string) (vpnBackend, error) {
	switch profileType {
	case ProfileTypeFortinet:
		return fortinetBackend{}, nil
	case ProfileTypeGlobalProtect:
		return globalProtectBackend{}, nil
	}
	return nil, fmt.Errorf("неизвестный тип профиля %q", profileType)
}
