package main

import (
	"context"
	"errors"
)

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
	// Prepare builds the client's argv for profile p authenticating with
	// auth. toolPath is the resolved binary (see
	// ComponentManager.ResolvePath), for finding helper scripts next to it.
	Prepare(p Profile, auth authInput, toolPath string) (backendLaunch, error)
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

// authInput is what the client authenticates with: the stored password, or
// (GlobalProtect SAML) the cookie Ingress obtained in its own login window.
type authInput struct {
	Password string
	SAML     *samlResult
}

// preAuthenticator is implemented by backends that may need to do work
// before the client starts — unprivileged, and possibly slow because it
// involves the user (a SAML login window).
type preAuthenticator interface {
	// NeedsPreAuth reports whether Connect must run PreAuth for p.
	NeedsPreAuth(p Profile) bool
	// PreAuth decides how to authenticate and gathers it. Cancelling ctx
	// (the user pressed Отмена) must abort promptly. log adds a line to the
	// connection log.
	PreAuth(ctx context.Context, p Profile, password string, log func(string)) (authInput, error)
}

type backendLaunch struct {
	Args []string
	// Stdin is written once right after the process starts (e.g. a password
	// for openconnect's --passwd-on-stdin). Never put secrets in Args: argv
	// is world-readable via ps.
	Stdin string
	// PromptReplies answers specific client prompts (trimmed prompt text →
	// reply) automatically, each at most once; a repeat of the same prompt
	// goes to Parse like any other. Replies are secrets: they're masked in
	// the log like Stdin.
	PromptReplies map[string]string
	// Target is what the log shows as "Подключение к <Target>...".
	Target string
	// WrapperOpts go to Ingress' own root wrapper (`--pty-exec`), not to
	// the tool: e.g. --routes=… for SSTP (see routewatch.go).
	WrapperOpts []string
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
	// Fallback (evError only): a generic summary line ("Failed to complete
	// authentication") — used only if nothing more specific was seen.
	Fallback bool
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
	// PromptText: a server-defined field (Label) with the server's message
	// (lineEvent.Value), e.g. a Cisco second factor ("Answer:", "Passcode:").
	// Shown in the 2FA modal with the label and free-form input.
	PromptText PromptKind = "text"
)

func backendFor(profileType string) (vpnBackend, error) {
	switch profileType {
	case ProfileTypeFortinet:
		return fortinetBackend{}, nil
	case ProfileTypeGlobalProtect:
		return globalProtectBackend{}, nil
	case ProfileTypeSSTP:
		return sstpBackend{}, nil
	case ProfileTypeCisco:
		// A fresh value per connection: it tracks the server's last form
		// message/error between lines.
		return &ciscoBackend{}, nil
	}
	return nil, errors.New(T("err.unknown_type", profileType))
}
