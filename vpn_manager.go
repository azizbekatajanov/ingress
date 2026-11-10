package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// elevatedProc abstracts over how a privileged VPN client process is
// actually spawned per OS. Linux/Windows wrap *exec.Cmd (pkexec / unimplemented,
// respectively); macOS is different in kind, not just detail — it's built on
// Security.framework's AuthorizationExecuteWithPrivileges (see elevate_darwin.go),
// which doesn't go through os/exec at all and hands back a single fd for
// combined stdin+stdout+stderr instead of separate pipes, so this interface
// is deliberately the lowest common denominator both shapes can implement.
type elevatedProc interface {
	Stdin() io.WriteCloser
	Stdout() io.Reader // combined stdout+stderr
	Start() error
	Wait() error
	Terminate() error
}

type Status string

const (
	StatusDisconnected Status = "disconnected"
	StatusConnecting   Status = "connecting"
	StatusOtp          Status = "otp"
	// StatusChoose: the client is waiting for the user to pick one of
	// ConnectionSnapshot.PromptOptions (e.g. a GlobalProtect gateway).
	StatusChoose    Status = "choose"
	StatusConnected Status = "connected"
)

type LogLine struct {
	Ts   string `json:"ts"`
	Text string `json:"text"`
}

// ConnectionSnapshot is what gets pushed to the frontend on every state change.
type ConnectionSnapshot struct {
	ProfileID      string    `json:"profileId"`
	Status         Status    `json:"status"`
	AssignedIP     string    `json:"assignedIp"`
	ConnectSeconds int       `json:"connectSeconds"`
	RxBytes        uint64    `json:"rxBytes"`
	TxBytes        uint64    `json:"txBytes"`
	OtpSecondsLeft int       `json:"otpSecondsLeft"`
	LogLines       []LogLine `json:"logLines"`
	// LastError is the most recent "ERROR:" line seen. Set so a failed
	// connection attempt is visible on the overview screen — the log tab
	// only exists while connected, so without this, failures before ever
	// reaching "connected" were invisible in the UI (only visible via the
	// stdout mirror in Terminal).
	LastError string `json:"lastError"`
	// PromptLabel/PromptOptions describe the pending choice (StatusChoose);
	// PromptLabel/PromptMessage a server-defined text field (StatusOtp
	// with a label — see PromptText). Empty label = classic 2FA code.
	PromptLabel   string   `json:"promptLabel"`
	PromptOptions []string `json:"promptOptions"`
	PromptMessage string   `json:"promptMessage"`
}

const otpWindow = 60 * time.Second

// What each output line means is the backend's business (see vpn_backend.go);
// only protocol-independent cleanup lives here.
var (
	// ansiEscapeRe strips ANSI SGR color codes (e.g. "\x1b[0;0m") that
	// openfortivpn/pppd intersperse in their output — confirmed live:
	// "\x1b[0;0mERROR:  Could not authenticate..." failed to match
	// the ^-anchored ERROR: pattern (a terminal renders the escape as
	// color, not visible text, which is why the raw log looked clean when
	// eyeballed but the regex saw a line that didn't start with "ERROR:").
	// Applied to every line before any other regex runs, in pump below.
	ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
)

type liveConnection struct {
	mu        sync.Mutex
	profileID string
	backend   vpnBackend
	proc      elevatedProc
	// redact is a secret written to the client's stdin (see
	// backendLaunch.Stdin). The pty echoes stdin back into the output, so
	// any line containing it is masked before it reaches the log.
	redact string
	// prevLine is the last non-empty output line before the current one —
	// context for a Fallback error (see lineEvent.Fallback).
	prevLine string
	// replies: see backendLaunch.PromptReplies; entries are deleted once used.
	replies     map[string]string
	stdin       io.WriteCloser
	cleanup     func()
	status      Status
	assignedIP  string
	iface       string
	startedAt   time.Time
	otpDeadline time.Time
	logLines    []LogLine
	lastError   string
	// errorSticky: lastError came from a sticky event (see lineEvent.Sticky).
	errorSticky bool
	// cancelPreAuth stops a running pre-auth step (closes the SAML window);
	// nil when the backend has none.
	cancelPreAuth context.CancelFunc
	// failed: the backend reported a fatal condition and Manager stopped the
	// client itself — unlike a user cancel, the failure must still surface.
	failed        bool
	promptLabel   string
	promptOptions []string
	promptMessage string
	rxBytes       uint64
	txBytes       uint64
	done          chan struct{}
	// cancelling is set the moment the user asks to cancel/disconnect, before
	// the process has actually exited. openfortivpn can still have a line or
	// two already in flight on its stdout at that point (e.g. the OTP prompt,
	// printed just before SIGTERM lands) — without this flag, handleLine
	// would process such a line and briefly flip status back to "otp" (or
	// "connected") right as the process is dying, which the frontend then
	// renders as the 2FA modal flashing open for an instant before
	// disconnect resolves. Confirmed live via that exact flash.
	cancelling bool
}

// Manager owns one VPN client subprocess per connected profile, so multiple
// profiles can be connected simultaneously and independently — the exact
// thing the official FortiClient can't do, per the original complaint.
type Manager struct {
	ctx context.Context
	// events sends a frontend event; swapped out in tests (the Wails runtime
	// needs a live app context).
	events func(name string, data ...interface{})
	// showWindow brings the window forward (nil in tests).
	showWindow func()
	mu         sync.Mutex
	conns      map[string]*liveConnection
	store      *ProfileStore
	components *ComponentManager
	onUpdate   func(ConnectionSnapshot)
}

func NewManager(ctx context.Context, store *ProfileStore, components *ComponentManager) *Manager {
	return &Manager{
		ctx:    ctx,
		events: func(name string, data ...interface{}) { wailsRuntime.EventsEmit(ctx, name, data...) },
		showWindow: func() {
			wailsRuntime.WindowShow(ctx)
			wailsRuntime.WindowUnminimise(ctx)
		},
		conns:      make(map[string]*liveConnection),
		store:      store,
		components: components,
	}
}

// SetOnUpdate registers a callback (used to keep the tray icon in sync) fired
// alongside every "vpn:update" event sent to the frontend.
func (m *Manager) SetOnUpdate(fn func(ConnectionSnapshot)) {
	m.onUpdate = fn
}

func (m *Manager) get(profileID string) *liveConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[profileID]
}

func (m *Manager) Snapshot(profileID string) ConnectionSnapshot {
	conn := m.get(profileID)
	if conn == nil {
		return ConnectionSnapshot{ProfileID: profileID, Status: StatusDisconnected}
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.snapshotLocked()
}

func (c *liveConnection) snapshotLocked() ConnectionSnapshot {
	s := ConnectionSnapshot{
		ProfileID:  c.profileID,
		Status:     c.status,
		AssignedIP: c.assignedIP,
		RxBytes:    c.rxBytes,
		TxBytes:    c.txBytes,
		LogLines:   append([]LogLine(nil), c.logLines...),
		LastError:  c.lastError,
	}
	if c.status == StatusChoose {
		s.PromptLabel = c.promptLabel
		s.PromptOptions = append([]string(nil), c.promptOptions...)
	}
	if c.status == StatusOtp {
		s.PromptLabel = c.promptLabel
		s.PromptMessage = c.promptMessage
	}
	if c.status == StatusConnected {
		s.ConnectSeconds = int(time.Since(c.startedAt).Seconds())
	}
	if c.status == StatusOtp {
		left := int(time.Until(c.otpDeadline).Seconds())
		if left < 0 {
			left = 0
		}
		s.OtpSecondsLeft = left
	}
	return s
}

func (m *Manager) emit(conn *liveConnection) {
	conn.mu.Lock()
	snap := conn.snapshotLocked()
	conn.mu.Unlock()
	m.events("vpn:update", snap)
	if m.onUpdate != nil {
		m.onUpdate(snap)
	}
}

func (c *liveConnection) addLog(text string) {
	c.mu.Lock()
	c.logLines = append(c.logLines, LogLine{Ts: time.Now().Format("15:04:05"), Text: text})
	c.mu.Unlock()
	// Mirrored to stdout so it's visible from Terminal (e.g. running the .app's
	// binary directly) even while the UI is stuck on the "connecting" spinner,
	// which has no log view — only "connected"/"otp" states surface one.
	log.Printf("[%s] %s", c.profileID, text)
}

// Connect spawns the profile's VPN client (see backendFor), elevated.
// Credentials never go on argv, where they'd be visible to `ps` — each
// backend passes them via a private temp file or stdin.
//
// Backends with a pre-auth step (GlobalProtect: prelogin, maybe a SAML
// window) run it asynchronously first: Connect returns right away with the
// profile in "connecting", and anything that goes wrong later is reported
// through the snapshot's LastError like any other failed attempt.
func (m *Manager) Connect(profileID string) error {
	if existing := m.get(profileID); existing != nil {
		existing.mu.Lock()
		st := existing.status
		existing.mu.Unlock()
		if st == StatusConnecting || st == StatusOtp || st == StatusChoose || st == StatusConnected {
			return fmt.Errorf("profile already %s", st)
		}
	}

	profile, ok := m.store.Get(profileID)
	if !ok {
		return fmt.Errorf("unknown profile %s", profileID)
	}
	if profile.Host == "" {
		return fmt.Errorf("profile has no host configured")
	}
	backend, err := backendFor(profile.Type)
	if err != nil {
		return err
	}
	toolPath, err := m.components.ResolvePath(backend.Component())
	if err != nil {
		return err
	}
	password, err := LoadPassword(profileID)
	if err != nil {
		return fmt.Errorf("reading password from keychain: %w", err)
	}

	conn := &liveConnection{
		profileID: profileID,
		backend:   backend,
		status:    StatusConnecting,
		startedAt: time.Now(),
		done:      make(chan struct{}),
	}

	pa, hasPreAuth := backend.(preAuthenticator)
	if !hasPreAuth || !pa.NeedsPreAuth(profile) {
		if err := m.launch(conn, profile, toolPath, authInput{Password: password}); err != nil {
			return err
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn.cancelPreAuth = cancel
	conn.addLog(T("log.connecting", profile.Host))
	m.mu.Lock()
	m.conns[profileID] = conn
	m.mu.Unlock()
	m.emit(conn)

	go func() {
		defer cancel()
		auth, err := pa.PreAuth(ctx, profile, password, conn.addLog)
		if err == nil {
			// Re-read: the user may have edited the profile meanwhile, and
			// PreAuth may have taken minutes.
			if fresh, ok := m.store.Get(profileID); ok {
				profile = fresh
			}
			err = m.launch(conn, profile, toolPath, auth)
		}
		if err != nil {
			m.abortPending(conn, err)
		}
	}()
	return nil
}

// launch starts the elevated client for conn. On error nothing is left
// running and conn is not registered (synchronous path) or must be
// finished by the caller via abortPending (pre-auth path).
func (m *Manager) launch(conn *liveConnection, profile Profile, toolPath string, auth authInput) error {
	launch, err := conn.backend.Prepare(profile, auth, toolPath)
	if err != nil {
		return err
	}
	cleanupLaunch := func() {
		if launch.Cleanup != nil {
			launch.Cleanup()
		}
	}

	conn.mu.Lock()
	cancelled := conn.cancelling
	conn.mu.Unlock()
	if cancelled {
		cleanupLaunch()
		return errSAMLCancelled
	}

	proc, elevateCleanup, err := elevatedCommand(toolPath, launch.Args...)
	if err != nil {
		cleanupLaunch()
		return err
	}

	conn.mu.Lock()
	conn.proc = proc
	conn.stdin = proc.Stdin()
	conn.redact = launch.Stdin
	conn.replies = launch.PromptReplies
	conn.cleanup = func() {
		elevateCleanup()
		cleanupLaunch()
	}
	// Cancelled while the admin prompt was up: terminate() saw no process
	// yet, so stop it as soon as it's running (pump then finishes it).
	cancelledDuringLaunch := conn.cancelling
	conn.mu.Unlock()
	defer func() {
		if cancelledDuringLaunch {
			proc.Terminate()
		}
	}()
	conn.addLog(T("log.connecting", launch.Target))

	m.mu.Lock()
	m.conns[conn.profileID] = conn
	m.mu.Unlock()

	if err := proc.Start(); err != nil {
		conn.cleanup()
		conn.mu.Lock()
		conn.proc = nil
		conn.mu.Unlock()
		if conn.cancelPreAuth == nil {
			m.mu.Lock()
			delete(m.conns, conn.profileID)
			m.mu.Unlock()
		}
		return err
	}
	if launch.Stdin != "" {
		if _, err := io.WriteString(conn.stdin, launch.Stdin+"\n"); err != nil {
			conn.addLog(T("log.stdin_failed", err))
		}
	}

	go m.pump(conn, proc.Stdout())
	go m.tick(conn)

	m.emit(conn)
	return nil
}

// abortPending ends a connection whose client never started (pre-auth
// failed, was cancelled, or the client couldn't be launched).
func (m *Manager) abortPending(conn *liveConnection, err error) {
	var cert *errUntrustedServerCert
	switch {
	case errors.Is(err, errSAMLCancelled) || conn.isCancelling():
		conn.addLog(T("log.cancelled"))
	case errors.As(err, &cert):
		msg := T("cert.server_unverified_short")
		if profile, ok := m.store.Get(conn.profileID); ok {
			if saved := conn.backend.SaveServerCert(&profile, cert.Pin); saved != "" {
				if m.store.Update(profile) == nil {
					conn.addLog(saved)
					m.profileUpdated(conn.profileID)
					msg = T("cert.server_unverified_saved")
				}
			}
		}
		conn.mu.Lock()
		conn.lastError, conn.failed = msg, true
		conn.mu.Unlock()
		conn.addLog(T("log.error", err.Error()))
	default:
		conn.mu.Lock()
		conn.lastError, conn.failed = err.Error(), true
		conn.mu.Unlock()
		conn.addLog(T("log.error", err.Error()))
	}
	m.finish(conn)
}

func (c *liveConnection) isCancelling() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelling
}

// promptFlushDelay bounds how long pump waits, once it has unterminated
// bytes buffered, before treating them as a complete line anyway. Needed for
// prompts like openfortivpn's "Two-factor authentication token: ", which is
// written with no trailing newline before the process blocks reading stdin —
// a plain newline-delimited reader (the previous implementation used
// bufio.Scanner) buffers that text forever waiting for a '\n' that never
// comes, so the OTP prompt is silently never seen and the modal never
// appears, even though the gateway already sent the code. Confirmed live: a
// connection stuck on "Подключение…" with nothing past "Connected to
// gateway." in the log, despite the code having arrived by email.
const promptFlushDelay = 300 * time.Millisecond

// pump reads log lines until the stream ends (EOF), which is the actual
// signal that the process has exited — not proc.Wait(). On macOS in
// particular, Wait() rests on a pid recovered via a decades-old fcntl trick
// (see elevate_darwin.go) that can fail on current macOS, returning
// instantly with "no child processes" before openfortivpn has done anything;
// treating that as "exited" caused connections to appear to reset instantly
// after the auth prompt. EOF on the actual output stream doesn't have that
// failure mode.
func (m *Manager) pump(conn *liveConnection, r io.Reader) {
	type readResult struct {
		chunk []byte
		err   error
	}
	reads := make(chan readResult)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				reads <- readResult{chunk: chunk}
			}
			if err != nil {
				reads <- readResult{err: err}
				return
			}
		}
	}()

	emit := func(raw []byte, prompt bool) {
		line := ansiEscapeRe.ReplaceAllString(strings.TrimRight(string(raw), "\r\n"), "")
		if conn.redact != "" && strings.Contains(line, conn.redact) {
			line = strings.ReplaceAll(line, conn.redact, "••••••")
		}
		conn.addLog(line)
		m.handleLine(conn, line, prompt)
	}

	var pending []byte
	for {
		var timeout <-chan time.Time
		if len(pending) > 0 {
			timeout = time.After(promptFlushDelay)
		}
		select {
		case res := <-reads:
			if res.err != nil {
				if len(pending) > 0 {
					emit(pending, false)
				}
				m.finish(conn)
				return
			}
			pending = append(pending, res.chunk...)
			for {
				idx := bytes.IndexByte(pending, '\n')
				if idx < 0 {
					break
				}
				emit(pending[:idx], false)
				pending = pending[idx+1:]
			}
		case <-timeout:
			// Nothing further arrived in time — the buffered bytes are
			// almost certainly a prompt awaiting input, not a truncated
			// in-progress line. Flush them through as a synthetic line.
			emit(pending, true)
			pending = nil
		}
	}
}

// handleLine applies what the backend reads into one output line to the
// connection's state. prompt: see vpnBackend.Parse.
func (m *Manager) handleLine(conn *liveConnection, line string, prompt bool) {
	conn.mu.Lock()
	status := conn.status
	cancelling := conn.cancelling
	reply, autoReply := conn.replies[strings.TrimSpace(line)]
	if prompt && autoReply && !cancelling {
		delete(conn.replies, strings.TrimSpace(line))
	}
	conn.mu.Unlock()

	if prompt && autoReply && !cancelling {
		conn.addLog(T("log.reprompt", strings.TrimSpace(line)))
		if _, err := io.WriteString(conn.stdin, reply+"\n"); err != nil {
			conn.addLog(T("log.reply_failed", err))
		}
		m.emit(conn)
		return
	}

	promoted := false
	for _, ev := range conn.backend.Parse(line, prompt) {
		switch ev.Kind {
		case evError:
			conn.mu.Lock()
			if ev.Fallback && conn.lastError != "" {
				conn.mu.Unlock()
				continue
			}
			if ev.Fallback && conn.prevLine != "" {
				// The client's own wording for the cause is usually the line
				// right before its generic summary.
				ev.Value = T("err.with_last_line", ev.Value, conn.prevLine)
			}
			if ev.Sticky || !conn.errorSticky {
				conn.lastError = ev.Value
				conn.errorSticky = conn.errorSticky || ev.Sticky
			}
			conn.mu.Unlock()

		case evFatal:
			if !cancelling {
				m.fail(conn, ev.Value)
				return
			}

		case evReply:
			if !cancelling {
				if _, err := io.WriteString(conn.stdin, ev.Value+"\n"); err != nil {
					conn.addLog(T("log.reply_failed", err))
				}
			}

		case evServerCert:
			if profile, ok := m.store.Get(conn.profileID); ok {
				if msg := conn.backend.SaveServerCert(&profile, ev.Value); msg != "" {
					if err := m.store.Update(profile); err == nil {
						conn.addLog(msg)
						m.profileUpdated(conn.profileID)
					}
				}
			}

		case evPrompt:
			if cancelling || status != StatusConnecting {
				continue
			}
			switch ev.Prompt {
			case PromptOTP:
				conn.mu.Lock()
				conn.status = StatusOtp
				conn.otpDeadline = time.Now().Add(otpWindow)
				conn.promptLabel, conn.promptMessage = "", ""
				conn.mu.Unlock()
				conn.addLog(T("log.otp_needed"))
			case PromptText:
				conn.mu.Lock()
				conn.status = StatusOtp
				// Push-style factors (Duo "push") take longer than typing a code.
				conn.otpDeadline = time.Now().Add(2 * otpWindow)
				conn.promptLabel, conn.promptMessage = ev.Label, ev.Value
				conn.mu.Unlock()
				conn.addLog(T("log.second_factor", ev.Label))
			case PromptChoice:
				conn.mu.Lock()
				conn.status = StatusChoose
				conn.promptLabel = ev.Label
				conn.promptOptions = ev.Options
				conn.mu.Unlock()
				conn.addLog(T("log.choice_needed", ev.Label))
			}
			m.emit(conn)
			// A connect started from the tray has no window on screen, and
			// the client is now blocked until the user answers.
			if m.showWindow != nil {
				m.showWindow()
			}
			return

		case evAssignedIP:
			conn.mu.Lock()
			conn.assignedIP = ev.Value
			if conn.iface == "" {
				conn.iface = conn.backend.DefaultInterface()
			}
			promoted = promoted || (!cancelling && conn.status != StatusConnected)
			conn.mu.Unlock()
			conn.addLog(T("log.ip_assigned", ev.Value))

		case evInterfaceUp:
			conn.mu.Lock()
			conn.iface = ev.Value
			promoted = promoted || (!cancelling && conn.status != StatusConnected)
			conn.mu.Unlock()
		}
	}

	if t := strings.TrimSpace(line); t != "" {
		conn.mu.Lock()
		conn.prevLine = t
		conn.mu.Unlock()
	}

	if promoted {
		conn.mu.Lock()
		conn.status = StatusConnected
		conn.startedAt = time.Now()
		// Errors the client recovered from on the way (retries, fallbacks)
		// mustn't resurface later as the reason for a disconnect.
		conn.lastError = ""
		conn.errorSticky = false
		conn.mu.Unlock()
		conn.addLog(T("log.tunnel_up"))
	}
	m.emit(conn)
}

// fail records a fatal reason and stops the client. Unlike a user cancel,
// finish() still surfaces it (window + error banner).
func (m *Manager) fail(conn *liveConnection, reason string) {
	conn.mu.Lock()
	conn.lastError = reason
	conn.errorSticky = true
	conn.failed = true
	conn.mu.Unlock()
	conn.addLog(T("log.error", reason))
	m.emit(conn)
	m.terminate(conn.profileID)
}

func (m *Manager) profileUpdated(profileID string) {
	// The frontend holds its own copy of the profile; without this its next
	// debounced save would write the old value back over the one just
	// stored.
	if saved, ok := m.store.Get(profileID); ok {
		m.events("profile:updated", saved)
	}
}

// tick refreshes duration/traffic (while connected) or the OTP countdown
// (while awaiting 2FA), once a second, until the process exits.
func (m *Manager) tick(conn *liveConnection) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-conn.done:
			return
		case <-ticker.C:
			conn.mu.Lock()
			status := conn.status
			if status == StatusConnected && conn.iface == "" && conn.assignedIP != "" {
				conn.iface = interfaceWithIP(conn.assignedIP)
			}
			iface := conn.iface
			expired := status == StatusOtp && time.Now().After(conn.otpDeadline)
			conn.mu.Unlock()

			if expired {
				conn.addLog(T("log.otp_expired"))
				m.CancelConnect(conn.profileID)
				return
			}
			if status == StatusConnected && iface != "" {
				if rx, tx, err := ifaceStats(iface); err == nil {
					conn.mu.Lock()
					conn.rxBytes, conn.txBytes = rx, tx
					conn.mu.Unlock()
				}
			}
			m.emit(conn)
		}
	}
}

// finish runs once pump() sees EOF on the process's output — the real
// "it's done" signal (see the comment on pump). proc.Wait() is still called
// to reap the process where the platform supports it, but only as a
// best-effort side effect logged for diagnostics, never as something that
// gates or contradicts the UI state.
func (m *Manager) finish(conn *liveConnection) {
	conn.mu.Lock()
	proc := conn.proc
	conn.mu.Unlock()
	if proc != nil {
		if err := proc.Wait(); err != nil {
			log.Printf("[%s] proc.Wait: %v (harmless if the process had already exited)", conn.profileID, err)
		}
	}
	close(conn.done)
	conn.mu.Lock()
	alreadyDisconnected := conn.status == StatusDisconnected
	conn.status = StatusDisconnected
	lastError := conn.lastError
	cancelling := conn.cancelling && !conn.failed
	conn.mu.Unlock()
	if !alreadyDisconnected {
		conn.addLog(T("log.disconnected"))
	}
	if conn.cleanup != nil {
		conn.cleanup()
	}
	m.emit(conn)

	// A failed connection attempt is otherwise invisible whenever the window
	// is hidden — easy to end up in, since profile rows are clickable right
	// from the tray (see tray.go) without ever showing the window at all. The
	// LastError plumbing into ConnectionSnapshot/#errorBanner was already
	// correct; nothing was there to look at it. Bring the window up and
	// select the profile that failed, so the user sees exactly which
	// profile and why instead of just noticing nothing happened. Skipped
	// when the user cancelled themselves (cancelling never leaves an error
	// set anyway, but this keeps the intent explicit).
	// A profile deleted mid-attempt must not be re-selected: that would
	// persist a dangling selectedProfileId and blank the UI.
	if _, exists := m.store.Get(conn.profileID); exists && lastError != "" && !cancelling {
		m.store.SetSelectedID(conn.profileID)
		m.events("profile:failed", conn.profileID)
		if m.showWindow != nil {
			m.showWindow()
		}
	}
}

// SubmitPrompt answers what the client is waiting for: a 2FA code
// (StatusOtp) or one of the offered options (StatusChoose), written to its
// stdin exactly where it's blocked reading. A chosen option is remembered in
// the profile (see vpnBackend.RememberChoice).
func (m *Manager) SubmitPrompt(profileID, value string) error {
	conn := m.get(profileID)
	if conn == nil {
		return fmt.Errorf("no pending connection for profile %s", profileID)
	}
	conn.mu.Lock()
	status := conn.status
	label, options := conn.promptLabel, conn.promptOptions
	if status != StatusOtp && status != StatusChoose {
		conn.mu.Unlock()
		return fmt.Errorf("profile is not waiting for input")
	}
	if status == StatusChoose && !containsString(options, value) {
		conn.mu.Unlock()
		return fmt.Errorf("unknown option %q", value)
	}
	conn.status = StatusConnecting
	conn.promptLabel, conn.promptOptions, conn.promptMessage = "", nil, ""
	conn.mu.Unlock()

	if status == StatusOtp && label == "" {
		conn.addLog(T("log.checking_code"))
	} else if status == StatusOtp {
		conn.addLog(T("log.sending_answer"))
	} else {
		conn.addLog(T("log.chosen", value))
		if profile, ok := m.store.Get(profileID); ok && conn.backend.RememberChoice(&profile, label, value) {
			if err := m.store.Update(profile); err == nil {
				m.profileUpdated(profileID)
			}
		}
	}
	m.emit(conn)
	_, err := io.WriteString(conn.stdin, value+"\n")
	return err
}

// SubmitOtp is SubmitPrompt for the 2FA modal.
func (m *Manager) SubmitOtp(profileID, code string) error {
	return m.SubmitPrompt(profileID, code)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// interfaceWithIP finds the network interface holding ip (how the tunnel
// interface is found for clients that don't print its name).
func interfaceWithIP(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var addrIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				addrIP = v.IP
			case *net.IPAddr:
				addrIP = v.IP
			}
			if addrIP != nil && addrIP.String() == ip {
				return ifc.Name
			}
		}
	}
	return ""
}

// CancelConnect and Disconnect both terminate the elevated client process
// gracefully; finish reconciles state once it actually exits.
func (m *Manager) CancelConnect(profileID string) error {
	return m.terminate(profileID)
}

func (m *Manager) Disconnect(profileID string) error {
	conn := m.get(profileID)
	if conn != nil {
		conn.addLog(T("log.stopping"))
		m.emit(conn)
	}
	return m.terminate(profileID)
}

func (m *Manager) terminate(profileID string) error {
	conn := m.get(profileID)
	if conn == nil {
		return nil
	}
	conn.mu.Lock()
	conn.cancelling = true
	proc, cancelPreAuth := conn.proc, conn.cancelPreAuth
	conn.mu.Unlock()
	if proc == nil {
		// Still in pre-auth: closing the SAML window / aborting prelogin
		// makes the Connect goroutine finish the connection.
		if cancelPreAuth != nil {
			cancelPreAuth()
		}
		return nil
	}
	return proc.Terminate()
}

// DisconnectAll stops every connection (and pending attempt) and waits up to
// timeout for them to finish — used before an in-app update restarts Ingress.
func (m *Manager) DisconnectAll(timeout time.Duration) {
	active := func() []string {
		m.mu.Lock()
		defer m.mu.Unlock()
		var ids []string
		for id, c := range m.conns {
			c.mu.Lock()
			if c.status != StatusDisconnected {
				ids = append(ids, id)
			}
			c.mu.Unlock()
		}
		return ids
	}
	for _, id := range active() {
		_ = m.Disconnect(id)
	}
	deadline := time.Now().Add(timeout)
	for len(active()) > 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
}
