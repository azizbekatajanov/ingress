package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// elevatedProc abstracts over how a privileged openfortivpn process is
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
	StatusConnected    Status = "connected"
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
}

const otpWindow = 60 * time.Second

// Heuristic detectors for openfortivpn/pppd's stdout+stderr. openfortivpn has
// no machine-readable status output, so state transitions are inferred from
// its human-readable log lines — these patterns are a best-effort v1 and may
// need tuning against a real gateway's exact wording.
var (
	otpPromptRe = regexp.MustCompile(`(?i)(one-time|otp|two-factor|2fa|verification code|token code)`)
	ipAssignRe  = regexp.MustCompile(`(?i)local\s+ip\s+address\s+([0-9.]+)`)
	ifaceUpRe   = regexp.MustCompile(`(?i)interface\s+(\S+)\s+is\s+up`)
	errorLineRe = regexp.MustCompile(`(?i)^\s*ERROR:\s*(.+)$`)
	// ansiEscapeRe strips ANSI SGR color codes (e.g. "\x1b[0;0m") that
	// openfortivpn/pppd intersperse in their output — confirmed live:
	// "\x1b[0;0mERROR:  Could not authenticate..." failed to match
	// errorLineRe's ^-anchored pattern (a terminal renders the escape as
	// color, not visible text, which is why the raw log looked clean when
	// eyeballed but the regex saw a line that didn't start with "ERROR:").
	// Applied to every line before any other regex runs, in pump below.
	ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	// Matches the one-line form of openfortivpn's untrusted-gateway-cert
	// error ("...rerun with:\n    --trusted-cert <sha256>"), which is easier
	// to parse reliably than the multi-line "sha256 digest:\n    <hash>" block.
	untrustedCertRe = regexp.MustCompile(`--trusted-cert\s+([0-9a-f]{64})`)
)

type liveConnection struct {
	mu         sync.Mutex
	profileID  string
	proc       elevatedProc
	stdin      io.WriteCloser
	cleanup    func()
	status     Status
	assignedIP string
	iface      string
	startedAt  time.Time
	otpDeadline time.Time
	logLines   []LogLine
	lastError  string
	rxBytes    uint64
	txBytes    uint64
	done       chan struct{}
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

// Manager owns one openfortivpn subprocess per connected profile, so multiple
// profiles can be connected simultaneously and independently — the exact
// thing the official FortiClient can't do, per the original complaint.
type Manager struct {
	ctx      context.Context
	mu       sync.Mutex
	conns    map[string]*liveConnection
	store    *ProfileStore
	onUpdate func(ConnectionSnapshot)
}

func NewManager(ctx context.Context, store *ProfileStore) *Manager {
	return &Manager{ctx: ctx, conns: make(map[string]*liveConnection), store: store}
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
	wailsRuntime.EventsEmit(m.ctx, "vpn:update", snap)
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

// Connect spawns openfortivpn for the given profile, elevated, with its
// credentials passed via a private 0600 temp config file (never on argv,
// where they'd be visible to `ps`).
func (m *Manager) Connect(profileID string) error {
	if existing := m.get(profileID); existing != nil {
		existing.mu.Lock()
		st := existing.status
		existing.mu.Unlock()
		if st == StatusConnecting || st == StatusOtp || st == StatusConnected {
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
	password, err := LoadPassword(profileID)
	if err != nil {
		return fmt.Errorf("reading password from keychain: %w", err)
	}

	cfgPath, err := writeOpenfortivpnConfig(profile, password)
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	target := fmt.Sprintf("%s:%s", profile.Host, profile.Port)
	proc, elevateCleanup, err := elevatedCommand("openfortivpn", target, "--config="+cfgPath)
	if err != nil {
		os.Remove(cfgPath)
		return err
	}

	conn := &liveConnection{
		profileID: profileID,
		proc:      proc,
		stdin:     proc.Stdin(),
		status:    StatusConnecting,
		startedAt: time.Now(),
		done:      make(chan struct{}),
		cleanup: func() {
			elevateCleanup()
			os.Remove(cfgPath)
		},
	}
	conn.addLog(fmt.Sprintf("Подключение к %s...", target))

	m.mu.Lock()
	m.conns[profileID] = conn
	m.mu.Unlock()

	if err := proc.Start(); err != nil {
		conn.cleanup()
		m.mu.Lock()
		delete(m.conns, profileID)
		m.mu.Unlock()
		return err
	}

	go m.pump(conn, proc.Stdout())
	go m.tick(conn)

	m.emit(conn)
	return nil
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

	emit := func(raw []byte) {
		line := ansiEscapeRe.ReplaceAllString(strings.TrimRight(string(raw), "\r\n"), "")
		conn.addLog(line)
		m.handleLine(conn, line)
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
					emit(pending)
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
				emit(pending[:idx])
				pending = pending[idx+1:]
			}
		case <-timeout:
			// Nothing further arrived in time — the buffered bytes are
			// almost certainly a prompt awaiting input, not a truncated
			// in-progress line. Flush them through as a synthetic line.
			emit(pending)
			pending = nil
		}
	}
}

func (m *Manager) handleLine(conn *liveConnection, line string) {
	conn.mu.Lock()
	status := conn.status
	cancelling := conn.cancelling
	conn.mu.Unlock()

	if match := errorLineRe.FindStringSubmatch(line); match != nil {
		conn.mu.Lock()
		conn.lastError = match[1]
		conn.mu.Unlock()
	}

	// openfortivpn refuses an unrecognized gateway cert and prints the exact
	// --trusted-cert value that would fix it. Auto-fill it into the profile
	// (but don't auto-reconnect — trusting a cert is a deliberate action,
	// this just saves copy-pasting the hash by hand) so the next click on
	// "Подключить" succeeds.
	if match := untrustedCertRe.FindStringSubmatch(line); match != nil {
		if profile, ok := m.store.Get(conn.profileID); ok && profile.TrustedCert == "" {
			profile.TrustedCert = match[1]
			if err := m.store.Update(profile); err == nil {
				conn.addLog("Сертификат шлюза сохранён как доверенный (trusted-cert) — нажмите «Подключить» ещё раз")
			}
		}
	}

	if !cancelling && status == StatusConnecting && otpPromptRe.MatchString(line) {
		conn.mu.Lock()
		conn.status = StatusOtp
		conn.otpDeadline = time.Now().Add(otpWindow)
		conn.mu.Unlock()
		conn.addLog("Требуется одноразовый код (2FA)")
		m.emit(conn)
		return
	}

	promoted := false
	if match := ipAssignRe.FindStringSubmatch(line); match != nil {
		conn.mu.Lock()
		conn.assignedIP = match[1]
		if conn.iface == "" {
			conn.iface = "ppp0"
		}
		promoted = !cancelling && conn.status != StatusConnected
		conn.mu.Unlock()
		conn.addLog(fmt.Sprintf("Назначен IP-адрес: %s", match[1]))
	}
	if match := ifaceUpRe.FindStringSubmatch(line); match != nil {
		conn.mu.Lock()
		conn.iface = match[1]
		promoted = !cancelling && conn.status != StatusConnected
		conn.mu.Unlock()
	}
	if promoted {
		conn.mu.Lock()
		conn.status = StatusConnected
		conn.startedAt = time.Now()
		conn.mu.Unlock()
		conn.addLog("Туннель установлен")
		m.emit(conn)
		return
	}

	m.emit(conn)
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
			iface := conn.iface
			expired := status == StatusOtp && time.Now().After(conn.otpDeadline)
			conn.mu.Unlock()

			if expired {
				conn.addLog("Код истёк, отключение")
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
	if err := conn.proc.Wait(); err != nil {
		log.Printf("[%s] proc.Wait: %v (harmless if the process had already exited)", conn.profileID, err)
	}
	close(conn.done)
	conn.mu.Lock()
	alreadyDisconnected := conn.status == StatusDisconnected
	conn.status = StatusDisconnected
	lastError := conn.lastError
	cancelling := conn.cancelling
	conn.mu.Unlock()
	if !alreadyDisconnected {
		conn.addLog("Отключено")
	}
	conn.cleanup()
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
	if lastError != "" && !cancelling {
		m.store.SetSelectedID(conn.profileID)
		wailsRuntime.EventsEmit(m.ctx, "profile:failed", conn.profileID)
		wailsRuntime.WindowShow(m.ctx)
		wailsRuntime.WindowUnminimise(m.ctx)
	}
}

// SubmitOtp writes the user's 2FA code to openfortivpn's stdin, exactly where
// it's waiting to read it.
func (m *Manager) SubmitOtp(profileID, code string) error {
	conn := m.get(profileID)
	if conn == nil {
		return fmt.Errorf("no pending connection for profile %s", profileID)
	}
	conn.mu.Lock()
	if conn.status != StatusOtp {
		conn.mu.Unlock()
		return fmt.Errorf("profile is not awaiting an OTP code")
	}
	conn.status = StatusConnecting
	conn.mu.Unlock()
	conn.addLog("Проверка одноразового кода...")
	m.emit(conn)
	_, err := io.WriteString(conn.stdin, code+"\n")
	return err
}

// CancelConnect and Disconnect both terminate the elevated openfortivpn
// process gracefully; awaitExit reconciles state once it actually exits.
func (m *Manager) CancelConnect(profileID string) error {
	return m.terminate(profileID)
}

func (m *Manager) Disconnect(profileID string) error {
	conn := m.get(profileID)
	if conn != nil {
		conn.addLog("Завершение туннеля...")
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
	conn.mu.Unlock()
	return conn.proc.Terminate()
}
