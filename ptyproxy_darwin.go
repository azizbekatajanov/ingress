//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// terminateSentinel is a single control byte (ASCII EOT) that authProc.Terminate
// (elevate_darwin.go) writes to ask this process to tear the tunnel down.
// Not a real close()/EOF: on this cgo-sourced fd, a concurrent Read() blocked
// in the other goroutine didn't reliably get interrupted by Close() — it just
// hung, confirmed live (Disconnect stuck forever on "Завершение туннеля...").
// A byte pushed through the same read loop that's already forwarding OTP
// input doesn't have that problem. EOT can't collide with a real OTP code
// (always printable digits/letters).
const terminateSentinel = 0x04

// terminateGrace is how long we wait for openfortivpn to exit cleanly after
// SIGTERM before escalating to SIGKILL. openfortivpn's SIGTERM handler does a
// graceful HTTPS logout round-trip to the gateway, which can hang indefinitely
// if the tunnel's own routes are already half torn down — confirmed live as
// "Завершение туннеля..." never resolving even though the sentinel byte was
// delivered and SIGTERM was sent. Without this escalation, a stuck tunnel also
// keeps holding pppd's routes/lock, which is why a second profile then also
// failed to connect.
const terminateGrace = 6 * time.Second

// runPtyExec is a hidden re-exec mode of this same binary, invoked as
// `ingress --pty-exec <tool> <args...>`. See elevate_darwin.go's
// elevatedCommand doc comment for why this exists: AuthorizationExecuteWithPrivileges
// hands its child a plain socket for stdio, not a pty, and pppd (spawned by
// openfortivpn once it's running as root) rejects that with a generic
// "mutually exclusive options" error. macOS's `script` utility can't paper
// over this either — it tries to copy termios settings from *its own*
// controlling terminal and errors out when there isn't one, which is exactly
// our situation. pty.Start() allocates a fresh pty unconditionally, with no
// dependency on our own stdio, closing that gap.
func runPtyExec(args []string) {
	if len(args) < 1 {
		os.Exit(64) // EX_USAGE
	}

	// AuthorizationExecuteWithPrivileges only raises the *effective* UID to 0,
	// not the real UID (unlike sudo, which sets both) — confirmed live via a
	// diagnostic print: this process showed euid=0 but uid=501. pppd's own
	// "requires root privilege" check for the noauth option reads getuid(),
	// the real UID, not geteuid(), so it saw a non-root real UID and refused,
	// which cascaded into pppd's generic "mutually exclusive options"
	// catch-all error. Setuid(0) here promotes the real UID too, and
	// openfortivpn/pppd inherit it correctly through the fork+exec chain below.
	if err := syscall.Setuid(0); err != nil {
		fmt.Fprintf(os.Stderr, "[pty-exec] setuid(0) failed: %v\n", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	f, err := pty.Start(cmd)
	if err != nil {
		os.Exit(1)
	}
	// pty.Start() (see creack/pty's start.go) always sets Setsid: true on
	// cmd.SysProcAttr, which as a side effect already puts the child in a
	// brand-new process group with pgid == its own pid — exactly what
	// killGroup (below) needs, with no extra SysProcAttr tweak required.
	// Setting Setpgid: true here too was tried and breaks pty.Start() outright:
	// Setsid + Setpgid together in one SysProcAttr is an invalid combination
	// at fork/exec, so the child never actually started — confirmed live as
	// every connect instantly logging "Отключено" right after "Подключение".

	// exited is closed once the child has actually exited (see the io.Copy
	// call below), so the escalation watchdog started on terminateSentinel
	// knows not to fire after a clean shutdown.
	exited := make(chan struct{})

	// Forward SIGTERM/SIGINT (if this process itself ever receives one) to
	// the real child so openfortivpn gets a chance to tear down the
	// tunnel/routes cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	// killGroup force-kills the whole process group. openfortivpn's SIGTERM
	// handler does a graceful HTTPS logout round-trip to the gateway, which
	// can hang indefinitely once the tunnel's own routes are half torn down
	// — confirmed live as "Завершение туннеля..." never resolving even
	// though SIGTERM was delivered. A stuck tunnel here also keeps holding
	// pppd's routes/lock, which is why a second profile's connect then also
	// failed — so this is the fix for both symptoms at once.
	killGroup := func() {
		if cmd.Process == nil {
			return
		}
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Process.Kill()
	}

	// Forward stdin to the pty (OTP code input, etc.), watching for
	// terminateSentinel as the cue to end the tunnel — see its doc comment
	// for why this isn't done via EOF/Close() instead. The first sentinel
	// sends SIGTERM and arms a terminateGrace watchdog; a second sentinel
	// (the user clicking Disconnect again because nothing happened) escalates
	// to an immediate SIGKILL instead of silently no-op'ing like before.
	go func() {
		buf := make([]byte, 4096)
		terminating := false
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if idx := bytes.IndexByte(chunk, terminateSentinel); idx >= 0 {
					if !terminating {
						if idx > 0 {
							f.Write(chunk[:idx])
						}
						terminating = true
						if cmd.Process != nil {
							cmd.Process.Signal(syscall.SIGTERM)
						}
						go func() {
							select {
							case <-time.After(terminateGrace):
								killGroup()
							case <-exited:
							}
						}()
					} else {
						killGroup()
						return
					}
					continue
				}
				if !terminating {
					f.Write(chunk)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	io.Copy(os.Stdout, f) // blocks until the child exits and the pty closes
	close(exited)
	cmd.Wait()
	f.Close()
}
