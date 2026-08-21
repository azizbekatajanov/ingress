//go:build linux

package main

// This is Linux's counterpart to ptyproxy_darwin.go — same "--pty-exec"
// hidden re-exec trick, different reason. pkexec does NOT forward signals
// to the process it elevates (a documented, by-design polkit limitation,
// not a bug to work around differently): sending SIGTERM to the `pkexec`
// process we spawn only ever hit pkexec itself, never openfortivpn running
// underneath it. Confirmed live: every Disconnect click just re-logged
// "Завершение туннеля..." forever — pump() never saw EOF because
// openfortivpn never actually received anything and kept running.
//
// The fix: elevate_linux.go now re-execs THIS binary via pkexec instead of
// openfortivpn directly (`pkexec ingress --pty-exec <openfortivpn> args...`,
// mirroring elevate_darwin.go). Once elevated, this process execs
// openfortivpn as its own direct child — signalling that child from here is
// a same-privilege operation, no cross-boundary signal delivery involved.
// No pty is needed here (unlike macOS): pkexec already keeps stdin/stdout/
// stderr properly connected, per elevate_linux.go's own comment.

import (
	"bytes"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// terminateSentinel matches ptyproxy_darwin.go's value, though the two
// never need to agree with each other — each platform's elevatedProc only
// ever talks to its own same-platform wrapper.
const terminateSentinel = 0x04

// terminateGrace mirrors ptyproxy_darwin.go's: how long to wait for
// openfortivpn to exit cleanly after SIGTERM (it does a graceful HTTPS
// logout round-trip to the gateway, which can hang) before escalating to
// SIGKILL of the whole process group.
const terminateGrace = 6 * time.Second

func runPtyExec(args []string) {
	if len(args) < 1 {
		os.Exit(64) // EX_USAGE
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	// New process group so killGroup below can take down openfortivpn's own
	// children (pppd) too, not just openfortivpn itself.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		os.Exit(1)
	}
	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}

	exited := make(chan struct{})

	// Forward SIGTERM/SIGINT (if this wrapper itself ever receives one) to
	// the real child, same as ptyproxy_darwin.go.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	killGroup := func() {
		if cmd.Process == nil {
			return
		}
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Process.Kill()
	}

	// Forward stdin to the child (OTP code input, etc.), watching for
	// terminateSentinel as the cue to end the tunnel. First sentinel sends
	// SIGTERM and arms a terminateGrace watchdog; a second sentinel (the
	// user clicking Disconnect again because nothing happened) escalates
	// straight to SIGKILL.
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
							stdin.Write(chunk[:idx])
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
					stdin.Write(chunk)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	cmd.Wait()
	close(exited)
	stdin.Close()
}
