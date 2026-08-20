//go:build linux

package main

import (
	"io"
	"os/exec"
	"syscall"
)

// unixElevatedProc wraps an *exec.Cmd behind the elevatedProc interface,
// merging stdout+stderr into one stream (via an io.Pipe) to match what
// macOS's AuthorizationExecuteWithPrivileges hands back — a single fd, not
// separate stdout/stderr — so vpn_manager.go can treat both the same way.
type unixElevatedProc struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.Reader
	pipeWriter io.WriteCloser
}

func (p *unixElevatedProc) Stdin() io.WriteCloser { return p.stdin }
func (p *unixElevatedProc) Stdout() io.Reader     { return p.stdout }
func (p *unixElevatedProc) Start() error          { return p.cmd.Start() }

func (p *unixElevatedProc) Wait() error {
	err := p.cmd.Wait()
	p.pipeWriter.Close() // unblocks the Stdout() reader with EOF
	return err
}

// Terminate sends SIGTERM, which pkexec forwards to openfortivpn, letting it
// tear down the tunnel/routes cleanly before exiting.
func (p *unixElevatedProc) Terminate() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Signal(syscall.SIGTERM)
}

// elevatedCommand runs `name args...` as root via pkexec, which shows the
// desktop's native polkit auth dialog and — unlike macOS's AppleScript
// "do shell script" equivalent — keeps stdin/stdout/stderr connected to the
// child process, so live log streaming and the interactive OTP prompt work.
func elevatedCommand(name string, args ...string) (elevatedProc, func(), error) {
	fullArgs := append([]string{name}, args...)
	cmd := exec.Command("pkexec", fullArgs...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	proc := &unixElevatedProc{cmd: cmd, stdin: stdin, stdout: pr, pipeWriter: pw}
	return proc, func() {}, nil
}

// runPtyExec is a no-op stub here — the "--pty-exec" hidden re-exec mode
// exists only to work around a macOS-specific AuthorizationExecuteWithPrivileges
// quirk (see ptyproxy_darwin.go); pkexec doesn't have that problem.
func runPtyExec(args []string) {}
