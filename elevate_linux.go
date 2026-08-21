//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
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

// Terminate writes terminateSentinel (see elevatedwrapper_linux.go) instead
// of signaling p.cmd.Process directly. That process is `pkexec`, and pkexec
// does not forward signals to the process it elevates — a documented,
// by-design polkit limitation. Sending SIGTERM there used to hit only
// pkexec itself, never openfortivpn running underneath it: confirmed live,
// every Disconnect click just re-logged "Завершение туннеля..." forever,
// since pump() never saw EOF. Writing the sentinel through the same stdin
// pipe that's already forwarding OTP input reaches elevatedwrapper_linux.go's
// runPtyExec instead, which — running at the same privilege level as the
// openfortivpn it directly spawned — can actually signal it.
func (p *unixElevatedProc) Terminate() error {
	_, err := p.stdin.Write([]byte{terminateSentinel})
	return err
}

// elevatedCommand runs `name args...` as root via pkexec, which shows the
// desktop's native polkit auth dialog and — unlike macOS's AppleScript
// "do shell script" equivalent — keeps stdin/stdout/stderr connected to the
// child process, so live log streaming and the interactive OTP prompt work.
//
// The actual tool doesn't run directly — like elevate_darwin.go, this
// re-execs this same binary as `pkexec ingress --pty-exec <tool> <args...>`
// (see elevatedwrapper_linux.go) rather than `pkexec <tool> <args...>`
// directly, purely so Terminate() above has a same-privilege process to
// signal.
func elevatedCommand(name string, args ...string) (elevatedProc, func(), error) {
	toolPath, err := exec.LookPath(name)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up %s: %w", name, err)
	}
	selfPath, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving own executable path: %w", err)
	}

	fullArgs := append([]string{selfPath, "--pty-exec", toolPath}, args...)
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
