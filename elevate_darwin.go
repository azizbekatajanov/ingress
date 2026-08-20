//go:build darwin

package main

/*
#cgo LDFLAGS: -framework Security

#include <Security/Security.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

// AuthorizationExecuteWithPrivileges has been deprecated since OS X 10.7 —
// Apple's replacement (SMAppService) requires installing a permanent
// launchd-managed helper tool, which is exactly the heavier
// install-once-persistent-daemon model this app deliberately chose *not* to
// build (see the original architecture decision: a plain per-connection
// prompt, no standing privileged helper). This deprecated API is still what
// gives us that: a native system authorization dialog on every connect, with
// no persistent process. It's still shipped/used widely (e.g. Sparkle) years
// after deprecation; the pragma below just silences the compiler warning for
// calling it.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// cachedAuthRef is reused across every rp_execute call for the lifetime of
// this process, instead of creating a fresh AuthorizationRef each time. This
// is what makes the admin prompt appear only once per app launch: the granted
// right is cached *on this specific ref* by AuthorizationCopyRights (below),
// and macOS only re-prompts once that cached credential is gone — either
// because the ref was freed with kAuthorizationFlagDestroyRights (the
// previous version of this code did exactly that, on every single call,
// which is why it prompted every time instead of even getting the OS's
// normal several-minutes credential cache) or because the credential's own
// timeout elapsed from inactivity.
static AuthorizationRef cachedAuthRef = NULL;

// rp_execute prompts for admin authorization (native macOS dialog — a
// password-only "shield" prompt; third-party apps cannot trigger Touch ID
// for this specific right, that's an Apple-only policy restriction) and, if
// granted, runs `tool` with `argv` as root. On success, *outFd is a single
// fd wired to the child's stdin+stdout+stderr combined, and *outPid is its
// process ID (recovered via fcntl(F_GETOWN) on that fd, since this API
// doesn't return a pid directly — the same trick STPrivilegedTask uses).
static int rp_execute(const char *tool, char *const *argv, pid_t *outPid, int *outFd) {
    OSStatus status;
    if (cachedAuthRef == NULL) {
        status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &cachedAuthRef);
        if (status != errAuthorizationSuccess) {
            cachedAuthRef = NULL;
            return (int)status;
        }
    }

    AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    AuthorizationFlags flags = kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize | kAuthorizationFlagExtendRights;
    status = AuthorizationCopyRights(cachedAuthRef, &rights, kAuthorizationEmptyEnvironment, flags, NULL);
    if (status != errAuthorizationSuccess) {
        // Don't reuse a ref that just failed to (re-)authorize.
        AuthorizationFree(cachedAuthRef, kAuthorizationFlagDefaults);
        cachedAuthRef = NULL;
        return (int)status;
    }

    FILE *pipe = NULL;
    status = AuthorizationExecuteWithPrivileges(cachedAuthRef, tool, kAuthorizationFlagDefaults, argv, &pipe);
    if (status != errAuthorizationSuccess) {
        return (int)status;
    }

    int fd = fileno(pipe);
    *outFd = fd;
    *outPid = fcntl(fd, F_GETOWN, 0);

    // Deliberately not freed here — see cachedAuthRef's comment. It's reused
    // by the next call and released implicitly when the process exits.
    return 0;
}
#pragma clang diagnostic pop
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// authMu serializes access to rp_execute's cachedAuthRef (a single C-level
// global, not safe for concurrent use from multiple goroutines — e.g. two
// profiles connecting at nearly the same moment). Only the authorize+spawn
// step is serialized; once elevatedCommand returns, each profile's tunnel
// runs fully independently.
var authMu sync.Mutex

// authProc wraps the fd AuthorizationExecuteWithPrivileges hands back.
// Stdin() and Stdout() intentionally return the *same* underlying file — the
// API merges stdin/stdout/stderr into one fd — so this must never be
// Close()'d independently from the other, or both break at once.
type authProc struct {
	pid  int
	file *os.File
}

func (p *authProc) Stdin() io.WriteCloser { return p.file }
func (p *authProc) Stdout() io.Reader     { return p.file }

// Start is a no-op: AuthorizationExecuteWithPrivileges already forked+exec'd
// the process synchronously inside elevatedCommand, unlike exec.Cmd's
// separate Start() step.
func (p *authProc) Start() error { return nil }

func (p *authProc) Wait() error {
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(p.pid, &ws, 0, nil)
	return err
}

// Terminate writes terminateSentinel (see ptyproxy_darwin.go) instead of
// signaling p.pid directly or closing the file. Two things were tried and
// both failed live: (1) p.pid comes from fcntl(F_GETOWN) — a decades-old
// trick (see rp_execute) that isn't reliable, and it returned a value that
// made syscall.Kill(p.pid, SIGTERM) kill this app's *own* process group,
// quitting the whole GUI when the user clicked Disconnect; (2) closing the
// file was meant to deliver EOF to the --pty-exec child's stdin read, but a
// concurrent Read() on this cgo-sourced fd didn't reliably get interrupted by
// Close() — Disconnect just hung instead. Writing a byte through the same
// read loop that's already forwarding OTP input has neither problem.
func (p *authProc) Terminate() error {
	_, err := p.file.Write([]byte{terminateSentinel})
	return err
}

// elevatedCommand prompts for admin rights via the native macOS authorization
// dialog (Security.framework) and runs `name args...` as root. Unlike
// AppleScript's "do shell script ... with administrator privileges" (the
// previous implementation here), this is the real API for this exact
// purpose, and gives a native system dialog instead of a custom popup — see
// the rp_execute comment above for why the deprecated
// AuthorizationExecuteWithPrivileges specifically, not SMAppService.
//
// The actual tool doesn't run directly — this re-execs this same binary as
// `ingress --pty-exec <tool> <args...>` (see ptyproxy_darwin.go). Diagnosed
// live: AuthorizationExecuteWithPrivileges hands the child a plain socket as
// stdin/stdout/stderr, not a pty. openfortivpn ran fine that way right up
// until spawning pppd, which then failed with pppd's generic "mutually
// exclusive options" error — confirmed via a side-by-side test that plain
// `sudo openfortivpn` (which inherits Terminal's real pty) works perfectly
// with the exact same config, while the identical command run without a
// controlling terminal (both this API and the earlier AppleScript-based
// sudo, which has the same no-tty property) hits it. macOS's `script`
// utility looked like an off-the-shelf fix but isn't: it tries to copy
// termios settings from *its own* controlling terminal and errors out
// ("Operation not supported on socket") when there isn't one — exactly our
// situation. So --pty-exec allocates a fresh pty itself (via creack/pty,
// independent of its own stdio) instead.
func elevatedCommand(name string, args ...string) (elevatedProc, func(), error) {
	toolPath, err := exec.LookPath(name)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up %s: %w", name, err)
	}
	selfPath, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving own executable path: %w", err)
	}

	fullArgs := append([]string{"--pty-exec", toolPath}, args...)

	cToolPath := C.CString(selfPath)
	defer C.free(unsafe.Pointer(cToolPath))

	cArgs := make([]*C.char, len(fullArgs)+1)
	for i, a := range fullArgs {
		cArgs[i] = C.CString(a)
	}
	cArgs[len(fullArgs)] = nil
	defer func() {
		for _, a := range cArgs[:len(fullArgs)] {
			C.free(unsafe.Pointer(a))
		}
	}()

	authMu.Lock()
	var pid C.pid_t
	var fd C.int
	rc := C.rp_execute(cToolPath, (**C.char)(unsafe.Pointer(&cArgs[0])), &pid, &fd)
	authMu.Unlock()
	if rc != 0 {
		return nil, nil, fmt.Errorf("authorization failed or was cancelled (status %d)", int(rc))
	}

	proc := &authProc{pid: int(pid), file: os.NewFile(uintptr(fd), toolPath)}
	return proc, func() {}, nil
}
