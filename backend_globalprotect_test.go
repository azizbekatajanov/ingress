package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Lines below are the exact formats openconnect v9.21 prints (see the
// source references in backend_globalprotect.go).

func TestGlobalProtectParse(t *testing.T) {
	gp := globalProtectBackend{}
	pin := "pin-sha256:xp3scfzy3rOgQEXnfPiYKrUk7D66a8b8O+gEXaMPleE="
	cases := []struct {
		line   string
		prompt bool
		want   []lineEvent
	}{
		{"Connected to 203.0.113.5:443", false, nil},
		{"2 gateway servers available:", false, nil},
		{"  US East (us-east.vpn.example.com) [priority 1]", false, nil},
		{"GATEWAY: [US East|EU West]:", true, []lineEvent{{Kind: evPrompt, Prompt: PromptChoice, Label: "GATEWAY:", Options: []string{"US East", "EU West"}}}},
		// single choice: openconnect answers it itself and prints a newline
		{"GATEWAY: [US East]:US East", false, nil},
		{"Challenge: ", true, []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}},
		{"Password: ", true, []lineEvent{{Kind: evFatal, Value: "сервер отклонил логин или пароль (запрос «Password:»)"}}},
		{"Username: ", true, []lineEvent{{Kind: evFatal, Value: "сервер запросил имя пользователя — проверьте его в настройках профиля"}}},
		{"    --servercert " + pin, false, []lineEvent{
			{Kind: evServerCert, Value: pin},
			{Kind: evError, Sticky: true, Value: "сертификат сервера не прошёл проверку — он сохранён в профиле, нажмите «Подключить» ещё раз, если доверяете этому серверу"},
		}},
		{"Enter 'yes' to accept, 'no' to abort; anything else to view: ", true, []lineEvent{{Kind: evReply, Value: "no"}}},
		{"Configured as 10.10.0.27, with SSL connected and ESP in progress", false, []lineEvent{{Kind: evAssignedIP, Value: "10.10.0.27"}}},
		{"ESP session established with server", false, nil},
		{"Failed to connect ESP tunnel; using HTTPS instead.", false, nil},
		{"Authentication failed: Invalid username or password", false, []lineEvent{{Kind: evError, Value: "Authentication failed: Invalid username or password"}}},
		{"Failed to obtain WebVPN cookie", false, []lineEvent{{Kind: evError, Value: "Failed to obtain WebVPN cookie"}}},
		{"SAML REDIRECT authentication is required via https://idp.example.com/sso", false, []lineEvent{{Kind: evFatal, Value: "сервер требует вход через SAML. Выберите способ входа «Автоматически» или «SAML»; если он уже выбран — значит, шлюз требует отдельный вход: выберите «Подключаться к: напрямую к шлюзу» и укажите адрес шлюза"}}},
		// a normal line ending in ':' is not a prompt unless it was left unterminated
		{"2 gateway servers available:", true, []lineEvent{{Kind: evFatal, Value: "сервер отклонил логин или пароль (запрос «2 gateway servers available:»)"}}},
	}
	for _, c := range cases {
		if got := gp.Parse(c.line, c.prompt); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q, %v) =\n  %+v\nwant\n  %+v", c.line, c.prompt, got, c.want)
		}
	}
}

func gpProfile() Profile {
	p := defaultProfile("gp1", ProfileTypeGlobalProtect)
	p.Host, p.Port, p.Username = "vpn.example.com", "443", "ivanov"
	return p
}

func TestGlobalProtectPrepare(t *testing.T) {
	// Managed-install layout: bin/openconnect + libexec/{vpnc-script,hipreport.sh}
	// A space in the path, like Ingress' real install location.
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(tmp, "Application Support", "openconnect")
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	os.MkdirAll(filepath.Join(root, "libexec"), 0o755)
	tool := filepath.Join(root, "bin", "openconnect")
	os.WriteFile(tool, nil, 0o755)
	os.WriteFile(filepath.Join(root, "libexec", "vpnc-script"), nil, 0o755)
	os.WriteFile(filepath.Join(root, "libexec", "hipreport.sh"), nil, 0o755)

	p := gpProfile()
	p.GlobalProtect.Gateway = "US East"
	p.GlobalProtect.ServerCert = "pin-sha256:abc="
	p.GlobalProtect.HipReport = true
	l, err := (globalProtectBackend{}).Prepare(p, authInput{Password: "hunter2"}, tool)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--protocol=gp", "--user=ivanov", "--passwd-on-stdin",
		"--authgroup=US East", "--servercert=pin-sha256:abc=",
		"--script='" + filepath.Join(root, "libexec", "vpnc-script") + "'",
		"--csd-wrapper=" + filepath.Join(root, "libexec", "hipreport.sh"),
		"vpn.example.com",
	}
	if !reflect.DeepEqual(l.Args, want) {
		t.Errorf("args =\n  %q\nwant\n  %q", l.Args, want)
	}
	if l.Stdin != "hunter2" || strings.Contains(strings.Join(l.Args, " "), "hunter2") {
		t.Error("password must go via stdin only")
	}

	// Direct-to-gateway, custom port, no helper scripts (system build).
	p = gpProfile()
	p.Port = "8443"
	p.GlobalProtect.ConnectTo = GPConnectGateway
	p.GlobalProtect.Gateway = "ignored when connecting to a gateway"
	l, err = (globalProtectBackend{}).Prepare(p, authInput{Password: "pw"}, "/nonexistent/bin/openconnect")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"--protocol=gp", "--user=ivanov", "--passwd-on-stdin", "--usergroup=gateway", "https://vpn.example.com:8443"}
	if !reflect.DeepEqual(l.Args, want) {
		t.Errorf("gateway args =\n  %q\nwant\n  %q", l.Args, want)
	}

	// Refusals that would otherwise hang on a prompt or fail obscurely.
	p = gpProfile()
	p.GlobalProtect.HipReport = true
	if _, err := (globalProtectBackend{}).Prepare(p, authInput{Password: "pw"}, "/nonexistent/bin/openconnect"); err == nil {
		t.Error("HIP report without hipreport.sh must be refused")
	}
	p = gpProfile()
	if _, err := (globalProtectBackend{}).Prepare(p, authInput{}, tool); err == nil {
		t.Error("empty password must be refused")
	}
	p.GlobalProtect.Auth = GPAuthSAML
	if _, err := (globalProtectBackend{}).Prepare(p, authInput{Password: "pw"}, tool); err == nil {
		t.Error("SAML auth without a SAML result must be refused")
	}
}

type fakeProc struct {
	stdin      bytes.Buffer
	terminated bool
}

func (f *fakeProc) Stdin() io.WriteCloser { return nopWriteCloser{&f.stdin} }
func (f *fakeProc) Stdout() io.Reader     { return strings.NewReader("") }
func (f *fakeProc) Start() error          { return nil }
func (f *fakeProc) Wait() error           { return nil }
func (f *fakeProc) Terminate() error      { f.terminated = true; return nil }

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func newGPTestConn(t *testing.T) (*Manager, *liveConnection, *fakeProc) {
	t.Helper()
	m, conn, _ := newTestManager(t, gpProfile())
	proc := &fakeProc{}
	conn.backend = globalProtectBackend{}
	conn.proc = proc
	conn.stdin = proc.Stdin()
	return m, conn, proc
}

func TestManagerGatewayChoiceIsRemembered(t *testing.T) {
	m, conn, proc := newGPTestConn(t)

	m.handleLine(conn, "GATEWAY: [US East|EU West]:", true)
	snap := conn.snapshotLocked()
	if snap.Status != StatusChoose || snap.PromptLabel != "GATEWAY:" || !reflect.DeepEqual(snap.PromptOptions, []string{"US East", "EU West"}) {
		t.Fatalf("snapshot = %+v", snap)
	}
	if err := m.SubmitPrompt("gp1", "Mars"); err == nil {
		t.Error("an option that wasn't offered must be refused")
	}
	if err := m.SubmitPrompt("gp1", "EU West"); err != nil {
		t.Fatal(err)
	}
	if proc.stdin.String() != "EU West\n" || conn.status != StatusConnecting {
		t.Errorf("stdin=%q status=%s", proc.stdin.String(), conn.status)
	}
	if got, _ := m.store.Get("gp1"); got.GlobalProtect.Gateway != "EU West" {
		t.Errorf("gateway not remembered: %q", got.GlobalProtect.Gateway)
	}

	m.handleLine(conn, "Configured as 10.10.0.27, with SSL connected and ESP in progress", false)
	if conn.status != StatusConnected || conn.assignedIP != "10.10.0.27" {
		t.Errorf("status=%s ip=%s", conn.status, conn.assignedIP)
	}
}

func TestManagerUntrustedCertFlow(t *testing.T) {
	m, conn, proc := newGPTestConn(t)
	pin := "pin-sha256:xp3scfzy3rOgQEXnfPiYKrUk7D66a8b8O+gEXaMPleE="

	m.handleLine(conn, `Certificate from VPN server "vpn.example.com" failed verification.`, false)
	m.handleLine(conn, "    --servercert "+pin, false)
	m.handleLine(conn, "Enter 'yes' to accept, 'no' to abort; anything else to view: ", true)
	m.handleLine(conn, "Failed to obtain WebVPN cookie", false)

	if proc.stdin.String() != "no\n" {
		t.Errorf("must answer no, wrote %q", proc.stdin.String())
	}
	if got, _ := m.store.Get("gp1"); got.GlobalProtect.ServerCert != pin {
		t.Errorf("pin not saved: %q", got.GlobalProtect.ServerCert)
	}
	if !strings.Contains(conn.lastError, "сертификат сервера") {
		t.Errorf("explanation overwritten by generic failure: %q", conn.lastError)
	}
}

func TestManagerRejectedPasswordFails(t *testing.T) {
	m, conn, proc := newGPTestConn(t)
	m.handleLine(conn, "Authentication failed: Invalid username or password", false)
	m.handleLine(conn, "Password: ", true)
	if !proc.terminated || !conn.failed || !strings.Contains(conn.lastError, "отклонил") {
		t.Errorf("terminated=%v failed=%v lastError=%q", proc.terminated, conn.failed, conn.lastError)
	}
}

func TestInterfaceWithIP(t *testing.T) {
	want := "lo0"
	if runtime.GOOS == "linux" {
		want = "lo"
	}
	if got := interfaceWithIP("127.0.0.1"); got != want {
		t.Errorf("interfaceWithIP(127.0.0.1) = %q, want %q", got, want)
	}
	if got := interfaceWithIP("192.0.2.254"); got != "" {
		t.Errorf("unassigned IP matched %q", got)
	}
}

func TestShellQuoteSurvivesSh(t *testing.T) {
	for _, s := range []string{"/Library/Application Support/x", "it's", "$HOME;rm -rf /"} {
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+shellQuote(s)).Output()
		if err != nil || string(out) != s {
			t.Errorf("sh round-trip of %q = %q, %v", s, out, err)
		}
	}
}
