package main

import (
	"reflect"
	"strings"
	"testing"
)

// feed runs captured openconnect output through a ciscoBackend; a line
// ending in "|PROMPT" is an unterminated prompt (see Manager.pump).
func feed(b *ciscoBackend, lines ...string) [][]lineEvent {
	var out [][]lineEvent
	for _, l := range lines {
		prompt := strings.HasSuffix(l, "|PROMPT")
		out = append(out, b.Parse(strings.TrimSuffix(l, "|PROMPT"), prompt))
	}
	return out
}

// Captured from openconnect 9.21 (ingress-deps r2) against ocserv with
// select-group and plain+OTP auth.
var ocservPreamble = []string{
	"POST https://localhost:4443/",
	"Connected to 127.0.0.1:4443",
	"SSL negotiation with localhost",
	"Server certificate verify failed: self-signed certificate",
	"Connected to HTTPS on localhost with ciphersuite TLSv1.2-ECDHE-RSA-AES256-GCM-SHA384",
	"XML POST enabled",
	"Please enter your username.",
}

func TestCiscoGroupPrompt(t *testing.T) {
	b := &ciscoBackend{}
	evs := feed(b, append(ocservPreamble, "Group: [Engineering|Sales]:|PROMPT")...)
	for _, e := range evs[:len(evs)-1] {
		if len(e) != 0 {
			t.Fatalf("preamble produced events: %+v", e)
		}
	}
	want := []lineEvent{{Kind: evPrompt, Prompt: PromptChoice, Label: "Group:", Options: []string{"Engineering", "Sales"}}}
	if got := evs[len(evs)-1]; !reflect.DeepEqual(got, want) {
		t.Fatalf("group prompt: %+v", got)
	}

	p := defaultProfile("c1", ProfileTypeCisco)
	if !b.RememberChoice(&p, "Group:", "Sales") || p.Cisco.Group != "Sales" {
		t.Errorf("group not remembered: %+v", p.Cisco)
	}
	if b.RememberChoice(&p, "Server:", "x") {
		t.Error("non-group selects must not overwrite the group")
	}
}

func TestCiscoSecondFactor(t *testing.T) {
	b := &ciscoBackend{}
	evs := feed(b, append(ocservPreamble,
		"POST https://localhost:4443/auth",
		"Please enter your password.",
		"POST https://localhost:4443/auth",
		"Please enter your OTP password.",
		"Password:|PROMPT",
	)...)
	want := []lineEvent{{Kind: evPrompt, Prompt: PromptText, Label: "Password", Value: "Please enter your OTP password."}}
	if got := evs[len(evs)-1]; !reflect.DeepEqual(got, want) {
		t.Fatalf("2FA prompt: %+v", got)
	}
}

func TestCiscoWrongPassword(t *testing.T) {
	b := &ciscoBackend{}
	evs := feed(b, append(ocservPreamble,
		"POST https://localhost:4443/auth",
		"Please enter your password.",
		"POST https://localhost:4443/auth",
		"Login failed.",
		"Please enter your password.",
		"Password:|PROMPT",
	)...)
	last := evs[len(evs)-1]
	if len(last) != 1 || last[0].Kind != evFatal || !strings.Contains(last[0].Value, "Login failed.") {
		t.Fatalf("wrong password: %+v", last)
	}
}

func TestCiscoWrongCodeAndOthers(t *testing.T) {
	cases := map[string]lineEvent{
		"Got HTTP response: HTTP/1.1 401 Authentication failed": {Kind: evError, Value: "сервер отклонил данные входа (401) — неверный пароль или код"},
		"Failed to complete authentication":                     {Kind: evError, Fallback: true, Value: "Failed to complete authentication"},
		"Error: Server asked us to run CSD hostscan.":           {Kind: evFatal, Value: "сервер требует проверку компьютера (Cisco hostscan/CSD), а Ingress её пока не поддерживает"},
		"No SSO handler": {Kind: evFatal, Value: "сервер требует вход через SSO (SAML), а для Cisco Ingress его пока не поддерживает — выберите на сервере группу с входом по паролю"},
		"Configured as 192.168.99.10, with SSL connected and DTLS in progress": {Kind: evAssignedIP, Value: "192.168.99.10"},
		"Enter 'yes' to accept, 'no' to abort; anything else to view: ":        {Kind: evReply, Value: "no"},
	}
	for line, want := range cases {
		got := (&ciscoBackend{}).Parse(line, false)
		if len(got) == 0 || !reflect.DeepEqual(got[0], want) {
			t.Errorf("Parse(%q) = %+v, want %+v", line, got, want)
		}
	}
	pin := "pin-sha256:2uDKADUPlKC0dZhKa8040ZsA1OKf2uwY131yrbcWC+M="
	got := (&ciscoBackend{}).Parse("    --servercert "+pin, false)
	if len(got) < 1 || got[0].Kind != evServerCert || got[0].Value != pin {
		t.Errorf("servercert: %+v", got)
	}
}

func TestCiscoPrepare(t *testing.T) {
	p := defaultProfile("c1", ProfileTypeCisco)
	p.Host, p.Port, p.Username = "vpn.example.com", "8443", "alice"
	p.Cisco.Group = "Sales"
	p.Cisco.ServerCert = "pin-sha256:abc="
	l, err := (&ciscoBackend{}).Prepare(p, authInput{Password: "secret"}, "/nonexistent/bin/openconnect")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--protocol=anyconnect", "--user=alice", "--passwd-on-stdin", "--authgroup=Sales", "--servercert=pin-sha256:abc=", "https://vpn.example.com:8443"}
	if !reflect.DeepEqual(l.Args, want) || l.Stdin != "secret" {
		t.Errorf("args = %q stdin=%q", l.Args, l.Stdin)
	}
	if _, err := (&ciscoBackend{}).Prepare(p, authInput{}, "/x"); err == nil {
		t.Error("empty password must be refused")
	}
}

func TestManagerCiscoFlow(t *testing.T) {
	p := defaultProfile("c1", ProfileTypeCisco)
	m, conn, _ := newTestManager(t, p)
	proc := &fakeProc{}
	conn.backend, conn.proc, conn.stdin = &ciscoBackend{}, proc, proc.Stdin()

	for _, l := range ocservPreamble {
		m.handleLine(conn, l, false)
	}
	m.handleLine(conn, "Group: [Engineering|Sales]:", true)
	if conn.status != StatusChoose {
		t.Fatalf("status = %s", conn.status)
	}
	if err := m.SubmitPrompt("c1", "Engineering"); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.store.Get("c1"); got.Cisco.Group != "Engineering" {
		t.Errorf("group not saved: %+v", got.Cisco)
	}

	m.handleLine(conn, "Please enter your OTP password.", false)
	m.handleLine(conn, "Password:", true)
	snap := conn.snapshotLocked()
	if snap.Status != StatusOtp || snap.PromptLabel != "Password" || snap.PromptMessage != "Please enter your OTP password." {
		t.Fatalf("2FA snapshot: %+v", snap)
	}
	if err := m.SubmitPrompt("c1", "push"); err != nil {
		t.Fatal(err)
	}
	if proc.stdin.String() != "Engineering\npush\n" {
		t.Errorf("stdin = %q", proc.stdin.String())
	}
	m.handleLine(conn, "Configured as 192.168.99.10, with SSL connected and DTLS in progress", false)
	if conn.status != StatusConnected {
		t.Errorf("status = %s", conn.status)
	}
}
