package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFortinetParse(t *testing.T) {
	cert := "e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db"
	cases := []struct {
		line string
		want []lineEvent
	}{
		{"INFO:   Connected to gateway.", nil},
		{"Two-factor authentication token: ", []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}},
		{"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.",
			[]lineEvent{{Kind: evError, Value: "Could not authenticate to gateway. Please check the password, client certificate, etc."}}},
		{"    --trusted-cert " + cert, []lineEvent{{Kind: evServerCert, Value: cert}}},
		{"local  IP address 10.211.1.20", []lineEvent{{Kind: evAssignedIP, Value: "10.211.1.20"}}},
		{"INFO:   Interface ppp0 is UP.", []lineEvent{{Kind: evInterfaceUp, Value: "ppp0"}}},
		{"Please enter one-time password:", []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}},
		{"Enter your token code", []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}},
		// hex digests with "2fa"/"otp"-like runs are not prompts
		{"    sha256 digest: a422fa7ce16631bff0b592a28556f993", nil},
	}
	for _, c := range cases {
		if got := (fortinetBackend{}).Parse(c.line, false); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %+v, want %+v", c.line, got, c.want)
		}
	}
}

func TestFortinetPrepareKeepsSecretsOffArgv(t *testing.T) {
	p := defaultProfile("p1", ProfileTypeFortinet)
	p.Host, p.Port = "vpn.example.com", "10443"
	l, err := (fortinetBackend{}).Prepare(p, authInput{Password: "hunter2"}, "/usr/bin/openfortivpn")
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != "vpn.example.com:10443" || l.Args[0] != l.Target {
		t.Errorf("target/args: %+v", l)
	}
	cfg := strings.TrimPrefix(l.Args[1], "--config=")
	if strings.Contains(strings.Join(l.Args, " "), "hunter2") {
		t.Error("password on argv")
	}
	if fi, err := os.Stat(cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", fi, err)
	}
	l.Cleanup()
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Error("Cleanup left the config file behind")
	}
}

// newTestManager returns a Manager with a temp profile store and recorded
// frontend events, plus a connection in the connecting state.
func newTestManager(t *testing.T, p Profile) (*Manager, *liveConnection, *[]string) {
	t.Helper()
	store := &ProfileStore{path: filepath.Join(t.TempDir(), "profiles.json")}
	store.cfg.Profiles = []Profile{p}
	var events []string
	m := &Manager{
		events: func(name string, _ ...interface{}) { events = append(events, name) },
		conns:  map[string]*liveConnection{},
		store:  store,
	}
	conn := &liveConnection{profileID: p.ID, backend: fortinetBackend{}, status: StatusConnecting, done: make(chan struct{})}
	m.conns[p.ID] = conn
	return m, conn, &events
}

func TestManagerFortinetFlow(t *testing.T) {
	p := defaultProfile("p1", ProfileTypeFortinet)
	m, conn, events := newTestManager(t, p)

	m.handleLine(conn, "INFO:   Connected to gateway.", false)
	if conn.status != StatusConnecting {
		t.Fatalf("status = %s", conn.status)
	}
	m.handleLine(conn, "Two-factor authentication token: ", true)
	if conn.status != StatusOtp || conn.otpDeadline.IsZero() {
		t.Fatalf("OTP prompt: status = %s", conn.status)
	}
	conn.status = StatusConnecting // what SubmitOtp does before writing the code
	m.handleLine(conn, "local  IP address 10.211.1.20", false)
	if conn.status != StatusConnected || conn.assignedIP != "10.211.1.20" || conn.iface != "ppp0" {
		t.Fatalf("connected: status=%s ip=%s iface=%s", conn.status, conn.assignedIP, conn.iface)
	}
	m.handleLine(conn, "INFO:   Interface ppp3 is UP.", false)
	if conn.iface != "ppp3" {
		t.Errorf("iface = %s", conn.iface)
	}
	if len(*events) == 0 || (*events)[0] != "vpn:update" {
		t.Errorf("events = %v", *events)
	}
}

func TestManagerIgnoresPromptsWhileCancelling(t *testing.T) {
	m, conn, _ := newTestManager(t, defaultProfile("p1", ProfileTypeFortinet))
	conn.cancelling = true
	m.handleLine(conn, "Two-factor authentication token: ", true)
	m.handleLine(conn, "local  IP address 10.211.1.20", false)
	if conn.status != StatusConnecting {
		t.Errorf("status changed while cancelling: %s", conn.status)
	}
}

func TestManagerSavesTrustedCertOnce(t *testing.T) {
	p := defaultProfile("p1", ProfileTypeFortinet)
	m, conn, events := newTestManager(t, p)
	cert := strings.Repeat("ab", 32)

	m.handleLine(conn, "ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist.", false)
	m.handleLine(conn, "    --trusted-cert "+cert, false)
	got, _ := m.store.Get("p1")
	if got.Fortinet.TrustedCert != cert {
		t.Fatalf("trusted cert = %q", got.Fortinet.TrustedCert)
	}
	if conn.lastError == "" {
		t.Error("error line not recorded")
	}
	found := false
	for _, e := range *events {
		found = found || e == "profile:updated"
	}
	if !found {
		t.Error("frontend not told about the updated profile")
	}

	// An existing pin is never replaced automatically.
	m.handleLine(conn, "    --trusted-cert "+strings.Repeat("cd", 32), false)
	if got, _ := m.store.Get("p1"); got.Fortinet.TrustedCert != cert {
		t.Error("existing trusted cert overwritten")
	}
}
