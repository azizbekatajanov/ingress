package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func transferTestProfiles() []Profile {
	f := defaultProfile("p1", ProfileTypeFortinet)
	f.Name, f.Host, f.Port, f.Username = "Office", "vpn.corp.example", "10443", "ivanov"
	f.Logo = true
	f.Fortinet.Realm = "staff"
	f.Fortinet.TrustedCert = "abc123"
	f.Fortinet.CaFile, f.Fortinet.UserCert, f.Fortinet.UserKey, f.Fortinet.PppdLog = "/ca.pem", "/me.pem", "/me.key", "/tmp/ppp.log"

	g := defaultProfile("p2", ProfileTypeGlobalProtect)
	g.Name, g.Host = "Bank GP", "gp.bank.example"
	g.GlobalProtect.Gateway = "EU West"
	g.GlobalProtect.ServerCert = "pin-sha256:xyz"
	g.GlobalProtect.UserKey = "/Users/me/secret.key"

	s := defaultProfile("p3", ProfileTypeSSTP)
	s.Name, s.Host = "Branch", "203.0.113.9"
	s.SSTP.Subnets = []string{"172.16.10.0/24"}
	s.SSTP.CaFile = "/ca.pem"
	s.SSTP.InsecureCert = true
	return []Profile{f, g, s}
}

func TestTransferRoundTrip(t *testing.T) {
	src := transferTestProfiles()
	data, err := exportProfiles(src, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseProfiles(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d profiles", len(got))
	}
	f, g, s := got[0], got[1], got[2]
	if f.ID != "" || f.Logo || f.Name != "Office" || f.Port != "10443" || f.Username != "ivanov" ||
		f.Fortinet.Realm != "staff" || f.Fortinet.TrustedCert != "abc123" || !f.Fortinet.SetDns {
		t.Errorf("fortinet = %+v %+v", f, f.Fortinet)
	}
	if g.GlobalProtect.Gateway != "EU West" || g.GlobalProtect.ServerCert != "pin-sha256:xyz" || g.GlobalProtect.Auth != GPAuthAuto {
		t.Errorf("globalprotect = %+v", g.GlobalProtect)
	}
	if len(s.SSTP.Subnets) != 1 || !s.SSTP.InsecureCert {
		t.Errorf("sstp = %+v", s.SSTP)
	}

	// Exporting must not touch the stored profiles.
	if src[0].Fortinet.UserKey != "/me.key" || src[1].GlobalProtect.UserKey == "" {
		t.Error("export stripped paths from the original profiles")
	}
}

func TestTransferLeavesOutSecretsAndLocalPaths(t *testing.T) {
	data, err := exportProfiles(transferTestProfiles(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, leak := range []string{"/me.key", "/me.pem", "/ca.pem", "secret.key", "ppp.log", `"id"`, `"logo"`, "password"} {
		if strings.Contains(text, leak) {
			t.Errorf("export contains %q:\n%s", leak, text)
		}
	}

	// A hand-made file with paths gets them dropped on import too.
	in := `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"cisco","host":"h.example","port":"443","username":"","cisco":{"group":"","serverCert":"","caFile":"/etc/ca","userCert":"/c","userKey":"/k"}}]}`
	ps, err := parseProfiles(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if c := ps[0].Cisco; c.CaFile != "" || c.UserCert != "" || c.UserKey != "" {
		t.Errorf("paths kept on import: %+v", c)
	}
}

func TestTransferRejectsBadFiles(t *testing.T) {
	good := `{"name":"X","type":"fortinet","host":"h.example","port":"443","username":"u"}`
	cases := map[string]string{
		"not json":       `hello`,
		"other format":   `{"format":"something","version":1,"profiles":[` + good + `]}`,
		"newer version":  `{"format":"ingress-profiles","version":2,"profiles":[` + good + `]}`,
		"no profiles":    `{"format":"ingress-profiles","version":1,"profiles":[]}`,
		"unknown field":  `{"format":"ingress-profiles","version":1,"profiles":[` + good + `],"password":"x"}`,
		"profile field":  `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"fortinet","host":"h","port":"443","username":"u","password":"pw"}]}`,
		"bad type":       `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"openvpn","host":"h","port":"443","username":""}]}`,
		"mixed settings": `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"fortinet","host":"h","port":"443","username":"","sstp":{}}]}`,
		"no host":        `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"fortinet","host":"","port":"443","username":""}]}`,
		"host with path": `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"fortinet","host":"evil.example/x","port":"443","username":""}]}`,
		"bad port":       `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X","type":"fortinet","host":"h","port":"99999","username":""}]}`,
		"control char":   `{"format":"ingress-profiles","version":1,"profiles":[{"name":"X\u0007","type":"fortinet","host":"h","port":"443","username":""}]}`,
		"trailing data":  `{"format":"ingress-profiles","version":1,"profiles":[` + good + `]} {}`,
		"too big":        `{"format":"ingress-profiles","version":1,"exportedAt":"` + strings.Repeat("x", transferMaxBytes) + `","profiles":[` + good + `]}`,
	}
	for name, in := range cases {
		if _, err := parseProfiles(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseProfiles(strings.NewReader(`{"format":"ingress-profiles","version":1,"profiles":[` + good + `]}`)); err != nil {
		t.Errorf("good file refused: %v", err)
	}
}

func TestTransferPreviewAndImport(t *testing.T) {
	store := &ProfileStore{path: filepath.Join(t.TempDir(), "profiles.json")}
	existing := transferTestProfiles()[0]
	store.cfg.Profiles = []Profile{existing}

	data, _ := exportProfiles(transferTestProfiles(), time.Now())
	ps, err := parseProfiles(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	pv := previewImport("x.ingress", ps, store.List())
	if pv.Items[0].Duplicate != "Office" || pv.Items[1].Duplicate != "" {
		t.Errorf("duplicates = %q, %q", pv.Items[0].Duplicate, pv.Items[1].Duplicate)
	}
	if pv.Items[0].Insecure || !pv.Items[2].Insecure {
		t.Errorf("insecure flags = %v %v", pv.Items[0].Insecure, pv.Items[2].Insecure)
	}

	added, err := store.AddImported(ps)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{existing.ID: true}
	for _, p := range added {
		if p.ID == "" || ids[p.ID] {
			t.Errorf("bad or duplicate id %q", p.ID)
		}
		ids[p.ID] = true
	}
	if len(store.List()) != 4 || store.SelectedID() != added[0].ID {
		t.Errorf("store has %d profiles, selected %s", len(store.List()), store.SelectedID())
	}
	if got, _ := store.Get(existing.ID); got.Fortinet.UserKey != "/me.key" {
		t.Error("the existing profile was changed")
	}

	// It survives a reload from disk.
	reloaded := &ProfileStore{path: store.path}
	if err := reloaded.load(); err != nil || len(reloaded.List()) != 4 {
		t.Fatalf("reload: %v, %d profiles", err, len(reloaded.List()))
	}
}

func TestTransferFileIsValidJSON(t *testing.T) {
	data, _ := exportProfiles(transferTestProfiles()[:1], time.Now())
	var f map[string]interface{}
	if err := json.Unmarshal(data, &f); err != nil || f["format"] != transferFormat || f["version"].(float64) != 1 {
		t.Errorf("file = %s (%v)", data, err)
	}
}

func TestSafeFileName(t *testing.T) {
	for in, want := range map[string]string{"Office VPN": "Office VPN", "a/b:c": "a_b_c", "  ": "ingress-profile", "..": "ingress-profile"} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
