package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A profiles.json exactly as 1.0.9 writes it.
const v109ProfilesJSON = `{
  "profiles": [
    {
      "id": "p20250819123456.000001",
      "name": "Офис",
      "host": "vpn.example.com",
      "port": "10443",
      "username": "ivanov",
      "realm": "staff",
      "logo": true,
      "caFile": "/Users/me/ca.pem",
      "userCert": "",
      "userKey": "",
      "trustedCert": "e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db",
      "insecureSsl": false,
      "setDns": false,
      "pppdUsePeerdns": true,
      "setRoutes": true,
      "halfInternetRoutes": true,
      "pppdLog": "/tmp/pppd.log"
    },
    {
      "id": "p20250819123456.000002",
      "name": "Новый профиль",
      "host": "",
      "port": "443",
      "username": "",
      "realm": "",
      "logo": false,
      "caFile": "",
      "userCert": "",
      "userKey": "",
      "trustedCert": "",
      "insecureSsl": false,
      "setDns": true,
      "pppdUsePeerdns": false,
      "setRoutes": true,
      "halfInternetRoutes": false,
      "pppdLog": ""
    }
  ],
  "selectedProfileId": "p20250819123456.000001",
  "theme": "dark",
  "skipQuitConfirm": true
}`

func writeProfilesFile(t *testing.T, content string) (*ProfileStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ProfileStore{path: path}
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestMigrateFrom109(t *testing.T) {
	s, dir := writeProfilesFile(t, v109ProfilesJSON)

	ps := s.List()
	if len(ps) != 2 {
		t.Fatalf("got %d profiles", len(ps))
	}
	p := ps[0]
	if p.Type != ProfileTypeFortinet || p.Fortinet == nil || p.GlobalProtect != nil {
		t.Fatalf("type/settings not migrated: %+v", p)
	}
	want := FortinetSettings{
		Realm: "staff", CaFile: "/Users/me/ca.pem",
		TrustedCert: "e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db",
		SetDns:      false, PppdUsePeerdns: true, SetRoutes: true, HalfInternetRoutes: true,
		PppdLog: "/tmp/pppd.log",
	}
	if *p.Fortinet != want {
		t.Errorf("fortinet settings = %+v\nwant %+v", *p.Fortinet, want)
	}
	if p.Name != "Офис" || p.Host != "vpn.example.com" || p.Port != "10443" || p.Username != "ivanov" || !p.Logo {
		t.Errorf("common fields lost: %+v", p)
	}
	if s.SelectedID() != "p20250819123456.000001" || s.Theme() != "dark" || !s.SkipQuitConfirm() {
		t.Error("top-level settings lost")
	}

	// Backup is the untouched original.
	backup, err := os.ReadFile(filepath.Join(dir, "profiles.v1.json"))
	if err != nil || string(backup) != v109ProfilesJSON {
		t.Fatalf("backup missing or modified: %v", err)
	}

	// Rewritten file is in the new shape, without the flat fields.
	data, _ := os.ReadFile(filepath.Join(dir, "profiles.json"))
	var raw struct {
		Profiles []map[string]any `json:"profiles"`
	}
	json.Unmarshal(data, &raw)
	if _, flat := raw.Profiles[0]["realm"]; flat {
		t.Error("flat legacy fields still written")
	}
	if raw.Profiles[0]["type"] != "fortinet" {
		t.Errorf("type not persisted: %v", raw.Profiles[0]["type"])
	}

	// Loading again is a no-op and doesn't touch the backup.
	os.WriteFile(filepath.Join(dir, "profiles.v1.json"), []byte("keep"), 0o600)
	s2 := &ProfileStore{path: filepath.Join(dir, "profiles.json")}
	if err := s2.load(); err != nil {
		t.Fatal(err)
	}
	if got := s2.List()[0].Fortinet.Realm; got != "staff" {
		t.Errorf("second load realm = %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "profiles.v1.json")); string(b) != "keep" {
		t.Error("existing backup was overwritten")
	}
}

func TestAddAndUpdateKeepTypeInvariant(t *testing.T) {
	s, _ := writeProfilesFile(t, `{"profiles": []}`)

	if _, err := s.Add("juniper"); err == nil {
		t.Error("unknown type must be rejected")
	}
	gp, err := s.Add(ProfileTypeGlobalProtect)
	if err != nil {
		t.Fatal(err)
	}
	if gp.GlobalProtect == nil || gp.Fortinet != nil || gp.GlobalProtect.Auth != GPAuthAuto || gp.GlobalProtect.ConnectTo != GPConnectPortal {
		t.Fatalf("GP defaults: %+v", gp)
	}

	// A stale/malicious frontend copy can't flip the type or smuggle in the
	// other protocol's settings.
	tampered := gp
	tampered.Type = ProfileTypeFortinet
	tampered.Fortinet = &FortinetSettings{Realm: "x"}
	tampered.GlobalProtect = &GlobalProtectSettings{Auth: "bogus", ConnectTo: GPConnectGateway, HipReport: true}
	if err := s.Update(tampered); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(gp.ID)
	if got.Type != ProfileTypeGlobalProtect || got.Fortinet != nil {
		t.Fatalf("type changed by Update: %+v", got)
	}
	if got.GlobalProtect.Auth != GPAuthAuto || got.GlobalProtect.ConnectTo != GPConnectGateway || !got.GlobalProtect.HipReport {
		t.Errorf("GP settings not normalized/kept: %+v", got.GlobalProtect)
	}

	ft, _ := s.Add(ProfileTypeFortinet)
	if ft.Fortinet == nil || !ft.Fortinet.SetDns || !ft.Fortinet.SetRoutes {
		t.Errorf("Fortinet defaults: %+v", ft.Fortinet)
	}
}

func TestOpenfortivpnConfigUsesNestedSettings(t *testing.T) {
	p := defaultProfile("p1", ProfileTypeFortinet)
	p.Username = "u"
	p.Fortinet.Realm = "staff"
	p.Fortinet.TrustedCert = "abc"
	path, err := writeOpenfortivpnConfig(p, "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	data, _ := os.ReadFile(path)
	for _, line := range []string{"username = u\n", "password = secret\n", "realm = staff\n", "trusted-cert = abc\n", "set-dns = true\n"} {
		if !strings.Contains(string(data), line) {
			t.Errorf("config missing %q:\n%s", line, data)
		}
	}
	if _, err := writeOpenfortivpnConfig(defaultProfile("p2", ProfileTypeGlobalProtect), ""); err == nil {
		t.Error("a GP profile must not produce an openfortivpn config")
	}
}
