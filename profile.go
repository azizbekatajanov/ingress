package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Profile types. A profile's type is chosen when it's created and never
// changes afterwards (Update keeps the stored one) — switching protocols
// means a different set of settings, so it's a new profile.
const (
	ProfileTypeFortinet      = "fortinet"
	ProfileTypeGlobalProtect = "globalprotect"
	ProfileTypeCisco         = "cisco"
)

func validProfileType(t string) bool {
	return t == ProfileTypeFortinet || t == ProfileTypeGlobalProtect || t == ProfileTypeCisco
}

// Profile holds one VPN profile's non-secret configuration: the fields every
// VPN type shares at the top, protocol-specific settings in the nested struct
// matching Type (the other one is always nil).
// Password is intentionally excluded — it lives in the OS keychain, see credentials.go.
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	// Logo reports that logos/<id>.png exists (see logo.go). Managed only by
	// SetLogo — Update ignores the incoming value so a debounced save from a
	// stale frontend copy can't wipe it.
	Logo bool `json:"logo"`

	Fortinet      *FortinetSettings      `json:"fortinet,omitempty"`
	GlobalProtect *GlobalProtectSettings `json:"globalprotect,omitempty"`
	Cisco         *CiscoSettings         `json:"cisco,omitempty"`
}

// CiscoSettings is what openconnect --protocol=anyconnect needs (Cisco
// Secure Client / AnyConnect, and ocserv servers).
type CiscoSettings struct {
	// Group is the connection profile ("tunnel group") picked last time
	// (openconnect --authgroup); empty means ask.
	Group string `json:"group"`
	// ServerCert pins the server certificate (--servercert pin-sha256:...),
	// auto-filled on first connect like GlobalProtect's.
	ServerCert string `json:"serverCert"`
	CaFile     string `json:"caFile"`
	UserCert   string `json:"userCert"`
	UserKey    string `json:"userKey"`
}

// FortinetSettings maps 1:1 onto openfortivpn's config file (see
// openfortivpn_config.go).
type FortinetSettings struct {
	Realm       string `json:"realm"`
	CaFile      string `json:"caFile"`
	UserCert    string `json:"userCert"`
	UserKey     string `json:"userKey"`
	TrustedCert string `json:"trustedCert"`
	InsecureSsl bool   `json:"insecureSsl"`

	SetDns             bool   `json:"setDns"`
	PppdUsePeerdns     bool   `json:"pppdUsePeerdns"`
	SetRoutes          bool   `json:"setRoutes"`
	HalfInternetRoutes bool   `json:"halfInternetRoutes"`
	PppdLog            string `json:"pppdLog"`
}

// GlobalProtect auth methods and connection targets.
const (
	GPAuthAuto     = "auto" // decided per connect from the portal's prelogin.esp
	GPAuthPassword = "password"
	GPAuthSAML     = "saml"

	GPConnectPortal  = "portal"
	GPConnectGateway = "gateway"
)

// GlobalProtectSettings is what openconnect --protocol=gp needs (wired up in
// a later phase; see design/v2-plan.md).
type GlobalProtectSettings struct {
	Auth      string `json:"auth"`      // GPAuth*
	ConnectTo string `json:"connectTo"` // GPConnect*
	// Gateway is the gateway picked from the portal's list last time
	// (openconnect --authgroup); empty means ask.
	Gateway string `json:"gateway"`
	// ServerCert pins the server certificate (openconnect --servercert,
	// "pin-sha256:..."), auto-filled like Fortinet's trusted-cert.
	ServerCert string `json:"serverCert"`
	HipReport  bool   `json:"hipReport"`
	CaFile     string `json:"caFile"`
	UserCert   string `json:"userCert"`
	UserKey    string `json:"userKey"`
}

func defaultFortinetSettings() *FortinetSettings {
	return &FortinetSettings{SetDns: true, SetRoutes: true}
}

func defaultGlobalProtectSettings() *GlobalProtectSettings {
	return &GlobalProtectSettings{Auth: GPAuthAuto, ConnectTo: GPConnectPortal}
}

func defaultProfile(id, profileType string) Profile {
	p := Profile{ID: id, Name: T("profile.new_name"), Type: profileType, Port: "443"}
	normalizeProfile(&p)
	return p
}

// normalizeProfile enforces the Type ↔ nested-settings invariant: the
// settings struct for p.Type exists (defaults if missing), the other is nil.
func normalizeProfile(p *Profile) {
	if !validProfileType(p.Type) {
		p.Type = ProfileTypeFortinet
	}
	switch p.Type {
	case ProfileTypeFortinet:
		if p.Fortinet == nil {
			p.Fortinet = defaultFortinetSettings()
		}
		p.GlobalProtect = nil
		p.Cisco = nil
	case ProfileTypeGlobalProtect:
		if p.GlobalProtect == nil {
			p.GlobalProtect = defaultGlobalProtectSettings()
		}
		gp := p.GlobalProtect
		if gp.Auth != GPAuthPassword && gp.Auth != GPAuthSAML {
			gp.Auth = GPAuthAuto
		}
		if gp.ConnectTo != GPConnectGateway {
			gp.ConnectTo = GPConnectPortal
		}
		p.Fortinet = nil
		p.Cisco = nil
	case ProfileTypeCisco:
		if p.Cisco == nil {
			p.Cisco = &CiscoSettings{}
		}
		p.Fortinet = nil
		p.GlobalProtect = nil
	}
}

// legacyProfile is the 1.0.x on-disk shape: no type, Fortinet settings flat
// on the profile. Only read during migration.
type legacyProfile struct {
	Type string `json:"type"`
	FortinetSettings
}

// profileConfig is the on-disk shape of profiles.json.
type profileConfig struct {
	Profiles          []Profile `json:"profiles"`
	SelectedProfileID string    `json:"selectedProfileId"`
	Theme             string    `json:"theme"`
	SkipQuitConfirm   bool      `json:"skipQuitConfirm"`
	// Language is the UI language picked in About ("en", "ru", "uz");
	// empty means follow the system.
	Language string `json:"language,omitempty"`
	// ComponentOverrides maps a component name (see components.go) to a
	// user-chosen binary path that takes precedence over Ingress' own build.
	ComponentOverrides map[string]string `json:"componentOverrides,omitempty"`
}

// ProfileStore owns profiles.json in the OS-appropriate config directory
// (~/Library/Application Support/ingress on macOS,
// %AppData%/ingress on Windows, ~/.config/ingress on Linux).
type ProfileStore struct {
	mu   sync.Mutex
	path string
	cfg  profileConfig
}

func NewProfileStore() (*ProfileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	appDir := filepath.Join(dir, "ingress")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		return nil, err
	}
	s := &ProfileStore{path: filepath.Join(appDir, "profiles.json")}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ProfileStore) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.cfg = profileConfig{Theme: "light"}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.cfg); err != nil {
		return err
	}
	migrated, err := migrateProfiles(data, s.cfg.Profiles)
	if err != nil {
		return err
	}
	if migrated {
		// Keep the 1.0.x file as it was: downgrading to 1.0.x would read the
		// new nested format as "all settings empty". Never overwrite an
		// existing backup (it's the oldest, most useful one).
		backup := filepath.Join(filepath.Dir(s.path), "profiles.v1.json")
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := os.WriteFile(backup, data, 0o600); err != nil {
				return fmt.Errorf("backing up profiles before migration: %w", err)
			}
		}
		return s.save()
	}
	return nil
}

// migrateProfiles upgrades 1.0.x profiles (no "type", flat Fortinet fields)
// in place, reading the flat fields from the raw file data. Reports whether
// anything changed and the file needs rewriting.
func migrateProfiles(data []byte, profiles []Profile) (bool, error) {
	var raw struct {
		Profiles []legacyProfile `json:"profiles"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, err
	}
	changed := false
	for i := range profiles {
		p := &profiles[i]
		if p.Type == "" && i < len(raw.Profiles) {
			p.Type = ProfileTypeFortinet
			settings := raw.Profiles[i].FortinetSettings
			p.Fortinet = &settings
			changed = true
		}
		before := *p
		normalizeProfile(p)
		if before.Type != p.Type || (before.Fortinet == nil) != (p.Fortinet == nil) || (before.GlobalProtect == nil) != (p.GlobalProtect == nil) || (before.Cisco == nil) != (p.Cisco == nil) {
			changed = true
		}
	}
	return changed, nil
}

func (s *ProfileStore) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *ProfileStore) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Profile, len(s.cfg.Profiles))
	copy(out, s.cfg.Profiles)
	return out
}

func (s *ProfileStore) Get(id string) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.cfg.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

func (s *ProfileStore) Add(profileType string) (Profile, error) {
	if !validProfileType(profileType) {
		return Profile{}, fmt.Errorf("unknown profile type %q", profileType)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := defaultProfile("p"+time.Now().Format("20060102150405.000000"), profileType)
	s.cfg.Profiles = append(s.cfg.Profiles, p)
	s.cfg.SelectedProfileID = p.ID
	return p, s.save()
}

func (s *ProfileStore) Update(p Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.cfg.Profiles {
		if existing.ID == p.ID {
			p.Logo = existing.Logo
			p.Type = existing.Type // immutable after creation
			normalizeProfile(&p)
			s.cfg.Profiles[i] = p
			return s.save()
		}
	}
	return os.ErrNotExist
}

func (s *ProfileStore) SetLogo(id string, has bool) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.cfg.Profiles {
		if p.ID == id {
			s.cfg.Profiles[i].Logo = has
			return s.cfg.Profiles[i], s.save()
		}
	}
	return Profile{}, os.ErrNotExist
}

func (s *ProfileStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.cfg.Profiles[:0]
	for _, p := range s.cfg.Profiles {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.cfg.Profiles = out
	if s.cfg.SelectedProfileID == id && len(out) > 0 {
		s.cfg.SelectedProfileID = out[0].ID
	}
	return s.save()
}

func (s *ProfileStore) SelectedID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.SelectedProfileID
}

func (s *ProfileStore) SetSelectedID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.SelectedProfileID = id
	return s.save()
}

func (s *ProfileStore) Theme() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Theme == "" {
		return "light"
	}
	return s.cfg.Theme
}

func (s *ProfileStore) SetTheme(theme string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Theme = theme
	return s.save()
}

func (s *ProfileStore) Language() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Language
}

func (s *ProfileStore) SetLanguage(lang string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Language = lang
	return s.save()
}

func (s *ProfileStore) SkipQuitConfirm() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.SkipQuitConfirm
}

func (s *ProfileStore) SetSkipQuitConfirm(skip bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.SkipQuitConfirm = skip
	return s.save()
}

func (s *ProfileStore) ComponentOverride(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.ComponentOverrides[name]
}

func (s *ProfileStore) SetComponentOverride(name, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == "" {
		delete(s.cfg.ComponentOverrides, name)
	} else {
		if s.cfg.ComponentOverrides == nil {
			s.cfg.ComponentOverrides = make(map[string]string)
		}
		s.cfg.ComponentOverrides[name] = path
	}
	return s.save()
}
