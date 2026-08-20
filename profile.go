package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Profile holds one VPN profile's non-secret configuration.
// Password is intentionally excluded — it lives in the OS keychain, see credentials.go.
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Realm    string `json:"realm"`

	CaFile              string `json:"caFile"`
	UserCert            string `json:"userCert"`
	UserKey             string `json:"userKey"`
	TrustedCert         string `json:"trustedCert"`
	InsecureSsl         bool   `json:"insecureSsl"`

	SetDns             bool   `json:"setDns"`
	PppdUsePeerdns     bool   `json:"pppdUsePeerdns"`
	SetRoutes          bool   `json:"setRoutes"`
	HalfInternetRoutes bool   `json:"halfInternetRoutes"`
	PppdLog            string `json:"pppdLog"`
}

func defaultProfile(id string) Profile {
	return Profile{
		ID:        id,
		Name:      "Новый профиль",
		Port:      "443",
		SetDns:    true,
		SetRoutes: true,
	}
}

// profileConfig is the on-disk shape of profiles.json.
type profileConfig struct {
	Profiles          []Profile `json:"profiles"`
	SelectedProfileID string    `json:"selectedProfileId"`
	Theme             string    `json:"theme"`
	SkipQuitConfirm   bool      `json:"skipQuitConfirm"`
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
	return nil
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

func (s *ProfileStore) Add() (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := defaultProfile("p" + time.Now().Format("20060102150405.000000"))
	s.cfg.Profiles = append(s.cfg.Profiles, p)
	s.cfg.SelectedProfileID = p.ID
	return p, s.save()
}

func (s *ProfileStore) Update(p Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.cfg.Profiles {
		if existing.ID == p.ID {
			s.cfg.Profiles[i] = p
			return s.save()
		}
	}
	return os.ErrNotExist
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
