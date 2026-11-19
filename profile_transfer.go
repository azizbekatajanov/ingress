package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Profile import/export: a .ingress file (JSON) with one or more profiles,
// e.g. for an admin to hand a working configuration to colleagues, or to
// move to another computer.
//
// What never goes into the file:
//   - passwords (they live in the keychain, not in Profile anyway);
//   - paths to CA/client certificates and keys, and the pppd log path —
//     they only mean something on the machine that wrote them, and a
//     client key path is personal;
//   - the profile's ID and logo, and app settings (theme, showHosts, …).
//
// Server-certificate pins and the remembered gateway/group are kept: they're
// part of a working setup.
//
// Import is strict: unknown fields, a newer format version, an invalid
// value or an oversized file reject the whole file rather than half-import
// it. Imported profiles get new IDs; nothing existing is overwritten.

const (
	transferFormat      = "ingress-profiles"
	transferVersion     = 1
	transferFileExt     = ".ingress"
	transferMaxBytes    = 1 << 20
	transferMaxProfiles = 100
	transferMaxField    = 256
)

type transferFile struct {
	Format     string            `json:"format"`
	Version    int               `json:"version"`
	ExportedAt string            `json:"exportedAt,omitempty"`
	Profiles   []transferProfile `json:"profiles"`
}

// transferProfile is Profile without ID and logo.
type transferProfile struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`

	Fortinet      *FortinetSettings      `json:"fortinet,omitempty"`
	GlobalProtect *GlobalProtectSettings `json:"globalprotect,omitempty"`
	Cisco         *CiscoSettings         `json:"cisco,omitempty"`
	SSTP          *SSTPSettings          `json:"sstp,omitempty"`
}

// stripLocalPaths clears the machine-specific file paths (see above).
func stripLocalPaths(p *Profile) {
	if f := p.Fortinet; f != nil {
		f.CaFile, f.UserCert, f.UserKey, f.PppdLog = "", "", "", ""
	}
	if g := p.GlobalProtect; g != nil {
		g.CaFile, g.UserCert, g.UserKey = "", "", ""
	}
	if c := p.Cisco; c != nil {
		c.CaFile, c.UserCert, c.UserKey = "", "", ""
	}
	if s := p.SSTP; s != nil {
		s.CaFile = ""
	}
}

// exportProfiles encodes ps as a .ingress file.
func exportProfiles(ps []Profile, now time.Time) ([]byte, error) {
	if len(ps) == 0 {
		return nil, errors.New(T("xfer.err.nothing"))
	}
	f := transferFile{Format: transferFormat, Version: transferVersion, ExportedAt: now.UTC().Format(time.RFC3339)}
	for _, p := range ps {
		p = cloneProfile(p)
		normalizeProfile(&p)
		stripLocalPaths(&p)
		f.Profiles = append(f.Profiles, transferProfile{
			Name: p.Name, Type: p.Type, Host: p.Host, Port: p.Port, Username: p.Username,
			Fortinet: p.Fortinet, GlobalProtect: p.GlobalProtect, Cisco: p.Cisco, SSTP: p.SSTP,
		})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// cloneProfile deep-copies the nested settings, so stripping paths from the
// copy doesn't touch the stored profile.
func cloneProfile(p Profile) Profile {
	if p.Fortinet != nil {
		v := *p.Fortinet
		p.Fortinet = &v
	}
	if p.GlobalProtect != nil {
		v := *p.GlobalProtect
		p.GlobalProtect = &v
	}
	if p.Cisco != nil {
		v := *p.Cisco
		p.Cisco = &v
	}
	if p.SSTP != nil {
		v := *p.SSTP
		v.Subnets = append([]string(nil), v.Subnets...)
		p.SSTP = &v
	}
	return p
}

// parseProfiles decodes and validates a .ingress file. The returned
// profiles have no ID yet.
func parseProfiles(r io.Reader) ([]Profile, error) {
	data, err := io.ReadAll(io.LimitReader(r, transferMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > transferMaxBytes {
		return nil, errors.New(T("xfer.err.too_big"))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f transferFile
	if err := dec.Decode(&f); err != nil {
		return nil, errors.New(T("xfer.err.not_ingress", err))
	}
	if dec.More() {
		return nil, errors.New(T("xfer.err.not_ingress", "trailing data"))
	}
	if f.Format != transferFormat {
		return nil, errors.New(T("xfer.err.not_ingress", fmt.Sprintf("format %q", f.Format)))
	}
	if f.Version < 1 || f.Version > transferVersion {
		return nil, errors.New(T("xfer.err.version", f.Version))
	}
	if len(f.Profiles) == 0 {
		return nil, errors.New(T("xfer.err.empty"))
	}
	if len(f.Profiles) > transferMaxProfiles {
		return nil, errors.New(T("xfer.err.too_many", transferMaxProfiles))
	}

	out := make([]Profile, 0, len(f.Profiles))
	for i, tp := range f.Profiles {
		p := Profile{
			Name: strings.TrimSpace(tp.Name), Type: tp.Type,
			Host: strings.TrimSpace(tp.Host), Port: strings.TrimSpace(tp.Port), Username: strings.TrimSpace(tp.Username),
			Fortinet: tp.Fortinet, GlobalProtect: tp.GlobalProtect, Cisco: tp.Cisco, SSTP: tp.SSTP,
		}
		if err := validateImported(p); err != nil {
			return nil, errors.New(T("xfer.err.profile", i+1, err))
		}
		if p.Port == "" {
			p.Port = "443"
		}
		normalizeProfile(&p)
		stripLocalPaths(&p)
		out = append(out, p)
	}
	return out, nil
}

func validateImported(p Profile) error {
	if !validProfileType(p.Type) {
		return errors.New(T("xfer.err.type", p.Type))
	}
	// A settings block for another protocol means the file was edited by
	// hand or is corrupt.
	blocks := map[string]bool{
		ProfileTypeFortinet: p.Fortinet != nil, ProfileTypeGlobalProtect: p.GlobalProtect != nil,
		ProfileTypeCisco: p.Cisco != nil, ProfileTypeSSTP: p.SSTP != nil,
	}
	for typ, present := range blocks {
		if present && typ != p.Type {
			return errors.New(T("xfer.err.mixed", typ, p.Type))
		}
	}
	if p.Name == "" {
		return errors.New(T("xfer.err.field", "name"))
	}
	if p.Host == "" || strings.ContainsAny(p.Host, " /\\@?#") {
		return errors.New(T("xfer.err.field", "host"))
	}
	if p.Port != "" {
		if n, err := strconv.Atoi(p.Port); err != nil || n < 1 || n > 65535 {
			return errors.New(T("xfer.err.field", "port"))
		}
	}
	for field, v := range map[string]string{"name": p.Name, "host": p.Host, "username": p.Username} {
		if len(v) > transferMaxField || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return errors.New(T("xfer.err.field", field))
		}
	}
	return nil
}

// ImportPreviewItem describes one profile of a file about to be imported.
type ImportPreviewItem struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	// Duplicate names the existing profile with the same type, server and
	// username, if any (unchecked by default in the preview).
	Duplicate string `json:"duplicate"`
	// Insecure: server certificate checks are turned off in this profile.
	Insecure bool `json:"insecure"`
}

type ImportPreview struct {
	Path  string              `json:"path"`
	Items []ImportPreviewItem `json:"items"`
}

func sameServer(a, b Profile) bool {
	return a.Type == b.Type && strings.EqualFold(a.Host, b.Host) && a.Port == b.Port && a.Username == b.Username
}

func previewImport(path string, ps []Profile, existing []Profile) ImportPreview {
	pv := ImportPreview{Path: path}
	for _, p := range ps {
		it := ImportPreviewItem{Name: p.Name, Type: p.Type, Host: p.Host, Port: p.Port, Username: p.Username}
		for _, e := range existing {
			if sameServer(p, e) {
				it.Duplicate = e.Name
				break
			}
		}
		it.Insecure = (p.Fortinet != nil && p.Fortinet.InsecureSsl) || (p.SSTP != nil && p.SSTP.InsecureCert)
		pv.Items = append(pv.Items, it)
	}
	return pv
}

func readProfileFile(path string) ([]Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProfiles(f)
}

// AddImported stores ps as new profiles (fresh IDs) and selects the first.
func (s *ProfileStore) AddImported(ps []Profile) ([]Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := map[string]bool{}
	for _, p := range s.cfg.Profiles {
		taken[p.ID] = true
	}
	next := time.Now()
	added := make([]Profile, 0, len(ps))
	for _, p := range ps {
		p = cloneProfile(p)
		// IDs follow Add's format, bumped past any already in use.
		for {
			p.ID = "p" + next.Format("20060102150405.000000")
			next = next.Add(time.Microsecond)
			if !taken[p.ID] {
				break
			}
		}
		taken[p.ID] = true
		p.Logo = false
		normalizeProfile(&p)
		added = append(added, p)
	}
	s.cfg.Profiles = append(s.cfg.Profiles, added...)
	if len(added) > 0 {
		s.cfg.SelectedProfileID = added[0].ID
	}
	return added, s.save()
}
