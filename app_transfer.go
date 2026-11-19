package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// --- Profile import/export (see profile_transfer.go) ---

func transferFilters() []wailsRuntime.FileFilter {
	return []wailsRuntime.FileFilter{{DisplayName: T("xfer.filter"), Pattern: "*" + transferFileExt}}
}

// ExportProfiles asks where to save the given profiles and writes them.
// Returns the path written, or "" if the user cancelled.
func (a *App) ExportProfiles(ids []string) (string, error) {
	var ps []Profile
	for _, id := range ids {
		if p, ok := a.store.Get(id); ok {
			ps = append(ps, p)
		}
	}
	data, err := exportProfiles(ps, time.Now())
	if err != nil {
		return "", err
	}
	name := "ingress-profiles"
	if len(ps) == 1 {
		name = safeFileName(ps[0].Name)
	}
	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           T("xfer.export_title"),
		DefaultFilename: name + transferFileExt,
		Filters:         transferFilters(),
	})
	if err != nil || path == "" {
		return "", err
	}
	if !strings.EqualFold(filepath.Ext(path), transferFileExt) {
		path += transferFileExt
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// safeFileName turns a profile name into a file name.
func safeFileName(name string) string {
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, r) || r < 32 {
			return '_'
		}
		return r
	}, strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." {
		return "ingress-profile"
	}
	return name
}

// PickImportFile asks for a .ingress file, reads and checks it, and returns
// what importing it would add. nil if the user cancelled.
func (a *App) PickImportFile() (*ImportPreview, error) {
	path, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title:   T("xfer.import_title"),
		Filters: transferFilters(),
	})
	if err != nil || path == "" {
		return nil, err
	}
	ps, err := readProfileFile(path)
	if err != nil {
		return nil, err
	}
	a.importMu.Lock()
	a.pendingImport = ps
	a.importMu.Unlock()
	pv := previewImport(filepath.Base(path), ps, a.store.List())
	return &pv, nil
}

// ImportProfiles adds the profiles at the given indexes of the file picked
// last (see PickImportFile).
func (a *App) ImportProfiles(indexes []int) ([]Profile, error) {
	a.importMu.Lock()
	pending := a.pendingImport
	a.pendingImport = nil
	a.importMu.Unlock()
	if pending == nil {
		return nil, errors.New(T("xfer.err.no_file"))
	}
	var chosen []Profile
	seen := map[int]bool{}
	for _, i := range indexes {
		if i < 0 || i >= len(pending) || seen[i] {
			return nil, errors.New(T("xfer.err.no_file"))
		}
		seen[i] = true
		chosen = append(chosen, pending[i])
	}
	if len(chosen) == 0 {
		return nil, nil
	}
	added, err := a.store.AddImported(chosen)
	if a.tray != nil {
		a.tray.OnProfilesChanged()
	}
	return added, err
}

// CancelImport forgets the file picked by PickImportFile.
func (a *App) CancelImport() {
	a.importMu.Lock()
	a.pendingImport = nil
	a.importMu.Unlock()
}
