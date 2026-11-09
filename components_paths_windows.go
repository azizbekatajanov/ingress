//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// componentsBaseDir: unused until Windows elevation exists (see
// elevate_windows.go); defined so the shared code compiles.
func componentsBaseDir() string { return filepath.Join(os.Getenv("ProgramFiles"), "Ingress") }
