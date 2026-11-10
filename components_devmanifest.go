//go:build devmanifest

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Dev-only (build with `-tags devmanifest`): lets a local build install
// components from a hand-made manifest before ingress-deps has published
// anything. Set INGRESS_DEV_MANIFEST=/path/to/manifest.json (same JSON shape
// as componentManifest; URLs may be file:// for local archives). Release
// builds never compile this file, so the root-side installer there only ever
// trusts builtinManifest.

const devManifestEnv = "INGRESS_DEV_MANIFEST"

func readManifestFile(path string) (componentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m componentManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return m, nil
}

func activeManifest() componentManifest {
	path := os.Getenv(devManifestEnv)
	if path == "" {
		return builtinManifest
	}
	m, err := readManifestFile(path)
	if err != nil {
		log.Printf("ingress: ignoring dev manifest: %v", err)
		return builtinManifest
	}
	return m
}

// devManifestArgs is appended to the elevated --install-component argv:
// neither AuthorizationExecuteWithPrivileges nor pkexec reliably passes the
// environment through, so the root side gets the path explicitly.
func devManifestArgs() []string {
	if path := os.Getenv(devManifestEnv); path != "" {
		return []string{"--dev-manifest", path}
	}
	return nil
}

func rootManifest(extra []string) (componentManifest, error) {
	if len(extra) == 0 {
		return builtinManifest, nil
	}
	if len(extra) == 2 && extra[0] == "--dev-manifest" {
		return readManifestFile(extra[1])
	}
	return nil, fmt.Errorf("unexpected arguments: %v", extra)
}

// Dev builds can point the updater at a local test release, signed with a
// throwaway key: INGRESS_UPDATE_URL (base URL ending in /) and
// INGRESS_UPDATE_PUBKEY (base64 ed25519 public key). Release builds never
// compile this in, so they only ever trust GitHub and the real key.
func init() {
	if u := os.Getenv("INGRESS_UPDATE_URL"); u != "" {
		updateBaseURL = u
	}
	if k := os.Getenv("INGRESS_UPDATE_PUBKEY"); k != "" {
		updatePublicKey = k
	}
	devAutoInstallUpdate = os.Getenv("INGRESS_UPDATE_AUTOINSTALL") == "1"
}
