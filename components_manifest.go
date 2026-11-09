package main

// ComponentBuild is one downloadable build of a component for one platform.
type ComponentBuild struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"` // lowercase hex of the whole .tar.gz
}

// componentManifest maps component → "GOOS/GOARCH" → build.
type componentManifest map[string]map[string]ComponentBuild

// builtinManifest is the single source of truth for which binaries this
// build of Ingress downloads. It's compiled in on purpose (decided for v2):
// the root-side installer (`--install-component`, components_root.go) looks
// the expected sha256 up here itself rather than trusting anything passed on
// argv, so a tampered download can't be installed even by a compromised
// unprivileged process. Updating a component therefore means releasing a new
// Ingress build.
//
// Archives come from the ingress-deps repo's releases and must have this
// layout at the archive root (no wrapping directory):
//
//	bin/<component>          the executable
//	libexec/...              helper scripts (vpnc-script, hipreport.sh)
//	LICENSES/...  SOURCES.txt
//
// A platform with no entry here is shown as "сборка пока недоступна".
// TODO(v2, phase 0): fill in once ingress-deps publishes its first release.
var builtinManifest = componentManifest{
	"openfortivpn": {
		// "darwin/arm64": {Version: "1.20.5-ingress.1", URL: depsURL("openfortivpn-1.20.5-ingress.1", "openfortivpn-1.20.5-ingress.1-darwin-arm64.tar.gz"), SHA256: "…"},
	},
	"openconnect": {
		// "darwin/arm64": {Version: "9.21-ingress.1", URL: depsURL("openconnect-9.21-ingress.1", "openconnect-9.21-ingress.1-darwin-arm64.tar.gz"), SHA256: "…"},
	},
}

const depsReleasesBase = "https://github.com/azizbekatajanov/ingress-deps/releases/download/"

func depsURL(tag, file string) string { return depsReleasesBase + tag + "/" + file }

var _ = depsURL // referenced from the commented-out manifest entries above
