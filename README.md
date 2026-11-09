# Ingress

A native desktop VPN client for **Fortinet SSL-VPN** (via [openfortivpn](https://github.com/adrienverge/openfortivpn)) and **Palo Alto GlobalProtect** (via [OpenConnect](https://www.infradead.org/openconnect/)), including GlobalProtect **SAML** login. It can hold **multiple VPN profiles connected at the same time**, each with its own tunnel, log and status. The official FortiClient and GlobalProtect apps can't do that.

Built with [Wails](https://wails.io) (Go backend, vanilla JS/HTML/CSS frontend).

## Features

- **Fortinet and GlobalProtect side by side.** Each profile has a type, Fortinet or GlobalProtect, chosen when it's created. Any mix of profiles can be connected in parallel, each as an independent client process.
- **No Homebrew, no packages to install.** On the first connect of a profile type, Ingress downloads its own pinned build of the VPN client from [ingress-deps](https://github.com/azizbekatajanov/ingress-deps). It verifies the sha256 against a manifest compiled into the app. It installs the client into a root-owned directory (`/Library/Application Support/Ingress` on macOS, `/opt/ingress` on Linux). The directory chain is re-checked before every connect.
  - The openconnect build carries [openconnect!656](https://gitlab.com/openconnect/openconnect/-/merge_requests/656), which GlobalProtect SAML needs on many gateways.
  - openfortivpn is pinned to 1.20.5, because 1.21+ can't bring the tunnel up on macOS Sonoma+ ([#1165](https://github.com/adrienverge/openfortivpn/issues/1165)).
  - The **Компоненты** screen shows what's installed and can install, update or remove a client. A custom binary path can be set per client. A system binary left over from 1.0.x keeps working until you choose.
- **GlobalProtect**
  - Login with a password, or with **SAML** in Ingress' own login window. In "auto" mode Ingress asks the portal how to log in. The IdP session is remembered between logins.
  - Portal with a **gateway picker**: the choice is remembered. Connecting directly to a gateway is also supported.
  - 2FA challenges, server-certificate pinning (auto-filled on first connect), optional **HIP report**, client certificates.
- **Fortinet**
  - 2FA/OTP modal with a countdown.
  - realm, CA cert, client cert/key, trusted-cert (auto-filled when the gateway's cert is unknown), insecure-ssl.
  - pppd networking flags: `set-dns`, `pppd-use-peerdns`, `set-routes`, `half-internet-routes`, `pppd-log`.
- **Live log tab** per profile. Secrets written to the client's stdin are masked.
- **Status tab**: connection duration, assigned IP, gateway, TX/RX bytes.
- **Menu bar / tray icon** with per-profile quick connect/disconnect and a live "connected" badge.
- **Passwords never touch disk.** They're stored in the OS keychain (Keychain/Credential Manager/Secret Service), not in the profile config file.
- Light/dark theme.

## Installation

Download the latest build for your platform from the [Releases page](https://github.com/azizbekatajanov/ingress/releases).

**macOS:** open the `.dmg` and drag Ingress into Applications. The build isn't notarized (no Apple Developer ID behind this project — it's a personal tool, not worth the $99/year), so **Gatekeeper will refuse to open it on first launch** ("Ingress" Not Opened — Apple could not verify "Ingress" is free of malware...). This is expected, not a broken build. To open it anyway:

```bash
xattr -cr /Applications/Ingress.app
```

or in Finder: right-click Ingress.app → **Open** (not a double-click) → confirm in the dialog that appears. Either only needs doing once, right after installing.

**Windows:** run the `-installer.exe`. Elevation with live log streaming isn't implemented yet (see the platform table below) — the UI works, but `Connect` returns an error.

**Linux (Debian/Ubuntu):** download the `.deb` and install it:

```bash
sudo apt install ./Ingress-*-linux-amd64.deb
```

Use `apt install ./file.deb`, not `dpkg -i`, so `apt` also pulls in `pkexec`, GTK and WebKit2GTK if they're missing, plus `ppp`, which Fortinet profiles need. This puts the binary at `/usr/bin/ingress` and adds an application-menu entry with an icon. `apt purge ingress` also removes the VPN clients Ingress installed in `/opt/ingress`.

**Linux (other distros):** extract the `.tar.gz` and run the `ingress` binary directly. There's no menu entry, so you launch it yourself. You need to install `pkexec` (polkit), and `ppp` for Fortinet profiles, separately.

On Linux, elevation is via `pkexec`, which shows your desktop's native polkit authentication dialog.

### Upgrading from 1.0.x

- Existing profiles become Fortinet profiles automatically. The original file is kept as `profiles.v1.json` next to `profiles.json`; to downgrade, put it back.
- If you installed openfortivpn with Homebrew, it keeps working. A banner offers to switch to Ingress' own build or keep using the system one. Homebrew itself is no longer needed.

## Platform support

| OS      | Status |
|---------|--------|
| macOS   | Fully implemented (arm64 and Intel, 12.0+). Elevation via `Security.framework`'s admin prompt, asked once per app launch rather than once per connect. SAML window: WKWebView. |
| Linux   | Implemented via `pkexec` (amd64). SAML window: WebKitGTK. |
| Windows | UI is there, but privilege elevation with live stdio (needed for log streaming and the interactive OTP prompt) isn't implemented yet — `Connect` returns an error. |

## Requirements (development)

- Go 1.25+
- Node 22 (see `.nvmrc`)
- [Wails CLI v2](https://wails.io/docs/gettingstarted/installation): `go install github.com/wailsapp/wails/v2/cmd/wails@latest`. On Apple Silicon, make sure it's an arm64 binary: an x86_64 `wails` fails on cgo while generating bindings.
- Linux: `libgtk-3-dev libwebkit2gtk-4.1-dev`, and build with `-tags webkit2_41`.

## Development

```bash
wails dev
```

Runs the app with hot-reload for the frontend. A dev server is also available at `http://localhost:34115` for browser-based debugging with access to the bound Go methods.

To install components from local archives (e.g. a fresh ingress-deps build) instead of the release, build with `-tags devmanifest` and set `INGRESS_DEV_MANIFEST` to a JSON file shaped like `componentManifest`. `file://` URLs are allowed there. See `components_devmanifest.go`. Release builds never compile this in.

## Building

```bash
wails build
```

Produces a packaged app at `build/bin/` (`Ingress.app` on macOS).

The VPN client builds come from [ingress-deps](https://github.com/azizbekatajanov/ingress-deps). To update them, publish a new release there and paste its `ingress-manifest.go.txt` into `components_manifest.go`.

## Configuration & data

Nothing user-specific lives in this repository. At runtime, Ingress stores:

- **Profile settings** (type, host, username, cert paths, etc. — no passwords) and component path overrides in `profiles.json` under the OS config directory:
  - `~/Library/Application Support/ingress` on macOS
  - `%AppData%/ingress` on Windows
  - `~/.config/ingress` on Linux
- **Passwords** in the OS-native secure store (Keychain / Credential Manager / Secret Service). SAML cookies are never stored.
- **Its own VPN clients** in `/Library/Application Support/Ingress/components` (macOS) or `/opt/ingress/components` (Linux), root-owned. Remove them from **Компоненты**.
- **The SAML login window's web data** (the IdP session):
  - macOS: WebKit's default store for the app
  - Linux: `~/.local/share/ingress/saml-cookies.sqlite`

## Licenses of bundled components

The VPN clients Ingress downloads are separate programs under their own licenses: openconnect (LGPL-2.1), openfortivpn (GPL-3.0 with OpenSSL exception), vpnc-scripts (GPL-2.0), OpenSSL (Apache-2.0). Each installed component carries its `LICENSES/` folder and a `SOURCES.txt` naming the exact sources and patches. The build scripts are in [ingress-deps](https://github.com/azizbekatajanov/ingress-deps).
