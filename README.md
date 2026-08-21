# Ingress

A native desktop GUI for [openfortivpn](https://github.com/adrienverge/openfortivpn) (FortiGate SSL-VPN) that can hold **multiple VPN profiles connected at the same time** — each with its own independent tunnel, log, and status — which the official FortiClient can't do.

Built with [Wails](https://wails.io) (Go backend, vanilla JS/HTML/CSS frontend).

## Features

- **Multiple simultaneous tunnels** — connect to any number of profiles/gateways in parallel, each an independent `openfortivpn` process.
- **2FA / one-time codes** — detects the gateway's OTP prompt (including prompts openfortivpn writes without a trailing newline) and shows a modal with a countdown.
- **Per-profile settings** — host/port, username, realm, CA cert, client cert/key, trusted-cert (auto-filled the moment the gateway rejects an unrecognized cert), insecure-ssl, plus the usual openfortivpn/pppd networking flags (`set-dns`, `pppd-use-peerdns`, `set-routes`, `half-internet-routes`, `pppd-log`).
- **Live log tab** mirroring openfortivpn/pppd's own output per profile.
- **Status tab** — connection duration, assigned IP, gateway, TX/RX bytes.
- **Menu bar / tray icon** with per-profile quick connect/disconnect and a live "connected" badge.
- **Passwords never touch disk** — stored in the OS keychain (Keychain/Credential Manager/Secret Service), not in the profile config file.
- Light/dark theme, and a warning banner if a known-broken openfortivpn version is detected (e.g. 1.21+ on macOS Sonoma, see [adrienverge/openfortivpn#1165](https://github.com/adrienverge/openfortivpn/issues/1165)), with a one-click Homebrew install/reinstall.

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

(`apt install ./file.deb`, not `dpkg -i`, so `apt` also pulls in `policykit-1`/GTK/WebKit2GTK if anything's missing.) This puts the binary at `/usr/bin/ingress` and adds a proper application-menu entry with icon.

**Linux (other distros):** extract the `.tar.gz` and run the `ingress` binary directly — no menu entry, you launch it yourself. `pkexec` (from `policykit-1`) needs to be installed separately.

Either way, elevation is via `pkexec`, which shows your desktop's native polkit authentication dialog.

## Platform support

| OS      | Status                                                                 |
|---------|-------------------------------------------------------------------------|
| macOS   | Fully implemented. Elevation via `Security.framework`'s admin prompt, asked once per app launch rather than once per connect. |
| Linux   | Implemented via `pkexec`.                                              |
| Windows | UI is there, but privilege elevation with live stdio (needed for log streaming and the interactive OTP prompt) isn't implemented yet — `Connect` returns an error. |

## Requirements

- [openfortivpn](https://github.com/adrienverge/openfortivpn) installed separately and on `PATH` (`brew install openfortivpn` on macOS; the app also offers to install it for you if missing).
- Go 1.25+
- Node 22 (see `.nvmrc`)
- [Wails CLI v2](https://wails.io/docs/gettingstarted/installation): `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

## Development

```bash
wails dev
```

Runs the app with hot-reload for the frontend. A dev server is also available at `http://localhost:34115` for browser-based debugging with access to the bound Go methods.

## Building

```bash
wails build
```

Produces a packaged app at `build/bin/` (`Ingress.app` on macOS).

## Configuration & data

Nothing user-specific lives in this repository. At runtime, Ingress stores:

- Profile settings (host, username, cert paths, etc. — no passwords) in `profiles.json` under the OS config directory (`~/Library/Application Support/ingress` on macOS, `%AppData%/ingress` on Windows, `~/.config/ingress` on Linux).
- Passwords in the OS-native secure store (Keychain / Credential Manager / Secret Service).
