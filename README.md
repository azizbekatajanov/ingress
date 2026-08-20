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
