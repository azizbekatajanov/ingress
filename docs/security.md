# Ingress security overview

This document is for security teams evaluating Ingress, and for anyone who
wants to know what the app does before installing it. Every claim here points
to the source file that implements it, so you can check it. Russian version:
[security.ru.md](security.ru.md).

*Applies to Ingress 2.1.x. Last reviewed: 2026-11-12.*

## Summary

- Ingress is an open-source (Apache-2.0) desktop GUI for the open-source VPN clients **openfortivpn** (Fortinet SSL-VPN), **openconnect** (GlobalProtect, Cisco AnyConnect) and **sstpc** (Microsoft SSTP).
- It installs **no background service, daemon, launch agent, kernel or network extension.** When the app is quit, nothing of it keeps running except tunnels you left connected, and those stop on Disconnect.
- **No telemetry, analytics or crash reporting.** Ingress only connects to the VPN servers you configure, to their identity provider during SAML login, and to `github.com` to download VPN client builds and check for updates. The update check can be turned off.
- **Root is used only for the VPN client process** (creating a tunnel needs it), for installing or removing Ingress' own VPN client builds, and for replacing the app during an update. Every elevation goes through the OS's own admin prompt.
- **Passwords live in the OS keychain**, never in the profile file and never on a command line.
- Downloaded VPN client builds are **pinned by sha256 in the app binary itself**. App updates are **signed with ed25519** by a key that never leaves the maintainer's machine.

## 1. Components

| Part | What it is | Runs as |
|---|---|---|
| `Ingress.app` / `ingress` | The GUI (Go + [Wails](https://wails.io), web UI rendered by the system WebView) | the user |
| `ingress --saml-login` | Separate window with a WebView for GlobalProtect SAML login ([saml.go](../saml.go)) | the user |
| `ingress --pty-exec <client> …` | Thin wrapper that starts the VPN client and stops it on Disconnect ([ptyproxy_darwin.go](../ptyproxy_darwin.go), [elevatedwrapper_linux.go](../elevatedwrapper_linux.go)) | root |
| `openfortivpn`, `openconnect`, `sstpc` | The actual VPN clients, built from upstream source in [ingress-deps](https://github.com/azizbekatajanov/ingress-deps) | root |
| `ingress --install-component` / `--remove-component` | Installs/removes a VPN client build ([components_root.go](../components_root.go)) | root, one-shot |
| `ingress --install-update` | Replaces the app bundle with a verified update, macOS only ([updater_darwin.go](../updater_darwin.go)) | root, one-shot, only if `/Applications/Ingress.app` isn't user-writable |

All root-side helpers are the same signed binary re-executed with a hidden flag. There are no separate helper tools on disk.

## 2. Privileges

### How root is obtained

- **macOS:** the native Security.framework admin dialog (`AuthorizationExecuteWithPrivileges`), see [elevate_darwin.go](../elevate_darwin.go). The authorization is kept for the lifetime of the app process, so you're asked **once per app launch**, not once per connect. macOS drops it after its normal inactivity timeout. No privileged helper is installed: when Ingress quits, the authorization is gone.
- **Linux:** `pkexec`, the desktop's polkit dialog ([elevate_linux.go](../elevate_linux.go)). No polkit rule is installed, so the policy is whatever your system defines.
- **Windows:** not implemented. The UI runs, but Connect returns an error ([elevate_windows.go](../elevate_windows.go)).

### What root is used for

1. **Running the VPN client.** Creating a tun/ppp interface, setting routes and DNS needs root. The client gets an absolute path, never a `PATH` lookup ([components.go](../components.go), `ResolvePath`).
2. **Routes for SSTP profiles.** `/sbin/route` (macOS) or `ip route` (Linux) on the tunnel interface, only for the networks listed in the profile ([routes_darwin.go](../routes_darwin.go), [routes_linux.go](../routes_linux.go)). `/etc/ppp/*` is never modified.
3. **Installing/removing VPN client builds** into a root-owned directory (section 4).
4. **Installing an update** when the app bundle isn't writable by the user (section 5).

Ingress never edits system configuration files, firewall rules, or other apps' settings. DNS and routes pushed by the VPN server are applied by the VPN client itself (openconnect's `vpnc-script`, openfortivpn's `set-dns`/`set-routes` options, which are configurable per profile).

## 3. Network connections

| Destination | Who connects | When | Why |
|---|---|---|---|
| VPN gateway / portal you configure | VPN client (root); Ingress itself for GlobalProtect prelogin | On Connect | The VPN connection |
| Your identity provider (IdP) | `ingress --saml-login` WebView | GlobalProtect SAML login | You sign in on the IdP's own page |
| `github.com/azizbekatajanov/ingress-deps/releases/download/…` | Ingress | First connect of a profile type, or Install/Update on the Components screen | Download a VPN client build |
| `github.com/azizbekatajanov/ingress/releases/latest/download/ingress-update.json` (+ `.sig`) | Ingress | 5 s after start, then every 24 h. **Off switch in About.** | Check for an update |
| `github.com/azizbekatajanov/ingress/releases/download/…` | Ingress | Only after you click Update | Download the update |

GitHub serves release downloads through redirects to its CDN (`objects.githubusercontent.com` / `release-assets.githubusercontent.com`). Allow those hosts if you filter egress.

Nothing else. No analytics, error reporting, licence checks or "phone home". The UI is bundled into the binary and loads nothing from the internet ([main.go](../main.go), `//go:embed all:frontend/dist`).

**TLS:** downloads are `https` only (anything else is rejected, [components.go](../components.go) `downloadVerified`). GlobalProtect prelogin verifies the server certificate against system roots, a CA file from the profile, or a pinned key ([gp_prelogin.go](../gp_prelogin.go)). The profile options "insecure SSL" / "don't verify" (Fortinet, SSTP) exist for test servers and are off by default.

## 4. Data stored on disk

| What | Where | Protection |
|---|---|---|
| Profiles (servers, usernames, options; **no passwords**) | `~/Library/Application Support/ingress/profiles.json` (macOS), `~/.config/ingress/` (Linux) | Directory 0700, file 0600 ([profile.go](../profile.go)) |
| Saved passwords | OS keychain, service name `ingress` | Keychain / Secret Service ([credentials.go](../credentials.go)) |
| Fortinet connection config (contains the password) | Temp file in the user's temp dir, for as long as the tunnel runs | 0600, deleted on disconnect ([openfortivpn_config.go](../openfortivpn_config.go)). Keeps the password off argv, where `ps` could show it to other users. |
| SAML web session (IdP cookies) | macOS: WebKit's default data store for Ingress; Linux: `~/.local/share/ingress/saml-cookies.sqlite` | So you don't sign in to the IdP every time ([saml_darwin.m](../saml_darwin.m), [saml_linux.c](../saml_linux.c)). The GlobalProtect prelogin cookie that SAML returns is passed to openconnect and never stored. |
| VPN client builds | `/Library/Application Support/Ingress/components/` (macOS), `/opt/ingress/components/` (Linux) | Owned by root, 0755, never group/other-writable |
| Connection logs | **Memory only**, shown in the Log tab | Secrets written to the client's stdin are masked ([vpn_manager.go](../vpn_manager.go)) |

Passwords and SAML cookies reach the VPN client through **stdin** (`--passwd-on-stdin`, `--password -`), never through command-line arguments.

## 5. Supply chain: what you download and how it's verified

### VPN client builds (ingress-deps)

- Built from **upstream release tags** (openconnect 9.21, openfortivpn 1.20.5, sstp-client 1.0.20), with the patches in [ingress-deps/patches](https://github.com/azizbekatajanov/ingress-deps/tree/main/patches). Each archive ships `LICENSES/` and `SOURCES.txt`.
- Patches we apply, all small and public:
  - openconnect `0001`: send an empty `passwd` next to the SAML cookie (needed by some GlobalProtect gateways; upstream MR !656).
  - openconnect `0002`: set `SSL_OP_LEGACY_SERVER_CONNECT`, so it can connect to older PAN-OS gateways that lack RFC 5746. Unsafe renegotiation itself stays disabled, and the cipher list and security level are unchanged.
  - sstp-client `0001`: read the password from stdin instead of argv.
  - sstp-client `0002`: fix a stack overflow in the pppd argument vector.
- The URL and **sha256 of every build are compiled into the Ingress binary** ([components_manifest.go](../components_manifest.go)). A new client version means a new Ingress release.
- Install path ([components_root.go](../components_root.go)):
  1. Download over https and check the sha256 (unprivileged).
  2. The root installer **reads the archive into memory, re-computes the sha256 against its own compiled-in manifest**, and extracts those same bytes. So the file can't be swapped between check and use.
  3. Extraction accepts only regular files and directories: no symlinks, hard links, devices or `..` paths, at most 300 MB unpacked. Files are staged and swapped in atomically.
  4. Everything is chowned to root and made non-writable by group/other.
- **Before every connect**, the whole directory chain to the binary is checked: no symlinks, owned by root, not group/other-writable ([components_secure_unix.go](../components_secure_unix.go)). If the check fails, the binary isn't run.

### App updates (macOS)

- Each release has `ingress-update.json` (version, archive URL, sha256) and an **ed25519 signature** of it. The private key is kept offline in the maintainer's keychain, not on GitHub ([updater.go](../updater.go), [tools/updatesign](../tools/updatesign)). **A compromised GitHub account can't publish an update Ingress will accept.**
- Nothing is installed without the user clicking Update.
- The new bundle must match the version in the signed manifest and pass `codesign --verify --deep --strict`. If root is needed, the root side **verifies the signature and hash again itself**, from a copy in `/var/root`.

### Code signing status, honestly

| Platform | Today | Planned |
|---|---|---|
| macOS | Ad-hoc code signature, **not notarized** (no Apple Developer ID). Gatekeeper warns on first launch of the `.dmg`. Built on the maintainer's Mac. | Build in CI with SLSA provenance (section 6) |
| Windows | Unsigned (and VPN connections don't work there yet) | Authenticode via SignPath Foundation |
| Linux | `.sha256` next to each file | SLSA provenance |

## 6. How to verify what you install

**Checksum.** Linux and Windows assets have a `.sha256` file next to them:

```bash
sha256sum -c Ingress-2.1.0-linux-amd64.deb.sha256
```

For macOS, the sha256 of each app archive (`Ingress-<version>-darwin-<arch>.zip`) is in the release's signed `ingress-update.json`:

```bash
shasum -a 256 Ingress-2.1.0-darwin-arm64.zip
plutil -extract 'assets.darwin/arm64.sha256' raw -o - ingress-update.json
```

The `.dmg` files have no published checksum yet. Use the `.zip`, or `install.sh`, which checks it for you.

**macOS signature integrity:**

```bash
codesign --verify --deep --strict --verbose=2 /Applications/Ingress.app
```

**`install.sh`**: read it before running it ([install.sh](../install.sh), ~60 lines). It downloads the update manifest, accepts only a URL under this repo's releases, checks the sha256 and the code signature, and copies the app to `/Applications`. Because `curl` doesn't set the quarantine attribute, Gatekeeper doesn't show its warning. That is the only reason this install path exists; the integrity checks above replace the ones Gatekeeper would have done. If you prefer, download the `.zip`/`.dmg` yourself, verify it as shown, and open it.

**Build provenance** *(planned, once releases are built in CI)*:

```bash
gh attestation verify Ingress-<version>-darwin-arm64.zip --repo azizbekatajanov/ingress
```

This proves the file was built by this repository's GitHub Actions workflow from a specific commit.

**Build it yourself:** everything is open source. See the README's *Building* section and the ingress-deps build scripts.

## 7. Threat model

**Ingress is designed to protect against:**

- a tampered or replaced download of a VPN client or an update (sha256 pinned in the binary; ed25519-signed updates; root side re-verifies);
- a compromised GitHub account pushing a malicious update (needs the offline signing key);
- a non-admin local process swapping a root-executed binary. Before every run, the binary and every directory above it, up to `/`, must be owned by root and not writable by group/other. This covers Ingress' own builds, custom paths set on the Components screen, and binaries found on `PATH`. Symlinks are resolved first and the resolved file is what runs. The root-side wrapper repeats the check before it starts the client ([components_secure_unix.go](../components_secure_unix.go) `trustedExecPath`). A Homebrew binary in `/opt/homebrew/bin` (owned by the user) is therefore refused, and Ingress offers its own build instead;
- other local users reading VPN passwords (keychain; stdin or 0600 file instead of argv);
- malicious archives (path traversal, symlinks, zip bombs).

**Outside Ingress' protection — know these:**

- **Libraries of custom and system binaries.** The ownership check covers the executable file, not the shared libraries it loads. Ingress' own builds link OpenSSL statically. A root-owned binary from elsewhere that loads libraries from a user-writable place is outside this check. **Recommendation for managed fleets: use only Ingress' own builds and don't set custom paths.**
- **Cached admin authorization on macOS.** After the first admin prompt, the running Ingress process can start root helpers without asking again until macOS expires the authorization. Code running inside the Ingress process during that window would inherit this.
- An attacker who already has admin rights or controls your user account.
- A malicious or compromised VPN gateway: it can push routes and DNS, as with any VPN client.
- Vulnerabilities in openconnect, openfortivpn, sstp-client, pppd, OpenSSL or the system WebView. We track upstream releases and ship rebuilt clients.

## 8. Compared with official vendor clients

Ingress connects to the same gateways using the open-source protocol implementations, but it is **not** a drop-in replacement for an endpoint-management agent. Make sure your policy allows that:

| Capability | FortiClient / GlobalProtect / Secure Client | Ingress |
|---|---|---|
| Fortinet EMS / ZTNA posture, endpoint telemetry | Yes | **No** |
| GlobalProtect HIP report | Real device posture | **Optional and off by default.** When on, it's generated by openconnect's `hipreport.sh`, which **does not inspect the device**: it reports fixed values. Don't treat it as posture evidence. |
| Cisco hostscan / CSD, Cisco SAML | Yes | **No** (Ingress says so instead of failing silently) |
| Always-on / pre-logon VPN, enforced "no split tunnel" | Policy-driven | No. The user connects and disconnects. Routes are what the server pushes or the profile lists. |
| Several tunnels at once | No | **Yes**, the main reason Ingress exists. Several corporate networks can be reachable from one machine at the same time; whether that's acceptable is your policy decision. |
| Background service / kernel extension | Yes | None |
| Source code | Closed | Open (Apache-2.0); the VPN clients are LGPL/GPL |

## 9. Planned hardening

- Build every release (macOS included) in GitHub Actions with **SLSA build-provenance attestations** and an **SBOM**, for both Ingress and ingress-deps.
- **Authenticode signing** of Windows builds via SignPath Foundation.
- Automatic **VirusTotal** scan of every release asset, with the report linked in the release notes.
- **CodeQL, govulncheck, gosec and OpenSSF Scorecard** in CI.

Reporting a vulnerability: [SECURITY.md](../SECURITY.md).
