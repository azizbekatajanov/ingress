package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// globalProtectBackend drives openconnect --protocol=gp (Palo Alto
// GlobalProtect), password login. SAML is phase 5 of design/v2-plan.md.
//
// The patterns below are taken from openconnect v9.21's own source (main.c,
// auth-globalprotect.c, gpst.c), not guessed from captured output:
//   - with --passwd-on-stdin the first password field is filled without a
//     prompt, and the gateway login replays the portal's credentials, so a
//     "<label>: " password prompt only ever appears when they were rejected;
//   - select fields print "LABEL [a|b|c]:" (single choice auto-answers);
//     the portal's gateway list is "GATEWAY:";
//   - 2FA arrives as a "Challenge: " password field;
//   - an untrusted server cert prints "    --servercert pin-sha256:..." and
//     waits on "Enter 'yes' to accept, 'no' to abort; ...";
//   - the tunnel is up at "Configured as <ip>, with SSL ...". The tun/utun
//     name is never printed; Manager finds it by the assigned IP.
type globalProtectBackend struct{}

// gpGatewayLabel is openconnect's label for the portal's gateway list.
const gpGatewayLabel = "GATEWAY:"

var (
	gpConfiguredRe = regexp.MustCompile(`^Configured as ([0-9A-Fa-f.:]+)`)
	gpSelectRe     = regexp.MustCompile(`^(.+?)\s*\[(.+)\]:\s*$`)
	gpServerCertRe = regexp.MustCompile(`^\s*--servercert\s+(pin-sha256:[A-Za-z0-9+/=]+)\s*$`)
	gpCertAskRe    = regexp.MustCompile(`^Enter 'yes' to accept, 'no' to abort`)
	gpChallengeRe  = regexp.MustCompile(`(?i)^challenge:\s*$`)
	gpUsernameRe   = regexp.MustCompile(`(?i)^(username|user name|login|e-?mail)\s*:\s*$`)
	gpSAMLRe       = regexp.MustCompile(`(?i)^SAML \S+ authentication is required via`)
	gpHIPMissingRe = regexp.MustCompile(`(?i)Server asked us to submit HIP report`)
	// Server/client errors worth showing on the overview. openconnect's
	// error output is free text (gpst.c prints the gateway's own <error>
	// message verbatim), so this is a list of known shapes rather than a
	// prefix like openfortivpn's "ERROR:".
	gpErrorRe = regexp.MustCompile(`(?i)^(` +
		`failed to .+|` +
		`.*authentication failed.*|` +
		`.*invalid username or password.*|` +
		`login failed.*|` +
		`invalid authentication cookie|` +
		`portal name not found|` +
		`valid client certificate is required|` +
		`server is neither a globalprotect portal nor a gateway\.?|` +
		`globalprotect portal configuration lists no gateway servers\.?|` +
		`none of the \d+ fingerprint\(s\) specified via --servercert match.*|` +
		`.*must be running as root.*|` +
		`creating ssl connection failed|` +
		`.*could not resolve.*|` +
		`gateway disconnected immediately.*` +
		`)$`)
)

func (globalProtectBackend) Component() string { return "openconnect" }

// No fixed name: utun numbers are allocated dynamically on macOS (and tunN
// on Linux); Manager looks the interface up by the assigned IP.
func (globalProtectBackend) DefaultInterface() string { return "" }

func (globalProtectBackend) Prepare(p Profile, secret, toolPath string) (backendLaunch, error) {
	gp := p.GlobalProtect
	if gp == nil {
		return backendLaunch{}, fmt.Errorf("profile %s has no GlobalProtect settings", p.ID)
	}
	if gp.Auth == GPAuthSAML {
		return backendLaunch{}, errors.New("вход через SAML пока не поддерживается — выберите «Логин и пароль»")
	}
	if p.Username == "" {
		return backendLaunch{}, errors.New("не указано имя пользователя")
	}
	if secret == "" {
		return backendLaunch{}, errors.New("не указан пароль")
	}

	server := p.Host
	if p.Port != "" && p.Port != "443" {
		server = "https://" + p.Host + ":" + p.Port
	}
	args := []string{"--protocol=gp", "--user=" + p.Username, "--passwd-on-stdin"}
	if gp.ConnectTo == GPConnectGateway {
		args = append(args, "--usergroup=gateway")
	} else if gp.Gateway != "" {
		args = append(args, "--authgroup="+gp.Gateway)
	}
	if gp.ServerCert != "" {
		args = append(args, "--servercert="+gp.ServerCert)
	}
	if gp.CaFile != "" {
		args = append(args, "--cafile="+gp.CaFile)
	}
	if gp.UserCert != "" {
		args = append(args, "--certificate="+gp.UserCert)
	}
	if gp.UserKey != "" {
		args = append(args, "--sslkey="+gp.UserKey)
	}

	helpers := openconnectHelperDirs(toolPath)
	if script := findHelper(helpers, "vpnc-script"); script != "" {
		// openconnect runs --script as `/bin/sh -c <script>` (script.c), so
		// it must be shell-quoted: Ingress' own install path has a space
		// ("/Library/Application Support/..."). --csd-wrapper is execv'd
		// directly and must NOT be quoted.
		args = append(args, "--script="+shellQuote(script))
	}
	// Otherwise openconnect falls back to its compiled-in default, which is
	// right for a system (Homebrew/apt) build.
	if gp.HipReport {
		hip := findHelper(helpers, "hipreport.sh")
		if hip == "" {
			return backendLaunch{}, errors.New("включён HIP report, но рядом с openconnect нет hipreport.sh — установите встроенную сборку в «Компоненты» или выключите HIP report")
		}
		args = append(args, "--csd-wrapper="+hip)
	}
	args = append(args, server)

	return backendLaunch{Args: args, Stdin: secret, Target: server}, nil
}

// openconnectHelperDirs lists where helper scripts live relative to the
// binary: libexec/ in Ingress' own archive layout, libexec/openconnect/ for
// Homebrew (bin/ is a symlink into the Cellar) and distro packages
// (/usr/bin → /usr/libexec/openconnect).
func openconnectHelperDirs(toolPath string) []string {
	if real, err := filepath.EvalSymlinks(toolPath); err == nil {
		toolPath = real
	}
	prefix := filepath.Dir(filepath.Dir(toolPath))
	return []string{
		filepath.Join(prefix, "libexec"),
		filepath.Join(prefix, "libexec", "openconnect"),
	}
}

func findHelper(dirs []string, name string) string {
	for _, d := range dirs {
		path := filepath.Join(d, name)
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func (globalProtectBackend) Parse(line string, prompt bool) []lineEvent {
	trimmed := strings.TrimSpace(line)

	if m := gpServerCertRe.FindStringSubmatch(line); m != nil {
		return []lineEvent{
			{Kind: evServerCert, Value: m[1]},
			{Kind: evError, Sticky: true, Value: "сертификат сервера не прошёл проверку — он сохранён в профиле, нажмите «Подключить» ещё раз, если доверяете этому серверу"},
		}
	}
	if gpCertAskRe.MatchString(trimmed) {
		// Never accept interactively: the pin is saved (evServerCert above)
		// and the user reconnects deliberately, same as Fortinet's
		// trusted-cert.
		return []lineEvent{{Kind: evReply, Value: "no"}}
	}
	if m := gpConfiguredRe.FindStringSubmatch(trimmed); m != nil {
		return []lineEvent{{Kind: evAssignedIP, Value: m[1]}}
	}
	if gpSAMLRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evFatal, Value: "портал требует вход через SAML, а он пока не поддерживается"}}
	}
	if gpHIPMissingRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evError, Value: "шлюз требует HIP report — включите его в настройках профиля (Дополнительно)"}}
	}

	if prompt {
		if m := gpSelectRe.FindStringSubmatch(trimmed); m != nil {
			return []lineEvent{{Kind: evPrompt, Prompt: PromptChoice, Label: m[1], Options: strings.Split(m[2], "|")}}
		}
		if gpChallengeRe.MatchString(trimmed) {
			return []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}
		}
		if gpUsernameRe.MatchString(trimmed) {
			return []lineEvent{{Kind: evFatal, Value: "сервер запросил имя пользователя — проверьте его в настройках профиля"}}
		}
		if strings.HasSuffix(trimmed, ":") {
			// The password went in via --passwd-on-stdin and is replayed to
			// the gateway, so any other field prompt means the credentials
			// were rejected (openconnect re-shows the blanked form) — or a
			// form Ingress doesn't know how to fill. Either way, waiting
			// would hang forever.
			return []lineEvent{{Kind: evFatal, Value: fmt.Sprintf("сервер отклонил логин или пароль (запрос «%s»)", trimmed)}}
		}
	}

	// ESP/DTLS problems fall back to TLS on their own — not errors.
	if gpErrorRe.MatchString(trimmed) && !strings.Contains(trimmed, "ESP") && !strings.Contains(trimmed, "DTLS") {
		return []lineEvent{{Kind: evError, Value: trimmed}}
	}
	return nil
}

// SaveServerCert auto-fills --servercert, like Fortinet's trusted-cert.
func (globalProtectBackend) SaveServerCert(p *Profile, cert string) string {
	if p.GlobalProtect == nil || p.GlobalProtect.ServerCert != "" {
		return ""
	}
	p.GlobalProtect.ServerCert = cert
	return "Сертификат сервера сохранён как доверенный (servercert) — нажмите «Подключить» ещё раз"
}

// RememberChoice keeps the picked gateway for --authgroup next time.
func (globalProtectBackend) RememberChoice(p *Profile, label, choice string) bool {
	if p.GlobalProtect == nil || label != gpGatewayLabel || p.GlobalProtect.Gateway == choice {
		return false
	}
	p.GlobalProtect.Gateway = choice
	return true
}

// shellQuote wraps s in single quotes for /bin/sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
