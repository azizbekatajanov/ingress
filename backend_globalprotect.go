package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// globalProtectBackend drives openconnect --protocol=gp (Palo Alto
// GlobalProtect): password login, or SAML through Ingress' own login window
// (PreAuth) with the resulting cookie handed to openconnect as an alternate
// secret — `--usergroup=portal:prelogin-cookie`. That alternate-secret path
// needs openconnect with MR !656 (an empty "passwd" field next to the
// cookie, which some gateways insist on); Ingress' own build carries it.
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
	gpChallengeRe       = regexp.MustCompile(`(?i)^challenge:\s*$`)
	gpAltSecretPromptRe = regexp.MustCompile(`^(prelogin-cookie|portal-userauthcookie|portal-prelogonuserauthcookie):\s*$`)
	gpSAMLRe            = regexp.MustCompile(`(?i)^SAML \S+ authentication is required via`)
	gpHIPMissingRe      = regexp.MustCompile(`(?i)Server asked us to submit HIP report`)
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

// NeedsPreAuth: anything but an explicit password login starts with
// prelogin (to find out whether the server wants SAML).
func (globalProtectBackend) NeedsPreAuth(p Profile) bool {
	return p.GlobalProtect != nil && p.GlobalProtect.Auth != GPAuthPassword
}

func (globalProtectBackend) PreAuth(ctx context.Context, p Profile, password string, log func(string)) (authInput, error) {
	gp := p.GlobalProtect
	log(T("gp.log.prelogin"))
	info, err := gpPrelogin(ctx, p)
	if err != nil {
		var cert *errUntrustedServerCert
		if errors.As(err, &cert) || ctx.Err() != nil || gp.Auth == GPAuthSAML {
			return authInput{}, err
		}
		// Auto: let openconnect try the password and report what's wrong.
		log(T("gp.log.prelogin_failed", err))
		return authInput{Password: password}, nil
	}
	if !info.usesSAML() {
		if gp.Auth == GPAuthSAML {
			return authInput{}, errors.New(T("gp.err.no_saml"))
		}
		log(T("gp.log.password_login"))
		return authInput{Password: password}, nil
	}

	req, err := samlRequestFromPrelogin(info, gpServerURL(p), T("saml.window_title", p.Name))
	if err != nil {
		return authInput{}, err
	}
	log(T("gp.log.saml_window"))
	res, err := samlLogin(ctx, req)
	if err != nil {
		return authInput{}, err
	}
	field, value := res.secretField()
	log(T("gp.log.saml_done", res.Username, field, len(value), T("saml.source."+res.Source)))
	return authInput{SAML: &res}, nil
}

func (globalProtectBackend) Prepare(p Profile, auth authInput, toolPath string) (backendLaunch, error) {
	gp := p.GlobalProtect
	if gp == nil {
		return backendLaunch{}, fmt.Errorf("profile %s has no GlobalProtect settings", p.ID)
	}
	target := "portal"
	if gp.ConnectTo == GPConnectGateway {
		target = "gateway"
	}

	var args []string
	var secret string
	var replies map[string]string
	if auth.SAML != nil {
		field, value := auth.SAML.secretField()
		args = []string{"--protocol=gp", "--user=" + auth.SAML.Username, "--usergroup=" + target + ":" + field, "--passwd-on-stdin"}
		secret = value
		// After SAML on the portal, openconnect replays credentials to the
		// gateway only if the portal returned a portal-userauthcookie; with
		// an alternate secret it otherwise re-asks the gateway form for the
		// same field ("prelogin-cookie: "). Answer once with the same cookie
		// — gateways sharing the portal's SAML accept it (checked against
		// openconnect's fake-gp-server in ingress-deps' tests).
		replies = map[string]string{field + ":": value}
	} else {
		if gp.Auth == GPAuthSAML {
			return backendLaunch{}, errors.New(T("gp.err.no_saml_result"))
		}
		if p.Username == "" {
			return backendLaunch{}, errors.New(T("err.no_username"))
		}
		if auth.Password == "" {
			return backendLaunch{}, errors.New(T("err.no_password"))
		}
		args = []string{"--protocol=gp", "--user=" + p.Username, "--passwd-on-stdin"}
		if target == "gateway" {
			args = append(args, "--usergroup=gateway")
		}
		secret = auth.Password
	}
	if target == "portal" && gp.Gateway != "" {
		args = append(args, "--authgroup="+gp.Gateway)
	}

	server := gpServerURL(p)
	if p.Port == "" || p.Port == "443" {
		server = p.Host // plain host, as openconnect users usually write it
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
			return backendLaunch{}, errors.New(T("gp.err.no_hipreport"))
		}
		args = append(args, "--csd-wrapper="+hip)
	}
	args = append(args, server)

	return backendLaunch{Args: args, Stdin: secret, PromptReplies: replies, Target: server}, nil
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

	if evs, ok := parseOpenconnectCommon(line, trimmed); ok {
		return evs
	}
	if gpSAMLRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evFatal, Value: T("gp.err.saml_required")}}
	}
	if gpHIPMissingRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evError, Value: T("gp.err.hip_required")}}
	}

	if prompt {
		if m := ocSelectRe.FindStringSubmatch(trimmed); m != nil {
			return []lineEvent{{Kind: evPrompt, Prompt: PromptChoice, Label: m[1], Options: strings.Split(m[2], "|")}}
		}
		if gpChallengeRe.MatchString(trimmed) {
			return []lineEvent{{Kind: evPrompt, Prompt: PromptOTP}}
		}
		if gpAltSecretPromptRe.MatchString(trimmed) {
			// Already answered once (see Prepare's PromptReplies): the
			// gateway wants its own SAML login, not the portal's cookie.
			return []lineEvent{{Kind: evFatal, Value: T("gp.err.gateway_own_saml")}}
		}
		if ocUsernameRe.MatchString(trimmed) {
			return []lineEvent{{Kind: evFatal, Value: T("err.username_asked")}}
		}
		if strings.HasSuffix(trimmed, ":") {
			// The password went in via --passwd-on-stdin and is replayed to
			// the gateway, so any other field prompt means the credentials
			// were rejected (openconnect re-shows the blanked form) — or a
			// form Ingress doesn't know how to fill. Either way, waiting
			// would hang forever.
			return []lineEvent{{Kind: evFatal, Value: T("gp.err.rejected", trimmed)}}
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
	return T("cert.servercert_saved")
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
