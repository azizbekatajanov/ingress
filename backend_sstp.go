package main

import (
	"errors"
	"net"
	"regexp"
	"runtime"
	"strings"
)

// sstpBackend drives sstpc (sstp-client, Microsoft SSTP). sstpc speaks SSTP
// over TLS and runs the system pppd for PPP, passing it the credentials in
// a 0600 temp file; pppd's own messages reach us because it inherits
// sstpc's stderr and gets "logfd 2". The password goes in on stdin
// ("--password -", an ingress-deps patch), never in argv.
//
// Routes are Ingress' job, not /etc/ppp/ip-up's: the profile says "all
// traffic" or a list of subnets, and the root wrapper adds them on the
// pppN interface pppd reports (routewatch.go).
type sstpBackend struct{}

// pppd options Ingress always passes: no auth demanded of the server, the
// compression/EAP refusals SSTP servers want, stay in the foreground, log
// to stderr (which ends up in our log).
var sstpBasePppdOptions = []string{"noauth", "refuse-eap", "noccp", "nodeflate", "nobsdcomp", "nodetach", "logfd", "2"}

// pppd options a profile may not add: they run programs or read files as
// root, or would break how Ingress drives and reads pppd. profiles.json is
// writable by the user, so it mustn't be a way to run code as root.
var sstpForbiddenPppdOptions = map[string]bool{
	"connect": true, "disconnect": true, "init": true, "welcome": true,
	"plugin": true, "pty": true, "notty": true, "socket": true, "record": true,
	"file": true, "call": true, "logfile": true, "logfd": true, "detach": true,
	"updetach": true, "nodetach": false, "ip-up-script": true, "ip-down-script": true,
	"ipv6-up-script": true, "ipv6-down-script": true, "ip-pre-up-script": true,
	"auth-up-script": true, "auth-down-script": true, "net-init-script": true,
	"net-pre-up-script": true, "net-down-script": true, "linkname": true,
	"ifname": true, "password": true, "user": true, "remotename": true,
	"pidfile": true, "allow-ip": true, "privgroup": true,
}

var (
	// "Nov 10 14:11:25 sstpc[507]: message " → "message"
	sstpLogPrefixRe = regexp.MustCompile(`^\w{3}\s+\d+\s+[\d:]+\s+sstpc\[\d+\]:\s*`)
	// macOS pppd with logfd: "Tue Nov 10 15:13:55 2026 : message"
	pppdTimePrefixRe = regexp.MustCompile(`^\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s+:\s*`)
	// sstp_die: "**Error: <msg>, (-1)"
	sstpDieRe        = regexp.MustCompile(`^\*\*Error:\s*(.+?),?\s*\(-?\d+\)\s*$`)
	sstpLocalIPRe    = regexp.MustCompile(`(?i)^local\s+IP\s+address\s+([0-9.]+)`)
	sstpAuthFailRe   = regexp.MustCompile(`(?i)(ms-)?chap(-v2)? authentication failed|^pap authentication failed|peer refused to authenticate`)
	sstpCertFailRe   = regexp.MustCompile(`(?i)verification of server certificate failed`)
	sstpLCPTimeoutRe = regexp.MustCompile(`(?i)LCP: timeout sending Config-Requests`)
)

func (sstpBackend) Component() string        { return "sstpc" }
func (sstpBackend) DefaultInterface() string { return "" }

func (sstpBackend) Prepare(p Profile, auth authInput, toolPath string) (backendLaunch, error) {
	s := p.SSTP
	if s == nil {
		return backendLaunch{}, errors.New(T("err.unknown_type", p.Type))
	}
	if p.Username == "" {
		return backendLaunch{}, errors.New(T("err.no_username"))
	}
	if auth.Password == "" {
		return backendLaunch{}, errors.New(T("err.no_password"))
	}
	routes, err := sstpRouteSpec(s)
	if err != nil {
		return backendLaunch{}, err
	}
	extra, err := sstpPppdOptions(s.PppdOptions)
	if err != nil {
		return backendLaunch{}, err
	}

	args := []string{"--log-stderr", "--log-level", "2"}
	switch {
	case s.InsecureCert:
		args = append(args, "--cert-warn")
	case s.CaFile != "":
		args = append(args, "--ca-cert", s.CaFile)
	case runtime.GOOS == "darwin":
		// sstpc looks in a CA directory by default, which macOS doesn't
		// have; its bundle file is the system store.
		args = append(args, "--ca-cert", "/etc/ssl/cert.pem")
	}
	if s.RouteMode == SSTPRoutesAll {
		// Keep the VPN server itself reachable through the current
		// gateway once 0/1 + 128/1 point into the tunnel.
		args = append(args, "--save-server-route")
	}
	server := p.Host
	if p.Port != "" && p.Port != "443" {
		server += ":" + p.Port
	}
	args = append(args, "--user", p.Username, "--password", "-", server, "--")
	args = append(args, sstpBasePppdOptions...)
	args = append(args, extra...)

	return backendLaunch{
		Args:        args,
		Stdin:       auth.Password,
		Target:      server,
		WrapperOpts: []string{routesArgPrefix + routes},
	}, nil
}

// sstpRouteSpec turns the profile's route settings into the root wrapper's
// --routes value: "all", or comma-separated CIDRs.
func sstpRouteSpec(s *SSTPSettings) (string, error) {
	if s.RouteMode == SSTPRoutesAll {
		return "all", nil
	}
	var nets []string
	for _, raw := range s.Subnets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil || n.IP.To4() == nil {
			return "", errors.New(T("sstp.err.bad_subnet", raw))
		}
		nets = append(nets, n.String())
	}
	if len(nets) == 0 {
		return "", errors.New(T("sstp.err.no_subnets"))
	}
	return strings.Join(nets, ","), nil
}

// sstpPppdOptions splits and checks the profile's extra pppd options.
func sstpPppdOptions(raw string) ([]string, error) {
	opts := strings.Fields(raw)
	for _, o := range opts {
		name := strings.TrimPrefix(strings.ToLower(o), "+")
		if sstpForbiddenPppdOptions[name] || strings.ContainsAny(o, "/\\`$;|&<>\"'") {
			return nil, errors.New(T("sstp.err.pppd_option", o))
		}
	}
	return opts, nil
}

func (sstpBackend) Parse(line string, _ bool) []lineEvent {
	msg := strings.TrimSpace(line)
	msg = sstpLogPrefixRe.ReplaceAllString(msg, "")
	msg = strings.TrimSpace(pppdTimePrefixRe.ReplaceAllString(msg, ""))
	if msg == "" {
		return nil
	}
	if m := sstpLocalIPRe.FindStringSubmatch(msg); m != nil {
		return []lineEvent{{Kind: evAssignedIP, Value: m[1]}}
	}
	if sstpAuthFailRe.MatchString(msg) {
		return []lineEvent{{Kind: evError, Sticky: true, Value: T("sstp.err.auth")}}
	}
	if sstpCertFailRe.MatchString(msg) {
		return []lineEvent{{Kind: evError, Sticky: true, Value: T("sstp.err.cert")}}
	}
	if sstpLCPTimeoutRe.MatchString(msg) {
		return []lineEvent{{Kind: evError, Value: T("sstp.err.lcp")}}
	}
	if m := sstpDieRe.FindStringSubmatch(msg); m != nil {
		return []lineEvent{{Kind: evError, Value: m[1]}}
	}
	return nil
}

// sstpc can't pin a certificate the way openfortivpn/openconnect do; trust
// is the CA file (or "don't verify") in the profile.
func (sstpBackend) SaveServerCert(*Profile, string) string { return "" }

func (sstpBackend) RememberChoice(*Profile, string, string) bool { return false }
