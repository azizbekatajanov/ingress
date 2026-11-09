package main

import (
	"fmt"
	"os"
	"regexp"
)

// fortinetBackend drives openfortivpn (Fortinet SSL-VPN).
type fortinetBackend struct{}

// Heuristic detectors for openfortivpn/pppd's stdout+stderr — see
// vpnBackend.Parse. Tuned against a real FortiGate's wording.
var (
	// Whole words only: 1.0.x matched substrings, so a --trusted-cert hash
	// that happened to contain "2fa" (~1.5% of certificates) opened the OTP
	// modal instead of the trust-this-cert flow.
	fortiOtpPromptRe = regexp.MustCompile(`(?i)\b(one-time|otp|two-factor|2fa|verification code|token code)\b`)
	fortiIPAssignRe  = regexp.MustCompile(`(?i)local\s+ip\s+address\s+([0-9.]+)`)
	fortiIfaceUpRe   = regexp.MustCompile(`(?i)interface\s+(\S+)\s+is\s+up`)
	fortiErrorLineRe = regexp.MustCompile(`(?i)^\s*ERROR:\s*(.+)$`)
	// Matches the one-line form of openfortivpn's untrusted-gateway-cert
	// error ("...rerun with:\n    --trusted-cert <sha256>"), which is easier
	// to parse reliably than the multi-line "sha256 digest:\n    <hash>" block.
	fortiUntrustedCertRe = regexp.MustCompile(`--trusted-cert\s+([0-9a-f]{64})`)
)

func (fortinetBackend) Component() string { return "openfortivpn" }

func (fortinetBackend) DefaultInterface() string { return "ppp0" }

// Prepare passes credentials via a private 0600 temp config file
// (`--config=`), never on argv.
func (fortinetBackend) Prepare(p Profile, secret string) (backendLaunch, error) {
	cfgPath, err := writeOpenfortivpnConfig(p, secret)
	if err != nil {
		return backendLaunch{}, fmt.Errorf("writing config: %w", err)
	}
	target := fmt.Sprintf("%s:%s", p.Host, p.Port)
	return backendLaunch{
		Args:    []string{target, "--config=" + cfgPath},
		Target:  target,
		Cleanup: func() { os.Remove(cfgPath) },
	}, nil
}

func (fortinetBackend) Parse(line string) []lineEvent {
	var evs []lineEvent
	if m := fortiErrorLineRe.FindStringSubmatch(line); m != nil {
		evs = append(evs, lineEvent{Kind: evError, Value: m[1]})
	}
	certMatch := fortiUntrustedCertRe.FindStringSubmatch(line)
	if certMatch != nil {
		evs = append(evs, lineEvent{Kind: evServerCert, Value: certMatch[1]})
	}
	if certMatch == nil && fortiOtpPromptRe.MatchString(line) {
		evs = append(evs, lineEvent{Kind: evPrompt, Prompt: PromptOTP})
	}
	if m := fortiIPAssignRe.FindStringSubmatch(line); m != nil {
		evs = append(evs, lineEvent{Kind: evAssignedIP, Value: m[1]})
	}
	if m := fortiIfaceUpRe.FindStringSubmatch(line); m != nil {
		evs = append(evs, lineEvent{Kind: evInterfaceUp, Value: m[1]})
	}
	return evs
}

// SaveServerCert auto-fills trusted-cert (but doesn't auto-reconnect —
// trusting a cert is a deliberate action, this just saves copy-pasting the
// hash by hand), so the next click on "Подключить" succeeds.
func (fortinetBackend) SaveServerCert(p *Profile, cert string) string {
	if p.Fortinet == nil || p.Fortinet.TrustedCert != "" {
		return ""
	}
	p.Fortinet.TrustedCert = cert
	return "Сертификат шлюза сохранён как доверенный (trusted-cert) — нажмите «Подключить» ещё раз"
}
