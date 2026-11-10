package main

import (
	"regexp"
	"strings"
)

// Output every openconnect protocol (GlobalProtect, AnyConnect, …) prints
// the same way — from openconnect's main.c / ssl code, confirmed against a
// real GP portal and an ocserv (AnyConnect) server.
var (
	ocConfiguredRe = regexp.MustCompile(`^Configured as ([0-9A-Fa-f.:]+)`)
	ocSelectRe     = regexp.MustCompile(`^(.+?)\s*\[(.+)\]:\s*$`)
	ocServerCertRe = regexp.MustCompile(`^\s*--servercert\s+(pin-sha256:[A-Za-z0-9+/=]+)\s*$`)
	ocCertAskRe    = regexp.MustCompile(`^Enter 'yes' to accept, 'no' to abort`)
	ocUsernameRe   = regexp.MustCompile(`(?i)^(username|user name|login|e-?mail)\s*:\s*$`)
	// openconnect's closing summary after any auth failure; the real reason
	// is printed before it.
	ocGenericFailRe = regexp.MustCompile(`^(Failed to complete authentication|Failed to obtain WebVPN cookie)\.?$`)
)

// parseOpenconnectCommon handles the protocol-independent lines. ok=false
// means the line is the protocol backend's to interpret.
func parseOpenconnectCommon(line, trimmed string) ([]lineEvent, bool) {
	if m := ocServerCertRe.FindStringSubmatch(line); m != nil {
		return []lineEvent{
			{Kind: evServerCert, Value: m[1]},
			{Kind: evError, Sticky: true, Value: "сертификат сервера не прошёл проверку — он сохранён в профиле, нажмите «Подключить» ещё раз, если доверяете этому серверу"},
		}, true
	}
	if ocCertAskRe.MatchString(trimmed) {
		// Never accept interactively: the pin is saved (evServerCert above)
		// and the user reconnects deliberately, like Fortinet's trusted-cert.
		return []lineEvent{{Kind: evReply, Value: "no"}}, true
	}
	if m := ocConfiguredRe.FindStringSubmatch(trimmed); m != nil {
		return []lineEvent{{Kind: evAssignedIP, Value: m[1]}}, true
	}
	if strings.Contains(trimmed, "unsafe legacy renegotiation disabled") {
		// OpenSSL 3 without SSL_OP_LEGACY_SERVER_CONNECT; Ingress' own
		// openconnect (ingress-deps patch 0002) connects to such servers.
		return []lineEvent{{Kind: evError, Sticky: true, Value: "сервер не поддерживает безопасное пересогласование TLS (RFC 5746), а этот openconnect на OpenSSL 3 отказывается к нему подключаться — используйте встроенную сборку OpenConnect в «Компоненты»"}}, true
	}
	if ocGenericFailRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evError, Fallback: true, Value: trimmed}}, true
	}
	return nil, false
}
