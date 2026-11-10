package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ciscoBackend drives openconnect --protocol=anyconnect (Cisco Secure
// Client / AnyConnect ASA and FTD, and ocserv): group, username, password
// and a second factor. SSO and hostscan (CSD) aren't supported yet — both
// end with a clear message instead of openconnect's generic failure.
//
// Unlike GlobalProtect, a field prompt after the password is normal here:
// it's how the server asks for the second factor. What tells a 2FA prompt
// from "your password was wrong" is the error the server sends with the
// re-shown form — openconnect prints it right before the prompt. Shapes
// below are from openconnect 9.21 talking to ocserv (captured in
// backend_cisco_test.go):
//
//	Please enter your username.          ← form message
//	Group: [Engineering|Sales]:          ← group select (label is the server's)
//	Please enter your OTP password.      ← second-factor form message
//	Password:                            ← its field
//	Login failed.                        ← form error, then the same form again
//
// It's stateful (message/error seen so far), so backendFor makes a fresh one
// per connection; Parse is only ever called from that connection's reader.
type ciscoBackend struct {
	lastMessage string // last line that looked like a form message
	rejected    string // the form error the server sent since the last prompt
}

var (
	ciscoGroupLabelRe = regexp.MustCompile(`(?i)group|профил|profile|realm|domain`)
	// Form errors the server sends (auth.c prints form->error verbatim).
	ciscoRejectRe = regexp.MustCompile(`(?i)^(login failed\.?|.*authentication failed.*|.*invalid (username|password|credentials).*|.*incorrect (username|password).*|.*access denied.*)$`)
	// Form messages ("Please enter your username.", "Enter your passcode").
	ciscoMessageRe = regexp.MustCompile(`(?i)^(please |enter |type |respond |answer |provide ).+`)
	ciscoCSDRe     = regexp.MustCompile(`(?i)Server asked us to run CSD hostscan`)
	ciscoSSORe     = regexp.MustCompile(`(?i)^No SSO handler|external browser`)
	ciscoErrorRe   = regexp.MustCompile(`(?i)^(failed to .+|.*could not resolve.*|creating ssl connection failed|none of the \d+ fingerprint\(s\) specified via --servercert match.*|.*must be running as root.*|server reported certificate error.*|client certificate missing or incorrect.*)$`)
)

func (*ciscoBackend) Component() string        { return "openconnect" }
func (*ciscoBackend) DefaultInterface() string { return "" }

func (*ciscoBackend) Prepare(p Profile, auth authInput, toolPath string) (backendLaunch, error) {
	c := p.Cisco
	if c == nil {
		return backendLaunch{}, fmt.Errorf("profile %s has no Cisco settings", p.ID)
	}
	if p.Username == "" {
		return backendLaunch{}, errors.New("не указано имя пользователя")
	}
	if auth.Password == "" {
		return backendLaunch{}, errors.New("не указан пароль")
	}

	args := []string{"--protocol=anyconnect", "--user=" + p.Username, "--passwd-on-stdin"}
	if c.Group != "" {
		args = append(args, "--authgroup="+c.Group)
	}
	if c.ServerCert != "" {
		args = append(args, "--servercert="+c.ServerCert)
	}
	if c.CaFile != "" {
		args = append(args, "--cafile="+c.CaFile)
	}
	if c.UserCert != "" {
		args = append(args, "--certificate="+c.UserCert)
	}
	if c.UserKey != "" {
		args = append(args, "--sslkey="+c.UserKey)
	}
	if script := findHelper(openconnectHelperDirs(toolPath), "vpnc-script"); script != "" {
		args = append(args, "--script="+shellQuote(script)) // see GP: run via sh -c
	}

	server := "https://" + p.Host
	if p.Port != "" && p.Port != "443" {
		server += ":" + p.Port
	}
	args = append(args, server)
	return backendLaunch{Args: args, Stdin: auth.Password, Target: server}, nil
}

func (b *ciscoBackend) Parse(line string, prompt bool) []lineEvent {
	trimmed := strings.TrimSpace(line)
	if evs, ok := parseOpenconnectCommon(line, trimmed); ok {
		return evs
	}
	if ciscoCSDRe.MatchString(trimmed) {
		return []lineEvent{{Kind: evFatal, Value: "сервер требует проверку компьютера (Cisco hostscan/CSD), а Ingress её пока не поддерживает"}}
	}
	if ciscoSSORe.MatchString(trimmed) {
		return []lineEvent{{Kind: evFatal, Value: "сервер требует вход через SSO (SAML), а для Cisco Ingress его пока не поддерживает — выберите на сервере группу с входом по паролю"}}
	}

	if prompt {
		rejected := b.rejected
		b.rejected = ""
		if m := ocSelectRe.FindStringSubmatch(trimmed); m != nil {
			return []lineEvent{{Kind: evPrompt, Prompt: PromptChoice, Label: m[1], Options: strings.Split(m[2], "|")}}
		}
		if rejected != "" {
			// The form came back with an error: wrong password, or a wrong
			// second factor on servers that re-ask instead of failing.
			return []lineEvent{{Kind: evFatal, Value: "сервер отклонил данные входа (" + rejected + ")"}}
		}
		if ocUsernameRe.MatchString(trimmed) {
			return []lineEvent{{Kind: evFatal, Value: "сервер запросил имя пользователя — проверьте его в настройках профиля"}}
		}
		if strings.HasSuffix(trimmed, ":") {
			// The password went in via --passwd-on-stdin; a further field
			// without an error is the second factor.
			return []lineEvent{{Kind: evPrompt, Prompt: PromptText, Label: strings.TrimSuffix(trimmed, ":"), Value: b.lastMessage}}
		}
		return nil
	}

	if strings.Contains(trimmed, "HTTP/1.1 401") {
		return []lineEvent{{Kind: evError, Value: "сервер отклонил данные входа (401) — неверный пароль или код"}}
	}
	if ciscoRejectRe.MatchString(trimmed) {
		b.rejected = trimmed
		return []lineEvent{{Kind: evError, Value: trimmed}}
	}
	if ciscoMessageRe.MatchString(trimmed) {
		b.lastMessage = trimmed
		return nil
	}
	if ciscoErrorRe.MatchString(trimmed) && !strings.Contains(trimmed, "DTLS") {
		return []lineEvent{{Kind: evError, Value: trimmed}}
	}
	return nil
}

func (*ciscoBackend) SaveServerCert(p *Profile, cert string) string {
	if p.Cisco == nil || p.Cisco.ServerCert != "" {
		return ""
	}
	p.Cisco.ServerCert = cert
	return "Сертификат сервера сохранён как доверенный (servercert) — нажмите «Подключить» ещё раз"
}

// RememberChoice keeps the picked group for --authgroup next time. The
// select's label is the server's own ("Group:", "GROUP:", localized…).
func (*ciscoBackend) RememberChoice(p *Profile, label, choice string) bool {
	if p.Cisco == nil || !ciscoGroupLabelRe.MatchString(label) || p.Cisco.Group == choice {
		return false
	}
	p.Cisco.Group = choice
	return true
}
