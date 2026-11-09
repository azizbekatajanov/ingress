package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const preloginSAML = `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Enter login credentials</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<saml-default-browser>no</saml-default-browser>
<saml-auth-status>0</saml-auth-status>
<saml-auth-method>REDIRECT</saml-auth-method>
<saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vc3NvP1NBTUxSZXF1ZXN0PWFiYw==</saml-request>
<saml-request-timeout>600</saml-request-timeout>
<region>DE</region>
</prelogin-response>`

const preloginPassword = `<prelogin-response><status>Success</status><authentication-message>Enter login credentials</authentication-message><username-label>Username</username-label></prelogin-response>`

func TestParseGPPrelogin(t *testing.T) {
	info, err := parseGPPrelogin([]byte(preloginSAML))
	if err != nil || !info.usesSAML() || info.SAMLMethod != "REDIRECT" {
		t.Fatalf("SAML prelogin: %+v %v", info, err)
	}
	info, err = parseGPPrelogin([]byte(preloginPassword))
	if err != nil || info.usesSAML() {
		t.Fatalf("password prelogin: %+v %v", info, err)
	}
	_, err = parseGPPrelogin([]byte(`<prelogin-response><status>Error</status><msg>Valid client certificate is required</msg></prelogin-response>`))
	if err == nil || !strings.Contains(err.Error(), "Valid client certificate") {
		t.Errorf("error prelogin: %v", err)
	}
	if _, err := parseGPPrelogin([]byte("<html>nope</html>")); err == nil {
		t.Error("non-GP response must be an error")
	}
}

func TestSAMLRequestFromPrelogin(t *testing.T) {
	info, _ := parseGPPrelogin([]byte(preloginSAML))
	req, err := samlRequestFromPrelogin(info, "https://vpn.example.com", "Вход")
	if err != nil || req.URL != "https://idp.example.com/sso?SAMLRequest=abc" || req.HTML != "" {
		t.Fatalf("REDIRECT: %+v %v", req, err)
	}

	form := `<html><body onload="document.forms[0].submit()"><form method="POST" action="https://idp.example.com/sso"></form></body></html>`
	req, err = samlRequestFromPrelogin(gpPreloginInfo{SAMLMethod: "POST", SAMLRequest: base64.StdEncoding.EncodeToString([]byte(form))}, "https://vpn.example.com", "Вход")
	if err != nil || req.HTML != form || req.BaseURL != "https://vpn.example.com" {
		t.Fatalf("POST: %+v %v", req, err)
	}

	bad := gpPreloginInfo{SAMLMethod: "REDIRECT", SAMLRequest: base64.StdEncoding.EncodeToString([]byte("javascript:alert(1)"))}
	if _, err := samlRequestFromPrelogin(bad, "https://vpn.example.com", "x"); err == nil {
		t.Error("non-https redirect must be refused")
	}
}

func TestSAMLCollector(t *testing.T) {
	c := newSAMLCollector()
	c.addHeaders("Content-Type: text/html\nSet-Cookie: x=y\n")
	if _, done := c.result(); done {
		t.Fatal("done too early")
	}
	// Headers form (header names are case-insensitive).
	c.addHeaders("Saml-Username: ivanov@example.com\nPrelogin-Cookie: COOKIE123\nSAML-Auth-Status: 1\n")
	r, done := c.result()
	if !done || r.Username != "ivanov@example.com" || r.PreloginCookie != "COOKIE123" {
		t.Fatalf("headers: %+v %v", r, done)
	}

	// HTML-comment form on the final page.
	c = newSAMLCollector()
	c.addBody(`<html><head></head><body><!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>PC42</prelogin-cookie><saml-username>petrov</saml-username><saml-slo>no</saml-slo> --></body></html>`)
	r, done = c.result()
	if !done || r.Username != "petrov" || r.PreloginCookie != "PC42" {
		t.Fatalf("body: %+v %v", r, done)
	}
	if f, v := r.secretField(); f != "prelogin-cookie" || v != "PC42" {
		t.Errorf("secretField = %s %s", f, v)
	}

	c = newSAMLCollector()
	c.addBody(`<!-- <saml-auth-status>-1</saml-auth-status><saml-message>User not assigned</saml-message> -->`)
	if r, done := c.result(); !done || r.Error != "User not assigned" {
		t.Fatalf("failure status: %+v %v", r, done)
	}
}

func TestGlobalProtectPrepareSAML(t *testing.T) {
	p := gpProfile()
	p.Username = "ignored-for-saml"
	p.GlobalProtect.Auth = GPAuthSAML
	p.GlobalProtect.Gateway = "EU West"
	res := &samlResult{Username: "ivanov@example.com", PreloginCookie: "COOKIE123"}
	l, err := (globalProtectBackend{}).Prepare(p, authInput{SAML: res}, "/nonexistent/bin/openconnect")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--protocol=gp", "--user=ivanov@example.com", "--usergroup=portal:prelogin-cookie", "--passwd-on-stdin", "--authgroup=EU West", "vpn.example.com"}
	if !reflect.DeepEqual(l.Args, want) || l.Stdin != "COOKIE123" {
		t.Errorf("args =\n  %q stdin=%q\nwant\n  %q", l.Args, l.Stdin, want)
	}

	p.GlobalProtect.ConnectTo = GPConnectGateway
	res = &samlResult{Username: "u", PortalUserauthcookie: "PUC"}
	l, _ = (globalProtectBackend{}).Prepare(p, authInput{SAML: res}, "/nonexistent/bin/openconnect")
	if !reflect.DeepEqual(l.Args[:4], []string{"--protocol=gp", "--user=u", "--usergroup=gateway:portal-userauthcookie", "--passwd-on-stdin"}) || l.Stdin != "PUC" {
		t.Errorf("gateway args = %q stdin=%q", l.Args, l.Stdin)
	}
}

// profileFor points a GP profile at an httptest server.
func profileFor(t *testing.T, srv *httptest.Server) Profile {
	u, _ := url.Parse(srv.URL)
	p := gpProfile()
	p.Host, p.Port = u.Hostname(), u.Port()
	return p
}

func TestGPPreloginCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/global-protect/prelogin.esp" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(preloginSAML))
	}))
	defer srv.Close()
	p := profileFor(t, srv)

	// Self-signed, nothing pinned: offer the pin openconnect would print.
	_, err := gpPrelogin(context.Background(), p)
	var cert *errUntrustedServerCert
	if !errors.As(err, &cert) || cert.Pin != certPin(srv.Certificate()) {
		t.Fatalf("untrusted: %v", err)
	}

	// Pinned: accepted.
	p.GlobalProtect.ServerCert = cert.Pin
	info, err := gpPrelogin(context.Background(), p)
	if err != nil || !info.usesSAML() {
		t.Fatalf("pinned: %+v %v", info, err)
	}

	// Wrong pin: refused, and not offered for trusting either.
	p.GlobalProtect.ServerCert = "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	_, err = gpPrelogin(context.Background(), p)
	if err == nil || errors.As(err, &cert) {
		t.Fatalf("wrong pin: %v", err)
	}
}

func TestGPPreAuthAutoFallsBackToPassword(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(preloginPassword))
	}))
	defer srv.Close()
	p := profileFor(t, srv)
	p.GlobalProtect.ServerCert = certPin(srv.Certificate())

	var logs []string
	auth, err := (globalProtectBackend{}).PreAuth(context.Background(), p, "pw", func(s string) { logs = append(logs, s) })
	if err != nil || auth.Password != "pw" || auth.SAML != nil {
		t.Fatalf("auto/no SAML: %+v %v", auth, err)
	}

	p.GlobalProtect.Auth = GPAuthSAML
	if _, err := (globalProtectBackend{}).PreAuth(context.Background(), p, "pw", func(string) {}); err == nil {
		t.Error("explicit SAML against a password-only server must say so")
	}

	// Server unreachable in auto mode: let openconnect try the password.
	srv.Close()
	p.GlobalProtect.Auth = GPAuthAuto
	auth, err = (globalProtectBackend{}).PreAuth(context.Background(), p, "pw", func(string) {})
	if err != nil || auth.Password != "pw" {
		t.Errorf("auto/unreachable: %+v %v", auth, err)
	}
}

func TestAbortPendingSavesOfferedPin(t *testing.T) {
	m, conn, events := newTestManager(t, gpProfile())
	conn.backend = globalProtectBackend{}
	m.abortPending(conn, &errUntrustedServerCert{Pin: "pin-sha256:abc=", Cause: errors.New("x509: unknown authority")})

	if got, _ := m.store.Get("gp1"); got.GlobalProtect.ServerCert != "pin-sha256:abc=" {
		t.Errorf("pin not saved: %q", got.GlobalProtect.ServerCert)
	}
	if conn.status != StatusDisconnected || !conn.failed || !strings.Contains(conn.lastError, "Подключить") {
		t.Errorf("status=%s failed=%v err=%q", conn.status, conn.failed, conn.lastError)
	}
	joined := strings.Join(*events, ",")
	if !strings.Contains(joined, "profile:updated") || !strings.Contains(joined, "profile:failed") {
		t.Errorf("events = %s", joined)
	}

	// A user cancel is quiet: no error, no window popping up.
	m, conn, events = newTestManager(t, gpProfile())
	conn.backend = globalProtectBackend{}
	m.abortPending(conn, errSAMLCancelled)
	if conn.lastError != "" || strings.Contains(strings.Join(*events, ","), "profile:failed") {
		t.Errorf("cancel surfaced as failure: %q %v", conn.lastError, *events)
	}
}

func TestSAMLCallback(t *testing.T) {
	xmlish := `<html><!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>CB42</prelogin-cookie><saml-username>j.doe@example.com</saml-username> --></html>`
	for name, raw := range map[string]string{
		"std base64":     "globalprotectcallback:" + base64.StdEncoding.EncodeToString([]byte(xmlish)),
		"url-escaped":    "globalprotectcallback:" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(xmlish))),
		"raw url base64": "globalprotectcallback:" + base64.RawURLEncoding.EncodeToString([]byte(xmlish)),
	} {
		c := newSAMLCollector()
		c.addCallback(raw)
		r, done := c.result()
		if !done || r.Username != "j.doe@example.com" || r.PreloginCookie != "CB42" || r.Source != "globalprotectcallback" {
			t.Errorf("%s: %+v %v", name, r, done)
		}
	}

	c := newSAMLCollector()
	c.addCallback("globalprotectcallback:cas-as=1&un=j.doe%40example.com&token=TOK123")
	r, done := c.result()
	if !done || r.Username != "j.doe@example.com" || r.PreloginCookie != "TOK123" {
		t.Errorf("CAS: %+v %v", r, done)
	}
}

func TestFallbackErrorQuotesPreviousLine(t *testing.T) {
	m, conn, _ := newGPTestConn(t)
	m.handleLine(conn, "Matching client config not found", false)
	m.handleLine(conn, "Failed to complete authentication", false)
	if !strings.Contains(conn.lastError, "Failed to complete authentication") || !strings.Contains(conn.lastError, "Matching client config not found") {
		t.Errorf("lastError = %q", conn.lastError)
	}
}
