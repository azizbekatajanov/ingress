package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// GlobalProtect prelogin: before starting openconnect, Ingress asks the
// portal (or gateway) how it wants to authenticate — the same
// prelogin.esp request openconnect itself makes (auth-globalprotect.c). If
// the answer is SAML, Ingress runs the SAML login in its own window (see
// saml.go) and hands openconnect the resulting cookie instead of a password;
// openconnect can't do SAML on its own outside NetworkManager.

type gpPreloginInfo struct {
	SAMLMethod  string // "REDIRECT" | "POST" | "" (no SAML)
	SAMLRequest string // base64: a URL (REDIRECT) or an HTML form (POST)
}

func (i gpPreloginInfo) usesSAML() bool { return i.SAMLMethod != "" && i.SAMLRequest != "" }

// errUntrustedServerCert: the server's certificate didn't verify and no pin
// is configured. Pin is the openconnect-style "pin-sha256:..." value to
// offer for trusting it (saved to the profile, same as when openconnect
// itself reports it).
type errUntrustedServerCert struct {
	Pin   string
	Cause error
}

func (e *errUntrustedServerCert) Error() string {
	return fmt.Sprintf("сертификат сервера не прошёл проверку: %v", e.Cause)
}

// certPin is openconnect's --servercert format: base64 SHA-256 of the
// certificate's SubjectPublicKeyInfo.
func certPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

func gpClientOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "Mac"
	case "windows":
		return "Windows"
	}
	return "Linux"
}

// gpServerURL is https://host[:port], the base for prelogin and SAML.
func gpServerURL(p Profile) string {
	if p.Port != "" && p.Port != "443" {
		return "https://" + net.JoinHostPort(p.Host, p.Port)
	}
	return "https://" + p.Host
}

func gpTLSConfig(gp *GlobalProtectSettings) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if gp.CaFile != "" {
		pem, err := os.ReadFile(gp.CaFile)
		if err != nil {
			return nil, fmt.Errorf("CA-сертификат: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA-сертификат %s не содержит PEM-сертификатов", gp.CaFile)
		}
		cfg.RootCAs = pool
	}
	if gp.UserCert != "" && gp.UserKey != "" {
		if pair, err := tls.LoadX509KeyPair(gp.UserCert, gp.UserKey); err == nil {
			cfg.Certificates = []tls.Certificate{pair}
		}
		// Otherwise (encrypted key, PKCS#12...) prelogin goes without it;
		// openconnect still gets the files and handles them itself.
	}
	if gp.ServerCert != "" {
		// Pinned: accept exactly that key, like openconnect --servercert.
		pin := gp.ServerCert
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if got := certPin(leaf); got != pin {
				return fmt.Errorf("сертификат сервера не совпадает с сохранённым (%s)", got)
			}
			return nil
		}
	}
	return cfg, nil
}

// fetchServerPin reads the server's leaf certificate without verifying it,
// to offer its pin after a verification failure.
func fetchServerPin(ctx context.Context, hostport string) (string, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no server certificate")
	}
	return certPin(certs[0]), nil
}

func gpPrelogin(ctx context.Context, p Profile) (gpPreloginInfo, error) {
	gp := p.GlobalProtect
	if gp == nil {
		return gpPreloginInfo{}, fmt.Errorf("profile %s has no GlobalProtect settings", p.ID)
	}
	tlsCfg, err := gpTLSConfig(gp)
	if err != nil {
		return gpPreloginInfo{}, err
	}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}

	path := "global-protect"
	if gp.ConnectTo == GPConnectGateway {
		path = "ssl-vpn"
	}
	url := fmt.Sprintf("%s/%s/prelogin.esp?tmp=tmp&clientVer=4100&clientos=%s", gpServerURL(p), path, gpClientOS())
	body := "tmp=tmp&kerberos-support=yes&ipv6-support=yes&clientVer=4100&clientos=" + gpClientOS()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return gpPreloginInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "PAN GlobalProtect")

	resp, err := client.Do(req)
	if err != nil {
		var unknownCA x509.UnknownAuthorityError
		var badHost x509.HostnameError
		var invalid x509.CertificateInvalidError
		if gp.ServerCert == "" && (errors.As(err, &unknownCA) || errors.As(err, &badHost) || errors.As(err, &invalid)) {
			hostport := p.Host + ":443"
			if p.Port != "" {
				hostport = net.JoinHostPort(p.Host, p.Port)
			}
			if pin, perr := fetchServerPin(ctx, hostport); perr == nil {
				return gpPreloginInfo{}, &errUntrustedServerCert{Pin: pin, Cause: err}
			}
		}
		return gpPreloginInfo{}, fmt.Errorf("запрос prelogin: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return gpPreloginInfo{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return gpPreloginInfo{}, fmt.Errorf("prelogin: сервер ответил %s", resp.Status)
	}
	return parseGPPrelogin(data)
}

func parseGPPrelogin(data []byte) (gpPreloginInfo, error) {
	var r struct {
		XMLName     xml.Name `xml:"prelogin-response"`
		Status      string   `xml:"status"`
		Msg         string   `xml:"msg"`
		SAMLMethod  string   `xml:"saml-auth-method"`
		SAMLRequest string   `xml:"saml-request"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return gpPreloginInfo{}, fmt.Errorf("ответ prelogin не похож на GlobalProtect: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(r.Status), "Success") {
		msg := strings.TrimSpace(r.Msg)
		if msg == "" {
			msg = r.Status
		}
		return gpPreloginInfo{}, fmt.Errorf("prelogin: %s", msg)
	}
	return gpPreloginInfo{
		SAMLMethod:  strings.ToUpper(strings.TrimSpace(r.SAMLMethod)),
		SAMLRequest: strings.TrimSpace(r.SAMLRequest),
	}, nil
}
