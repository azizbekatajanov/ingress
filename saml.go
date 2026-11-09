package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// SAML login for GlobalProtect, in a separate process:
//
//	ingress --saml-login   (samlRequest JSON on stdin, samlResult JSON on stdout)
//
// It's a separate process because Wails v2 owns the one native window and
// the main run loop; a second web view inside the same NSApplication would
// fight it. The child opens a plain window with a WebView on the IdP page
// and watches every response for the GlobalProtect result, which the portal
// returns at the end of the SAML flow either as HTTP headers or as XML-ish
// tags inside an HTML comment (both forms exist in the wild — gp-saml-gui
// checks both, and so does this):
//
//	saml-username, prelogin-cookie | portal-userauthcookie, saml-auth-status

type samlRequest struct {
	Title string `json:"title"`
	// Exactly one of URL (REDIRECT method) or HTML (POST method: an
	// auto-submitting form) is set; BaseURL is the origin for HTML.
	URL     string `json:"url,omitempty"`
	HTML    string `json:"html,omitempty"`
	BaseURL string `json:"baseUrl,omitempty"`
}

type samlResult struct {
	Username             string `json:"username,omitempty"`
	PreloginCookie       string `json:"preloginCookie,omitempty"`
	PortalUserauthcookie string `json:"portalUserauthcookie,omitempty"`
	// Source says where the result was found ("заголовки ответа",
	// "страница", "globalprotectcallback") — logged for diagnostics.
	Source    string `json:"source,omitempty"`
	Cancelled bool   `json:"cancelled,omitempty"`
	Error     string `json:"error,omitempty"`
}

// secretField is the openconnect --usergroup suffix naming which cookie the
// result carries (prelogin-cookie preferred, as openconnect documents).
func (r samlResult) secretField() (field, value string) {
	if r.PreloginCookie != "" {
		return "prelogin-cookie", r.PreloginCookie
	}
	return "portal-userauthcookie", r.PortalUserauthcookie
}

// samlRequestFromPrelogin turns prelogin's saml-request into what the
// window loads.
func samlRequestFromPrelogin(info gpPreloginInfo, base, title string) (samlRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(info.SAMLRequest)
	if err != nil {
		return samlRequest{}, fmt.Errorf("saml-request не в base64: %w", err)
	}
	switch info.SAMLMethod {
	case "REDIRECT":
		u := strings.TrimSpace(string(decoded))
		if !strings.HasPrefix(u, "https://") {
			return samlRequest{}, fmt.Errorf("SAML REDIRECT ведёт не на https: %q", u)
		}
		return samlRequest{Title: title, URL: u}, nil
	case "POST":
		return samlRequest{Title: title, HTML: string(decoded), BaseURL: base}, nil
	}
	return samlRequest{}, fmt.Errorf("неизвестный метод SAML %q", info.SAMLMethod)
}

// samlCollector accumulates GlobalProtect result fields seen in headers and
// page bodies, and decides when the login is complete.
type samlCollector struct {
	mu     sync.Mutex
	fields map[string]string
	source string // where the last useful field came from
}

var samlFieldNames = []string{"saml-username", "prelogin-cookie", "portal-userauthcookie", "saml-auth-status", "saml-message"}

var samlBodyFieldRe = regexp.MustCompile(`<(saml-username|prelogin-cookie|portal-userauthcookie|saml-auth-status|saml-message)>([^<]*)</(?:saml-username|prelogin-cookie|portal-userauthcookie|saml-auth-status|saml-message)>`)

func newSAMLCollector() *samlCollector {
	return &samlCollector{fields: map[string]string{}}
}

// addHeaders takes "Name: value" lines.
func (c *samlCollector) addHeaders(block string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range strings.Split(block, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		for _, f := range samlFieldNames {
			if name == f {
				c.fields[f] = strings.TrimSpace(value)
				c.source = "заголовки ответа"
			}
		}
	}
}

func (c *samlCollector) addBody(html string) {
	c.addBodyFrom(html, "страница")
}

func (c *samlCollector) addBodyFrom(html, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range samlBodyFieldRe.FindAllStringSubmatch(html, -1) {
		c.fields[m[1]] = strings.TrimSpace(m[2])
		c.source = source
	}
}

// addCallback handles a globalprotectcallback: URL — how portals set to
// "use default browser for SAML" (prelogin <saml-default-browser>yes) hand
// the result back: either base64 of the same XML-ish tags as the final
// page, or CAS-style "cas-as=1&un=<user>&token=<cookie>".
func (c *samlCollector) addCallback(rawURL string) {
	data := strings.TrimPrefix(rawURL, "globalprotectcallback:")
	data = strings.TrimPrefix(data, "//")
	// PathUnescape, not QueryUnescape: "+" is a base64 character here,
	// not an encoded space.
	if unescaped, err := url.PathUnescape(data); err == nil {
		data = unescaped
	}
	if strings.Contains(data, "cas-as=") {
		q, err := url.ParseQuery(strings.TrimPrefix(rawURL, "globalprotectcallback:"))
		if err != nil {
			return
		}
		c.mu.Lock()
		if un := q.Get("un"); un != "" {
			c.fields["saml-username"] = un
		}
		if token := q.Get("token"); token != "" {
			c.fields["prelogin-cookie"] = token
		}
		c.source = "globalprotectcallback (CAS)"
		c.mu.Unlock()
		return
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(strings.TrimSpace(data)); err == nil {
			c.addBodyFrom(string(decoded), "globalprotectcallback")
			return
		}
	}
	c.addBodyFrom(data, "globalprotectcallback")
}

// result reports a finished login (success or explicit failure), or false
// while the user is still going through the IdP.
func (c *samlCollector) result() (samlResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fields["saml-auth-status"] == "-1" {
		msg := c.fields["saml-message"]
		if msg == "" {
			msg = "сервер сообщил об ошибке SAML-входа"
		}
		return samlResult{Error: msg}, true
	}
	r := samlResult{
		Username:             c.fields["saml-username"],
		PreloginCookie:       c.fields["prelogin-cookie"],
		PortalUserauthcookie: c.fields["portal-userauthcookie"],
	}
	if r.Username != "" && (r.PreloginCookie != "" || r.PortalUserauthcookie != "") {
		r.Source = c.source
		return r, true
	}
	return samlResult{}, false
}

// writeSAMLResult is the child's only output.
func writeSAMLResult(r samlResult) {
	json.NewEncoder(os.Stdout).Encode(r)
}

// runSAMLLoginMode is the child process entry point (--saml-login).
func runSAMLLoginMode() int {
	var req samlRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		writeSAMLResult(samlResult{Error: "bad request: " + err.Error()})
		return 1
	}
	if err := runSAMLWindow(req); err != nil {
		writeSAMLResult(samlResult{Error: err.Error()})
		return 1
	}
	return 0
}

var errSAMLCancelled = errors.New("SAML-вход отменён")

// samlLogin runs the SAML window (unprivileged child process) and waits for
// its result. Cancelling ctx closes the window.
func samlLogin(ctx context.Context, req samlRequest) (samlResult, error) {
	self, err := os.Executable()
	if err != nil {
		return samlResult{}, err
	}
	cmd := exec.CommandContext(ctx, self, "--saml-login")
	in, err := json.Marshal(req)
	if err != nil {
		return samlResult{}, err
	}
	cmd.Stdin = strings.NewReader(string(in))
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return samlResult{}, err
	}
	if err := cmd.Start(); err != nil {
		return samlResult{}, err
	}
	var res samlResult
	got := false
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if json.Unmarshal(sc.Bytes(), &res) == nil {
			got = true
		}
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return samlResult{}, errSAMLCancelled
	}
	if !got {
		if waitErr != nil {
			return samlResult{}, fmt.Errorf("окно SAML-входа завершилось с ошибкой: %v", waitErr)
		}
		return samlResult{}, errors.New("окно SAML-входа закрылось без результата")
	}
	if res.Cancelled {
		return samlResult{}, errSAMLCancelled
	}
	if res.Error != "" {
		return samlResult{}, errors.New(res.Error)
	}
	return res, nil
}
