package main

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func sstpProfile() Profile {
	p := defaultProfile("s1", ProfileTypeSSTP)
	p.Host, p.Port, p.Username = "vpn.example.com", "443", "alice"
	p.SSTP.Subnets = []string{"172.16.10.0/24"}
	p.SSTP.CaFile = "/etc/ppp/ssl/vpn.crt"
	return p
}

func TestSSTPPrepare(t *testing.T) {
	p := sstpProfile()
	l, err := (sstpBackend{}).Prepare(p, authInput{Password: "s3cr#t pw"}, "/x/sstpc")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--log-stderr", "--log-level", "2", "--ca-cert", "/etc/ppp/ssl/vpn.crt",
		"--user", "alice", "--password", "-", "vpn.example.com", "--",
		"noauth", "refuse-eap", "noccp", "nodeflate", "nobsdcomp", "nodetach", "logfd", "2"}
	if !reflect.DeepEqual(l.Args, want) {
		t.Errorf("args =\n%q\nwant\n%q", l.Args, want)
	}
	if l.Stdin != "s3cr#t pw" || strings.Contains(strings.Join(l.Args, " "), "s3cr") {
		t.Error("password must go via stdin only")
	}
	if !reflect.DeepEqual(l.WrapperOpts, []string{"--routes=172.16.10.0/24"}) {
		t.Errorf("wrapper opts %q", l.WrapperOpts)
	}

	p.Port = "8443"
	p.SSTP.RouteMode = SSTPRoutesAll
	p.SSTP.CaFile = ""
	p.SSTP.InsecureCert = true
	p.SSTP.PppdOptions = "mtu 1400  require-mppe-128"
	l, err = (sstpBackend{}).Prepare(p, authInput{Password: "pw"}, "/x/sstpc")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(l.Args, " ")
	for _, s := range []string{"--cert-warn", "--save-server-route", "vpn.example.com:8443", "logfd 2 mtu 1400 require-mppe-128"} {
		if !strings.Contains(joined, s) {
			t.Errorf("missing %q in %q", s, joined)
		}
	}
	if l.WrapperOpts[0] != "--routes=all" {
		t.Errorf("wrapper opts %q", l.WrapperOpts)
	}

	// No CA file, verification on: macOS gets its system bundle.
	p.SSTP.InsecureCert = false
	l, _ = (sstpBackend{}).Prepare(p, authInput{Password: "pw"}, "/x/sstpc")
	if runtime.GOOS == "darwin" && !strings.Contains(strings.Join(l.Args, " "), "--ca-cert /etc/ssl/cert.pem") {
		t.Errorf("macOS without CA file should use /etc/ssl/cert.pem: %q", l.Args)
	}
}

func TestSSTPPrepareRejects(t *testing.T) {
	cases := map[string]func(p *Profile){
		"no subnets":     func(p *Profile) { p.SSTP.Subnets = nil },
		"bad subnet":     func(p *Profile) { p.SSTP.Subnets = []string{"172.16.10.0"} },
		"ipv6 subnet":    func(p *Profile) { p.SSTP.Subnets = []string{"fd00::/64"} },
		"connect script": func(p *Profile) { p.SSTP.PppdOptions = "connect /tmp/x.sh" },
		"plugin":         func(p *Profile) { p.SSTP.PppdOptions = "plugin evil.so" },
		"path":           func(p *Profile) { p.SSTP.PppdOptions = "mtu /etc/passwd" },
		"shell":          func(p *Profile) { p.SSTP.PppdOptions = "mtu $(id)" },
		"logfile":        func(p *Profile) { p.SSTP.PppdOptions = "logfile x" },
		"no username":    func(p *Profile) { p.Username = "" },
	}
	for name, mutate := range cases {
		p := sstpProfile()
		mutate(&p)
		if _, err := (sstpBackend{}).Prepare(p, authInput{Password: "pw"}, "/x/sstpc"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Host bits in a subnet are normalised, not refused.
	p := sstpProfile()
	p.SSTP.Subnets = []string{" 10.1.2.3/16 ", "", "192.168.5.0/24"}
	l, err := (sstpBackend{}).Prepare(p, authInput{Password: "pw"}, "/x/sstpc")
	if err != nil || l.WrapperOpts[0] != "--routes=10.1.0.0/16,192.168.5.0/24" {
		t.Errorf("%v %q", err, l.WrapperOpts)
	}
}

// Lines as sstpc 1.0.20 and pppd print them (sstpc's log format from
// libsstp-log; pppd's from its own source).
func TestSSTPParse(t *testing.T) {
	b := sstpBackend{}
	cases := map[string][]lineEvent{
		"Nov 10 14:11:25 sstpc[50750]: Resolved vpn.example.com to 203.0.113.5 ": nil,
		"Nov 10 14:11:25 sstpc[50750]: Connected to vpn.example.com ":            nil,
		"Using interface ppp0":                                                     nil,
		"Connect: ppp0 <--> /dev/ttys004":                                          nil,
		"CHAP authentication succeeded":                                            nil,
		"local  IP address 192.168.100.2":                                          {{Kind: evAssignedIP, Value: "192.168.100.2"}},
		"remote IP address 192.168.100.1":                                          nil,
		"MS-CHAP authentication failed: E=691 Authentication failure":              {{Kind: evError, Sticky: true, Value: T("sstp.err.auth")}},
		"CHAP authentication failed":                                               {{Kind: evError, Sticky: true, Value: T("sstp.err.auth")}},
		"Nov 10 14:11:25 sstpc[50750]: Verification of server certificate failed ": {{Kind: evError, Sticky: true, Value: T("sstp.err.cert")}},
		"**Error: Could not connect to the server, Connection refused (61), (-1)":  {{Kind: evError, Value: "Could not connect to the server, Connection refused (61)"}},
		"LCP: timeout sending Config-Requests":                                     {{Kind: evError, Value: T("sstp.err.lcp")}},
	}
	for line, want := range cases {
		if got := b.Parse(line, false); !reflect.DeepEqual(got, want) {
			t.Errorf("Parse(%q) = %+v, want %+v", line, got, want)
		}
	}
}

func TestRouteWatcher(t *testing.T) {
	var out bytes.Buffer
	var added []string
	w := &routeWatcher{out: &out, targets: routeTargets("172.16.10.0/24,10.0.0.0/8"), add: func(cidr, iface string) error {
		added = append(added, cidr+"@"+iface)
		if cidr == "10.0.0.0/8" {
			return errors.New("File exists")
		}
		return nil
	}}
	// Lines split across writes, \r\n from the pty.
	for _, chunk := range []string{"Using inter", "face ppp3\r\nlocal  IP address 192.168.100.2\r\nremote IP ad", "dress 192.168.100.1\r\n", "remote IP address 1.2.3.4\r\n"} {
		w.Write([]byte(chunk))
	}
	if !reflect.DeepEqual(added, []string{"172.16.10.0/24@ppp3", "10.0.0.0/8@ppp3"}) {
		t.Fatalf("added %v", added)
	}
	s := out.String()
	if !strings.Contains(s, "Using interface ppp3") || !strings.Contains(s, "172.16.10.0/24") || !strings.Contains(s, "File exists") {
		t.Errorf("output: %q", s)
	}

	if got := routeTargets("all"); !reflect.DeepEqual(got, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
		t.Errorf("all → %v", got)
	}
	if got := routeTargets("1.2.3.0/24,garbage,-net"); !reflect.DeepEqual(got, []string{"1.2.3.0/24"}) {
		t.Errorf("garbage kept: %v", got)
	}
	var plain bytes.Buffer
	if newRouteWatcher(&plain, "") != &plain {
		t.Error("no routes should mean no watcher")
	}
}

func TestTakeWrapperOpts(t *testing.T) {
	defer setLanguage("ru")
	rest, routes := takeWrapperOpts([]string{"--routes=all", "--lang=uz", "/x/sstpc", "--user", "a"})
	if routes != "all" || language() != "uz" || !reflect.DeepEqual(rest, []string{"/x/sstpc", "--user", "a"}) {
		t.Errorf("rest=%q routes=%q lang=%s", rest, routes, language())
	}
	rest, routes = takeWrapperOpts([]string{"/usr/bin/openfortivpn", "--routes=x"})
	if routes != "" || len(rest) != 2 {
		t.Errorf("options after the tool must be left alone: %q %q", rest, routes)
	}
}
