package main

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func TestStartedHidden(t *testing.T) {
	if !startedHidden([]string{"-psn_0_1", hiddenArg}) || startedHidden(nil) || startedHidden([]string{"--saml-login"}) {
		t.Error("startedHidden misreads its arguments")
	}
}

func TestLaunchAgentArgs(t *testing.T) {
	got := launchAgentArgs("/Applications/Ingress.app/Contents/MacOS/ingress")
	want := []string{"/usr/bin/open", "-g", "-a", "/Applications/Ingress.app", "--args", hiddenArg}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("bundle: %v", got)
	}
	if got := launchAgentArgs("/Users/me/dev/ingress"); len(got) != 2 || got[1] != hiddenArg {
		t.Errorf("dev build: %v", got)
	}
}

func TestLaunchAgentPlistEscapes(t *testing.T) {
	data := launchAgentPlist([]string{"/Apps/A&B <x>.app", hiddenArg})
	var v struct {
		Dict struct {
			Strings []string `xml:"string"`
			Arrays  []struct {
				Strings []string `xml:"string"`
			} `xml:"array"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(data, &v); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, data)
	}
	if v.Dict.Strings[0] != launchAgentLabel || len(v.Dict.Arrays) != 1 || v.Dict.Arrays[0].Strings[0] != "/Apps/A&B <x>.app" {
		t.Errorf("parsed = %+v", v)
	}
}

func TestDesktopEntryQuoting(t *testing.T) {
	entry := string(desktopEntry(`/opt/my "apps"/$HOME/in\gress`))
	want := `Exec="/opt/my \\"apps\\"/\\$HOME/in\\\\gress" --hidden`
	if !strings.Contains(entry, want+"\n") {
		t.Errorf("entry =\n%s\nwant line %s", entry, want)
	}
}

func TestConnectOnLaunchIsNotExported(t *testing.T) {
	p := defaultProfile("p1", ProfileTypeFortinet)
	p.Host, p.ConnectOnLaunch = "h.example", true
	data, err := exportProfiles([]Profile{p}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "connectOnLaunch") {
		t.Error("connectOnLaunch leaked into the export")
	}
}
