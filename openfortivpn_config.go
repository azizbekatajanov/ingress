package main

import (
	"fmt"
	"os"
	"strings"
)

// writeOpenfortivpnConfig writes a private (0600, via os.CreateTemp) config
// file for `openfortivpn --config=`, keeping the username/password/certs off
// argv entirely — argv is world-readable via `ps`, a config file isn't.
// Field mapping per design/README.md's "openfortivpn CLI mapping" section.
func writeOpenfortivpnConfig(p Profile, password string) (string, error) {
	f := p.Fortinet
	if f == nil {
		return "", fmt.Errorf("profile %s has no Fortinet settings", p.ID)
	}
	var b strings.Builder
	writeStr := func(key, val string) {
		if val != "" {
			fmt.Fprintf(&b, "%s = %s\n", key, val)
		}
	}
	writeBool := func(key string, val bool) {
		fmt.Fprintf(&b, "%s = %v\n", key, val)
	}

	writeStr("username", p.Username)
	writeStr("password", password)
	writeStr("realm", f.Realm)
	writeStr("ca-file", f.CaFile)
	writeStr("user-cert", f.UserCert)
	writeStr("user-key", f.UserKey)
	writeStr("trusted-cert", f.TrustedCert)
	writeBool("insecure-ssl", f.InsecureSsl)
	writeBool("set-dns", f.SetDns)
	writeBool("pppd-use-peerdns", f.PppdUsePeerdns)
	writeBool("set-routes", f.SetRoutes)
	writeBool("half-internet-routes", f.HalfInternetRoutes)
	writeStr("pppd-log", f.PppdLog)

	file, err := os.CreateTemp("", "ingress-*.conf")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.WriteString(b.String()); err != nil {
		os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}
