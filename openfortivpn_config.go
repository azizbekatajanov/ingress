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
	writeStr("realm", p.Realm)
	writeStr("ca-file", p.CaFile)
	writeStr("user-cert", p.UserCert)
	writeStr("user-key", p.UserKey)
	writeStr("trusted-cert", p.TrustedCert)
	writeBool("insecure-ssl", p.InsecureSsl)
	writeBool("set-dns", p.SetDns)
	writeBool("pppd-use-peerdns", p.PppdUsePeerdns)
	writeBool("set-routes", p.SetRoutes)
	writeBool("half-internet-routes", p.HalfInternetRoutes)
	writeStr("pppd-log", p.PppdLog)

	f, err := os.CreateTemp("", "ingress-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(b.String()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
