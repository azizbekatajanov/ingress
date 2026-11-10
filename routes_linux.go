package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func addRoute(cidr, iface string) error {
	ip := ""
	for _, p := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if _, err := os.Stat(p); err == nil {
			ip = p
			break
		}
	}
	if ip == "" {
		return errors.New("ip (iproute2) not found")
	}
	out, err := exec.Command(ip, "route", "add", cidr, "dev", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
