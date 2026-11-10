package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func addRoute(cidr, iface string) error {
	out, err := exec.Command("/sbin/route", "-n", "add", "-net", cidr, "-interface", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
