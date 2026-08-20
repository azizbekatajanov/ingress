//go:build darwin

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// ifaceStats reads cumulative RX/TX byte counters for a network interface
// (e.g. "ppp0") by parsing `netstat -ibn`, since macOS has no /proc or /sys
// equivalent exposing this directly.
func ifaceStats(iface string) (rx, tx uint64, err error) {
	out, err := exec.Command("netstat", "-ibn").Output()
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return 0, 0, nil
	}
	header := strings.Fields(lines[0])
	ibytesCol, obytesCol := -1, -1
	for i, h := range header {
		switch h {
		case "Ibytes":
			ibytesCol = i
		case "Obytes":
			obytesCol = i
		}
	}
	if ibytesCol == -1 || obytesCol == -1 {
		return 0, 0, nil
	}
	for _, line := range lines[1:] {
		cols := strings.Fields(line)
		if len(cols) <= ibytesCol || len(cols) <= obytesCol {
			continue
		}
		if cols[0] != iface {
			continue
		}
		i, _ := strconv.ParseUint(cols[ibytesCol], 10, 64)
		o, _ := strconv.ParseUint(cols[obytesCol], 10, 64)
		if i > rx {
			rx = i
		}
		if o > tx {
			tx = o
		}
	}
	return rx, tx, nil
}
