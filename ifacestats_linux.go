//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ifaceStats reads cumulative RX/TX byte counters straight from sysfs, which
// Linux exposes per-interface — no subprocess or parsing needed here, unlike macOS.
func ifaceStats(iface string) (rx, tx uint64, err error) {
	base := filepath.Join("/sys/class/net", iface, "statistics")
	rxBytes, err := os.ReadFile(filepath.Join(base, "rx_bytes"))
	if err != nil {
		return 0, 0, err
	}
	txBytes, err := os.ReadFile(filepath.Join(base, "tx_bytes"))
	if err != nil {
		return 0, 0, err
	}
	rx, _ = strconv.ParseUint(strings.TrimSpace(string(rxBytes)), 10, 64)
	tx, _ = strconv.ParseUint(strings.TrimSpace(string(txBytes)), 10, 64)
	return rx, tx, nil
}
