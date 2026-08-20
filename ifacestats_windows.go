//go:build windows

package main

// ifaceStats is not implemented on Windows yet (needs GetIfEntry2 via the
// IP Helper API). Returning zero rather than an error: RX/TX counters are a
// cosmetic nice-to-have on the status screen, not load-bearing like
// elevatedCommand, so v1 just shows 0 B here instead of failing the connection.
func ifaceStats(iface string) (rx, tx uint64, err error) {
	return 0, 0, nil
}
