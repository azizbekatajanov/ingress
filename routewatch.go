package main

import (
	"bytes"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Routes for tunnels whose client doesn't set them itself (SSTP: sstpc +
// pppd). Ingress' root wrapper (`ingress --pty-exec --routes=<spec> <tool>
// …`) already sees all of the tool's output; once pppd has reported the
// interface ("Using interface ppp0") and the far end ("remote IP address
// …"), it adds the routes on that interface. They go away with the
// interface, so there's nothing to clean up.
//
// spec is "all" (0.0.0.0/1 + 128.0.0.0/1: everything, without replacing
// the default route) or comma-separated IPv4 CIDRs.

const routesArgPrefix = "--routes="

var (
	routeIfaceRe  = regexp.MustCompile(`Using interface (ppp\d+)`)
	routeRemoteRe = regexp.MustCompile(`(?i)remote\s+IP\s+address\s+([0-9.]+)`)
)

// takeWrapperOpts removes --routes= / --lang= from the front of the
// wrapper's argv (the tool path, always absolute, comes after them).
func takeWrapperOpts(args []string) (rest []string, routes string) {
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch {
		case strings.HasPrefix(args[0], routesArgPrefix):
			routes = strings.TrimPrefix(args[0], routesArgPrefix)
		case strings.HasPrefix(args[0], langArgPrefix):
			setLanguage(strings.TrimPrefix(args[0], langArgPrefix))
		default:
			return args, routes
		}
		args = args[1:]
	}
	return args, routes
}

// routeTargets validates spec; nil if there's nothing (valid) to route.
func routeTargets(spec string) []string {
	if spec == "" {
		return nil
	}
	if spec == "all" {
		return []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	var out []string
	for _, c := range strings.Split(spec, ",") {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n.IP.To4() != nil {
			out = append(out, n.String())
		}
	}
	return out
}

type routeWatcher struct {
	out     io.Writer
	targets []string
	add     func(cidr, iface string) error // addRoute, swapped in tests

	mu     sync.Mutex
	buf    []byte
	iface  string
	remote string
	done   bool
}

// newRouteWatcher returns out itself when there's nothing to route.
func newRouteWatcher(out io.Writer, spec string) io.Writer {
	targets := routeTargets(spec)
	if len(targets) == 0 {
		return out
	}
	return &routeWatcher{out: out, targets: targets, add: addRoute}
}

func (w *routeWatcher) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return n, err
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexAny(w.buf, "\r\n")
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		if m := routeIfaceRe.FindStringSubmatch(line); m != nil {
			w.iface = m[1]
		}
		if m := routeRemoteRe.FindStringSubmatch(line); m != nil {
			w.remote = m[1]
		}
		if w.iface != "" && w.remote != "" {
			w.done = true
			w.buf = nil
			for _, cidr := range w.targets {
				if aerr := w.add(cidr, w.iface); aerr != nil {
					io.WriteString(w.out, T("routes.failed", cidr, w.iface, aerr)+"\n")
				} else {
					io.WriteString(w.out, T("routes.added", cidr, w.iface)+"\n")
				}
			}
			break
		}
	}
	if len(w.buf) > 64<<10 { // no newline for a long time: don't grow forever
		w.buf = nil
	}
	return n, err
}
