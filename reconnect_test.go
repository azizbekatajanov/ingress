package main

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type reconnectRig struct {
	m        *Manager
	conn     *liveConnection
	mu       sync.Mutex
	events   []string
	notes    []string
	dials    int
	dialErr  error
	isOnline bool
}

func (r *reconnectRig) count(list *[]string, want string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range *list {
		if strings.Contains(e, want) {
			n++
		}
	}
	return n
}

func (r *reconnectRig) dialCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// newReconnectRig: a Manager whose profile p1 has a tunnel that is up.
// Dialing only counts calls; delays are tiny.
func newReconnectRig(t *testing.T, delay time.Duration) *reconnectRig {
	t.Helper()
	prev := language()
	setLanguage("en")
	t.Cleanup(func() { setLanguage(prev) })
	p := defaultProfile("p1", ProfileTypeFortinet)
	p.Host = "203.0.113.7"
	store := &ProfileStore{path: filepath.Join(t.TempDir(), "profiles.json")}
	store.cfg.Profiles = []Profile{p}
	r := &reconnectRig{isOnline: true}
	r.m = &Manager{
		conns:           map[string]*liveConnection{},
		store:           store,
		reconnectDelays: []time.Duration{delay},
	}
	r.m.events = func(name string, _ ...interface{}) {
		r.mu.Lock()
		r.events = append(r.events, name)
		r.mu.Unlock()
	}
	r.m.notify = func(title, _ string) {
		r.mu.Lock()
		r.notes = append(r.notes, title)
		r.mu.Unlock()
	}
	r.m.online = func(Profile) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.isOnline
	}
	r.m.dial = func(string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.dials++
		return r.dialErr
	}
	r.conn = r.newConn(true)
	return r
}

// newConn registers a fresh connection for p1, as Connect would.
func (r *reconnectRig) newConn(up bool) *liveConnection {
	conn := &liveConnection{profileID: "p1", backend: fortinetBackend{}, status: StatusConnecting, done: make(chan struct{})}
	if up {
		conn.status, conn.everConnected = StatusConnected, true
	}
	r.m.mu.Lock()
	r.m.conns["p1"] = conn
	r.m.mu.Unlock()
	return conn
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReconnectDelayBacksOff(t *testing.T) {
	m := &Manager{}
	want := []time.Duration{5, 10, 20, 40, 60, 60, 60}
	for i, w := range want {
		if got := m.reconnectDelay(i + 1); got != w*time.Second {
			t.Errorf("attempt %d: delay %v, want %v", i+1, got, w*time.Second)
		}
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	r := newReconnectRig(t, time.Hour)
	r.m.finish(r.conn)

	snap := r.m.Snapshot("p1")
	if snap.Status != StatusReconnecting || snap.ReconnectAttempt != 1 || snap.ReconnectMax != reconnectMaxAttempts || snap.ReconnectSecondsLeft < 3590 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if r.count(&r.events, "profile:failed") != 0 {
		t.Error("a dropped tunnel being reconnected must not be reported as failed")
	}
	if r.count(&r.notes, "connection lost") != 1 {
		t.Errorf("notifications = %v", r.notes)
	}

	// Disconnect while waiting stops it, without touching the dead process.
	proc := &fakeProc{}
	r.conn.proc = proc
	if err := r.m.Disconnect("p1"); err != nil {
		t.Fatal(err)
	}
	if proc.terminated {
		t.Error("the exited client must not be signalled again")
	}
	if s := r.m.Snapshot("p1"); s.Status != StatusDisconnected || s.ReconnectAttempt != 0 {
		t.Errorf("after disconnect: %+v", s)
	}
	if r.dialCount() != 0 {
		t.Error("dialled after the user disconnected")
	}
}

func TestReconnectDialsAndSucceeds(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.m.finish(r.conn)
	waitFor(t, "the reconnect attempt", func() bool { return r.dialCount() == 1 })

	// The attempt (a new connection) comes up.
	conn := r.newConn(false)
	if s := r.m.Snapshot("p1"); s.Status != StatusConnecting || s.ReconnectAttempt != 1 {
		t.Fatalf("during the attempt: %+v", s)
	}
	r.m.handleLine(conn, "local  IP address 10.211.1.20", false)
	if r.m.reconnectFor("p1") != nil {
		t.Error("reconnect state left after the tunnel came back")
	}
	if r.count(&r.notes, "reconnected") != 1 {
		t.Errorf("notifications = %v", r.notes)
	}
}

func TestReconnectNotForUserCancelOrFirstFailure(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.conn.cancelling = true
	r.m.finish(r.conn)
	if r.m.reconnectFor("p1") != nil {
		t.Error("reconnecting after the user disconnected")
	}

	r2 := newReconnectRig(t, time.Millisecond)
	r2.conn.everConnected = false
	r2.conn.lastError = "timeout"
	r2.m.finish(r2.conn)
	if r2.m.reconnectFor("p1") != nil {
		t.Error("a connect that never came up must fail, not retry")
	}
	if r2.count(&r2.events, "profile:failed") != 1 {
		t.Errorf("events = %v", r2.events)
	}
}

func TestReconnectStopsWhenLoginRejected(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.m.finish(r.conn)
	waitFor(t, "the reconnect attempt", func() bool { return r.dialCount() == 1 })

	conn := r.newConn(false)
	conn.lastError = "Could not authenticate to gateway. Please check the password, client certificate, etc."
	r.m.finish(conn)
	if r.m.reconnectFor("p1") != nil {
		t.Fatal("kept retrying a refused login")
	}
	if r.count(&r.events, "profile:failed") != 1 {
		t.Errorf("events = %v", r.events)
	}
	time.Sleep(20 * time.Millisecond)
	if r.dialCount() != 1 {
		t.Errorf("dials = %d", r.dialCount())
	}
}

func TestReconnectGivesUpAfterMaxAttempts(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.m.finish(r.conn)
	for i := 1; i <= reconnectMaxAttempts; i++ {
		waitFor(t, "an attempt", func() bool { return r.dialCount() == i })
		conn := r.newConn(false)
		conn.lastError = "SSL connect failed"
		r.m.finish(conn)
	}
	if r.m.reconnectFor("p1") != nil {
		t.Fatal("still reconnecting after the last attempt")
	}
	s := r.m.Snapshot("p1")
	if s.Status != StatusDisconnected || !strings.Contains(s.LastError, "SSL connect failed") {
		t.Errorf("snapshot = %+v", s)
	}
	if r.count(&r.events, "profile:failed") != 1 || r.count(&r.notes, "couldn't reconnect") != 1 {
		t.Errorf("events = %v, notifications = %v", r.events, r.notes)
	}
}

func TestReconnectDialErrors(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.dialErr = errors.New("keychain locked")
	r.m.finish(r.conn)
	waitFor(t, "giving up", func() bool { return r.count(&r.events, "profile:failed") == 1 })
	if r.dialCount() != reconnectMaxAttempts {
		t.Errorf("dials = %d", r.dialCount())
	}
	if s := r.m.Snapshot("p1"); s.Status != StatusDisconnected || !strings.Contains(s.LastError, "keychain locked") {
		t.Errorf("snapshot = %+v", s)
	}

	// Cancelling the admin prompt is the user saying no: stop quietly.
	r2 := newReconnectRig(t, time.Millisecond)
	r2.dialErr = &elevateCancelledError{}
	r2.m.finish(r2.conn)
	waitFor(t, "stopping", func() bool { return r2.dialCount() == 1 && r2.m.reconnectFor("p1") == nil })
	time.Sleep(20 * time.Millisecond)
	if r2.dialCount() != 1 || r2.count(&r2.events, "profile:failed") != 0 {
		t.Errorf("dials = %d, events = %v", r2.dialCount(), r2.events)
	}
}

func TestReconnectWaitsForNetwork(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.isOnline = false
	r.m.finish(r.conn)
	waitFor(t, "the offline state", func() bool { return r.m.Snapshot("p1").ReconnectOffline })
	if r.dialCount() != 0 {
		t.Error("dialled with no network")
	}
	if s := r.m.Snapshot("p1"); s.ReconnectAttempt != 1 {
		t.Errorf("waiting offline used up attempts: %+v", s)
	}
	r.m.stopReconnect("p1")
}

func TestReconnectNotifiesWhenCodeNeeded(t *testing.T) {
	r := newReconnectRig(t, time.Millisecond)
	r.m.finish(r.conn)
	waitFor(t, "the reconnect attempt", func() bool { return r.dialCount() == 1 })
	conn := r.newConn(false)
	r.m.handleLine(conn, "Two-factor authentication token: ", true)
	if r.count(&r.notes, "code needed") != 1 {
		t.Errorf("notifications = %v", r.notes)
	}
	// The code timing out cancels the attempt — and the reconnect.
	if err := r.m.CancelConnect("p1"); err != nil {
		t.Fatal(err)
	}
	if r.m.reconnectFor("p1") != nil {
		t.Error("still reconnecting after the code prompt was cancelled")
	}
}
