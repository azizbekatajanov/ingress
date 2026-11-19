package main

import (
	"context"
	"errors"
	"net"
	"regexp"
	"time"
)

// Auto-reconnect. When a tunnel that was up goes away without the user
// asking — the client lost the server, the network changed, the Mac woke
// from sleep — Manager starts it again, waiting longer after each failed
// attempt (reconnectDelays). Each attempt is an ordinary Connect, so a 2FA
// code or a SAML login is asked for exactly as on a manual connect; the
// user is told through a system notification.
//
// It stops for good when:
//   - the user cancels or disconnects (also: the 2FA code timed out, or the
//     admin-rights prompt was cancelled) — see stopReconnect;
//   - the server rejected the login (reconnectRejected): retrying a wrong
//     password a few times can lock the account;
//   - reconnectMaxAttempts attempts failed, or the network stayed down for
//     reconnectOfflineLimit. Then the failure surfaces like any other.

const (
	reconnectMaxAttempts  = 6
	reconnectOfflineLimit = 30 * time.Minute
	reconnectOfflinePoll  = 5 * time.Second
)

// defaultReconnectDelays: the wait before attempt 1, 2, …; the last value
// repeats.
var defaultReconnectDelays = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}

// authRejectedRe matches error texts that mean the credentials were refused
// (openfortivpn: "Could not authenticate to gateway…").
var authRejectedRe = regexp.MustCompile(`(?i)could not authenticate|authentication failed|login failed|invalid (username|password|credentials)|incorrect (username|password)|access denied`)

// reconnectState is a profile's pending auto-reconnect. Guarded by Manager.mu.
type reconnectState struct {
	attempt int       // attempts started so far
	nextAt  time.Time // when the next attempt starts; zero while one runs
	offline bool      // waiting for the network to come back
	since   time.Time // when the tunnel dropped
	stop    chan struct{}
}

func (m *Manager) reconnectDelay(attempt int) time.Duration {
	d := m.reconnectDelays
	if len(d) == 0 {
		d = defaultReconnectDelays
	}
	i := attempt - 1
	if i < 0 {
		i = 0
	}
	if i >= len(d) {
		i = len(d) - 1
	}
	return d[i]
}

// reconnectRejected reports whether conn ended in a way a retry can't fix.
func reconnectRejected(conn *liveConnection) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.rejected || conn.errorSticky || authRejectedRe.MatchString(conn.lastError)
}

func (m *Manager) reconnectFor(profileID string) *reconnectState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconnects[profileID]
}

// stopReconnect cancels a pending auto-reconnect; true if there was one.
func (m *Manager) stopReconnect(profileID string) bool {
	m.mu.Lock()
	rs := m.reconnects[profileID]
	if rs != nil {
		delete(m.reconnects, profileID)
		close(rs.stop)
	}
	m.mu.Unlock()
	return rs != nil
}

// continueReconnect is called by finish once conn has ended on its own (not
// cancelled by the user). It schedules the next attempt and returns true,
// or returns false when the end must be reported as a failure: nothing to
// reconnect, the login was rejected, or the attempts ran out (lastError
// then says so).
func (m *Manager) continueReconnect(conn *liveConnection, everConnected bool) bool {
	id := conn.profileID
	if reconnectRejected(conn) {
		if m.stopReconnect(id) {
			conn.addLog(T("log.reconnect_rejected"))
		}
		return false
	}

	m.mu.Lock()
	if m.reconnects == nil {
		m.reconnects = make(map[string]*reconnectState)
	}
	rs := m.reconnects[id]
	if rs == nil && !everConnected {
		m.mu.Unlock()
		return false // an ordinary failed connect, not a dropped tunnel
	}
	first := rs == nil
	if first {
		rs = &reconnectState{since: time.Now(), stop: make(chan struct{})}
		m.reconnects[id] = rs
	}
	if rs.attempt >= reconnectMaxAttempts {
		delete(m.reconnects, id)
		close(rs.stop)
		m.mu.Unlock()
		m.reconnectGaveUp(conn)
		return false
	}
	delay := m.reconnectDelay(rs.attempt + 1)
	rs.nextAt = time.Now().Add(delay)
	attempt := rs.attempt
	m.mu.Unlock()

	conn.addLog(T("log.reconnect_scheduled", int(delay.Seconds()), attempt+1, reconnectMaxAttempts))
	if first {
		m.notifyProfile(id, "notify.dropped")
	}
	go m.reconnectLoop(id, rs)
	return true
}

// reconnectGaveUp makes sure the failure has a reason to show.
func (m *Manager) reconnectGaveUp(conn *liveConnection) {
	conn.mu.Lock()
	if conn.lastError == "" {
		conn.lastError = T("err.reconnect_gave_up", reconnectMaxAttempts)
	} else {
		conn.lastError = T("err.reconnect_gave_up_with", reconnectMaxAttempts, conn.lastError)
	}
	conn.mu.Unlock()
	conn.addLog(T("log.reconnect_stopped"))
	m.notifyProfile(conn.profileID, "notify.gave_up")
}

// reconnectLoop waits for rs's next attempt (refreshing the countdown once
// a second) and starts it. It returns once an attempt is running — finish
// or the "connected" promotion take it from there — or rs was cancelled.
func (m *Manager) reconnectLoop(id string, rs *reconnectState) {
	for {
		// Wait for nextAt.
		for {
			m.mu.Lock()
			current, nextAt := m.reconnects[id] == rs, rs.nextAt
			m.mu.Unlock()
			if !current {
				return
			}
			wait := time.Until(nextAt)
			if wait <= 0 {
				break
			}
			if wait > time.Second {
				wait = time.Second
			}
			select {
			case <-rs.stop:
				return
			case <-time.After(wait):
				m.emitProfile(id)
			}
		}

		profile, ok := m.store.Get(id)
		if !ok {
			m.stopReconnect(id)
			return
		}

		// No network (Wi-Fi switching, just woke up): wait for it without
		// using up attempts.
		if !m.isOnline(profile) {
			m.mu.Lock()
			if m.reconnects[id] != rs {
				m.mu.Unlock()
				return
			}
			expired := time.Since(rs.since) > reconnectOfflineLimit
			wasOffline := rs.offline
			rs.offline = true
			rs.nextAt = time.Now().Add(reconnectOfflinePoll)
			if expired {
				delete(m.reconnects, id)
				close(rs.stop)
			}
			m.mu.Unlock()
			if expired {
				m.giveUpPending(id)
				return
			}
			if !wasOffline {
				m.addLogTo(id, T("log.reconnect_offline"))
			}
			m.emitProfile(id)
			continue
		}

		m.mu.Lock()
		if m.reconnects[id] != rs {
			m.mu.Unlock()
			return
		}
		rs.attempt++
		rs.offline = false
		rs.nextAt = time.Time{}
		attempt := rs.attempt
		m.mu.Unlock()
		m.addLogTo(id, T("log.reconnect_attempt", attempt, reconnectMaxAttempts))
		m.emitProfile(id)

		err := m.dialProfile(id)
		if err == nil {
			return
		}
		// The attempt couldn't even start (no admin rights, keychain, …).
		m.addLogTo(id, T("log.error", err.Error()))
		var cancelled *elevateCancelledError
		m.mu.Lock()
		if m.reconnects[id] != rs {
			m.mu.Unlock()
			return
		}
		giveUp := errors.As(err, &cancelled) || attempt >= reconnectMaxAttempts
		if giveUp {
			delete(m.reconnects, id)
			close(rs.stop)
		} else {
			rs.nextAt = time.Now().Add(m.reconnectDelay(attempt + 1))
		}
		m.mu.Unlock()
		if errors.As(err, &cancelled) {
			m.addLogTo(id, T("log.reconnect_stopped"))
			m.emitProfile(id)
			return
		}
		if giveUp {
			m.setLastError(id, err.Error())
			m.giveUpPending(id)
			return
		}
		m.emitProfile(id)
	}
}

// giveUpPending reports a reconnect that ended between attempts, the way
// finish reports a failed connection.
func (m *Manager) giveUpPending(id string) {
	conn := m.get(id)
	if conn == nil {
		conn = &liveConnection{profileID: id, status: StatusDisconnected, done: make(chan struct{})}
		close(conn.done)
		m.mu.Lock()
		m.conns[id] = conn
		m.mu.Unlock()
	}
	m.reconnectGaveUp(conn)
	m.emit(conn)
	m.store.SetSelectedID(id)
	m.events("profile:failed", id)
	if m.showWindow != nil {
		m.showWindow()
	}
}

// reconnectSucceeded ends rs once a reconnect attempt brought the tunnel up.
func (m *Manager) reconnectSucceeded(conn *liveConnection) {
	if m.stopReconnect(conn.profileID) {
		conn.addLog(T("log.reconnected"))
		m.notifyProfile(conn.profileID, "notify.reconnected")
	}
}

func (m *Manager) dialProfile(id string) error {
	if m.dial != nil {
		return m.dial(id)
	}
	return m.connect(id)
}

func (m *Manager) isOnline(p Profile) bool {
	if m.online != nil {
		return m.online(p)
	}
	return hostResolves(p.Host)
}

// hostResolves: a cheap "is there a network" probe — the gateway's name
// resolves (an IP literal always does).
func hostResolves(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

func (m *Manager) notifyProfile(id, key string) {
	if m.notify == nil {
		return
	}
	name := id
	if p, ok := m.store.Get(id); ok {
		name = p.Name
	}
	m.notify(T(key+"_title", name), T(key+"_body"))
}

func (m *Manager) addLogTo(id, text string) {
	if conn := m.get(id); conn != nil {
		conn.addLog(text)
	}
}

func (m *Manager) setLastError(id, text string) {
	if conn := m.get(id); conn != nil {
		conn.mu.Lock()
		conn.lastError = text
		conn.mu.Unlock()
	}
}

// emitProfile sends the profile's current snapshot (also when no live
// connection exists — e.g. waiting to reconnect).
func (m *Manager) emitProfile(id string) {
	snap := m.Snapshot(id)
	m.events("vpn:update", snap)
	if m.onUpdate != nil {
		m.onUpdate(snap)
	}
}

// decorateReconnect adds the auto-reconnect state to a snapshot: a
// disconnected profile waiting for its next attempt reads "reconnecting".
func (m *Manager) decorateReconnect(s *ConnectionSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := m.reconnects[s.ProfileID]
	if rs == nil {
		return
	}
	s.ReconnectMax = reconnectMaxAttempts
	if s.Status == StatusDisconnected {
		s.Status = StatusReconnecting
		s.ReconnectAttempt = rs.attempt + 1
		s.ReconnectOffline = rs.offline
		if !rs.nextAt.IsZero() {
			left := int((time.Until(rs.nextAt) + time.Second - 1) / time.Second)
			if left < 0 {
				left = 0
			}
			s.ReconnectSecondsLeft = left
		}
	} else {
		s.ReconnectAttempt = rs.attempt
	}
}

// elevateCancelledError: the user dismissed the admin-rights prompt.
type elevateCancelledError struct{}

func (*elevateCancelledError) Error() string { return T("elevate.cancelled") }
