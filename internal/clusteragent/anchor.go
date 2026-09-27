package clusteragent

import (
	"sync/atomic"
	"time"
)

// anchorSaveEvery is how far MAIN's clock must move before the high-water is
// written to the state file again: often enough that a restart loses at most
// this much of a partition, seldom enough that a 2 s heartbeat does not rewrite
// the file (the state is saved on its own occasions anyway). The first statement
// on a node with no floor at all always writes one.
const anchorSaveEvery = 60 * 1000

// anchorPoint is MAIN's clock at a moment of this process's monotonic clock.
type anchorPoint struct {
	mainMs int64
	at     time.Time
}

// MainAnchorMs is MAIN's clock as the node may rely on it for a judgement that
// nothing unauthenticated may move — how much of a lease is left, above all.
//
// It differs from MainNowMs in two ways that matter:
//
//   - Only an authenticated statement of MAIN's moves it: a MAC'd, unboxed reply,
//     a panel-signed denial, a panel-signed re-key document. MainNowMs is also
//     set from the pre-token challenge, which carries no signature at all — good
//     enough for stamping a request MAIN will check the window of, and no basis
//     for deciding a node may stop serving viewers.
//   - It only ever moves forward. Between statements it advances on this
//     process's monotonic clock, so moving the machine's wall clock, in either
//     direction, gains nothing; across a restart it resumes from the last MAIN
//     time an authenticated statement carried (State.MainSeenMs) and counts from
//     there, which undercounts a long outage rather than over.
//
// Zero until MAIN has been heard from at all, on this node, ever: a caller with
// a judgement to make must treat 0 as "no anchor" rather than as 1970.
func (c *Client) MainAnchorMs() int64 {
	p := c.anchor.Load()
	if p == nil || p.mainMs <= 0 {
		return 0
	}
	since := c.now().Sub(p.at).Milliseconds()
	if since < 0 {
		since = 0
	}
	return p.mainMs + since
}

// anchorFrom re-anchors on a statement of MAIN's, if that statement is newer
// than the one the anchor stands on, and keeps the high-water in the state file
// so a restart cannot start further back.
//
// The comparison is against the last statement's own number, not against what
// the anchor has extrapolated to: a replayed older reply carries an older
// number and is ignored, while a fresh statement always wins, even when this
// machine's clock has over-run and the extrapolation is ahead of MAIN. MAIN is
// the authority on its own clock; the extrapolation only fills the gaps between
// its statements.
func (c *Client) anchorFrom(mainMs int64) {
	if mainMs <= 0 {
		return
	}
	if p := c.anchor.Load(); p != nil && mainMs <= p.mainMs {
		return
	}
	c.anchor.Store(&anchorPoint{mainMs: mainMs, at: c.now()})
	if mainMs-c.anchorSaved.Load() < anchorSaveEvery {
		return
	}
	// TryLock, not Lock: this runs on every authenticated reply, from callers that
	// may already hold the state (a refresh saving its epoch), and the floor is
	// only a floor — skipping a write costs the next restart a minute of anchor,
	// while a deadlock here would cost the node its control loop. The next
	// advance writes it.
	if !c.State.mu.TryLock() {
		return
	}
	defer c.State.mu.Unlock()
	c.State.MainSeenMs = mainMs
	c.anchorSaved.Store(mainMs)
	// A failed write costs the floor, not this process's anchor: that is stored.
	_ = c.State.saveLocked()
}

// seedAnchor starts the anchor from the last MAIN time this node recorded, so a
// restart while MAIN is unreachable still has one.
func (c *Client) seedAnchor() {
	c.anchorSaved.Store(c.State.MainSeenMs)
	if c.State.MainSeenMs > 0 {
		c.anchor.Store(&anchorPoint{mainMs: c.State.MainSeenMs, at: c.now()})
	}
}

// anchorHolder is the field's type, declared here so client.go carries only the
// field: an atomic pointer, because the anchor is two values that must move
// together and is read from the heartbeat loop and the local socket alike.
type anchorHolder = atomic.Pointer[anchorPoint]
