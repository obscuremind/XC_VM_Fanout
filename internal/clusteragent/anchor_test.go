package clusteragent

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTheAnchorMovesOnlyForwardAndOnlyOnMainsOwnTime(t *testing.T) {
	_, st := newFake(t)
	c := NewClient(st, "xc_agent/test")
	at := time.Unix(1800000000, 0)
	c.now = func() time.Time { return at }

	if c.MainAnchorMs() != 0 {
		t.Fatalf("an anchor before MAIN was ever heard: %d", c.MainAnchorMs())
	}
	// The looser offset (the pre-token challenge sets exactly this, and it
	// carries no signature) must not give the node an anchor.
	c.offsetMs.Store(90 * 1000)
	if c.MainAnchorMs() != 0 {
		t.Fatalf("an unauthenticated offset moved the anchor: %d", c.MainAnchorMs())
	}

	mainMs := int64(1800000500) * 1000
	c.setMainTime(mainMs)
	if c.MainAnchorMs() != mainMs {
		t.Fatalf("anchor %d, want %d", c.MainAnchorMs(), mainMs)
	}

	// Between statements it advances on the elapsed time, not on MAIN's.
	at = at.Add(5 * time.Second)
	if got := c.MainAnchorMs(); got != mainMs+5000 {
		t.Fatalf("anchor %d after 5 s, want %d", got, mainMs+5000)
	}

	// A replayed older statement of MAIN's does not pull it back...
	c.setMainTime(mainMs - 60*1000)
	if got := c.MainAnchorMs(); got != mainMs+5000 {
		t.Fatalf("an older main_time moved the anchor to %d", got)
	}
	// ...and neither does the machine's clock going backwards, which is the whole
	// reason a node may not judge a lease by its own clock.
	at = at.Add(-2 * time.Hour)
	if got := c.MainAnchorMs(); got != mainMs {
		t.Fatalf("a clock rolled back left the anchor at %d, want %d", got, mainMs)
	}

	// A later statement of MAIN's re-anchors on MAIN's own number, even when this
	// machine's clock over-ran and the extrapolation had gone further: MAIN is the
	// authority on its clock, and only a number older than the last one is refused.
	at = time.Unix(1800009000, 0)
	if got := c.MainAnchorMs(); got != mainMs+9000*1000 {
		t.Fatalf("extrapolation %d", got)
	}
	c.setMainTime(mainMs + 3600*1000)
	at = at.Add(time.Second)
	if got := c.MainAnchorMs(); got != mainMs+3600*1000+1000 {
		t.Fatalf("anchor %d, want MAIN's own time plus a second", got)
	}
}

func TestTheAnchorKeepsAFloorAcrossARestart(t *testing.T) {
	_, st := newFake(t)
	st.path = filepath.Join(t.TempDir(), "agent.json")
	c := NewClient(st, "xc_agent/test")
	at := time.Unix(1800000000, 0)
	c.now = func() time.Time { return at }

	// The first statement on a node with no floor writes one.
	first := at.UnixMilli() + 30*1000
	c.setMainTime(first)
	if st.MainSeenMs != first {
		t.Fatalf("no floor after the first statement: %d", st.MainSeenMs)
	}
	// The next 30 s do not rewrite the file; a minute on does.
	c.setMainTime(first + 30*1000)
	if st.MainSeenMs != first {
		t.Fatalf("rewrote the floor for 30 s: %d", st.MainSeenMs)
	}
	mainMs := first + 5*60*1000
	c.setMainTime(mainMs)
	if st.MainSeenMs != mainMs {
		t.Fatalf("floor %d, want %d", st.MainSeenMs, mainMs)
	}

	loaded, err := LoadState(st.path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MainSeenMs != mainMs {
		t.Fatalf("the floor did not reach the file: %d", loaded.MainSeenMs)
	}
	// A restart, with MAIN unreachable: the anchor resumes from the floor and
	// counts forward from now — undercounting the downtime, never over.
	restarted := NewClient(loaded, "xc_agent/test")
	later := at.Add(3 * time.Hour)
	restarted.now = func() time.Time { return later }
	// A real process seeds at construction, with its own clock; here the clock is
	// replaced first, so seed again against it.
	restarted.seedAnchor()
	if got := restarted.MainAnchorMs(); got != mainMs {
		t.Fatalf("after a restart the anchor is %d, want the floor %d", got, mainMs)
	}
	later = later.Add(time.Minute)
	if got := restarted.MainAnchorMs(); got != mainMs+60*1000 {
		t.Fatalf("the restarted anchor does not advance: %d", got)
	}
}
