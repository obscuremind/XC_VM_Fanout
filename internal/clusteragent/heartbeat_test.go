package clusteragent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// beatMain records when each heartbeat arrived; slow ops hang until the
// request is given up.
type beatMain struct {
	*fakeMain
	mu    sync.Mutex
	beats []time.Time
	slow  map[string]bool
}

func newBeatMain(t *testing.T, urls ...string) (*beatMain, *Agent) {
	f, st := newFake(t)
	m := &beatMain{fakeMain: f, slow: map[string]bool{}}
	f.answer = func(w http.ResponseWriter, r *http.Request, reqCtx, nonce []byte) {
		op := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		m.mu.Lock()
		if op == "heartbeat" {
			m.beats = append(m.beats, time.Now())
		}
		slow := m.slow[op] || (op == "heartbeat" && len(m.beats)%2 == 0 && m.slow["every-other-heartbeat"])
		m.mu.Unlock()
		if slow {
			io.Copy(io.Discard, r.Body) // so the server notices the client giving up
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		// As MAIN answers: every reply carries its clock, which is what the agent
		// anchors on (anchor.go).
		f.box(w, reqCtx, map[string]any{"state": "active", "mode": 1, "main_time_ms": time.Now().UnixMilli()})
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	st.MainURLs = append(urls, srv.URL+"/cluster/v1/")
	st.Enrolled = true
	return m, &Agent{Client: NewClient(st, "xc_agent/test"), Logf: t.Logf}
}

func (m *beatMain) gaps() (n int, worst time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 1; i < len(m.beats); i++ {
		worst = max(worst, m.beats[i].Sub(m.beats[i-1]))
	}
	return len(m.beats), worst
}

func runFor(t *testing.T, a *Agent, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: %v", err)
	}
}

func TestHeartbeatsStayWithinTheGapWhenMainIsSlow(t *testing.T) {
	old := MaxHeartbeatGap
	MaxHeartbeatGap = 300 * time.Millisecond
	defer func() { MaxHeartbeatGap = old }()
	m, a := newBeatMain(t)
	a.Interval = 10 * time.Second // capped at the gap
	m.slow["every-other-heartbeat"] = true
	runFor(t, a, 2*time.Second)
	n, worst := m.gaps()
	if n < 4 || worst > MaxHeartbeatGap+300*time.Millisecond {
		t.Fatalf("%d heartbeats, worst gap %s", n, worst)
	}
}

func TestATokenRefreshDoesNotHoldTheHeartbeats(t *testing.T) {
	m, a := newBeatMain(t)
	m.slow["token_refresh"] = true
	a.Interval = 100 * time.Millisecond
	// The token is due for refresh from the start.
	s, _ := a.Client.current()
	s.tok.RefreshAt = 0
	runFor(t, a, 1500*time.Millisecond)
	if n, worst := m.gaps(); n < 8 || worst > 500*time.Millisecond {
		t.Fatalf("%d heartbeats, worst gap %s while a refresh hung", n, worst)
	}
}

func TestAnUnreachableURLGoesLast(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String() + "/cluster/v1/"
	l.Close() // connection refused
	_, a := newBeatMain(t, dead)
	ctx := context.Background()
	if _, err := a.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := a.Client.urls(); got[len(got)-1] != dead {
		t.Fatalf("order after a failure: %v", got)
	}
	// Retried first once URLRetry has passed.
	a.Client.now = func() time.Time { return time.Now().Add(URLRetry + time.Second) }
	if got := a.Client.urls(); got[0] != dead {
		t.Fatalf("order after URLRetry: %v", got)
	}
}
