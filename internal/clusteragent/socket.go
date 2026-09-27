package clusteragent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// The local socket (plan, section 7, "Local socket and data plane"): the
// node's PHP asks MAIN something that needs an answer before it can go on,
// through the agent, which holds the node's token:
//
//	POST /v1/main/{op}   body: the op's JSON payload; reply: MAIN's opened reply
//	/v1/conn/...         the connection registry (registry.go)
//	POST /v1/nonce       a parent's one-shot nonce window (dataplane.go)
//	POST /v1/file_digest an owner's signature over what it served (dataplane.go)
//
// Only the ops in SocketOps pass. The socket is xc_vm's alone (0660, in the
// agent's state directory); everything that is only a report goes through
// the event spool instead (events.go).

// SocketOps are the MAIN ops the node's PHP may call through the socket.
var SocketOps = map[string]bool{
	"recording_complete": true,
	// The encoding queue is MAIN's table, so a node in mode 2 claims its own
	// rows and reports what it started here (the panel's QueueSink).
	"queue_enqueue": true,
	"queue_claim":   true,
	"queue_update":  true,
}

// MaxSocketBody caps a request from PHP.
const MaxSocketBody = 1 << 20

// SocketDeadline is how long after a request's arrival the agent answers
// the socket: the node's PHP waits 15 s (ADR 0004, ingest permits).
var SocketDeadline = 12 * time.Second

// callForSocket calls MAIN for the node's PHP. A refusal of MAIN's bulk
// ingest lane (503 RATE_LIMITED with lane) is sent again after the busy wait
// only while that wait and a whole try (the MAIN client's timeout) still end
// by SocketDeadline after the request arrived; otherwise the refusal goes
// back at once, as a 409, and the PHP caller asks again on its own.
func (a *Agent) callForSocket(ctx context.Context, arrived time.Time, op string, body json.RawMessage, out *json.RawMessage) error {
	ctx, cancel := context.WithDeadline(ctx, arrived.Add(SocketDeadline))
	defer cancel()
	try := 10 * time.Second
	if a.Client.HTTP != nil && a.Client.HTTP.Timeout > 0 {
		try = a.Client.HTTP.Timeout
	}
	for {
		err := a.Client.Call(ctx, op, body, out, false)
		if laneRefusal(err) == nil {
			return err
		}
		a.busyRefusals.Add(1)
		w, _ := busyWait(err)
		if time.Now().Add(w + try).After(arrived.Add(SocketDeadline)) {
			return err
		}
		if !sleep(ctx, w) {
			return err
		}
	}
}

// ServeSocket listens on path until ctx ends.
func (a *Agent) ServeSocket(ctx context.Context, path string) error {
	os.Remove(path) // a stale socket from a previous run
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return err
	}
	srv := &http.Server{Handler: a.socketHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	err = srv.Serve(l)
	os.Remove(path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *Agent) socketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived := time.Now()
		if strings.HasPrefix(r.URL.Path, "/v1/conn/") {
			if a.Registry == nil {
				http.Error(w, "no registry", http.StatusServiceUnavailable)
				return
			}
			a.Registry.connHandler(w, r)
			return
		}
		// The data plane's own helpers (dataplane.go): the node's PHP asking for
		// a nonce window or a signature with the node key, neither of which it
		// has. Nothing here reaches MAIN.
		if a.dataPlaneHandler(w, r) {
			return
		}
		op, ok := strings.CutPrefix(r.URL.Path, "/v1/main/")
		if r.Method != http.MethodPost || !ok || !SocketOps[op] {
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxSocketBody+1))
		if err != nil || len(body) > MaxSocketBody || !json.Valid(body) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var out json.RawMessage
		if err := a.callForSocket(r.Context(), arrived, op, json.RawMessage(body), &out); err != nil {
			status := http.StatusBadGateway
			var d *Denial
			if errors.As(err, &d) {
				status = http.StatusConflict
			}
			if laneRefusal(err) == nil { // MAIN busy is not an error
				a.logf("cluster: socket %s: %v", op, err)
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
}
