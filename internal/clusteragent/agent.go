package clusteragent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Agent runs a node's control loop: finish enrolment, say hello, heartbeat,
// and refresh the token before it expires.
type Agent struct {
	Client    *Client
	Version   string
	Interval  time.Duration
	Telemetry func() map[string]any
	Logf      func(format string, args ...any)
	// FlowsFile receives the node's mode and flow bits from MAIN's replies,
	// for the LB's PHP (Core\Cluster\NodeFlows); "" writes nothing.
	FlowsFile string
	// Exec runs MAIN's commands (commands.go); nil leaves the commands lane off.
	Exec Executor
	// SpoolDir is where the node's PHP spools events for MAIN (events.go);
	// "" leaves the event lanes off.
	SpoolDir string
	// SocketPath is the local socket the node's PHP calls MAIN through
	// (socket.go); "" leaves it off.
	SocketPath string
	// FanoutCtl is xc_fanout's control socket, whose GET /events the agent
	// follows while STREAMS is on (fanout.go); "" leaves it off.
	FanoutCtl string
	// ReplicaDir is where the node keeps its replica (replica.go); "" leaves
	// it off.
	ReplicaDir string
	// Apply applies the materialised replica after it changed (cluster:apply);
	// nil applies nothing.
	Apply func(ctx context.Context) error
	// Registry holds the node's viewers while CONNECTIONS is on (registry.go);
	// Run makes it when SpoolDir is set.
	Registry *Registry
	// ArtefactDir is where the agent downloads the artefacts MAIN grants
	// (config/cluster/artefacts, artefact.go); "" fetches none.
	ArtefactDir string
	// Types lists the command types the node's PHP runs (TypesViaPHP),
	// asked before each hello; nil says no artefact feature.
	Types func(ctx context.Context) ([]string, error)

	pubMu     sync.Mutex // one reply published at a time (hellos run beside the heartbeats)
	flowsSeen string
	flows     atomic.Int64 // the flow bits from MAIN's latest reply
	// MAIN's event cursors from the latest hello, plus one (0: not known yet).
	cursorP0, cursorP1 atomic.Int64
	fanoutLive         atomic.Bool  // the fanout's /events feed is being followed
	snapshotting       atomic.Bool  // a conn_snapshot is being sent
	state              atomic.Value // string: the node state in MAIN's latest reply
	admits             admitCache   // conn_admit's admitting answers (admission.go)
	p2Touch            atomic.Bool  // HLS touches go on the P2 lane (touch.go)
	helloing           atomic.Bool  // a hello is being retried in the background
	refreshing         atomic.Bool  // a token refresh runs in the background
	stopCh             chan error   // a background loop's fatal refusal, for Run
	run                Executor     // what runs MAIN's commands (localExec over Exec); nil: none
	sealedMu           sync.Mutex   // one batch of sealed commands at a time (sealed.go)
	fenced             atomic.Bool  // MAIN refuses the session for want of a licence
	acking             atomic.Bool  // sealed commands are being acked
	httpsFailing       atomic.Bool  // HTTPS fails under https_required (policy.go)
	nonceOnce          sync.Once    // the data plane's nonce window (dataplane.go)
	nonces             *nonceCache
	busyRefusals       atomic.Int64 // ingest lane refusals: MAIN busy, not failing (retry.go)
	replicaMu          sync.Mutex   // one replica sync or check at a time (replica.go)
	replicaKeys        string       // the keys the stored records were last checked with (replicaMu)
	kickOnce           sync.Once
	syncKick           chan struct{} // config.changed: sync now (replica.go)
	applyKick          chan struct{} // the CONFIG flow changed: apply now
	streamsKick        chan struct{} // a config sync ended: a streams sync now (streams.go)
	applyMu            sync.Mutex    // one cluster:apply at a time
	lastApply          time.Time
	configSeen         atomic.Int64 // the CONFIG and STREAMS bits of the flows last published, +1 (0: none yet)
	streamsSeen        atomic.Int32 // the STREAMS bit last published: 0 none yet, 1 off, 2 on
	streamsFileMu      sync.Mutex   // streams.json against the flow turning off (streams.go)
	stateFileMu        sync.Mutex   // replica/state.json, written by the config and streams syncs
	// One streams sync at a time, on its own loop (RunStreams): never
	// under replicaMu, so a long walk holds up no config sync.
	streamsMu      sync.Mutex
	streamsRecheck atomic.Bool // the node's keys changed: check the stored stream records
	// The stream records that did not verify at the last check, left out
	// of the next walk's hashes, and whether that resync is due now; the
	// resync interval (streamsMu).
	streamsBad       map[int64]bool
	streamsResyncNow bool
	streamsEvery     time.Duration
	artefactOn       atomic.Bool // the node's PHP runs artefact.fetch: say FeatureArtefact
	typesSeen        atomic.Bool
	artefactOnce     sync.Once
	artefactKick     chan struct{} // a command was kept: look now (artefact.go)
	// When the agent last said hello because MAIN answered through a
	// fallback URL only, and under which policy version (Run's loop only).
	fallbackHelloAt  time.Time
	fallbackHelloVer int
}

// Reply is what MAIN returns to enrol_complete, hello and heartbeat.
type Reply struct {
	State   string `json:"state"`
	Mode    int    `json:"mode"`
	Flows   int    `json:"flows"`
	Gen     int    `json:"gen"`
	Pending int    `json:"pending"`
	// PolicyVer, in heartbeat replies, is MAIN's current transport policy;
	// a newer one than the node holds makes it say hello again to fetch it.
	PolicyVer int `json:"policy_ver"`
	// WantConnSnapshot, in heartbeat replies: MAIN's store for this node
	// drifted from the digest the heartbeat carried; send the registry.
	WantConnSnapshot bool `json:"want_conn_snapshot"`
	// OfflineAdmission, in hello and heartbeat replies: the offline policy
	// for viewers MAIN cannot admit (admission.go); an older MAIN omits it.
	OfflineAdmission string `json:"offline_admission"`
	// P2Types, in hello and heartbeat replies: the event types MAIN takes on
	// the P2 lane (touch.go); an older MAIN omits it.
	P2Types []string `json:"p2_types"`
	// Cursors, in hello replies, are the last event numbers MAIN applied per lane.
	Cursors *struct {
		P0 int64 `json:"p0"`
		P1 int64 `json:"p1"`
	} `json:"cursors"`
	Policy *Policy `json:"policy"`
}

// Features are what this agent tells MAIN at hello that it does, so MAIN
// stands down its own copy: "hls_reaper" (Registry.Reap).
var Features = []string{"hls_reaper"}

// FeatureConfigChanged, said at hello by an agent that keeps the replica and
// runs MAIN's commands, has MAIN send it config.changed (replica.go); an
// agent that keeps the replica also says FeatureStreams (streams.go), and
// one whose node's PHP runs artefact.fetch FeatureArtefact (artefact.go).
const FeatureConfigChanged = "config_changed"

// FeatureHTTPS says MAIN has answered this node over HTTPS.
const FeatureHTTPS = "https"

// features is what this agent says at hello.
func (a *Agent) features() []string {
	out := append([]string{}, Features...)
	if a.ReplicaDir != "" && (a.Exec != nil || a.run != nil) {
		out = append(out, FeatureConfigChanged)
	}
	if a.ReplicaDir != "" {
		// The R2 streams section, kept as streams.go does.
		out = append(out, FeatureStreams)
	}
	if a.ArtefactDir != "" && (a.Exec != nil || a.run != nil) && a.artefactOn.Load() {
		// Only while the node's PHP runs artefact.fetch (artefact.go).
		out = append(out, FeatureArtefact)
	}
	if a.Client != nil && a.Client.HTTPSAnswered() {
		// MAIN has answered this node over HTTPS: it may be moved to
		// https_required without losing it (known.go).
		out = append(out, FeatureHTTPS)
	}
	return out
}

// BusyRefusals counts the ingest lane refusals MAIN has sent (503
// RATE_LIMITED with lane): busy, not failing, so never logged as errors.
func (a *Agent) BusyRefusals() int64 { return a.busyRefusals.Load() }

// ErrStop is returned when MAIN has told the node to stop: it was revoked or
// is unknown, or its enrolment was never completed in time. An expired token
// is not a stop: the node re-keys.
var ErrStop = errors.New("clusteragent: stopped by MAIN")

// RekeyPoll is how often a node that cannot re-key yet (licence withdrawn,
// quarantined) asks again; MAIN allows one attempt a minute.
var RekeyPoll = 60 * time.Second

func (a *Agent) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

func (a *Agent) identity() map[string]any {
	return map[string]any{"instance_id": a.Client.State.InstanceID, "boot_id": bootID(), "agent_version": a.Version, "arch": assetArch()}
}

// assetArch names this machine as the xc_agent release assets do
// (xc_agent-linux-<arch>), so MAIN can offer the node the binary it pinned for
// it rather than guess which one it can run.
func assetArch() string {
	if runtime.GOARCH == "arm" {
		return "armv7"
	}
	return runtime.GOARCH
}

// heartbeatEvery is the pace MAIN's policy asks for (heartbeat_sec), else the
// -interval flag, else 2 s. MAIN's liveness assumes heartbeats at most
// MaxHeartbeatGap apart, so that bounds either. Only the policy's value is held
// to MinHeartbeat: the flag is for a node run by hand (and for a test that
// wants the loop to spin), and it was never bounded below.
func (a *Agent) heartbeatEvery() time.Duration {
	d := a.Interval
	if d <= 0 {
		d = 2 * time.Second
	}
	if a.Client != nil && a.Client.State != nil {
		if sec := a.Client.State.heartbeatSec(); sec > 0 {
			d = max(time.Duration(sec)*time.Second, MinHeartbeat)
		}
	}
	return min(d, MaxHeartbeatGap)
}

// fatal reports whether a refusal means the loop must stop.
func fatal(err error) bool {
	var d *Denial
	if !errors.As(err, &d) {
		return false
	}
	switch d.Reason {
	case "NODE_REVOKED", "UNKNOWN_NODE", "ENROL_EXPIRED":
		return true
	}
	return false
}

func (a *Agent) enrolled() bool {
	st := a.Client.State
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.Enrolled
}

// recover re-keys until it works, MAIN stops the node, or ctx ends. Only an
// enrolled node can: MAIN re-keys active nodes only.
func (a *Agent) recover(ctx context.Context) error {
	if !a.enrolled() {
		return errors.Join(ErrStop, errors.New("clusteragent: the first token expired before enrolment completed"))
	}
	backoff := 5 * time.Second
	for {
		tok, err := a.Client.Rekey(ctx, a.identity())
		if err == nil {
			a.logf("cluster: re-keyed (epoch %d)", tok.Epoch)
			return nil
		}
		if fatal(err) {
			return errors.Join(ErrStop, err)
		}
		wait := backoff
		var d *Denial
		switch {
		case errors.Is(err, ErrUnlicensed):
			wait = RekeyPoll
		case errors.As(err, &d) && d.Reason == "RATE_LIMITED":
			wait = max(time.Second, time.Duration(retryAfterMs(d))*time.Millisecond)
		case errors.As(err, &d) && (d.Reason == "LICENCE_INVALID" || d.Reason == "NOT_ACTIVE"):
			wait = RekeyPoll
		default:
			if w, ok := busyWait(err); ok {
				wait = w // MAIN is starting: no longer backoff
				break
			}
			backoff = min(backoff*2, 5*time.Minute)
		}
		a.logf("cluster: re-key: %v (retry in %s)", err, wait)
		if !sleep(ctx, jitter(wait)) {
			return ctx.Err()
		}
	}
}

// publish writes the mode and flows MAIN just sent, when they changed. The
// file is replaced atomically; PHP reads it at request or loop start.
func (a *Agent) publish(r *Reply) {
	if r == nil || r.State == "" {
		return
	}
	a.pubMu.Lock()
	defer a.pubMu.Unlock()
	a.flows.Store(int64(r.Flows))
	// With STREAMS off, streams.json says 0 before flows.json says so.
	a.streamsFlow(r.Flows)
	a.state.Store(r.State)
	a.setOfflineAdmission(r.OfflineAdmission)
	a.setP2(a.p2Wanted(r))
	if a.FlowsFile == "" {
		a.flowsApply(r.Flows)
		return
	}
	doc := map[string]any{"mode": r.Mode, "flows": r.Flows, "state": r.State}
	var features []string
	if a.fanoutLive.Load() {
		// PHP's reconcile leaves the supervised streams' state to these events.
		features = append(features, "fanout_events")
	}
	if a.Registry != nil {
		// The node's own reaper (UsersCronJob, MySQL mode) leaves idle HLS
		// viewers to the registry's.
		features = append(features, "hls_reaper")
	}
	if features != nil {
		doc["features"] = features
	}
	b, _ := json.Marshal(doc)
	if string(b) == a.flowsSeen {
		// Unchanged: touch it, so the PHP side knows the agent is alive and
		// keeps spooling events (EventSpool::STALE_AFTER).
		now := time.Now()
		os.Chtimes(a.FlowsFile, now, now)
		return
	}
	tmp := a.FlowsFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		a.logf("cluster: writing flows: %v", err)
		return
	}
	if err := os.Rename(tmp, a.FlowsFile); err != nil {
		a.logf("cluster: writing flows: %v", err)
		return
	}
	a.flowsSeen = string(b)
	// The caches change hands once PHP can read the new CONFIG bit.
	a.flowsApply(r.Flows)
	a.logf("cluster: mode %d, flows %d (%s)", r.Mode, r.Flows, r.State)
}

// Unpublish removes the flows file, so the LB's PHP falls back to the legacy
// paths: called when MAIN stops the node.
func (a *Agent) Unpublish() {
	if a.FlowsFile != "" {
		os.Remove(a.FlowsFile)
	}
}

func (a *Agent) apply(r *Reply) {
	a.publish(r)
	if r != nil && r.Cursors != nil {
		a.cursorP0.Store(r.Cursors.P0 + 1)
		a.cursorP1.Store(r.Cursors.P1 + 1)
	}
	if r == nil {
		return
	}
	// A MAC'd reply: a policy not older than the one held is adopted.
	if _, err := a.Client.State.adoptPolicy(r.Policy, false); err != nil {
		a.logf("cluster: saving policy: %v", err)
	}
}

// Start completes enrolment when needed and says hello.
func (a *Agent) Start(ctx context.Context) (*Reply, error) {
	st := a.Client.State
	if !st.Enrolled {
		var r Reply
		if err := a.Client.Call(ctx, "enrol_complete", a.identity(), &r, true); err != nil {
			return nil, err
		}
		st.mu.Lock()
		st.Enrolled = true
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			return nil, err
		}
		a.apply(&r)
		a.logf("cluster: enrolled (state %s, mode %d)", r.State, r.Mode)
	}
	var r Reply
	hello := a.identity()
	a.checkTypes(ctx)
	hello["features"] = a.features()
	// The policy whose main_urls the agent dials (adopted, never merely seen).
	hello["policy_ver"] = st.policyVer()
	if err := a.Client.Call(ctx, "hello", hello, &r, false); err != nil {
		return nil, err
	}
	a.apply(&r)
	return &r, nil
}

// Run loops until ctx ends or MAIN stops the node. Transport failures back off
// and retry; they never change the node's state. A node whose tokens are gone
// re-keys and carries on.
func (a *Agent) Run(ctx context.Context) error {
	interval := a.heartbeatEvery()
	backoff := interval
	a.stopCh = make(chan error, 1)
	if a.Exec != nil && a.run == nil {
		a.run = a.localExec(a.Exec)
	}
	if a.Client.OnDenial == nil {
		a.Client.OnDenial = func(d *Denial) {
			if d.Reason == "LICENCE_INVALID" && d.CommandsSealed != "" {
				go a.takeSealed(ctx, d)
			}
			if d.Reason == "HTTPS_REQUIRED" {
				a.httpsFailing.Store(true)
			}
		}
	}
	var policyDone sync.WaitGroup
	defer policyDone.Wait()
	pctx, stopPolicy := context.WithCancel(ctx)
	defer stopPolicy()
	policyDone.Add(1)
	go func() {
		defer policyDone.Done()
		a.RunPolicyRecovery(pctx)
	}()
	for {
		_, err := a.Start(ctx)
		if err == nil {
			a.httpsFailing.Store(false)
			break
		}
		if fatal(err) {
			return errors.Join(ErrStop, err)
		}
		a.httpsTrouble(err)
		if a.licenceGone(err) {
			// FENCED: ask again at the heartbeat's pace, so the kills MAIN
			// sends with its refusal keep coming (sealed.go).
			a.setFenced(true)
			if !sleep(ctx, interval) {
				return ctx.Err()
			}
			continue
		}
		if needsRekey(err) {
			if err := a.recover(ctx); err != nil {
				return err
			}
			continue
		}
		if w, ok := busyWait(err); ok {
			// MAIN is busy, not failing: come back when it says, with no
			// longer backoff.
			a.logf("cluster: start: %v (retry in %s)", err, w)
			if !sleep(ctx, w) {
				return ctx.Err()
			}
			continue
		}
		a.logf("cluster: start: %v (retry in %s)", err, backoff)
		if !sleep(ctx, backoff) {
			return ctx.Err()
		}
		backoff = min(backoff*2, time.Minute)
	}
	if a.run != nil {
		cctx, stopCommands := context.WithCancel(ctx)
		defer stopCommands()
		go a.RunCommands(cctx, a.run)
	}
	if a.run != nil && a.ArtefactDir != "" {
		// Stopped and waited for on return: a download writes beside the state.
		actx, stopArtefacts := context.WithCancel(ctx)
		var artefactsDone sync.WaitGroup
		artefactsDone.Add(1)
		defer artefactsDone.Wait()
		defer stopArtefacts()
		go func() {
			defer artefactsDone.Done()
			a.RunArtefacts(actx)
		}()
	}
	if a.Registry == nil && a.SpoolDir != "" {
		spool := a.SpoolDir
		a.Registry = NewRegistry(filepath.Join(filepath.Dir(spool), "registry.snap"), func(ev []map[string]any) error { return spoolP0(spool, ev) }, a.logf)
	}
	if a.Registry != nil && a.Registry.Admit == nil {
		a.Registry.Admit = a.admit
	}
	if a.Registry != nil && a.Registry.P2 == nil {
		a.Registry.P2 = a.p2Touch.Load
	}
	if a.Registry != nil {
		// What registry.snap restored, checked against what still serves it.
		go a.RebuildRegistry(ctx)
	}
	if a.Registry != nil {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for tick := 1; ; tick++ {
				select {
				case <-ctx.Done():
					a.Registry.Save()
					return
				case <-t.C:
					if tick%5 == 0 && a.flows.Load()&FlowConnections != 0 {
						if n := a.Registry.Reap(HLSReapAfter); n > 0 {
							a.logf("cluster: ended %d idle HLS viewer(s)", n)
						}
					}
					if err := a.Registry.Save(); err != nil {
						a.logf("cluster: saving the connection registry: %v", err)
					}
				}
			}
		}()
	}
	if a.SocketPath != "" {
		sctx, stopSocket := context.WithCancel(ctx)
		defer stopSocket()
		go func() {
			if err := a.ServeSocket(sctx, a.SocketPath); err != nil {
				a.logf("cluster: local socket: %v", err)
			}
		}()
	}
	if a.FanoutCtl != "" && a.SpoolDir != "" {
		fctx, stopFanout := context.WithCancel(ctx)
		defer stopFanout()
		go a.RunFanoutEvents(fctx)
	}
	if a.ReplicaDir != "" {
		// Stopped and waited for on return, like the policy recovery: its
		// sync and cluster:apply end with rctx.
		rctx, stopReplica := context.WithCancel(ctx)
		var replicaDone sync.WaitGroup
		replicaDone.Add(1)
		defer replicaDone.Wait()
		defer stopReplica()
		go func() {
			defer replicaDone.Done()
			a.RunReplica(rctx)
		}()
	}
	if a.SpoolDir != "" {
		ectx, stopEvents := context.WithCancel(ctx)
		defer stopEvents()
		for _, lane := range Lanes {
			go a.RunEvents(ectx, lane)
		}
		if a.Registry != nil {
			go a.RunTouches(ectx)
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-a.stopCh:
			return errors.Join(ErrStop, err)
		case <-t.C:
		}
		// The fleet's pace is MAIN's to set (lb_telemetry_interval_sec, carried
		// by the policy): a change reaches this node with the policy its next
		// hello adopts, and the ticker follows without a restart.
		if want := a.heartbeatEvery(); want != interval {
			a.logf("cluster: heartbeat every %s (was %s)", want, interval)
			interval, backoff = want, want
			t.Reset(want)
		}
		if tok, ok := a.Client.Current(); ok && a.Client.MainNowMs()/1000 >= tok.RefreshAt {
			a.refreshLater(ctx)
		}
		hctx, cancel := context.WithTimeout(ctx, MaxHeartbeatGap)
		r, err := a.Heartbeat(hctx)
		cancel()
		a.fallbackHello(ctx)
		if err != nil {
			if fatal(err) {
				return errors.Join(ErrStop, err)
			}
			if a.licenceGone(err) {
				a.setFenced(true)
				continue
			}
			if needsRekey(err) {
				a.logf("cluster: heartbeat: %v; re-keying", err)
				if err := a.recover(ctx); err != nil {
					return err
				}
				a.helloLater(ctx, "after the re-key")
				continue
			}
			a.logf("cluster: heartbeat: %v", err)
			a.httpsTrouble(err)
			if w, ok := busyWait(err); ok && !sleep(ctx, w) {
				// MAIN is starting: its silence clock starts when it is ready.
				return ctx.Err()
			}
			continue
		}
		a.setFenced(false)
		a.httpsFailing.Store(false)
		if a.hasUnackedSealed() && a.acking.CompareAndSwap(false, true) {
			go func() {
				defer a.acking.Store(false)
				a.ackSealed(ctx)
			}()
		}
		if r.WantConnSnapshot {
			go a.snapshot(ctx)
		}
		if r.PolicyVer > a.Client.State.policyVer() {
			a.helloLater(ctx, fmt.Sprintf("fetching policy %d", r.PolicyVer))
		}
		if r.State == "quarantined" {
			a.logf("cluster: MAIN has quarantined this node; an admin must decide")
		}
	}
}

// snapshot sends the registry MAIN asked for. A snapshot given up while
// MAIN's bulk lane stays busy is not an error: MAIN asks again while its
// store drifts.
func (a *Agent) snapshot(ctx context.Context) {
	err := a.SendSnapshot(ctx)
	switch {
	case err == nil:
	case laneRefusal(err) != nil:
		a.logf("cluster: connection snapshot: MAIN stayed busy; left for MAIN to ask again")
	default:
		a.logf("cluster: connection snapshot: %v", err)
	}
}

// fallbackHello says hello when MAIN answered through a fallback URL only
// (known.go), to fetch MAIN's policy: at most once per URLRetry for the same
// policy version, since a MAIN whose policy is the one held answers each
// hello with it again while its URLs stay unreachable.
func (a *Agent) fallbackHello(ctx context.Context) {
	if !a.Client.fellBack.Swap(false) {
		return
	}
	ver := a.Client.State.policyVer()
	if ver == a.fallbackHelloVer && !a.fallbackHelloAt.IsZero() && time.Since(a.fallbackHelloAt) < URLRetry {
		return
	}
	a.fallbackHelloAt, a.fallbackHelloVer = time.Now(), ver
	a.helloLater(ctx, "MAIN answered through a fallback URL")
}

// MaxHeartbeatGap is the longest MAIN may go between two of the node's
// heartbeats (ADR 0004, "The cluster bus (Phase 2, third increment):
// heartbeats"): the interval is capped at it, and a heartbeat not answered
// within it is given up so the next one goes out on time. Nothing else runs
// on the heartbeat loop: a token refresh, and a hello after a re-key or for a
// newer policy, run beside it.
var MaxHeartbeatGap = 3 * time.Second

// refreshLater refreshes the token in the background; one runs at a time.
func (a *Agent) refreshLater(ctx context.Context) {
	if !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.refreshing.Store(false)
		if _, err := a.Client.Refresh(ctx); err != nil {
			if fatal(err) {
				a.stop(err)
				return
			}
			// The current token lasts to exp; a later heartbeat re-keys if it must.
			a.logf("cluster: token refresh: %v", err)
		}
	}()
}

// setFenced notes whether MAIN refuses the session for want of a licence.
func (a *Agent) setFenced(on bool) {
	if a.fenced.Swap(on) == on {
		return
	}
	if on {
		a.logf("cluster: MAIN's licence is not valid; heartbeats go on for the kills MAIN sends with its refusals")
	} else {
		a.logf("cluster: MAIN accepts the session again")
	}
}

func (a *Agent) hasUnackedSealed() bool {
	st := a.Client.State
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, k := range st.SealedCmds {
		if !k.Acked {
			return true
		}
	}
	return false
}

// helloLater says hello in the background, while the heartbeats go on, until
// it works, MAIN stops the node (Run then returns) or ctx ends. MAIN busy
// (503 RATE_LIMITED) is retried when MAIN says, anything else with a backoff.
// One runs at a time.
func (a *Agent) helloLater(ctx context.Context, why string) {
	if !a.helloing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.helloing.Store(false)
		backoff := 2 * time.Second
		for {
			_, err := a.Start(ctx)
			if err == nil {
				return
			}
			if fatal(err) {
				a.stop(err)
				return
			}
			wait := backoff
			if w, ok := busyWait(err); ok {
				wait = w
			} else {
				backoff = min(backoff*2, time.Minute)
			}
			a.logf("cluster: hello (%s): %v (retry in %s)", why, err, wait)
			if !sleep(ctx, wait) {
				return
			}
		}
	}()
}

// stop hands a background loop's fatal refusal to Run.
func (a *Agent) stop(err error) {
	if a.stopCh == nil {
		return
	}
	select {
	case a.stopCh <- err:
	default:
	}
}

// Heartbeat sends one heartbeat and publishes the reply's mode and flows. A
// node whose CONNECTIONS flow is on adds its registry's digest.
func (a *Agent) Heartbeat(ctx context.Context) (*Reply, error) {
	payload := map[string]any{"root_ready": RootReady(a.Client.State), "policy_ver": a.Client.State.policyVer()}
	if a.Telemetry != nil {
		payload["telemetry"] = a.Telemetry()
	}
	if audit := a.readAudit(); audit != nil {
		payload["audit"] = audit
	}
	if a.Registry != nil && a.flows.Load()&FlowConnections != 0 {
		payload["conn_digest"] = a.Registry.Digest()
	}
	var r Reply
	if err := a.Client.Call(ctx, "heartbeat", payload, &r, false); err != nil {
		return nil, err
	}
	a.publish(&r)
	return &r, nil
}

// jitter spreads d by ±10 %, so a fleet recovering together does not arrive at once.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d - d/10 + time.Duration(mrand.Int63n(int64(d/5)+1))
}

// RootPinDir is where root pins the panel key for root commands.
var RootPinDir = "/etc/xc_vm/cluster"

// RootReady reports whether root's pin of the panel key matches the one this
// agent holds, so MAIN may send this node root commands (cluster:root checks
// them against that pin).
func RootReady(st *State) bool {
	pub, err1 := os.ReadFile(filepath.Join(RootPinDir, "main_sign.pub"))
	node, err2 := os.ReadFile(filepath.Join(RootPinDir, "node"))
	st.mu.Lock()
	defer st.mu.Unlock()
	return err1 == nil && err2 == nil && strings.TrimSpace(string(pub)) == hex.EncodeToString(st.PanelSignPub) &&
		strings.TrimSpace(string(node)) == st.NodeUUID
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
