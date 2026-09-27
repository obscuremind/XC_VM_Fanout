package clusteragent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cc "github.com/Vateron-Media/XC_VM_Fanout/internal/clustercrypto"
)

// Proto is the protocol version this agent speaks.
const Proto = 1

// MaxReply caps a reply body read from MAIN.
const MaxReply = 8 << 20

const octet = "application/octet-stream"

// Denial is a panel-signed refusal that names this node and this request.
type Denial struct {
	Status int
	Reason string `json:"reason"`
	Node   string `json:"node"`
	Nonce  string `json:"req_nonce"`
	// MainTimeMs is MAIN's clock when it refused; RetryAfterMs and Op are set
	// on the refusals that ask for a later retry (retry.go).
	MainTimeMs   int64  `json:"main_time_ms"`
	RetryAfterMs int64  `json:"retry_after_ms"`
	Op           string `json:"op"`
	// Lane, on a 503 RATE_LIMITED to an ingest op: the ingest permit's lane
	// ("p0" or "bulk") that had none free (retry.go). A per-op semaphore's
	// refusal has none.
	Lane string `json:"lane"`
	// CommandsSealed, on a hard-mode LICENCE_INVALID: the node's pending
	// restrictive commands, sealed to it (sealed.go).
	CommandsSealed string          `json:"commands_sealed"`
	Doc            json.RawMessage `json:"-"`
}

func (d *Denial) Error() string { return fmt.Sprintf("MAIN refused (%d %s)", d.Status, d.Reason) }

// ErrTransport is any reply that is not authenticated: it is never acted on.
var ErrTransport = errors.New("clusteragent: unauthenticated or failed reply")

// ErrNoEpoch means the node holds no usable token.
var ErrNoEpoch = errors.New("clusteragent: no usable token epoch")

type session struct {
	epoch uint64
	tok   *cc.Token
	keys  cc.SessionKeys
}

// Client talks to MAIN for one node.
type Client struct {
	State *State
	HTTP  *http.Client
	Agent string

	// LongHTTP carries the commands long-poll, which MAIN holds open.
	LongHTTP *http.Client
	// P0HTTP carries P0 events alone, over a keep-alive connection of their
	// own with one request in flight, so a bulk upload never queues them
	// (ADR 0004, ingest permits).
	P0HTTP *http.Client
	// BulkHTTP carries the artefact op: one request in flight, under its
	// own timeout (ArtefactTimeout).
	BulkHTTP *http.Client

	// OnDenial, when set, sees every verified denial of a session op.
	OnDenial func(*Denial)

	mu       sync.Mutex
	sessions map[uint64]session
	offsetMs atomic.Int64 // MAIN time − local time, from authenticated replies
	// anchor is MAIN's clock as a judgement may rely on it: authenticated
	// statements only, forward only (anchor.go). offsetMs is the looser one.
	// anchorSaved is the floor last written to the state file, read without the
	// state's lock.
	anchor      anchorHolder
	anchorSaved atomic.Int64
	now         func() time.Time
	// failed holds the MAIN URLs that could not be reached (connect, TLS or
	// timeout), each until it is tried first again (URLRetry).
	failed map[string]time.Time
	// fellBack is set when MAIN answered through a fallback URL only (a
	// known-good set's URL the current policy does not list); the agent then
	// says hello to fetch MAIN's policy (Agent.Run).
	fellBack atomic.Bool

	// httpsAnswered is set once MAIN has answered over an https:// URL: the
	// node then reports the https feature, which is what lets an operator move
	// the fleet to https_required (known.go).
	httpsAnswered atomic.Bool
}

// URLRetry is how long a MAIN URL that could not be reached is tried after
// the others (plan, "Endpoints and HTTPS": fall back, retry HTTPS every 10
// minutes).
var URLRetry = 10 * time.Minute

// DialTimeout bounds connecting to one MAIN URL, so a dead URL leaves time
// for the next within a heartbeat.
var DialTimeout = 2 * time.Second

func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = DialTimeout
	return t
}

// newP0Transport is P0's own: one connection to a MAIN URL, kept alive, so
// one P0 request is in flight at a time and never waits behind bulk.
func newP0Transport() *http.Transport {
	t := newTransport()
	t.MaxConnsPerHost = 1
	t.MaxIdleConnsPerHost = 1
	return t
}

// urls is MAIN's URLs in the order to try them: the current policy's URLs,
// then the fallback URLs of the known-good sets (known.go), each group in its
// order, with the ones that recently could not be reached last (the current
// ones, then the fallback ones).
func (c *Client) urls() []string {
	c.State.mu.Lock()
	all := append(append([]string{}, c.State.MainURLs...), c.State.fallbackURLsLocked()...)
	c.State.mu.Unlock()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var good, bad []string
	for _, u := range all {
		if until, ok := c.failed[u]; ok && now.Before(until) {
			bad = append(bad, u)
			continue
		}
		delete(c.failed, u)
		good = append(good, u)
	}
	return append(good, bad...)
}

// reached notes whether a MAIN URL answered. err is the request's error, or
// ErrTransport for an answer that did not authenticate; a failure the
// caller's own context caused says nothing of the URL. A URL that failed is
// only tried after the others for URLRetry, never dropped.
func (c *Client) reached(ctx context.Context, base string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		delete(c.failed, base)
	case ctx.Err() == nil:
		if c.failed == nil {
			c.failed = map[string]time.Time{}
		}
		if _, ok := c.failed[base]; !ok {
			c.failed[base] = c.now().Add(URLRetry)
		}
	}
}

// NewClient opens every stored epoch's token (verifying the panel signature)
// and returns a client. Epochs whose tokens do not open are dropped.
func NewClient(st *State, agent string) *Client {
	c := &Client{
		State:    st,
		HTTP:     &http.Client{Timeout: 10 * time.Second, Transport: newTransport()},
		LongHTTP: &http.Client{Timeout: 45 * time.Second, Transport: newTransport()},
		P0HTTP:   &http.Client{Timeout: 10 * time.Second, Transport: newP0Transport()},
		BulkHTTP: &http.Client{Timeout: ArtefactTimeout, Transport: newP0Transport()},
		Agent:    agent,
		sessions: map[uint64]session{},
		now:      time.Now,
	}
	c.seedAnchor()
	for _, e := range st.Epochs {
		c.openEpoch(e)
	}
	return c
}

func (c *Client) openEpoch(e Epoch) error {
	tok, keys, err := cc.OpenToken(e.EphSk, c.State.PanelSignPub, c.State.NodeUUID, e.TokenSealed)
	if err != nil {
		return err
	}
	if tok.Epoch != e.Epoch || tok.ServerID != c.State.ServerID {
		return errors.New("clusteragent: token does not match its epoch")
	}
	c.mu.Lock()
	c.sessions[e.Epoch] = session{epoch: e.Epoch, tok: tok, keys: keys}
	for n := range c.sessions {
		if n+1 < e.Epoch {
			delete(c.sessions, n)
		}
	}
	c.mu.Unlock()
	return nil
}

// MainNowMs is MAIN's clock as last observed.
func (c *Client) MainNowMs() int64 { return c.now().UnixMilli() + c.offsetMs.Load() }

// Current is the newest epoch valid now (nbf ≤ now < exp, MAIN time).
func (c *Client) Current() (*cc.Token, bool) {
	s, ok := c.current()
	return s.tok, ok
}

func (c *Client) current() (session, bool) {
	now := c.MainNowMs() / 1000
	c.mu.Lock()
	defer c.mu.Unlock()
	var best session
	found := false
	for _, s := range c.sessions {
		if s.tok.Nbf <= now && now < s.tok.Exp && (!found || s.epoch > best.epoch) {
			best, found = s, true
		}
	}
	return best, found
}

// Call performs one authenticated operation with the current epoch and
// decodes the boxed reply into out. signNode adds X-XCVM-Node-Sig (required
// for enrol_complete and token_refresh).
func (c *Client) Call(ctx context.Context, op string, payload, out any, signNode bool) error {
	s, ok := c.current()
	if !ok {
		return ErrNoEpoch
	}
	return c.call(ctx, s, op, payload, out, signNode)
}

// CallP0 sends a P0 events batch over P0's own connection (P0HTTP).
func (c *Client) CallP0(ctx context.Context, payload, out any) error {
	s, ok := c.current()
	if !ok {
		return ErrNoEpoch
	}
	return c.callVia(ctx, c.P0HTTP, s, "events", payload, out, false)
}

// A REPLAY that says when a request stamped anew will pass is retried once
// (retry.go).
func (c *Client) call(ctx context.Context, s session, op string, payload, out any, signNode bool) error {
	return c.callVia(ctx, nil, s, op, payload, out, signNode)
}

// callVia is call over hc; nil takes the op's usual client.
func (c *Client) callVia(ctx context.Context, hc *http.Client, s session, op string, payload, out any, signNode bool) error {
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return withReplay(ctx, c.setMainTime, func() error { return c.callOnce(ctx, hc, s, op, plain, out, signNode) })
}

// setMainTime takes MAIN's clock from an authenticated main_time_ms: a MAC'd
// reply, a panel-signed denial or a panel-signed re-key document. It moves both
// the offset requests are stamped with and the anchor a judgement may rely on.
func (c *Client) setMainTime(mainMs int64) {
	c.offsetMs.Store(mainMs - c.now().UnixMilli())
	c.anchorFrom(mainMs)
}

func (c *Client) callOnce(ctx context.Context, hc *http.Client, s session, op string, plain []byte, out any, signNode bool) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ts := uint64(c.MainNowMs())
	path := cc.PathPrefix + op
	reqCtx, err := cc.RequestContext(cc.Request{
		Proto: Proto, Agent: c.Agent, Method: "POST", Path: path, ContentType: octet,
		Node: c.State.NodeUUID, Epoch: s.epoch, TsMs: ts, Nonce: nonce,
	})
	if err != nil {
		return err
	}
	body, err := cc.Box(s.keys.EncUp, reqCtx, plain)
	if err != nil {
		return err
	}
	h := http.Header{}
	h.Set(cc.HProto, strconv.Itoa(Proto))
	h.Set(cc.HAgent, c.Agent)
	h.Set(cc.HNode, c.State.NodeUUID)
	h.Set(cc.HEpoch, strconv.FormatUint(s.epoch, 10))
	h.Set(cc.HTs, strconv.FormatUint(ts, 10))
	h.Set(cc.HNonce, hex.EncodeToString(nonce))
	h.Set(cc.HSig, hex.EncodeToString(cc.MAC(s.keys.MacUp, reqCtx, body)))
	h.Set("Content-Type", octet)
	if signNode {
		h.Set(cc.HNodeSig, hex.EncodeToString(cc.SignNode(c.State.SignKey(), "request", append(append([]byte{}, reqCtx...), cc.SHA256(body)...))))
	}

	if hc == nil {
		hc = c.HTTP
		if op == "commands" && c.LongHTTP != nil {
			hc = c.LongHTTP
		}
	}
	var lastErr error = ErrTransport
	for _, base := range c.urls() {
		st, rh, rb, err := c.postWith(ctx, hc, strings.TrimRight(base, "/")+"/"+op, h, body)
		if err != nil {
			c.reached(ctx, base, err)
			lastErr = err
			continue
		}
		if st == http.StatusOK && strings.EqualFold(rh.Get("Content-Type"), octet) {
			err := c.openReply(s, reqCtx, st, rh, rb, out)
			if errors.Is(err, ErrTransport) {
				// An answer that does not authenticate is this URL's failure
				// (ADR 0004, "MAIN endpoint changes (Phase 3, third
				// increment)"): whoever answers there now is not MAIN.
				c.reached(ctx, base, ErrTransport)
				lastErr = err
				continue
			}
			// The MAC verified and the BOX opened: MAIN answered here, and
			// that is final even when the reply does not decode into out.
			c.reached(ctx, base, nil)
			c.answered(base)
			return err
		}
		c.reached(ctx, base, nil)
		if d := c.denial(st, rh, rb, nonce); d != nil {
			if d.Reason != "HTTPS_REQUIRED" {
				// Reached MAIN, but one that refuses ops over this URL is no
				// known-good answer.
				c.answered(base)
			}
			if c.OnDenial != nil {
				c.OnDenial(d)
			}
			return d
		}
		lastErr = fmt.Errorf("%w: HTTP %d from %s", ErrTransport, st, base)
	}
	return lastErr
}

func (c *Client) post(ctx context.Context, url string, h http.Header, body []byte) (int, http.Header, []byte, error) {
	return c.postWith(ctx, c.HTTP, url, h, body)
}

func (c *Client) postWith(ctx context.Context, hc *http.Client, url string, h http.Header, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header = h.Clone()
	res, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(res.Body, MaxReply+1))
	if err != nil || len(rb) > MaxReply {
		return 0, nil, nil, ErrTransport
	}
	return res.StatusCode, res.Header, rb, nil
}

func (c *Client) openReply(s session, reqCtx []byte, status int, h http.Header, body []byte, out any) error {
	ts, err1 := strconv.ParseUint(h.Get(cc.HTs), 10, 64)
	nonce, err2 := hex.DecodeString(h.Get(cc.HNonce))
	mac, err3 := hex.DecodeString(h.Get(cc.HSig))
	if err1 != nil || err2 != nil || err3 != nil || len(nonce) != 16 {
		return ErrTransport
	}
	resCtx, err := cc.ResponseContext(reqCtx, uint32(status), h.Get("Content-Type"), ts, nonce)
	if err != nil || !cc.VerifyMAC(s.keys.MacDown, resCtx, body, mac) {
		return ErrTransport
	}
	plain, err := cc.Unbox(s.keys.EncDown, resCtx, body)
	if err != nil {
		return ErrTransport
	}
	var probe struct {
		MainTimeMs int64 `json:"main_time_ms"`
	}
	if json.Unmarshal(plain, &probe) == nil && probe.MainTimeMs > 0 {
		c.setMainTime(probe.MainTimeMs)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(plain, out)
}

// denial returns a verified refusal about this request, or nil.
func (c *Client) denial(status int, h http.Header, body, nonce []byte) *Denial {
	sig, err := base64.RawURLEncoding.DecodeString(h.Get(cc.HPanelSig))
	if err != nil || !cc.VerifyPanel(c.State.PanelSignPub, "den", body, sig) {
		return nil
	}
	var d Denial
	if json.Unmarshal(body, &d) != nil || d.Node != c.State.NodeUUID || d.Nonce != hex.EncodeToString(nonce) {
		return nil
	}
	d.Status = status
	d.Doc = append(json.RawMessage{}, body...)
	return &d
}

// Health fetches and verifies MAIN's signed health document from one URL.
func (c *Client) Health(ctx context.Context, base string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/health", nil)
	if err != nil {
		return nil, err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(res.Header.Get(cc.HPanelSig))
	if err != nil || !cc.VerifyPanel(c.State.PanelSignPub, "hlt", body, sig) {
		return nil, ErrTransport
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// Refresh obtains the next epoch. The ephemeral key is persisted before the
// request goes out, so a retry (after a lost reply or a restart) presents the
// same key and MAIN re-sends the same token rather than minting another.
func (c *Client) Refresh(ctx context.Context) (*cc.Token, error) {
	s, ok := c.current()
	if !ok {
		return nil, ErrNoEpoch
	}
	c.State.mu.Lock()
	if len(c.State.PendingEphSk) != 32 {
		sk, _, err := cc.NewX25519()
		if err != nil {
			c.State.mu.Unlock()
			return nil, err
		}
		c.State.PendingEphSk = sk
		if err := c.State.saveLocked(); err != nil {
			c.State.mu.Unlock()
			return nil, err
		}
	}
	ephSk := append([]byte{}, c.State.PendingEphSk...)
	c.State.mu.Unlock()
	ephPub, err := cc.X25519Public(ephSk)
	if err != nil {
		return nil, err
	}
	var reply struct {
		TokenSealed string          `json:"token_sealed"`
		Epoch       uint64          `json:"epoch"`
		Lease       json.RawMessage `json:"lease"`
	}
	if err := c.call(ctx, s, "token_refresh", map[string]string{"eph_pub": base64.StdEncoding.EncodeToString(ephPub)}, &reply, true); err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(reply.TokenSealed)
	if err != nil {
		return nil, ErrTransport
	}
	e := Epoch{Epoch: reply.Epoch, EphSk: ephSk, TokenSealed: sealed}
	if err := c.openEpoch(e); err != nil {
		return nil, err
	}
	c.State.AddEpoch(e)
	c.State.mu.Lock()
	c.State.PendingEphSk = nil
	// The lease this token serves on. A resent token (MAIN re-sends the same one
	// for the same ephemeral key) comes with a lease minted at that moment, so
	// this runs on every reply, not only on a new epoch.
	acceptLease(c.State, reply.Lease)
	err = c.State.saveLocked()
	c.State.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	tok := c.sessions[e.Epoch].tok
	c.mu.Unlock()
	return tok, nil
}
