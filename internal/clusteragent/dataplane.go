package clusteragent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cc "github.com/Vateron-Media/XC_VM_Fanout/internal/clustercrypto"
)

// The data plane's two local helpers (plan, section 6.6), asked for by the
// node's PHP over the local socket while it serves a relay or file request:
//
//	POST /v1/nonce        {nonce}                              -> {fresh}
//	POST /v1/file_digest  {tid, owner_sid, size, sha256, iat?}  -> {header}
//
// Both are the node's own: no call to MAIN, nothing stored on disk.
//
//   - A parent verifying a child's relay or file request must see each nonce
//     once. MAIN has the cluster bus for that; a load balancer serving as a
//     parent has only its agent, so the window lives here.
//   - The owner of a file vouches for what it served with its node key, which
//     the agent holds and the node's PHP does not (Core\Cluster\Crypto\
//     FileDigest verifies the same document on the fetcher's side).

// NonceWindow is how long a spent nonce is remembered: longer than the request
// window a signature is accepted in, so nothing replays inside it.
const NonceWindow = 180 * time.Second

// MaxNonces bounds each half of the window. A parent under a flood refuses
// rather than growing: a refused relay retries, an exhausted agent would not.
const MaxNonces = 100000

// nonceCache is a two-bucket set: the live bucket takes new nonces, the
// previous one is still consulted, and a rotation drops what is older than two
// windows. No goroutine and no timer — a bucket rotates on use.
type nonceCache struct {
	mu       sync.Mutex
	live     map[string]struct{}
	previous map[string]struct{}
	rotated  time.Time
	now      func() time.Time // tests
}

func newNonceCache() *nonceCache {
	return &nonceCache{live: map[string]struct{}{}, previous: map[string]struct{}{}}
}

// fresh reports whether this nonce has not been seen, and remembers it. A full
// bucket answers false (fail closed).
func (c *nonceCache) fresh(nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	clock := time.Now
	if c.now != nil {
		clock = c.now
	}
	now := clock()
	if c.rotated.IsZero() {
		c.rotated = now
	}
	if now.Sub(c.rotated) >= NonceWindow {
		// One rotation covers any gap: everything older than the window is gone.
		if now.Sub(c.rotated) >= 2*NonceWindow {
			c.previous = map[string]struct{}{}
		} else {
			c.previous = c.live
		}
		c.live = map[string]struct{}{}
		c.rotated = now
	}
	if _, seen := c.live[nonce]; seen {
		return false
	}
	if _, seen := c.previous[nonce]; seen {
		return false
	}
	if len(c.live) >= MaxNonces {
		return false
	}
	c.live[nonce] = struct{}{}
	return true
}

// dataPlaneHandler serves the two routes; it answers 404 for anything else so
// the socket handler can fall through.
func (a *Agent) dataPlaneHandler(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/nonce":
		a.serveNonce(w, r)
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/file_digest":
		a.serveFileDigest(w, r)
		return true
	}
	return false
}

// readJSON decodes a bounded request body, answering 400 itself when it cannot.
func decodeBody(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(into); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func replyJSON(w http.ResponseWriter, doc map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (a *Agent) serveNonce(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Nonce string `json:"nonce"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	// 16 bytes as hex, as the relay auth header carries it.
	if _, err := hex.DecodeString(body.Nonce); err != nil || len(body.Nonce) != 32 {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	a.nonceOnce.Do(func() { a.nonces = newNonceCache() })
	replyJSON(w, map[string]any{"fresh": a.nonces.fresh(strings.ToLower(body.Nonce))})
}

// fileDigestDoc is the document the owner signs, with its fields in the order
// the panel's FileDigest sorts them (ksort): a byte of difference and the
// fetcher's verification fails.
type fileDigestDoc struct {
	Iat      int64  `json:"iat"`
	OwnerSid int64  `json:"owner_sid"`
	Sha256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Tid      string `json:"tid"`
	Typ      string `json:"typ"`
	V        int    `json:"v"`
}

func (a *Agent) serveFileDigest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tid      string `json:"tid"`
		OwnerSid int64  `json:"owner_sid"`
		Size     int64  `json:"size"`
		Sha256   string `json:"sha256"`
		Iat      int64  `json:"iat"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	sum := strings.ToLower(body.Sha256)
	if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 || body.Size < 0 || body.OwnerSid <= 0 || body.Tid == "" || len(body.Tid) > 64 {
		http.Error(w, "bad digest fields", http.StatusBadRequest)
		return
	}
	if len(a.Client.State.NodeSignSeed) != ed25519.SeedSize {
		http.Error(w, "no node key", http.StatusServiceUnavailable)
		return
	}
	iat := body.Iat
	if iat <= 0 {
		iat = time.Now().Unix()
	}
	doc, err := json.Marshal(fileDigestDoc{Iat: iat, OwnerSid: body.OwnerSid, Sha256: sum, Size: body.Size, Tid: body.Tid, Typ: "xcvm-file-digest", V: 1})
	if err != nil {
		http.Error(w, "doc", http.StatusInternalServerError)
		return
	}
	sig := cc.SignNode(a.Client.State.SignKey(), "digest", doc)
	replyJSON(w, map[string]any{"header": base64.RawURLEncoding.EncodeToString(doc) + "." + base64.RawURLEncoding.EncodeToString(sig)})
}
