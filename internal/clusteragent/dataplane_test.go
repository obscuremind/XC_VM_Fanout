package clusteragent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	cc "github.com/Vateron-Media/XC_VM_Fanout/internal/clustercrypto"
)

// A parent verifying a child's relay or file request must see each nonce once.
// MAIN has the cluster bus for that; a load balancer serving as a parent has
// only its agent, so the window lives in the agent (plan, section 6.6).
func TestNonceWindowSpendsEachOnce(t *testing.T) {
	c := newNonceCache()
	at := time.Unix(1800000000, 0)
	c.now = func() time.Time { return at }

	if !c.fresh("a") || c.fresh("a") {
		t.Fatal("a nonce was accepted twice")
	}
	if !c.fresh("b") {
		t.Fatal("another nonce was refused")
	}

	// One window on: the previous bucket still answers for what it holds.
	at = at.Add(NonceWindow)
	if c.fresh("a") {
		t.Fatal("a nonce from the previous window was accepted")
	}
	if !c.fresh("c") {
		t.Fatal("a new nonce in the new window was refused")
	}

	// Two windows on: nothing older survives, and the cache has not grown.
	at = at.Add(2 * NonceWindow)
	if !c.fresh("a") {
		t.Fatal("a nonce two windows old is not a replay any signature could use")
	}
	if len(c.live)+len(c.previous) > 2 {
		t.Fatalf("buckets hold %d+%d entries after a rotation", len(c.live), len(c.previous))
	}
}

func TestNonceWindowRefusesRatherThanGrow(t *testing.T) {
	c := newNonceCache()
	at := time.Unix(1800000000, 0)
	c.now = func() time.Time { return at }
	for i := 0; i < MaxNonces; i++ {
		c.live[strconv.Itoa(i)] = struct{}{}
	}
	// A parent under a flood refuses the request (which retries) instead of
	// growing until the agent dies.
	if c.fresh("one more") {
		t.Fatal("a full window accepted a nonce")
	}
}

// The owner of a file vouches for what it served with its node key, which the
// agent holds and the node's PHP does not. The document must be byte-identical
// to the panel's FileDigest (sorted keys), or the fetcher's verification fails.
func TestFileDigestIsSignedWithTheNodeKey(t *testing.T) {
	_, st := newFake(t)
	a := &Agent{Client: NewClient(st, "t"), Logf: t.Logf}

	rec := httptest.NewRecorder()
	body := `{"tid":"tid_0123456789","owner_sid":5,"size":1234,"sha256":"` + strings.Repeat("ab", 32) + `","iat":1800000000}`
	a.dataPlaneHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/file_digest", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("file_digest: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Header string `json:"header"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(out.Header, ".")
	if len(parts) != 2 {
		t.Fatalf("header %q", out.Header)
	}
	doc, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	// The panel's document, key for key and in its order.
	want := `{"iat":1800000000,"owner_sid":5,"sha256":"` + strings.Repeat("ab", 32) + `","size":1234,"tid":"tid_0123456789","typ":"xcvm-file-digest","v":1}`
	if string(doc) != want {
		t.Fatalf("document\n got %s\nwant %s", doc, want)
	}
	pub := st.SignKey().Public().(ed25519.PublicKey)
	if !cc.VerifyNode(pub, "digest", doc, sig) {
		t.Fatal("the signature does not verify under the node key with purpose digest")
	}
	if cc.VerifyNode(pub, "relay", doc, sig) {
		t.Fatal("the purpose is not bound")
	}
}

func TestDataPlaneRefusesWhatItCannotSign(t *testing.T) {
	_, st := newFake(t)
	a := &Agent{Client: NewClient(st, "t"), Logf: t.Logf}

	for name, body := range map[string]string{
		"no sha256": `{"tid":"t0123456789","owner_sid":5,"size":1}`,
		"short sha": `{"tid":"t0123456789","owner_sid":5,"size":1,"sha256":"ab"}`,
		"no owner":  `{"tid":"t0123456789","owner_sid":0,"size":1,"sha256":"` + strings.Repeat("ab", 32) + `"}`,
		"no ticket": `{"tid":"","owner_sid":5,"size":1,"sha256":"` + strings.Repeat("ab", 32) + `"}`,
		"bad size":  `{"tid":"t0123456789","owner_sid":5,"size":-1,"sha256":"` + strings.Repeat("ab", 32) + `"}`,
		"not json":  `nope`,
	} {
		rec := httptest.NewRecorder()
		a.dataPlaneHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/file_digest", strings.NewReader(body)))
		if rec.Code == http.StatusOK {
			t.Errorf("%s: signed anyway", name)
		}
	}

	for name, body := range map[string]string{
		"not hex":   `{"nonce":"zz"}`,
		"too short": `{"nonce":"abcd"}`,
		"missing":   `{}`,
	} {
		rec := httptest.NewRecorder()
		a.dataPlaneHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/nonce", strings.NewReader(body)))
		if rec.Code == http.StatusOK {
			t.Errorf("%s: accepted as a nonce", name)
		}
	}
}
