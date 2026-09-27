package clusteragent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cc "github.com/Vateron-Media/XC_VM_Fanout/internal/clustercrypto"
)

// leaseDoc is the document xcvm_core signs, with its fields as the extension
// writes them (ADR-002, "Lease").
func leaseDoc(uuid string, sid int64, gen uint64, iat, exp int64) map[string]any {
	return map[string]any{
		"v": 1, "typ": "xcvm-lease", "node_uuid": uuid, "server_id": sid,
		"gen": gen, "iat": iat, "exp": exp, "kid": "00000000",
	}
}

// wireLease is what MAIN puts beside a token: the signed bytes and the
// signature, base64, with the exp announced alongside (LeaseService::wire).
func wireLease(panel ed25519.PrivateKey, doc map[string]any, announced int64) json.RawMessage {
	payload, _ := json.Marshal(doc)
	sig := ed25519.Sign(panel, cc.PanelSigInput("lea", payload))
	raw, _ := json.Marshal(map[string]any{
		"payload": base64.StdEncoding.EncodeToString(payload),
		"sig":     base64.StdEncoding.EncodeToString(sig),
		"exp":     announced,
	})
	return raw
}

func TestALeaseThatCameWithATokenIsKept(t *testing.T) {
	f, st := newFake(t)
	iat, exp := int64(1800000000), int64(1800000000+13*3600)

	if !acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 4, iat, exp), exp)) {
		t.Fatalf("a lease from MAIN was refused: %s", st.LeaseRefused)
	}
	if st.Lease.Exp != exp || st.Lease.Iat != iat || st.Lease.Gen != 4 || st.Lease.ServerID != st.ServerID {
		t.Fatalf("stored %+v", st.Lease)
	}
	if st.LeaseRefused != "" {
		t.Fatalf("refusal left behind: %q", st.LeaseRefused)
	}
	// The bytes are kept as they arrived, so whatever judges the lease later —
	// the node's PHP through the extension, which resolves the panel key through
	// its own pin — verifies what MAIN signed.
	if !cc.VerifyPanel(st.PanelSignPub, "lea", st.Lease.Payload, st.Lease.Sig) {
		t.Fatal("the stored bytes do not verify under `lea`")
	}
	var doc map[string]any
	if json.Unmarshal(st.Lease.Payload, &doc) != nil || doc["typ"] != "xcvm-lease" {
		t.Fatalf("the stored payload is not the document: %s", st.Lease.Payload)
	}
}

func TestNoLeaseAtAllIsNotARefusal(t *testing.T) {
	// MAIN sends the token without a lease whenever the extension signs none
	// (its licence, its clock, a node below its floor). The node keeps the lease
	// it holds and records nothing: "none sent" is not "one refused".
	f, st := newFake(t)
	exp := int64(1800000000 + 3600)
	acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, 1800000000, exp), exp))
	held := fmt.Sprintf("%+v", *st.Lease)

	for _, absent := range []json.RawMessage{nil, {}, json.RawMessage("null")} {
		if acceptLease(st, absent) {
			t.Fatal("something was stored for a lease that never arrived")
		}
		if st.LeaseRefused != "" || fmt.Sprintf("%+v", *st.Lease) != held {
			t.Fatalf("an absent lease disturbed the one held: %+v refused=%q", st.Lease, st.LeaseRefused)
		}
	}
}

func TestWhatANodeRefusesAndWhy(t *testing.T) {
	f, st := newFake(t)
	iat := int64(1800000000)
	exp := iat + 13*3600
	_, stranger, _ := ed25519.GenerateKey(nil)

	tampered := wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp), exp)
	var w map[string]any
	json.Unmarshal(tampered, &w)
	sig, _ := base64.StdEncoding.DecodeString(w["sig"].(string))
	sig[0] ^= 1
	w["sig"] = base64.StdEncoding.EncodeToString(sig)
	tamperedRaw, _ := json.Marshal(w)

	other := leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp)
	other["typ"] = "xcvm-token"
	v2 := leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp)
	v2["v"] = 2

	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"not an object", json.RawMessage(`"a lease"`), "not a lease object"},
		{"payload not base64", json.RawMessage(`{"payload":"!!!","sig":"","exp":1}`), "the payload is not base64"},
		{"signature too short", json.RawMessage(fmt.Sprintf(`{"payload":%q,"sig":"AAAA","exp":1}`, base64.StdEncoding.EncodeToString([]byte("{}")))), "the signature is not 64 base64'd bytes"},
		{"signed by a stranger", wireLease(stranger, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp), exp), "not signed under `lea` by the panel key this node holds"},
		{"signature tampered with", tamperedRaw, "not signed under `lea` by the panel key this node holds"},
		{"another document type", wireLease(f.panel, other, exp), "signed under `lea` but not a lease document"},
		{"a version this agent does not read", wireLease(f.panel, v2, exp), "a lease version this agent does not read"},
		{"another node's", wireLease(f.panel, leaseDoc("11111111-1111-4111-a111-111111111111", st.ServerID, 1, iat, exp), exp), "another node's lease"},
		{"another server's", wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID+1, 1, iat, exp), exp), "another server's lease"},
		{"no generation", wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 0, iat, exp), exp), "a lease with no window"},
		{"expiring before it starts", wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, iat), iat), "a lease with no window"},
		{"a window past 26 h", wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, iat+MaxLeaseSec+1), iat+MaxLeaseSec+1), "a window longer than the 26 h a lease may hold"},
		{"an exp that disagrees with itself", wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp), exp+60), "the exp announced beside the lease is not the one inside it"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st.Lease, st.LeaseRefused = nil, ""
			if acceptLease(st, c.raw) {
				t.Fatal("kept")
			}
			if st.Lease != nil {
				t.Fatalf("stored anyway: %+v", st.Lease)
			}
			if st.LeaseRefused != c.want {
				t.Fatalf("reason %q, want %q", st.LeaseRefused, c.want)
			}
		})
	}
}

func TestTheLongestWindowALeaseMayHoldIsKept(t *testing.T) {
	// The extension caps `exp - iat` at 26 h and refuses only what is longer, so
	// a fleet on the maximum tolerance sits exactly on this boundary: a `>=` here
	// would drop every lease it is sent.
	f, st := newFake(t)
	iat := int64(1800000000)
	exp := iat + MaxLeaseSec
	if !acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp), exp)) {
		t.Fatalf("a 26 h lease was refused: %s", st.LeaseRefused)
	}
}

func TestTheNewerLeaseWinsAndAReplayDoesNot(t *testing.T) {
	f, st := newFake(t)
	iat := int64(1800000000)
	long := wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 2, iat, iat+13*3600), iat+13*3600)
	if !acceptLease(st, long) {
		t.Fatalf("first lease: %s", st.LeaseRefused)
	}

	// An operator lowers lb_partition_tolerance_h: the next lease is SHORTER and
	// must still replace the one held — the node is meant to hold less.
	shortExp := iat + 60 + 2*3600
	if !acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 2, iat+60, shortExp), shortExp)) {
		t.Fatalf("a shorter, newer lease was refused: %s", st.LeaseRefused)
	}
	if st.Lease.Exp != shortExp {
		t.Fatalf("kept the longer window: %+v", st.Lease)
	}

	// The same first lease presented again is a copy replayed at a later
	// request, and never widens the window back.
	if acceptLease(st, long) {
		t.Fatal("a replayed lease replaced a newer one")
	}
	if st.Lease.Exp != shortExp || st.LeaseRefused != "older than the lease this node already holds" {
		t.Fatalf("after the replay: %+v refused=%q", st.Lease, st.LeaseRefused)
	}

	// A generation that went backwards is the same replay under another name.
	backExp := iat + 3600 + 13*3600
	if acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat+3600, backExp), backExp)) {
		t.Fatal("a lease from an older generation was kept")
	}
	if st.Lease.Exp != shortExp {
		t.Fatalf("the older generation replaced the lease held: %+v", st.Lease)
	}
}

func TestAMalformedLeaseCostsTheNodeItsLeaseAndNotItsEnrolment(t *testing.T) {
	// The lease rides in the same reply as the token. A lease the node cannot
	// read must not cost it the token — install still finishes, and the reason
	// is on record.
	path := filepath.Join(t.TempDir(), "agent.json")
	uuid := "0f8fad5b-d9cb-469f-a165-70867728950e"
	if _, err := Keygen(path, uuid); err != nil {
		t.Fatal(err)
	}
	st, err := loadRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, panel, _ := ed25519.GenerateKey(nil)
	ephPub, err := cc.X25519Public(st.PendingEphSk)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	secret[0] = 9
	now := time.Now().Unix()
	doc, _ := json.Marshal(map[string]any{
		"v": 1, "typ": "xcvm-token", "node_uuid": uuid, "server_id": 3, "gen": 1, "epoch": 1,
		"iat": now, "nbf": now - 120, "exp": now + 4500, "kid": "00000000", "rotation_min": 60,
		"grace_min": 15, "refresh_at": now + 1800, "token": hex.EncodeToString(secret),
	})
	body := binary.BigEndian.AppendUint32(nil, uint32(len(doc)))
	body = append(append(body, doc...), ed25519.Sign(panel, cc.PanelSigInput("tok", doc))...)
	sealed, err := cc.Seal(ephPub, "token", uuid, body)
	if err != nil {
		t.Fatal(err)
	}

	d := InstallData{ServerID: 3, PanelSignPub: pub, MainURLs: []string{"http://10.0.0.1:25461/cluster/v1/"}, Epoch: 1, TokenSealed: sealed,
		Lease: json.RawMessage(`{"payload":"not base64 at all","sig":"","exp":0}`)}
	if err := Install(path, d); err != nil {
		t.Fatalf("a malformed lease stopped the install: %v", err)
	}
	installed, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed.Epochs) != 1 || installed.Lease != nil {
		t.Fatalf("epochs %d lease %+v", len(installed.Epochs), installed.Lease)
	}
	if installed.LeaseRefused != "the payload is not base64" {
		t.Fatalf("reason %q", installed.LeaseRefused)
	}

	// And the report an operator reads at the console of that node.
	out, err := LeaseReport(path, time.Unix(now, 0))
	if err != nil || !strings.HasPrefix(out, "lease: none") {
		t.Fatalf("report %q err %v", out, err)
	}
}

func TestTheLeaseReportAnswersOnAnUnfinishedNode(t *testing.T) {
	// An operator runs this at the console of a node that cannot reach MAIN,
	// which includes one whose enrolment never finished: it must not need the
	// complete state LoadState insists on.
	path := filepath.Join(t.TempDir(), "agent.json")
	uuid := "0f8fad5b-d9cb-469f-a165-70867728950e"
	if _, err := Keygen(path, uuid); err != nil {
		t.Fatal(err)
	}
	out, err := LeaseReport(path, time.Unix(1800000000, 0))
	if err != nil {
		t.Fatalf("on a keygen'd state: %v", err)
	}
	if !strings.Contains(out, "none") {
		t.Fatalf("report %q", out)
	}

	f, st := newFake(t)
	st.path = path
	iat := int64(1800000000)
	exp := iat + 7200
	if !acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 3, iat, exp), exp)) {
		t.Fatal(st.LeaseRefused)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	out, err = LeaseReport(path, time.Unix(iat+3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"generation 3", "verifies", "1h0m0s left", "MAIN does not vouch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
	// Past its exp, by the only clock this machine has, and said as such.
	out, _ = LeaseReport(path, time.Unix(exp+60, 0))
	if !strings.Contains(out, "expired 1m0s ago") {
		t.Fatalf("report %q", out)
	}
}

// The node's PHP judges the lease from a file this agent refreshes; the point of
// the increment is that it keeps refreshing it while MAIN cannot be reached,
// because a file that has gone stale reads as "no statement, serve".
func TestTheLeaseStateIsPublishedEveryTickEvenWithMainGone(t *testing.T) {
	m, a := newBeatMain(t)
	dir := t.TempDir()
	a.FlowsFile = filepath.Join(dir, "flows.json")
	a.Interval = 50 * time.Millisecond
	f := m.fakeMain
	iat := time.Now().Unix()
	exp := iat + 13*3600
	st := a.Client.State
	if !acceptLease(st, wireLease(f.panel, leaseDoc(st.NodeUUID, st.ServerID, 1, iat, exp), exp)) {
		t.Fatal(st.LeaseRefused)
	}
	runFor(t, a, 400*time.Millisecond)

	read := func() map[string]any {
		b, err := os.ReadFile(filepath.Join(dir, "lease_state.json"))
		if err != nil {
			t.Fatalf("no lease state published: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := read()
	if int64(doc["exp"].(float64)) != exp || int64(doc["gen"].(float64)) != 1 {
		t.Fatalf("published %v", doc)
	}
	if int64(doc["anchor_ms"].(float64)) <= 0 {
		t.Fatalf("no anchor published: %v", doc)
	}
	first := int64(doc["wrote_at_ms"].(float64))

	// MAIN gone: the heartbeats fail and the file must still be rewritten.
	a.Client.State.MainURLs = []string{"http://127.0.0.1:1/cluster/v1/"}
	runFor(t, a, 400*time.Millisecond)
	again := read()
	if int64(again["wrote_at_ms"].(float64)) <= first {
		t.Fatalf("the file was not refreshed while MAIN was unreachable: %v then %v", first, again["wrote_at_ms"])
	}
	if int64(again["exp"].(float64)) != exp {
		t.Fatalf("the lease changed with MAIN gone: %v", again)
	}
}
