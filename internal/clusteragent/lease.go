package clusteragent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	cc "github.com/Vateron-Media/XC_VM_Fanout/internal/clustercrypto"
)

// MaxLeaseSec is the extension's own ceiling on a lease window (ADR-002,
// "Lease"): `exp - iat` may be 26 h exactly, never more.
const MaxLeaseSec = 26 * 3600

// Lease is the lease MAIN signed for this node — its statement of how long the
// node may keep serving viewers once it can no longer reach MAIN. It is kept
// exactly as it arrived, the signed bytes and the signature, so whatever comes
// to judge it later (the node's PHP through the extension's
// `cluster_lease_verify`, which resolves the panel key through the pin, or this
// agent) judges the bytes MAIN signed rather than a re-encoding of them.
//
// Nothing reads it yet. This agent stores it and reports it; the state machine
// that acts on it — and the MAIN-time anchor it has to be judged against, which
// this agent does not yet hold in any form worth trusting — is the increment
// after (ADR 0004, Phase 9).
type Lease struct {
	// Payload is the exact document MAIN signed, and Sig its 64-byte signature
	// under the panel tag `lea`.
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
	// Exp, Iat, Gen and ServerID are the document's own fields, kept beside it
	// so a reader needs no JSON pass to answer "until when, for which
	// generation".
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Gen      uint64 `json:"gen"`
	ServerID int64  `json:"server_id"`
}

// acceptLease verifies a lease that arrived beside a token and records it on
// st. The caller holds st's lock (or owns st outright) and saves afterwards.
//
// It returns false and records nothing when MAIN sent no lease at all, which is
// ordinary: MAIN sends the token without one whenever the extension refuses to
// sign (its licence, its clock, a node below its revocation floor), and the node
// then keeps whatever lease it holds. Every other refusal leaves its reason in
// State.LeaseRefused, because "MAIN sent none" and "MAIN sent one this node
// refuses" are two facts an operator needs told apart.
//
// raw is a json.RawMessage on purpose: the lease rides in the same reply as the
// token, and a lease whose base64 is broken must cost the node its lease, not
// its session. Nothing here fails the surrounding decode.
func acceptLease(st *State, raw json.RawMessage) bool {
	refuse := func(why string) bool {
		st.LeaseRefused = why
		return false
	}
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var w struct {
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
		Exp     int64  `json:"exp"`
	}
	if json.Unmarshal(raw, &w) != nil {
		return refuse("not a lease object")
	}
	payload, err := base64.StdEncoding.DecodeString(w.Payload)
	if err != nil || len(payload) == 0 {
		return refuse("the payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(w.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return refuse("the signature is not 64 base64'd bytes")
	}
	if !cc.VerifyPanel(st.PanelSignPub, "lea", payload, sig) {
		return refuse("not signed under `lea` by the panel key this node holds")
	}
	var doc struct {
		V        int    `json:"v"`
		Typ      string `json:"typ"`
		NodeUUID string `json:"node_uuid"`
		ServerID int64  `json:"server_id"`
		Gen      uint64 `json:"gen"`
		Iat      int64  `json:"iat"`
		Exp      int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &doc) != nil {
		return refuse("the signed document is not JSON")
	}
	switch {
	case doc.Typ != "xcvm-lease":
		return refuse("signed under `lea` but not a lease document")
	case doc.V != 1:
		return refuse("a lease version this agent does not read")
	case doc.NodeUUID != st.NodeUUID:
		return refuse("another node's lease")
	case doc.ServerID != st.ServerID:
		return refuse("another server's lease")
	case doc.Gen == 0 || doc.Iat <= 0 || doc.Exp <= doc.Iat:
		return refuse("a lease with no window")
	case doc.Exp-doc.Iat > MaxLeaseSec:
		// The extension caps this itself, so a document past the cap was not
		// written by one, whoever signed it.
		return refuse("a window longer than the 26 h a lease may hold")
	case w.Exp != doc.Exp:
		return refuse("the exp announced beside the lease is not the one inside it")
	}
	// Newer wins, and only newer. A lease issued before the one held is a copy
	// replayed at a later request and never replaces it; one issued now does, a
	// shorter window included — an operator who lowers
	// `lb_partition_tolerance_h` means this node to hold less, not to keep what
	// it was handed before. A generation that went backwards is the same replay
	// under another name.
	if st.Lease != nil && (doc.Iat < st.Lease.Iat || doc.Gen < st.Lease.Gen) {
		return refuse("older than the lease this node already holds")
	}
	st.Lease = &Lease{Payload: payload, Sig: sig, Exp: doc.Exp, Iat: doc.Iat, Gen: doc.Gen, ServerID: doc.ServerID}
	st.LeaseRefused = ""
	return true
}

// LeaseReport is `xc_agent lease`: what this node holds, for an operator at the
// console of a node that cannot reach MAIN. It reads the state file directly,
// so it answers on a node whose enrolment never finished, and it re-checks the
// signature against the panel key in that same file.
//
// The remaining window is reported against this machine's clock, which is the
// clock a lease exists to distrust — MAIN vouches for none of it — so the line
// says so rather than implying an answer it cannot give.
func LeaseReport(path string, now time.Time) (string, error) {
	st, err := loadRaw(path)
	if err != nil {
		return "", err
	}
	if st.Lease == nil {
		return "lease: none. MAIN has sent this node no lease.\n", nil
	}
	l := st.Lease
	signed := "signature: verifies under `lea` against the panel key in this state file"
	if !cc.VerifyPanel(st.PanelSignPub, "lea", l.Payload, l.Sig) {
		signed = "signature: DOES NOT VERIFY against the panel key in this state file"
	}
	left := l.Exp - now.Unix()
	window := fmt.Sprintf("%s left by this machine's clock, which MAIN does not vouch for", (time.Duration(left) * time.Second).String())
	if left <= 0 {
		window = fmt.Sprintf("expired %s ago by this machine's clock, which MAIN does not vouch for", (time.Duration(-left) * time.Second).String())
	}
	// And against the clock a judgement would use: MAIN's own, as the last
	// authenticated statement carried it (anchor.go). A running agent advances
	// that on its monotonic clock; from the file it is a floor, so what it gives
	// is how much of the lease was certainly still unspent then.
	heard := "MAIN has not been heard from on this node yet"
	if st.MainSeenMs > 0 {
		unspent := l.Exp - st.MainSeenMs/1000
		heard = fmt.Sprintf("%s of it was still unspent when MAIN was last heard (%d)", (time.Duration(unspent) * time.Second).String(), st.MainSeenMs/1000)
		if unspent <= 0 {
			heard = fmt.Sprintf("already spent when MAIN was last heard (%d)", st.MainSeenMs/1000)
		}
	}
	return fmt.Sprintf("lease: server %d, generation %d\nissued: %d  expires: %d (%d s window)\n%s\n%s\n%s\n",
		l.ServerID, l.Gen, l.Iat, l.Exp, l.Exp-l.Iat, window, heard, signed), nil
}
