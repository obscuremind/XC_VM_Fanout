// Package clusteragent is the LB side of the XC_VM cluster API: the node's
// persistent identity and token epochs, and a client for MAIN's
// /cluster/v1/ operations (enrol_complete, hello, heartbeat, token_refresh,
// token_rekey, commands, ack, events, conn_snapshot, conn_admit, config).
//
// Every reply is authenticated before it is believed: a session reply by its
// MAC and BOX under the epoch's down keys, a refusal by the pinned panel key
// and by naming this node and this request's nonce. Anything else is a
// transport error and changes nothing.
//
// Refusals that ask for a later retry (REPLAY with retry_after_ms, a busy or
// starting MAIN's 503) are in retry.go; the transport policy and the
// https_required recovery in policy.go; the kills a hard-mode LICENCE_INVALID
// carries in sealed.go; viewer admission in admission.go; the P2 lane in
// touch.go; the registry's rebuild after a restart in rebuild.go; the
// ingest lanes' busy refusals in retry.go; the known-good URL sets in
// known.go; the node replica's sections in replica.go and its R2 streams
// section in streams.go; the connect audit the heartbeat relays in audit.go;
// the artefacts MAIN grants in artefact.go.
package clusteragent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Epoch is one token epoch the node holds: the per-epoch X25519 secret the
// token was sealed to, and the sealed token itself (opened on load, so a
// tampered state file cannot inject a token the panel did not sign).
type Epoch struct {
	Epoch       uint64 `json:"epoch"`
	EphSk       []byte `json:"eph_sk"`
	TokenSealed []byte `json:"token_sealed,omitempty"`
}

// State is the node's persistent identity, written 0600 and atomically.
type State struct {
	NodeUUID     string `json:"node_uuid"`
	ServerID     int64  `json:"server_id"`
	NodeSignSeed []byte `json:"node_sign_seed"`
	NodeBoxSk    []byte `json:"node_box_sk"`
	PanelSignPub []byte `json:"panel_sign_pub"`
	// PanelBoxPub is the key re-key bodies are sealed to (see rekey.go).
	PanelBoxPub []byte   `json:"panel_box_pub,omitempty"`
	MainURLs    []string `json:"main_urls"`
	PolicyVer   int      `json:"policy_ver"`
	// Transport is the policy's cluster_transport; HTTPURLs the plain-HTTP
	// MAIN URLs of every policy held, for the challenge while HTTPS fails
	// under https_required (policy.go).
	Transport string   `json:"transport,omitempty"`
	HTTPURLs  []string `json:"http_urls,omitempty"`
	// HeartbeatSec is the pace MAIN's policy sets (lb_telemetry_interval_sec,
	// 1-3 s), kept here so a restart holds it before the first hello answers.
	HeartbeatSec int `json:"heartbeat_sec,omitempty"`
	// KnownGoodURLs are the last KnownGoodSets URL sets MAIN answered on,
	// newest first (known.go).
	KnownGoodURLs []URLSet `json:"known_good_urls,omitempty"`
	Enrolled      bool     `json:"enrolled"`
	InstanceID    string   `json:"instance_id"`
	Epochs        []Epoch  `json:"epochs"` // newest first
	// PendingEphSk is the key of a token_refresh whose reply has not arrived.
	// It is persisted before the request is sent, so a retry after a crash or
	// a lost reply uses the same key and MAIN re-sends the same token.
	PendingEphSk []byte `json:"pending_eph_sk,omitempty"`
	// CmdSeq is the highest command seq this node has handled (commands.go).
	CmdSeq uint64 `json:"cmd_seq,omitempty"`
	// OfflineAdmission is MAIN's lb_offline_admission from the last hello or
	// heartbeat reply (admission.go); "" until one arrives (local).
	OfflineAdmission string `json:"offline_admission,omitempty"`
	// SealedCmds are the commands run from LICENCE_INVALID denials, kept
	// until they expire (sealed.go).
	SealedCmds []SealedCmd `json:"sealed_cmds,omitempty"`
	// HeldCmds are the commands kept for their artefact's download, and the
	// node.root commands waiting behind one, until they are acked
	// (artefact.go).
	HeldCmds []HeldCmd `json:"held_cmds,omitempty"`
	// Lease is MAIN's statement of how long this node may keep serving without
	// reaching it, as it arrived beside a token (lease.go). Nil until MAIN sends
	// one; nothing acts on it yet.
	Lease *Lease `json:"lease,omitempty"`
	// MainSeenMs is the highest MAIN clock an authenticated statement has
	// carried, kept so a restart's anchor cannot start further back than the last
	// time MAIN was heard (anchor.go). Written at most once a minute.
	MainSeenMs int64 `json:"main_seen_ms,omitempty"`
	// LeaseRefused is why the last lease MAIN sent was not kept, or "" when the
	// one held was the last one sent. It is written here rather than logged
	// because the paths a lease arrives on do not log (the Client is silent by
	// design) and because an operator reads it after the fact, on a node that
	// may have been restarted since.
	LeaseRefused string `json:"lease_refused,omitempty"`

	path string
	mu   sync.Mutex
}

// LoadState reads a complete state file: one the install flow has finished.
func LoadState(path string) (*State, error) {
	s, err := loadRaw(path)
	if err != nil {
		return nil, err
	}
	if len(s.NodeSignSeed) != ed25519.SeedSize || len(s.PanelSignPub) != ed25519.PublicKeySize || s.NodeUUID == "" {
		return nil, errors.New("clusteragent: state is incomplete (enrolment not finished)")
	}
	return s, nil
}

func loadRaw(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("clusteragent: state %s: %w", path, err)
	}
	s.path = path
	return &s, nil
}

// NewState returns a state that Save writes to path.
func NewState(path string) *State { return &State{path: path} }

// Save writes the state atomically (temp file, fsync, rename), mode 0600.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *State) saveLocked() error {
	sort.Slice(s.Epochs, func(i, j int) bool { return s.Epochs[i].Epoch > s.Epochs[j].Epoch }) // newest first
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// SignKey is the node's Ed25519 key.
func (s *State) SignKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(s.NodeSignSeed) }

// AddEpoch records a newly issued epoch and keeps at most the two newest,
// matching MAIN, which never holds more than a node's current and next epoch.
func (s *State) AddEpoch(e Epoch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Epoch{e}
	for _, old := range s.Epochs {
		if old.Epoch != e.Epoch {
			out = append(out, old)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch > out[j].Epoch })
	if len(out) > 2 {
		out = out[:2]
	}
	s.Epochs = out
}
