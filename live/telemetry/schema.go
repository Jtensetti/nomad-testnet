// Package telemetry decides what a Nomad process is allowed to say about
// itself.
//
// Operational output is the easiest place to lose the core privacy invariant,
// because nothing about a metric feels like a wire event. A counter named for
// the object a reader wanted, a log line carrying a basin, a crash dump with a
// share in it: each is a private-dependent externally observable record, and
// the invariant does not care that it left through a log file rather than a
// socket.
//
// Two mechanisms, deliberately different in kind. The schema is an allowlist
// over field NAMES, so a new field cannot ship without someone adding it here
// and writing down why it is public. The scanner works over VALUES, so a field
// that is allowed by name but carries something it should not is still caught.
// A name allowlist alone would pass `operator_id: <a reader's object ID>`.
package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Field is one permitted emission field and the reason it may be published.
type Field struct {
	Name string
	Why  string
}

// allowed is the complete set of fields any Nomad process may emit.
//
// Every entry is a quantity whose value is fixed by public protocol state or
// by an adversary's own actions. Nothing here varies with which object a
// reader wanted, which basin a query fell into, or how much anybody published.
var allowed = []Field{
	{"started_at", "process start, a public operational fact"},
	{"updated_at", "emission time, a public operational fact"},
	{"operator_id", "the operator's own published identity; it identifies the operator, never a user"},
	{"topology_digest", "the signed topology this process is serving; public by construction"},
	{"sent", "cells emitted, which is a pure function of the public cadence and uptime"},
	{"received", "datagrams received, which an adversary sets by sending them"},
	{"stored", "cells admitted to the public cache under public replication policy"},
	{"relayed", "work cells relayed under public replication policy"},
	{"cover_sent", "cover cells emitted; with sent, this is the public cadence split"},
	{"wrong_size", "malformed datagrams, an adversary-set quantity"},
	{"unknown_peer", "datagrams from unsigned sources, an adversary-set quantity"},
	{"auth_rejected", "authentication failures, an adversary-set quantity"},
	{"replay_rejected", "replays refused, an adversary-set quantity"},
	{"duplicate", "duplicate cells, an adversary-set quantity"},
	{"queue_dropped", "relay queue overflow under public policy"},
	{"cache_rejected", "cache admission refusals under public policy"},
	{"send_dropped", "emissions lost to a local send failure; host state and an " +
		"adversary's own pressure, never user activity, and the alarm that " +
		"replaced the node stopping"},
	{"health_deferred", "health-file writes that failed; local disk state only"},
	{"last_sent_at", "when the last cell went out; an observer on the link reads " +
		"this off the wire, and it is the liveness signal a node that no longer " +
		"stops on a local failure has to publish instead"},
}

// forbidden names things that must never be emitted even though a developer
// might reasonably reach for them. Each is a real counter that exists in the
// codebase and is deliberately operator-local.
var forbidden = map[string]string{
	"pending":          "airlock occupancy is the count the fixed batch size exists to hide",
	"deposits_pending": "airlock occupancy is the count the fixed batch size exists to hide",
	"dropped_full":     "a full-batch drop count is airlock occupancy by another name",
	"dropped_session":  "a per-session drop count identifies how much one client published",
	"real_deposits":    "the number of real deposits in a batch is the publication volume",
	"queries":          "a query is the private fact the whole system exists to protect",
	"basin":            "a basin is a coarse query and is equally private",
	"object_id":        "which object was wanted is private reader activity",
	"objects_served":   "per-object counts are private reader activity",
	"fragment":         "publication content",
	"plaintext":        "publication or object content",
	"share":            "a threshold share is secret key material",
	"secret":           "secret key material",
	"private_key":      "secret key material",
	"session_key":      "an uplink session key identifies and decrypts a publisher",
	"deposit_id":       "a deposit ID is a per-publisher slot name",
	"reader_id":        "a stable user identifier",
	"client_id":        "a stable user identifier",
}

// ErrFieldNotAllowed reports an emission field that is not on the allowlist.
var ErrFieldNotAllowed = errors.New("emission field is not on the telemetry allowlist")

// Allowed returns the permitted fields, sorted, for documentation and tests.
func Allowed() []Field {
	out := append([]Field(nil), allowed...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func allowedNames() map[string]struct{} {
	names := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		names[field.Name] = struct{}{}
	}
	return names
}

// ValidateEmission parses a JSON emission and rejects any field that is not
// explicitly allowed.
//
// It fails closed on unknown names rather than screening for known-bad ones.
// A denylist would pass every field nobody thought of, and the fields nobody
// thinks of are exactly where private state ends up.
func ValidateEmission(encoded []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return fmt.Errorf("emission is not a JSON object: %w", err)
	}
	names := allowedNames()
	unknown := make([]string, 0)
	for name := range fields {
		if _, ok := names[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		for _, name := range unknown {
			if why, banned := forbidden[name]; banned {
				return fmt.Errorf("%w: %q is explicitly forbidden: %s",
					ErrFieldNotAllowed, name, why)
			}
		}
		return fmt.Errorf("%w: %v (add it to live/telemetry with the reason it is public)",
			ErrFieldNotAllowed, unknown)
	}
	return nil
}

// ForbiddenReason reports why a field name may never be emitted, if it is one
// of the named traps.
func ForbiddenReason(name string) (string, bool) {
	why, banned := forbidden[name]
	return why, banned
}
