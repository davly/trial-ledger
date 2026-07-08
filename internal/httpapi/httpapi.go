// Package httpapi is the thin Nexus-facing transport shell over the
// existing internal/auditledger engine. It exposes the top consumer
// capability `audit_trail_append` (Nexus capability namespace) as a
// single fail-closed HTTP endpoint so the Nexus capability-hub can
// route to trial-ledger by capability.
//
// What this package is (and is NOT):
//
//   - It is a TRANSPORT shell only. ALL domain logic lives in
//     internal/auditledger (Append / Mirror-Mark stamp / closed-enum
//     validation). This package adds no business logic; it decodes a
//     request, calls the real ledger, and encodes the real Record.
//   - It is NOT a turn-key 21 CFR Part 11 server. The backing ledger
//     is the same in-memory append-only ring the CLI uses (lost on
//     restart). A production `audit_trail_append` SLA additionally
//     requires the Phase-2 WAL persistence swap — flagged loudly to
//     the operator, never advertised as durable here.
//
// Trust boundary (the load-bearing security contract):
//
//   - The /v1/audit/append route is the Nexus-facing surface. It is
//     mounted OUTSIDE any future app-wide auth group: the ONLY gate is
//     a constant-time X-Nexus-Service-Token check (crypto/subtle).
//     trial-ledger has no cookie/login auth today, so there is no
//     302-redirect-before-token-check hazard (the RubberDuck STEP-1.5
//     finding) — but the route is deliberately structured so the
//     service-token check is the boundary, fail-closed, and would
//     remain so if app-wide auth is added later.
//   - FAIL-CLOSED: an EMPTY configured service token rejects EVERY
//     request with 401 (never fail-open). A wrong/absent token ⇒ 401.
//   - PROVENANCE: X-User-Id is mandatory on the append route; 400 if
//     absent. The originating consumer/user id is stamped INTO the
//     cold-verifiable Mirror-Marked row (auditledger.Record.OriginatorID),
//     so "which consumer originated this audit row" is part of the
//     receipt a regulator re-derives.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"github.com/davly/trial-ledger/internal/auditledger"
)

// HeaderServiceToken is the machine-trust header Nexus sets on every
// call (Nexus <-> trial-ledger shared secret).
const HeaderServiceToken = "X-Nexus-Service-Token"

// HeaderUserID is the provenance header — who originated the request.
// Nexus sets it only after validating the end-user/consumer JWT and
// resolving the user. trial-ledger requires it and stamps it into the
// row.
const HeaderUserID = "X-User-Id"

// maxAppendBody bounds the request body. eCRF JSON can be verbose (the
// CLI uses a 1 MiB scanner buffer); we match that ceiling.
const maxAppendBody = 1 << 20 // 1 MiB

// Ledger is the minimal surface this transport needs from the real
// engine. *auditledger.Ledger satisfies it. Declaring it as an
// interface keeps the handler honest (it can only Append — it cannot
// reach past the engine) and lets a test inject a recording double to
// PROVE the real engine is the thing being invoked.
type Ledger interface {
	Append(in auditledger.AppendInput) (auditledger.Record, error)
}

// Server is the Nexus-facing transport shell. Construct via NewServer
// with a process-lifetime singleton ledger and the configured service
// token.
type Server struct {
	ledger       Ledger
	serviceToken string
}

// NewServer wires the transport over an existing ledger. serviceToken
// is the shared Nexus secret; an empty serviceToken makes the append
// route fail-closed (401 for everything) — the configured-empty case
// is treated as "not provisioned", never as "auth disabled".
func NewServer(ledger Ledger, serviceToken string) *Server {
	return &Server{ledger: ledger, serviceToken: serviceToken}
}

// Handler returns the http.Handler for the Nexus-facing surface.
//
// Routing is deliberately flat (net/http ServeMux, no framework, no
// middleware stack): /v1/healthz is the only unauthenticated route;
// /v1/audit/append is the ONLY capability route and the service-token
// check is its boundary. Mounting the capability route here — not
// inside any wider auth group — is the STEP-1.5 discipline made
// structural: the token check is reached directly, fail-closed.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/audit/append", s.requireServiceToken(s.handleAppend))
	return mux
}

// handleHealthz is an unauthenticated liveness probe. It does NOT touch
// the ledger and reveals nothing scoped — it only reports the transport
// is up. Durability is intentionally NOT asserted here (the backing
// ledger is in-memory; see package doc).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"capability": "audit_trail_append",
	})
}

// requireServiceToken is the fail-closed machine-trust gate. It wraps a
// capability handler and is the entire trust boundary for the
// Nexus-facing route.
//
//   - EMPTY configured token  ⇒ 401 for EVERY request (fail-closed;
//     "not provisioned" is never "auth off").
//   - constant-time compare   ⇒ no timing oracle on the secret.
func (s *Server) requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authOK(r.Header.Get(HeaderServiceToken)) {
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid "+HeaderServiceToken)
			return
		}
		next(w, r)
	}
}

// authOK constant-time compares the presented token to the configured
// one. An empty configured token is fail-closed: nothing authenticates.
func (s *Server) authOK(presented string) bool {
	if s.serviceToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.serviceToken)) == 1
}

// appendResponse is the wire shape Nexus's TrialLedgerProvider maps. It
// is exactly the engine's Record (which already carries id / at /
// action / ... / mirrorMark, and now originatorId). We return the
// Record directly rather than a hand-rolled DTO so the cold-verifiable
// canonical bytes are exactly what the engine produced.
type appendResponse = auditledger.Record

// handleAppend is the audit_trail_append capability handler. It is a
// pure transport shim: decode AppendInput, require provenance, stamp
// the originator, call the REAL ledger.Append, encode the REAL Record.
func (s *Server) handleAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// PROVENANCE (mandatory): refuse an unattributed append. trial-ledger
	// trusts data scope to nothing but the Nexus-forwarded originator.
	userID := r.Header.Get(HeaderUserID)
	if userID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing "+HeaderUserID+" (provenance required)")
		return
	}

	var in auditledger.AppendInput
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAppendBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid AppendInput JSON: "+err.Error())
		return
	}

	// Stamp the originating consumer/user id INTO the cold-verifiable
	// row. This makes provenance part of the Mirror-Marked receipt. The
	// header is authoritative — a body-supplied OriginatorID (if any) is
	// overwritten so the consumer cannot spoof attribution.
	in.OriginatorID = userID

	rec, err := s.ledger.Append(in)
	if err != nil {
		// auditledger.Append only returns validation errors (closed-enum
		// action, required-field) — all client faults ⇒ 400.
		writeJSONError(w, http.StatusBadRequest, "append rejected: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, appendResponse(rec))
}

// writeJSON encodes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError emits a uniform { "error": "..." } body.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
