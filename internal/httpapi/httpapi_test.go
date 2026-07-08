package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/davly/trial-ledger/internal/auditledger"
	"github.com/davly/trial-ledger/internal/mirrormark"
)

const testServiceToken = "svc_token_trial_ledger_unit_test"

// realLedger builds a ledger over a deterministic, NON-placeholder
// (corpus, key) so the Mirror-Mark stamped by Append cold-verifies in
// the test — that round-trip is the proof the REAL signing engine ran,
// not a stub that echoed a fixed string.
func realLedger() (*auditledger.Ledger, [sha256.Size]byte, []byte) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x5A
	}
	key := []byte("iik_httpapi_unit_test_trial_ledger")
	return auditledger.NewLedger(mirrormark.NewMirrorMarker(corpus, key)), corpus, key
}

func appendBody(t *testing.T) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"Action":    "ecr.create",
		"Actor":     "investigator-alice",
		"TrialID":   "NCT06000001",
		"SubjectID": "S-007",
		"RecordRef": "ecrf/visit-3/page-2",
		"Detail":    "subject visit 3 vitals submitted",
	})
	if err != nil {
		t.Fatalf("marshal append body: %v", err)
	}
	return bytes.NewReader(b)
}

// TestAppend_Reachable_WithToken_InvokesRealEngine is the load-bearing
// STEP-1.5 test: the Nexus-facing capability route is REACHABLE with the
// service token (200, not redirected/blocked) AND the REAL auditledger
// engine is invoked (the returned Record carries a genuine monotonic
// ID, the X-User-Id provenance stamped into the row, and a Mirror-Mark
// that cold-verifies via mirrormark.Verify — a stub could not produce
// a mark that re-derives against the real (corpus, key)).
func TestAppend_Reachable_WithToken_InvokesRealEngine(t *testing.T) {
	ledger, corpus, key := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", appendBody(t))
	req.Header.Set(HeaderServiceToken, testServiceToken)
	req.Header.Set(HeaderUserID, "consumer-clinical-edc-42")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("reachability FAILED: want 200 with valid service token, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var got auditledger.Record
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode Record: %v (body=%s)", err, rec.Body.String())
	}

	// Real-engine signals: monotonic ID allocated (engine, not echo),
	// computer-generated timestamp set, action preserved.
	if got.ID == 0 {
		t.Errorf("Record.ID is 0 — real engine allocates a monotonic ID from 1")
	}
	if got.At.IsZero() {
		t.Errorf("Record.At is zero — real engine sets a computer-generated UTC timestamp")
	}
	if got.Action != auditledger.ActionCreate {
		t.Errorf("Record.Action = %q, want %q", got.Action, auditledger.ActionCreate)
	}

	// PROVENANCE baked into the cold-verifiable row.
	if got.OriginatorID != "consumer-clinical-edc-42" {
		t.Errorf("Record.OriginatorID = %q, want the X-User-Id value stamped in", got.OriginatorID)
	}

	// THE proof the real signing engine ran: the Mirror-Mark must
	// cold-verify against the row's canonical bytes and the (corpus,
	// key) the ledger was built with. A stub returning a canned string
	// cannot satisfy this.
	if got.MirrorMark == "" || !strings.HasPrefix(got.MirrorMark, "lore@v1:") {
		t.Fatalf("Record.MirrorMark missing/ill-formed: %q", got.MirrorMark)
	}
	ok, err := mirrormark.Verify(got.MirrorMark, corpus, got.CanonicalBytes(), key)
	if !ok || err != nil {
		t.Fatalf("Mirror-Mark did NOT cold-verify (engine not really invoked?): ok=%v err=%v", ok, err)
	}

	// And the row really landed in the real ledger (state mutated).
	if ledger.Len() != 1 {
		t.Errorf("ledger.Len() = %d, want 1 — the append must have hit the real ledger", ledger.Len())
	}
}

// TestAppend_RejectsWithoutToken proves the route is fail-closed: no
// service token ⇒ 401, and the engine is never touched.
func TestAppend_RejectsWithoutToken(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", appendBody(t))
	req.Header.Set(HeaderUserID, "consumer-x") // provenance present, token absent
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without service token, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if ledger.Len() != 0 {
		t.Errorf("engine was invoked despite missing token — ledger.Len()=%d, want 0", ledger.Len())
	}
}

// TestAppend_RejectsWrongToken — a non-matching token ⇒ 401.
func TestAppend_RejectsWrongToken(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", appendBody(t))
	req.Header.Set(HeaderServiceToken, "the-wrong-token")
	req.Header.Set(HeaderUserID, "consumer-x")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with wrong service token, got %d", rec.Code)
	}
}

// TestAppend_EmptyConfiguredToken_FailsClosed — the critical fail-open
// guard: a server configured with an EMPTY token must reject EVERY
// request (even one presenting an empty token header), never fail-open.
func TestAppend_EmptyConfiguredToken_FailsClosed(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, "").Handler() // empty configured token

	// Present an empty token header — a fail-open bug would match
	// ""=="" and let it through. Fail-closed must 401.
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", appendBody(t))
	req.Header.Set(HeaderServiceToken, "")
	req.Header.Set(HeaderUserID, "consumer-x")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("FAIL-OPEN BUG: empty configured token must 401 everything, got %d", rec.Code)
	}
	if ledger.Len() != 0 {
		t.Errorf("engine invoked under empty-token fail-closed — ledger.Len()=%d, want 0", ledger.Len())
	}
}

// TestAppend_RequiresProvenance — valid token but no X-User-Id ⇒ 400,
// and the engine is not touched (an unattributed audit row is refused).
func TestAppend_RequiresProvenance(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", appendBody(t))
	req.Header.Set(HeaderServiceToken, testServiceToken)
	// no X-User-Id
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when X-User-Id absent, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if ledger.Len() != 0 {
		t.Errorf("engine invoked despite missing provenance — ledger.Len()=%d, want 0", ledger.Len())
	}
}

// TestAppend_RejectsInvalidAction — the real engine's closed-enum
// (R115) validation surfaces as a 400 through the transport (further
// proof the request reaches the real Append, which is the only place
// that enforces the AuditAction enum).
func TestAppend_RejectsInvalidAction(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	body := bytes.NewReader([]byte(`{"Action":"bogus.action","Actor":"a","TrialID":"T","RecordRef":"r"}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", body)
	req.Header.Set(HeaderServiceToken, testServiceToken)
	req.Header.Set(HeaderUserID, "consumer-x")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for closed-enum violation, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// recordingLedger is a double that proves the handler forwards the
// decoded + provenance-stamped AppendInput into the Ledger interface
// unchanged (the header value wins over any body-supplied originator).
type recordingLedger struct{ last auditledger.AppendInput }

func (r *recordingLedger) Append(in auditledger.AppendInput) (auditledger.Record, error) {
	r.last = in
	return auditledger.Record{ID: 1, Action: in.Action, MirrorMark: "lore@v1:stub"}, nil
}

// TestAppend_HeaderOriginatorWinsOverBody — a consumer cannot spoof
// attribution: the X-User-Id header is authoritative and overwrites any
// originatorId smuggled in the body.
func TestAppend_HeaderOriginatorWinsOverBody(t *testing.T) {
	rl := &recordingLedger{}
	h := NewServer(rl, testServiceToken).Handler()

	// DisallowUnknownFields would reject an unknown JSON key, so the
	// only way a body could carry an originator is the real field name.
	body := bytes.NewReader([]byte(`{"Action":"ecr.view","Actor":"a","TrialID":"T","RecordRef":"r","OriginatorID":"SPOOFED"}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", body)
	req.Header.Set(HeaderServiceToken, testServiceToken)
	req.Header.Set(HeaderUserID, "real-originator")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if rl.last.OriginatorID != "real-originator" {
		t.Errorf("header must win: OriginatorID = %q, want %q", rl.last.OriginatorID, "real-originator")
	}
}

// TestHealthz_Unauthenticated — liveness is reachable without a token.
func TestHealthz_Unauthenticated(t *testing.T) {
	ledger, _, _ := realLedger()
	h := NewServer(ledger, testServiceToken).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz want 200, got %d", rec.Code)
	}
}
