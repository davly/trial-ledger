// escape_informed_test.go — pins the 2026-07-10 escape-service wire-in
// contract (escape_informed.go):
//
//	(1) nil decider => Append identical to the bare ledger, fields
//	    empty (DARK default; the decorator may be applied
//	    unconditionally).
//	(2) routine actions (ecr.create/modify/view) NEVER call the wire,
//	    even when armed.
//	(3) trust-boundary action + armed => /v1/escape consulted with the
//	    trial's REAL prior rows as observation history, verdict + mark
//	    stamped in-row and COVERED by the row's own Mirror-Mark
//	    (SelfCheck still green; canonical bytes carry the fields).
//	(4) wire error => append proceeds unchanged, fields empty (R175
//	    fail-closed: the trail is never blocked).
//
// httptest is confined to _test.go (the firewall production scans
// exclude tests); the production package stays HTTP-free.
package auditledger

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/davly/trial-ledger/internal/mirrormark"
	"github.com/davly/trial-ledger/internal/trust"
)

func testMarker() *mirrormark.MirrorMarker {
	var corpus [32]byte
	for i := range corpus {
		corpus[i] = 0xE5
	}
	return mirrormark.NewMirrorMarker(corpus, []byte("iik_test_ESCAPE_INFORMED_NOT_FOR_PRODUCTION"))
}

func signInput() AppendInput {
	return AppendInput{
		Action:     ActionSign,
		Actor:      "investigator-alice",
		TrialID:    "NCT06000001",
		SubjectID:  "S-007",
		RecordRef:  "ecrf/visit-3/page-2",
		RecordHash: strings.Repeat("a", 64),
		Detail:     "investigator review signature",
	}
}

// stubDecider spins an httptest escape-service returning the given
// verdict and hands back a REAL *trust.Client pointed at it, plus a
// call counter — the wire (marshal, POST /v1/escape, sanitize, parse)
// is exercised end-to-end.
func stubDecider(t *testing.T, verdict string, capture *trust.EscapeRequest, calls *int) *trust.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/escape" || r.Method != http.MethodPost {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if calls != nil {
			*calls++
		}
		if capture != nil {
			if err := json.NewDecoder(r.Body).Decode(capture); err != nil {
				t.Errorf("decode request: %v", err)
			}
		}
		_ = json.NewEncoder(w).Encode(trust.EscapeResponse{
			Verdict:    verdict,
			Score:      0.77,
			Factors:    trust.FactorScores{Novelty: 0.9, Staleness: 0.6, ContextMismatch: 0.3, QualityDecay: 0.1},
			MirrorMark: "mm1:tl-test-mark",
		})
	}))
	t.Cleanup(ts.Close)
	return trust.NewClient(ts.URL, 2*time.Second)
}

func TestEscapeInformed_NilDecider_IdenticalDarkAppend(t *testing.T) {
	l := NewEscapeInformedLedger(NewLedger(testMarker()), nil)
	rec, err := l.Append(signInput())
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if rec.EscapeVerdict != "" || rec.EscapeMark != "" {
		t.Fatalf("dark append must not stamp escape fields: %+v", rec)
	}
	// Canonical bytes must be byte-identical to a bare-ledger row shape
	// (omitempty => the new fields do not appear at all).
	if cb := rec.CanonicalBytes(); bytes.Contains(cb, []byte("escapeVerdict")) || bytes.Contains(cb, []byte("escapeMark")) {
		t.Fatalf("dark canonical bytes must not carry the escape keys: %s", cb)
	}
	if _, _, err := l.SelfCheck(); err != nil {
		t.Fatalf("self-check after dark append: %v", err)
	}
}

func TestEscapeInformed_RoutineAction_NeverCallsWire(t *testing.T) {
	calls := 0
	l := NewEscapeInformedLedger(NewLedger(testMarker()), stubDecider(t, "escape", nil, &calls))
	in := signInput()
	in.Action = ActionCreate
	rec, err := l.Append(in)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if calls != 0 {
		t.Fatalf("routine ecr.create must not consult escape-service; got %d calls", calls)
	}
	if rec.EscapeVerdict != "" || rec.EscapeMark != "" {
		t.Fatalf("routine append must not stamp escape fields: %+v", rec)
	}
}

func TestEscapeInformed_TrustBoundaryAction_StampsVerdictInRow(t *testing.T) {
	var req trust.EscapeRequest
	calls := 0
	l := NewEscapeInformedLedger(NewLedger(testMarker()), stubDecider(t, "escape", &req, &calls))

	// Seed real history: two routine rows on the same trial.
	seed := signInput()
	seed.Action = ActionCreate
	if _, err := l.Append(seed); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	seed.Action = ActionModify
	if _, err := l.Append(seed); err != nil {
		t.Fatalf("seed modify: %v", err)
	}

	rec, err := l.Append(signInput())
	if err != nil {
		t.Fatalf("sign append: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one wire call for the esig.sign row; got %d", calls)
	}
	if rec.EscapeVerdict != "escape" || rec.EscapeMark != "mm1:tl-test-mark" {
		t.Fatalf("verdict + mark must be stamped in-row; got %q / %q", rec.EscapeVerdict, rec.EscapeMark)
	}
	// The fields are covered by the row's own Mirror-Mark.
	if cb := rec.CanonicalBytes(); !bytes.Contains(cb, []byte(`"escapeVerdict":"escape"`)) || !bytes.Contains(cb, []byte(`"escapeMark":"mm1:tl-test-mark"`)) {
		t.Fatalf("canonical bytes must carry the stamped fields: %s", cb)
	}
	if _, _, err := l.SelfCheck(); err != nil {
		t.Fatalf("self-check with stamped row: %v", err)
	}
	// Wire-shape: the trial's REAL prior rows fed the factors.
	if len(req.ObservationHistory) != 2 {
		t.Fatalf("observation history must carry the 2 prior rows; got %d", len(req.ObservationHistory))
	}
	if req.SituationHash == "" || !strings.Contains(req.CurrentContext, "esig.sign") || !strings.Contains(req.CurrentContext, "NCT06000001") {
		t.Fatalf("situation hash + context must carry the append context; got %+v", req)
	}
	if req.AuditEnvelope.ReviewerClass != trust.ReviewerClassMHRA || req.AuditEnvelope.Jurisdiction != "UK_MHRA" {
		t.Fatalf("audit envelope must be the MHRA envelope; got %+v", req.AuditEnvelope)
	}
}

func TestEscapeInformed_WireError_AppendProceedsUnstamped(t *testing.T) {
	dead := trust.NewClient("http://127.0.0.1:1", 200*time.Millisecond)
	l := NewEscapeInformedLedger(NewLedger(testMarker()), dead)
	rec, err := l.Append(signInput())
	if err != nil {
		t.Fatalf("append must never be blocked by the audit wire (R175): %v", err)
	}
	if rec.EscapeVerdict != "" || rec.EscapeMark != "" {
		t.Fatalf("wire error must leave fields empty (stamp did not land): %+v", rec)
	}
	if _, _, err := l.SelfCheck(); err != nil {
		t.Fatalf("self-check after fail-closed append: %v", err)
	}
}

func TestIsTrustBoundaryAction_ClosedSet(t *testing.T) {
	want := map[AuditAction]bool{
		ActionSign:              true,
		ActionWithdrawSignature: true,
		ActionDelete:            true,
		ActionLock:              true,
		ActionCreate:            false,
		ActionModify:            false,
		ActionView:              false,
	}
	for a, expect := range want {
		if got := IsTrustBoundaryAction(a); got != expect {
			t.Errorf("IsTrustBoundaryAction(%s) = %v, want %v", a, got, expect)
		}
	}
}
