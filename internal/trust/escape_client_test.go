package trust

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClient_Decide_HappyPath confirms MHRA-envelope ships verbatim
// and the response is parsed end-to-end.
func TestClient_Decide_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/escape" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}

		var got EscapeRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("server: decode body: %v", err)
		}

		if got.AuditEnvelope.ReviewerClass != ReviewerClassMHRA {
			t.Errorf("reviewer_class = %q, want %q",
				got.AuditEnvelope.ReviewerClass, ReviewerClassMHRA)
		}
		if got.AuditEnvelope.StatutoryRef != StatutoryRefMHRAClinicalTrialsReg {
			t.Errorf("statutory_ref = %q, want %q",
				got.AuditEnvelope.StatutoryRef, StatutoryRefMHRAClinicalTrialsReg)
		}
		if got.AuditEnvelope.Jurisdiction != "UK_MHRA" {
			t.Errorf("jurisdiction = %q, want UK_MHRA",
				got.AuditEnvelope.Jurisdiction)
		}
		if got.AuditEnvelope.CohortRole != CohortRoleTrialLedger {
			t.Errorf("cohort_role = %q, want %q",
				got.AuditEnvelope.CohortRole, CohortRoleTrialLedger)
		}

		resp := EscapeResponse{
			Verdict:       "escape",
			Score:         0.82,
			Factors:       FactorScores{Novelty: 0.85, Staleness: 0.8, ContextMismatch: 0.8, QualityDecay: 0.85},
			AuditEnvelope: got.AuditEnvelope,
			MirrorMark:    "lore@v1:test-mark-trial-ledger",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 2*time.Second)
	req := EscapeRequest{
		SituationHash:  "trial-ledger-amend-001",
		CurrentContext: "protocol_amendment:phase3",
		AuditEnvelope:  MHRAEnvelope("UK_MHRA"),
	}

	resp, err := c.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if resp.Verdict != "escape" {
		t.Errorf("Verdict = %q, want escape", resp.Verdict)
	}
	if resp.MirrorMark != "lore@v1:test-mark-trial-ledger" {
		t.Errorf("MirrorMark = %q, want test mark", resp.MirrorMark)
	}
}

// TestClient_Decide_FailClosed_ServerError confirms R175 — when
// escape-service returns 5xx, the LOCAL halt decision must stand
// (surfaced via ErrEscapeServiceUnreachable).
func TestClient_Decide_FailClosed_ServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "synthetic outage", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "trial-ledger-amend-fail",
		AuditEnvelope: MHRAEnvelope("UK_MHRA"),
	})
	if err == nil {
		t.Fatal("expected error on 5xx, got nil — R175 fail-closed violated")
	}
	if !errors.Is(err, ErrEscapeServiceUnreachable) {
		t.Errorf("err = %v, want ErrEscapeServiceUnreachable", err)
	}
}

// TestClient_Decide_FailClosed_EmptyMark covers the empty-mark edge.
func TestClient_Decide_FailClosed_EmptyMark(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"verdict":"escape","score":0.9,"mirror_mark":""}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "trial-ledger-empty-mark",
		AuditEnvelope: MHRAEnvelope("UK_MHRA"),
	})
	if err == nil {
		t.Fatal("expected error on empty mark, got nil")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("err = %v, want ErrInvalidResponse", err)
	}
}

// TestClient_Decide_SanitizeShim_RejectsNaN pins the IMP-T2-12 Phase 3
// safety-critical sanitize shim. NaN in Observation.Quality MUST be
// rejected flagship-side; no wire bytes leave trial-ledger.
func TestClient_Decide_SanitizeShim_RejectsNaN(t *testing.T) {
	t.Parallel()

	// Server SHOULD NEVER be hit — sanitize fires first.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"verdict":"stay","mirror_mark":"x"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "trial-ledger-nan",
		AuditEnvelope: MHRAEnvelope("UK_MHRA"),
		ObservationHistory: []Observation{
			{Hash: "obs1", Timestamp: 1, Quality: math.NaN(), Context: "phase3"},
		},
	})
	if err == nil {
		t.Fatal("expected sanitize-shim error on NaN, got nil")
	}
	if !errors.Is(err, ErrSafetyCriticalInputRejected) {
		t.Errorf("err = %v, want ErrSafetyCriticalInputRejected", err)
	}
	if calls != 0 {
		t.Errorf("escape-service hit %d times; sanitize-shim should refuse before wire", calls)
	}
}

// TestClient_Decide_SanitizeShim_RejectsInf pins Inf rejection.
func TestClient_Decide_SanitizeShim_RejectsInf(t *testing.T) {
	t.Parallel()

	c := NewClient("http://unused.example", 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "trial-ledger-inf",
		AuditEnvelope: MHRAEnvelope("UK_MHRA"),
		ObservationHistory: []Observation{
			{Hash: "obs1", Timestamp: 1, Quality: math.Inf(1), Context: "phase3"},
		},
	})
	if err == nil {
		t.Fatal("expected sanitize-shim error on +Inf, got nil")
	}
	if !errors.Is(err, ErrSafetyCriticalInputRejected) {
		t.Errorf("err = %v, want ErrSafetyCriticalInputRejected", err)
	}
}

// TestMHRAEnvelope_PopulatesDiscriminators pins the canonical MHRA
// discriminators verbatim — change-detector test.
func TestMHRAEnvelope_PopulatesDiscriminators(t *testing.T) {
	t.Parallel()

	env := MHRAEnvelope("UK_MHRA")
	if env.ReviewerClass != ReviewerClassMHRA {
		t.Errorf("ReviewerClass = %q, want %q", env.ReviewerClass, ReviewerClassMHRA)
	}
	if env.StatutoryRef != StatutoryRefMHRAClinicalTrialsReg {
		t.Errorf("StatutoryRef = %q, want %q", env.StatutoryRef, StatutoryRefMHRAClinicalTrialsReg)
	}
	if env.Jurisdiction != "UK_MHRA" {
		t.Errorf("Jurisdiction = %q, want UK_MHRA", env.Jurisdiction)
	}
	if env.CohortRole != CohortRoleTrialLedger {
		t.Errorf("CohortRole = %q, want %q", env.CohortRole, CohortRoleTrialLedger)
	}
	if strings.TrimSpace(env.LastReviewed) == "" {
		t.Error("LastReviewed must be non-empty (escape-service rejects)")
	}
	if _, err := time.Parse(time.RFC3339, env.LastReviewed); err != nil {
		t.Errorf("LastReviewed not RFC3339: %v", err)
	}
}
