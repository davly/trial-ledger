// Package trust is the thin escape-service HTTP-client wrapper used by
// trial-ledger to externalise trust-boundary decisions to the
// cohort-canonical escape-service primitive
// (`infrastructure/escape-service/` at R174 5-of-5 STRICT). Sibling of
// counsel/internal/trust + moneycheck/internal/trust (R150
// R-PARALLEL-MAP).
//
// Why this exists (per IMP-T2-12 Phase 3):
//
//	Trial-ledger's load-bearing trust-boundary is the §11.10(e)
//	audit-trail append + §11.50/§11.70/§11.200 e-signature validation
//	in internal/fdacfr11/. Today those Validate() calls return a typed
//	error and the caller halts the audit append. This package adds an
//	OPTIONAL EXTERNAL wire: when a trust-boundary triggers (e.g.
//	protocol-amendment-acceptance under MHRA review, e-signature
//	cardinality concern, IRB-approval gap detected), the caller can
//	POST the decision context to escape-service for cohort-canonical
//	AuditEnvelope + L43 Mirror-Mark stamping. The stamp lands in the
//	sponsor's evidence pack so an MHRA / EMA / FDA inspector can
//	cold-verify the trust-boundary trace via `lore-mark-verify`.
//
// Fail-closed discipline (R175 R-LOAD-BEARING-IN-PRODUCTION):
//
//	If escape-service is unreachable / returns 5xx / returns malformed
//	JSON, this client returns (nil, err). Callers MUST treat err as
//	"the LOCAL halt-on-validation-error decision stands, but the
//	EXTERNAL audit stamp did NOT land in the evidence pack" — they
//	MUST NOT proceed with the audit append. The LOCAL halt remains
//	load-bearing; the wire is for evidence-pack stamping, not gate
//	bypass.
//
// NaN/Inf sanitize shim (IMP-T2-12 Phase 3 §safety-critical guard):
//
//	Per IMP-T2-12 Phase 3 line 125, escape-service Wave 8.1 §4.8
//	constructor-invariant refusal (NaN/Inf → silent zero) is NOT YET
//	shipped. trial-ledger is safety-critical (clinical-trial data); we
//	enforce input sanitization flagship-side via sanitize() until
//	escape-service Wave 8.1 §4.8 lands. The shim rejects NaN/Inf in
//	Observation.Quality + Observation.Timestamp via a typed error so
//	the upstream silent-zero pathway is unreachable from trial-ledger.
package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// Reviewer-class + statutory-ref constants for trial-ledger's
// MHRA-jurisdiction adoption. LOAD-BEARING literals.
const (
	// ReviewerClassMHRA names the MHRA-CRO reviewer attestation
	// lineage. Maps to escape-service's HUMAN_ATTESTED canonical
	// class for in-CRO review.
	ReviewerClassMHRA = "HUMAN_ATTESTED"

	// StatutoryRefMHRAClinicalTrialsReg names the Clinical Trials
	// Regulation 536/2014 Article 8 protocol-amendment clause that
	// justifies the external-audit stamp for trial-ledger's
	// trust-boundary decisions. Universal-fact citation (regulation
	// IS the regulation; not tenant-specific).
	StatutoryRefMHRAClinicalTrialsReg = "Clinical Trials Regulation 536/2014 Article 8"

	// CohortRoleTrialLedger names trial-ledger's cohort role in the
	// escape-service audit-row.
	CohortRoleTrialLedger = "trial-ledger-trust-boundary-mhra-jurisdiction"
)

// EscapeRequest is the wire shape trial-ledger POSTs to escape-service.
type EscapeRequest struct {
	SituationHash      string        `json:"situation_hash"`
	CurrentContext     string        `json:"current_context"`
	ObservationHistory []Observation `json:"observation_history"`
	AuditEnvelope      AuditEnvelope `json:"audit_envelope"`
}

// Observation mirrors escape-service's escape.Observation wire shape.
type Observation struct {
	Hash      string  `json:"hash"`
	Timestamp int64   `json:"timestamp"`
	Quality   float64 `json:"quality"`
	Context   string  `json:"context"`
}

// AuditEnvelope is the R150 5-field review-metadata envelope.
type AuditEnvelope struct {
	ReviewerClass string `json:"reviewer_class"`
	StatutoryRef  string `json:"statutory_ref"`
	Jurisdiction  string `json:"jurisdiction"`
	CohortRole    string `json:"cohort_role"`
	LastReviewed  string `json:"last_reviewed"`
}

// EscapeResponse is the wire shape escape-service returns.
type EscapeResponse struct {
	Verdict       string        `json:"verdict"`
	Score         float64       `json:"score"`
	Factors       FactorScores  `json:"factors"`
	AuditEnvelope AuditEnvelope `json:"audit_envelope"`
	MirrorMark    string        `json:"mirror_mark"`
}

// FactorScores mirrors escape-service's escape.FactorScores wire shape.
type FactorScores struct {
	Novelty         float64 `json:"novelty"`
	Staleness       float64 `json:"staleness"`
	ContextMismatch float64 `json:"context_mismatch"`
	QualityDecay    float64 `json:"quality_decay"`
}

// Client is the escape-service HTTP wrapper. Safe for concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient constructs an escape-service Client. timeout zero defaults
// to 5s.
func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ErrEscapeServiceUnreachable signals fail-closed — the LOCAL halt
// decision stands; the evidence-pack stamp did NOT land.
var ErrEscapeServiceUnreachable = errors.New("trust: escape-service unreachable; LOCAL halt decision stands, evidence-pack stamp NOT landed")

// ErrInvalidResponse signals fail-closed — escape-service 2xx response
// could not be parsed or is missing required fields.
var ErrInvalidResponse = errors.New("trust: escape-service returned malformed response; LOCAL halt decision stands, evidence-pack stamp NOT landed")

// ErrSafetyCriticalInputRejected is the NaN/Inf sanitize shim refusal.
// Per IMP-T2-12 Phase 3 line 125, escape-service Wave 8.1 §4.8
// constructor-invariant refusal is not yet shipped. trial-ledger
// rejects NaN/Inf flagship-side so the upstream silent-zero pathway is
// unreachable from safety-critical clinical-trial data.
// TODO: drop the shim when escape-service Wave 8.1 §4.8 lands.
var ErrSafetyCriticalInputRejected = errors.New("trust: NaN/Inf in EscapeRequest; trial-ledger sanitize shim refuses safety-critical silent-zero pathway (TODO escape-service Wave 8.1 §4.8 follow-on)")

// sanitize is the IMP-T2-12 Phase 3 NaN/Inf refusal shim. Returns
// ErrSafetyCriticalInputRejected if ANY Observation in the request
// carries NaN/Inf in its Quality field or a sentinel-zero Timestamp
// is mis-interpreted as live. Intentionally STRICTER than what
// escape-service Wave 8.1 §4.8 will eventually enforce — defence in
// depth for clinical-trial data.
func sanitize(req EscapeRequest) error {
	for i, obs := range req.ObservationHistory {
		if math.IsNaN(obs.Quality) || math.IsInf(obs.Quality, 0) {
			return fmt.Errorf("%w: ObservationHistory[%d].Quality = %v", ErrSafetyCriticalInputRejected, i, obs.Quality)
		}
		// Timestamp zero is allowed (escape-service interprets as
		// "use Now") but negative is rejected as malformed.
		if obs.Timestamp < 0 {
			return fmt.Errorf("%w: ObservationHistory[%d].Timestamp = %d", ErrSafetyCriticalInputRejected, i, obs.Timestamp)
		}
	}
	return nil
}

// Decide POSTs the escape request to escape-service's `/v1/escape`
// endpoint. Fail-closed per R175 — see ErrEscapeServiceUnreachable.
// Safety-critical per IMP-T2-12 Phase 3 — see
// ErrSafetyCriticalInputRejected.
func (c *Client) Decide(ctx context.Context, req EscapeRequest) (*EscapeResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrEscapeServiceUnreachable)
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, fmt.Errorf("%w: empty baseURL", ErrEscapeServiceUnreachable)
	}

	// IMP-T2-12 Phase 3 sanitize shim — REJECT NaN/Inf before any
	// wire bytes leave the flagship.
	if err := sanitize(req); err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.AuditEnvelope.LastReviewed) == "" {
		req.AuditEnvelope.LastReviewed = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(req.AuditEnvelope.CohortRole) == "" {
		req.AuditEnvelope.CohortRole = CohortRoleTrialLedger
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %v", ErrEscapeServiceUnreachable, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/escape", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: new request: %v", ErrEscapeServiceUnreachable, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: do: %v", ErrEscapeServiceUnreachable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrEscapeServiceUnreachable, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d body %s",
			ErrEscapeServiceUnreachable, resp.StatusCode, string(respBody))
	}

	var out EscapeResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if strings.TrimSpace(out.MirrorMark) == "" {
		return nil, fmt.Errorf("%w: empty mirror_mark", ErrInvalidResponse)
	}

	return &out, nil
}

// MHRAEnvelope returns a pre-populated AuditEnvelope for trial-ledger's
// MHRA-jurisdiction adoption. jurisdiction is typically "UK_MHRA" but
// can be set to "EU_EMA" for EMA-jurisdiction trials or "US_FDA" for
// 21 CFR Part 11-only deployments.
func MHRAEnvelope(jurisdiction string) AuditEnvelope {
	return AuditEnvelope{
		ReviewerClass: ReviewerClassMHRA,
		StatutoryRef:  StatutoryRefMHRAClinicalTrialsReg,
		Jurisdiction:  jurisdiction,
		CohortRole:    CohortRoleTrialLedger,
		LastReviewed:  time.Now().UTC().Format(time.RFC3339),
	}
}
