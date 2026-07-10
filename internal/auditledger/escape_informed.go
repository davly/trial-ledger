// escape_informed.go — 2026-07-10 full-wiring: FIRST REAL CONSUMER of
// the internal/trust escape-service client (IMP-T2-12 Phase 3 wire; the
// R145.B net/http carve-out for internal/trust was pre-approved for
// exactly this client — this file itself stays HTTP-free and only
// composes the carved-out wrapper).
//
// What this file adds:
//
//	EscapeInformedLedger — a decorator over *Ledger (implements the
//	same Append contract, so httpapi.Server takes it unchanged) that,
//	for TRUST-BOUNDARY actions only (esig.sign / esig.withdraw /
//	ecr.delete / ecr.lock — the §11.10(e) events the IMP-T2-12 Phase 3
//	client doc names), consults the cohort-canonical escape-service
//	`/v1/escape` BEFORE the append and CONSUMES the verdict by landing
//	it INSIDE the cold-verifiable row:
//
//	  - ObservationHistory is the trial's REAL prior audit rows (most
//	    recent first, capped), so escape-service's Novelty / Staleness
//	    / ContextMismatch factors genuinely operate over the trial's
//	    activity — a first-ever signature on a trial reads novel; a
//	    signature over a long-idle record reads stale.
//	  - On success, Record.EscapeVerdict + Record.EscapeMark are
//	    stamped and COVERED by the row's own Mirror-Mark: an MHRA /
//	    EMA / FDA inspector re-deriving the trail sees exactly which
//	    trust-boundary events the cohort trust plane flagged
//	    ("escape") and can cold-verify escape-service's counterpart
//	    stamp via lore-mark-verify — the sponsor's evidence pack, the
//	    client's original purpose.
//
//	DELIBERATELY NO CONTROL-FLOW GATE: unlike counsel (verdict
//	tighten) and moneycheck (disposition escalation), a §11.10(e)
//	audit trail's conservative action is to RECORD — an audit
//	primitive that refuses appends on an advisory verdict would
//	itself be a compliance failure. The verdict informs the EVIDENCE
//	(what the trail says about the event), never blocks the append.
//
//	If the decider is nil, or the action is not a trust-boundary
//	action, or escape-service is unreachable / 5xx / malformed, the
//	append proceeds exactly as today with both fields empty (R175
//	fail-closed: the LOCAL behaviour stands; the stamp did not land;
//	the trail is never blocked by an audit-wire outage). DARK BY
//	DEFAULT: the decorator is only constructed when
//	TRIAL_LEDGER_ESCAPE_SERVICE_URL is set (cmd/trial-ledger-server).
package auditledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/davly/trial-ledger/internal/trust"
)

// escapeObservationCap bounds how many prior audit rows ship as
// observation history per call (most recent first). Keeps the wire
// body small on long-running trials while still feeding the factors
// a real activity window.
const escapeObservationCap = 64

// EscapeDecider is the seam interface satisfied by *trust.Client.
// Kept to the client's exact one-method signature so tests can
// substitute an httptest-backed client without net access.
type EscapeDecider interface {
	Decide(ctx context.Context, req trust.EscapeRequest) (*trust.EscapeResponse, error)
}

// EscapeInformedLedger decorates a *Ledger with the escape-service
// consult described in the file header. It intentionally exposes the
// full read surface of the inner ledger (List / AllSorted / SelfCheck
// / ...) via embedding; only Append is intercepted.
type EscapeInformedLedger struct {
	*Ledger
	decider EscapeDecider
}

// NewEscapeInformedLedger wraps inner. A nil decider yields a
// decorator whose Append is byte-identical to inner.Append (the dark
// default); callers may therefore wrap unconditionally.
func NewEscapeInformedLedger(inner *Ledger, decider EscapeDecider) *EscapeInformedLedger {
	return &EscapeInformedLedger{Ledger: inner, decider: decider}
}

// Append consults escape-service for trust-boundary actions (when
// armed) and appends via the inner ledger. See the file header for the
// full contract; the inner Append's validation + Mirror-Mark stamping
// are unchanged.
func (l *EscapeInformedLedger) Append(in AppendInput) (Record, error) {
	verdict, mark := "", ""
	if l.decider != nil && IsTrustBoundaryAction(in.Action) {
		if ext, err := l.decider.Decide(context.Background(), l.buildEscapeRequest(in)); err == nil {
			verdict, mark = ext.Verdict, ext.MirrorMark
		}
		// err != nil: R175 fail-closed — the LOCAL behaviour stands
		// (append proceeds, fields stay empty, stamp did not land).
		// The §11.10(e) trail must never be blocked by the audit wire.
	}
	return l.Ledger.appendWithEscape(in, verdict, mark)
}

// IsTrustBoundaryAction reports whether the action is one of the
// §11.10(e) trust-boundary events the IMP-T2-12 Phase 3 client doc
// names as escape-service-stampable (signature lifecycle + destructive
// / submission-gating record events). Routine data entry (ecr.create /
// ecr.modify / ecr.view) never leaves the process.
func IsTrustBoundaryAction(a AuditAction) bool {
	switch a {
	case ActionSign, ActionWithdrawSignature, ActionDelete, ActionLock:
		return true
	}
	return false
}

// buildEscapeRequest projects the pending append + the trial's real
// audit history onto the escape-service wire shape.
func (l *EscapeInformedLedger) buildEscapeRequest(in AppendInput) trust.EscapeRequest {
	ctxStr := "auditledger|" + string(in.Action) + "|trial=" + in.TrialID

	prior := l.Ledger.List(in.TrialID, "", escapeObservationCap)
	obs := make([]trust.Observation, 0, len(prior))
	for _, r := range prior {
		obs = append(obs, trust.Observation{
			Hash:      sha256Hex(r.TrialID + "|" + string(r.Action) + "|" + r.RecordRef),
			Timestamp: r.At.Unix(),
			// Every ledger row is Mirror-Marked by construction (R175
			// — no unmarked code path), so prior observations carry
			// full quality; decay is escape-service's job.
			Quality: 1.0,
			Context: "auditledger|" + string(r.Action) + "|trial=" + r.TrialID,
		})
	}

	return trust.EscapeRequest{
		SituationHash:      sha256Hex(in.TrialID + "|" + string(in.Action) + "|" + in.RecordRef + "|" + in.RecordHash),
		CurrentContext:     ctxStr,
		ObservationHistory: obs,
		AuditEnvelope: trust.AuditEnvelope{
			ReviewerClass: trust.ReviewerClassMHRA,
			StatutoryRef:  trust.StatutoryRefMHRAClinicalTrialsReg,
			Jurisdiction:  "UK_MHRA",
			CohortRole:    trust.CohortRoleTrialLedger,
			LastReviewed:  time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
