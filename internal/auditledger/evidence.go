// Additive `.evidence`-bundle export path (2026-05-29).
//
// What this file is
// -----------------
// The THIRD production wire-in of the limitless-evidence-bundle SPEC v1
// format (apps/limitless-evidence-bundle), after Folio (#1) and bias-audit
// (#2). It makes trial-ledger the third real consumer of the regulator-
// readable `.evidence` artefact: a read-only export that streams a snapshot
// of the append-only FDA 21 CFR Part 11 §11.10(e) audit trail as a single
// cold-verifiable `.evidence` bundle (KAT-1 anchor + content-hash + L43
// Mirror-Mark over the exported rows).
//
// Why this is a high-value regulator story: trial-ledger's audit trail is
// the §11.10(e) "computer-generated, time-stamped audit trail" an FDA
// reviewer (or an EU CTR / MHRA inspector) must be able to independently
// re-derive. A `.evidence` bundle is exactly that: a self-contained,
// keyless artefact the regulator cold-verifies with their own copy of the
// (lore corpus, key) — no trust in trial-ledger's running service required.
//
// Why this is purely ADDITIVE (R145-strict / no-silent-behaviour-changes)
// ----------------------------------------------------------------------
//   - It adds NO method that mutates ledger state. ExportEvidenceSnapshot
//     reads via the existing defensive-copy accessors (AllSorted / List)
//     and never appends, deletes, or re-stamps a row.
//   - It does NOT change Record.CanonicalBytes, Append, Sign, or VerifyAll
//     — the per-row Mirror-Mark wire format is byte-for-byte unchanged
//     (pinned by TestExportEvidence_ExistingLedgerBehaviourUnchanged and
//     the pre-existing auditledger_test.go suite).
//   - The bundle binds a SEPARATE envelope (LedgerEvidencePayload) whose
//     bytes are distinct from any single row's CanonicalBytes; existing
//     per-row cold-verify (VerifyAll) is untouched.
//
// Canonical Phase-2 path (SPEC.md §10): trial-ledger computes the
// MIRROR_MARK with its OWN in-process signer (the ledger's bound
// MirrorMarker over the canonical envelope bytes) and hands it to the
// public evidence.PackWithMark — the evidence-bundle repo never sees
// trial-ledger's HMAC key, so its stdlib-only verifier stays the
// independent cold-verify path. This mirrors Folio's conduit.MirrorMarker
// → evidence.PackWithMark flow and bias-audit's ledger-as-signer flow
// exactly; trial-ledger's signer is the auditledger.Ledger's bound
// *mirrormark.MirrorMarker (the object that owns the corpus + key).
//
// Byte-determinism (load-bearing)
// -------------------------------
// The envelope is marshalled EXACTLY ONCE (buildLedgerEvidencePayload) and
// the resulting bytes feed BOTH marker.Sign() AND evidence.PackWithMark
// (whose CONTENT_HASH = SHA-256 of those same bytes). A regulator
// reproduces the bytes by json.Marshal-ing the same envelope shape (Go's
// encoding/json is field-declaration-order deterministic). The returned
// EvidenceExport carries the bundle AND those exact payload bytes so the
// cold-verify input is reproduced verbatim — no re-marshal, no field-
// ordering risk.
//
// Self-check before return (SPEC.md §10 self-check contract)
// ----------------------------------------------------------
// ExportEvidenceSnapshot self-verifies the freshly-packed bundle in two
// parts that together cover the full chain, WITHOUT exposing the key:
//
//	(1) evidence.Verify(ModeOffline) — the evidence-repo verifier's
//	    structural-integrity + KAT-1 anchor checks (no key needed).
//	(2) the marker's own VerifyMark over the canonical payload with the
//	    ledger's (corpus, key) — proves the mark binds the exported bytes
//	    + corpus. CONTENT_HASH is SHA-256(payload) set by PackWithMark
//	    from these same bytes, so a passing mark over the same payload
//	    pins the content-hash too.
//
// A bundle that does not self-verify is never returned (the caller gets an
// error instead) — a malformed/non-verifying artefact never escapes.
//
// Stdlib-only beyond the evidence-bundle module: crypto/sha256 +
// encoding/json + encoding/hex + time, plus the existing
// internal/mirrormark and the public
// github.com/davly/limitless-evidence-bundle/pkg/evidence.
package auditledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/davly/limitless-evidence-bundle/pkg/evidence"
)

// EvidencePayloadVersion is the wire-format tag for the LedgerEvidencePayload
// envelope this path signs. Bumping it signals a backwards-incompatible
// payload shape to downstream verifiers (who compare on string equality, so
// an unknown version fails closed). Distinct from the bundle's own
// LIMITLESS-EVIDENCE-v1 wire tag — this versions the trial-ledger payload
// shape INSIDE the bundle.
const EvidencePayloadVersion = "v1"

// evidenceDomain is the closed METADATA domain label for trial-ledger audit-
// trail evidence bundles. A regulator portal can branch on this without
// parsing the payload.
const evidenceDomain = "trial-ledger.auditledger"

// EvidenceRegulatoryRegime is the regulatory regime the exported audit
// trail attests to, stamped into the envelope so a bundle is self-
// describing about WHICH regime it serves. trial-ledger's audit trail is
// the FDA 21 CFR Part 11 §11.10(e) "computer-generated, time-stamped audit
// trail"; the same trail is also probative for EU CTR / MHRA inspection,
// but the load-bearing regime the canonical-bytes shape was designed for is
// named here.
const EvidenceRegulatoryRegime = "FDA 21 CFR Part 11 (e-records/e-signatures); 11.10(e) audit trail"

// ErrEvidenceNoCorpus is returned by ExportEvidenceSnapshot when the
// ledger's marker is running on a placeholder corpus (no real lore corpus
// wired). A `.evidence` bundle's whole value is that it cold-verifies
// against a real lore corpus; emitting one stamped with a placeholder
// corpus would yield an artefact that CANNOT cold-verify (worse than honest
// silence), so the export refuses. This mirrors Folio's marker-absent → 503
// contract and bias-audit's placeholder-corpus refusal (a `.evidence`
// bundle has no meaningful degraded form). Production hosts inject a real
// corpus via TRIAL_LEDGER_LORE_CORPUS_SHA_PATH; dev ledgers using the
// placeholder corpus get this error.
var ErrEvidenceNoCorpus = errors.New("auditledger: cannot export .evidence bundle with placeholder corpus SHA (marker not wired to a real lore corpus)")

// LedgerEvidencePayload is the canonical envelope whose JSON bytes the
// `.evidence` bundle binds (CONTENT_HASH + MIRROR_MARK). It is
// self-describing about the slice of the audit trail it covers so a
// regulator holding only the bundle + payload knows WHAT was exported, not
// just that SOMETHING was.
//
// Field order is load-bearing: Go's encoding/json marshals struct fields in
// declaration order, and the cold-verify recipe re-marshals this exact
// shape. Adding a field later is wire-additive only if it sits at the end
// AND uses omitempty (so previously-issued payloads re-marshal to identical
// bytes).
type LedgerEvidencePayload struct {
	// PayloadVersion lets a recipient branch on shape before anything else.
	PayloadVersion string `json:"payloadVersion"`
	// RegulatoryRegime names the regime this audit trail attests to (FDA 21
	// CFR Part 11). Self-describing so a regulator portal can route the
	// bundle without parsing rows.
	RegulatoryRegime string `json:"regulatoryRegime"`
	// Subject identifies what this evidence covers (the audit-trail slice).
	Subject string `json:"subject"`
	// ExportedAt is the UTC instant the export was produced.
	ExportedAt time.Time `json:"exportedAt"`
	// TrialFilter echoes the trial scope applied (empty = all trials).
	TrialFilter string `json:"trialFilter"`
	// ActionFilter echoes the AuditAction scope applied (empty = all actions).
	ActionFilter AuditAction `json:"actionFilter"`
	// Count is len(Records) — a cheap completeness cross-check for the
	// auditor that does not require counting the array.
	Count int `json:"count"`
	// Records is the exported audit-trail rows, in ID-ascending order (the
	// canonical append order the ledger's AllSorted accessor returns). Each
	// row still carries its per-row Mirror-Mark (the Record.MirrorMark
	// field), so a regulator can ALSO cold-verify each row individually via
	// VerifyAll, independent of this bundle's envelope-level mark.
	Records []Record `json:"records"`
}

// EvidenceExport pairs the cold-verify artefact (Bundle) with the exact
// bytes it binds (PayloadBytes) so a consumer can verify offline without
// re-deriving the payload. Mirrors Folio's AuditEvidenceResponse and
// bias-audit's EvidenceExport shape.
type EvidenceExport struct {
	// Bundle is the `.evidence` bundle text (LIMITLESS-EVIDENCE-v1 wire
	// format): KAT-1 anchor + content-hash + Mirror-Mark over PayloadBytes.
	Bundle []byte
	// PayloadBytes is the EXACT canonical JSON of the LedgerEvidencePayload
	// the bundle binds, emitted verbatim so the consumer's cold-verify input
	// is byte-identical to what trial-ledger signed.
	PayloadBytes []byte
	// Mark is the envelope-level v1 Mirror-Mark trial-ledger computed over
	// PayloadBytes with the ledger's own (corpus, key). Returned so a caller
	// can self-check the Mirror-Mark step without the HMAC key ever leaving
	// the marker; also the value the bundle's MIRROR_MARK section carries.
	Mark string
}

// EvidenceScope selects which audit-trail rows the export covers. The zero
// value (both fields empty) exports the entire trail. A non-empty Trial
// scopes to one trial; a non-empty Action scopes to one AuditAction; both
// narrow to the intersection. Scoping is read-only — it reuses the existing
// defensive-copy accessors and never mutates the ledger.
//
// The scope axes (Trial + Action) mirror the ledger's existing
// List(trialID, action, n) read surface, so no new read path is introduced.
type EvidenceScope struct {
	// Trial, when non-empty, restricts the export to rows for this trial.
	Trial string
	// Action, when non-empty, restricts the export to rows of this AuditAction.
	Action AuditAction
}

// ExportEvidenceSnapshot builds a regulator-readable `.evidence` bundle from
// a read-only snapshot of the audit trail, scoped by `scope`. It is the
// canonical Phase-2 consumer path (SPEC.md §10): trial-ledger signs the
// envelope with its OWN in-process signer (the ledger's bound MirrorMarker)
// and hands the mark to evidence.PackWithMark, so the evidence-bundle repo
// never sees the ledger's key.
//
// `now` is the export timestamp stamped into the envelope (injected for
// deterministic tests; production passes time.Now().UTC()).
//
// Returns ErrEvidenceNoCorpus when the marker is running on a placeholder
// corpus (a bundle would not cold-verify — fail loud rather than emit an
// unverifiable artefact). Returns a wrapped error if pack or the pre-emit
// self-check fails. On success the returned bundle is guaranteed to pass
// evidence.Verify(ModeFull, PayloadBytes, key) for the ledger's own key.
//
// READ-ONLY: this method appends/deletes/re-stamps nothing. It reads through
// the existing defensive-copy accessors, so a concurrent Append is safe and
// the ledger's observable state is unchanged by an export.
func (l *Ledger) ExportEvidenceSnapshot(scope EvidenceScope, now time.Time) (EvidenceExport, error) {
	// A placeholder corpus cannot produce a cold-verifiable bundle. Refuse
	// rather than emit an artefact that fails a regulator's re-verify
	// (Folio's marker-absent → 503 analogue; bias-audit's placeholder-corpus
	// refusal). The marker is the authority on whether it is placeholder-
	// backed — there is no non-marked code path (R175), so the marker is
	// always non-nil here.
	corpusPlaceholder, _ := l.marker.UsingPlaceholders()
	if corpusPlaceholder {
		return EvidenceExport{}, ErrEvidenceNoCorpus
	}

	records := l.snapshotForScope(scope)

	payload, payloadBytes, err := buildLedgerEvidencePayload(scope, records, now)
	if err != nil {
		// json.Marshal on the fixed envelope shape is structurally
		// unreachable; wrapped for forward-compat.
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence payload marshal: %w", err)
	}

	// MIRROR_MARK via trial-ledger's OWN in-process signer over the
	// canonical bytes (the canonical Phase-2 path). evidence.PackWithMark
	// takes this mark verbatim — the evidence-bundle repo never sees the
	// ledger's key.
	mark := l.marker.Sign(payloadBytes)

	corpus := l.marker.CorpusSHA()
	in := evidence.PackInput{
		CorpusSHAHex: hex.EncodeToString(corpus[:]),
		Payload:      payloadBytes,
		Meta: evidence.Metadata{
			CreatedAt:   payload.ExportedAt.Format(time.RFC3339),
			Creator:     "trial-ledger auditledger evidence " + EvidencePayloadVersion,
			Subject:     payload.Subject,
			Domain:      evidenceDomain,
			CorpusLabel: "infrastructure/lore (trial-ledger-bound corpus)",
		},
	}
	raw, err := evidence.PackWithMark(in, mark)
	if err != nil {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence pack: %w", err)
	}

	// Self-check before return (SPEC.md §10), in two parts covering the full
	// chain without exposing the key:
	//   (1) structural-integrity + KAT-1 anchor (no key needed)
	offline := evidence.Verify(raw, evidence.ModeOffline, nil, nil)
	if offline.Class != "PASS" {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence self-verify (offline) did not pass: verdict=%s failures=%v", offline.Verdict, offline.Failures)
	}
	//   (2) Mirror-Mark over the canonical payload, via the marker's own
	//       (corpus, key) — re-derives the mark, pinning content + corpus.
	if ok, verr := l.marker.VerifyMark(mark, payloadBytes); !ok {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence self-verify (mark) did not pass: %w", verr)
	}

	return EvidenceExport{
		Bundle:       raw,
		PayloadBytes: payloadBytes,
		Mark:         mark,
	}, nil
}

// snapshotForScope returns a read-only, defensively-copied slice of audit-
// trail rows matching scope in ID-ascending (canonical append) order,
// reusing the existing accessors so no new read path is introduced.
// Both-empty scope = the whole trail.
//
// AllSorted / List both already return defensive copies, so the returned
// slice is detached from ledger state; narrowing in-slice afterwards is
// safe.
func (l *Ledger) snapshotForScope(scope EvidenceScope) []Record {
	// Whole-trail (and trial-only) cases come straight from AllSorted /
	// List, which already return ID-ordered defensive copies. List returns
	// most-recent-first, so we re-sort to canonical ascending order for a
	// stable, append-order envelope regardless of scope.
	var rows []Record
	switch {
	case scope.Trial == "" && scope.Action == "":
		return l.AllSorted()
	default:
		// List filters by (trial, action) using the existing read surface;
		// n=0 means "all matching". Either axis empty is a wildcard there.
		rows = l.List(scope.Trial, scope.Action, 0)
	}
	// List returns most-recent-first; re-order ascending by ID so the
	// envelope is in canonical append order (matches the whole-trail path).
	sortByIDAsc(rows)
	return rows
}

// sortByIDAsc orders rows ascending by ID in place. Kept local (rather than
// re-using sort.Slice inline at the call site) so the canonical ordering is
// stated once.
func sortByIDAsc(rows []Record) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j-1].ID > rows[j].ID; j-- {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}

// buildLedgerEvidencePayload assembles the envelope and marshals it ONCE.
// Returns (envelope, canonicalBytes, err). The canonical bytes are the
// single source of truth for both the Mirror-Mark and the bundle's
// CONTENT_HASH — they MUST NOT be re-marshalled separately downstream.
//
// Pure over its inputs (no ledger reads — the caller passes the already-read
// records), so it is unit-testable in isolation.
func buildLedgerEvidencePayload(scope EvidenceScope, records []Record, now time.Time) (LedgerEvidencePayload, []byte, error) {
	// Normalise a nil slice to an empty slice so the JSON is `[]` not
	// `null` — a regulator re-marshalling the same envelope must reproduce
	// identical bytes regardless of whether the slice happened to be empty.
	if records == nil {
		records = []Record{}
	}
	payload := LedgerEvidencePayload{
		PayloadVersion:   EvidencePayloadVersion,
		RegulatoryRegime: EvidenceRegulatoryRegime,
		Subject:          evidenceSubject(scope),
		ExportedAt:       now.UTC(),
		TrialFilter:      scope.Trial,
		ActionFilter:     scope.Action,
		Count:            len(records),
		Records:          records,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return LedgerEvidencePayload{}, nil, err
	}
	return payload, b, nil
}

// evidenceSubject builds the bundle subject string from the scope, so the
// bundle is self-describing about which slice it covers.
func evidenceSubject(scope EvidenceScope) string {
	switch {
	case scope.Trial != "" && scope.Action != "":
		return "trial-ledger:audittrail:trial=" + scope.Trial + ":action=" + string(scope.Action)
	case scope.Trial != "":
		return "trial-ledger:audittrail:trial=" + scope.Trial
	case scope.Action != "":
		return "trial-ledger:audittrail:action=" + string(scope.Action)
	default:
		return "trial-ledger:audittrail:all"
	}
}

// compile-time guard: the evidence path depends on sha256.Size matching the
// marker's corpus width. If the cohort corpus width ever changes this fails
// to build rather than silently emitting a wrong-width CORPUS_SHA.
var _ = [1]struct{}{}[sha256.Size-32]
