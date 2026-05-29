// Additive `.evidence`-bundle export tests (2026-05-29).
//
// These are the "trial-ledger is a REAL consumer, not a library" proof,
// mirroring Folio's handlers_audit_evidence_test.go and bias-audit's
// evidence_test.go. The load-bearing test
// (TestExportEvidence_EndToEnd_FullVerifyPasses) takes REAL audit-trail
// rows (appended through the production Append path) → exports a .evidence
// bundle via the production export path → runs the limitless-evidence-bundle
// repo's OWN full verify chain (KAT-1 + content-hash + Mirror-Mark) over it
// → asserts PASS. That round trip is exactly the Phase-2 acceptance test
// SPEC.md §10 names for a consumer.
//
// They also pin the additive contract: placeholder corpus → refuse (a
// .evidence bundle has no meaningful unsigned form); the export is read-only
// over the ledger; and the existing per-row ledger behaviour
// (CanonicalBytes / Append / VerifyAll wire format) is byte-for-byte
// unchanged.

package auditledger

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davly/limitless-evidence-bundle/pkg/evidence"
	"github.com/davly/trial-ledger/internal/mirrormark"
)

// realCorpusKey returns a deterministic NON-placeholder corpus + key so the
// emitted bundle cold-verifies. The 0xC4 fill matches the value Folio's
// auditMarkerForTest and bias-audit's realCorpusKey use, keeping the harness
// recognisable across the three consumers.
func realCorpusKey() ([sha256.Size]byte, []byte) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0xC4
	}
	return corpus, []byte("iik_test_TRIAL_LEDGER_evidence")
}

// signedLedger returns a ledger backed by a real (non-placeholder) marker
// and seeded — through the production Append path — with a few
// representative audit-trail rows, so the exported bundle covers real data
// (not an empty trail). NewMirrorMarker leaves the placeholder flags false,
// so this marker is treated as production-backed by the export path.
func signedLedger(t *testing.T) (*Ledger, [sha256.Size]byte, []byte, time.Time) {
	t.Helper()
	corpus, key := realCorpusKey()
	l := NewLedger(mirrormark.NewMirrorMarker(corpus, key))
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	create := validInput()
	create.Action = ActionCreate
	create.TrialID = "NCT06000001"
	if _, err := l.Append(create); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	sign := validInput()
	sign.Action = ActionSign
	sign.TrialID = "NCT06000001"
	sign.Actor = "investigator-bob"
	if _, err := l.Append(sign); err != nil {
		t.Fatalf("seed sign: %v", err)
	}

	other := validInput()
	other.Action = ActionModify
	other.TrialID = "NCT06000002"
	if _, err := l.Append(other); err != nil {
		t.Fatalf("seed other-trial: %v", err)
	}

	return l, corpus, key, now
}

// TestExportEvidence_EndToEnd_FullVerifyPasses is the load-bearing proof.
// Real audit-trail rows → production export path → bundle → evidence-repo
// ModeFull verify (KAT + content-hash + Mirror-Mark) → PASS.
func TestExportEvidence_EndToEnd_FullVerifyPasses(t *testing.T) {
	l, _, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}
	if len(export.Bundle) == 0 {
		t.Fatal("empty bundle in export")
	}
	if !strings.HasPrefix(string(export.Bundle), "LIMITLESS-EVIDENCE-v1\n") {
		head := string(export.Bundle)
		if len(head) > 40 {
			head = head[:40]
		}
		t.Fatalf("bundle missing v1 magic header; got %q", head)
	}

	// THE PROOF: run the evidence-bundle repo's own full verify chain over the
	// produced bundle, using the exact payload bytes the export carried and the
	// key the ledger signed under. This is the cold-verify a regulator runs.
	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key)
	if res.Class != "PASS" {
		t.Fatalf("evidence full-verify did NOT pass: class=%s verdict=%s failures=%v",
			res.Class, res.Verdict, res.Failures)
	}
	if !res.KAT1Verified || !res.ContentHashVerified || !res.MirrorMarkVerified {
		t.Fatalf("not all chain steps verified: %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit_code 0 on PASS, got %d", res.ExitCode)
	}
	if res.Domain != evidenceDomain {
		t.Fatalf("bundle domain = %q, want %q", res.Domain, evidenceDomain)
	}

	// The payload must actually carry the seeded rows (not an empty export).
	var payload LedgerEvidencePayload
	if err := json.Unmarshal(export.PayloadBytes, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 3 {
		t.Fatalf("expected 3 exported rows (3 seeded), got %d", payload.Count)
	}
	if payload.Count != len(payload.Records) {
		t.Fatalf("Count (%d) != len(Records) (%d)", payload.Count, len(payload.Records))
	}
	if payload.PayloadVersion != EvidencePayloadVersion {
		t.Fatalf("payload version = %q, want %q", payload.PayloadVersion, EvidencePayloadVersion)
	}
	// The FDA 21 CFR Part 11 regime must be stamped (the regulator-story field).
	if payload.RegulatoryRegime != EvidenceRegulatoryRegime {
		t.Fatalf("payload regulatoryRegime = %q, want %q", payload.RegulatoryRegime, EvidenceRegulatoryRegime)
	}
	if !strings.Contains(payload.RegulatoryRegime, "21 CFR Part 11") {
		t.Fatalf("regulatoryRegime should name 21 CFR Part 11; got %q", payload.RegulatoryRegime)
	}
	// Each exported row must still carry its per-row Mirror-Mark — the bundle
	// envelope does not replace per-row cold-verify.
	for i, r := range payload.Records {
		if r.MirrorMark == "" {
			t.Fatalf("exported row %d has empty per-row MirrorMark", i)
		}
	}
	// Records must be in canonical ascending-ID (append) order.
	for i := 1; i < len(payload.Records); i++ {
		if payload.Records[i-1].ID >= payload.Records[i].ID {
			t.Fatalf("exported rows not ID-ascending at %d: %d >= %d", i, payload.Records[i-1].ID, payload.Records[i].ID)
		}
	}
}

// TestExportEvidence_PayloadBytesAreByteExact pins the byte-determinism
// contract: the export's payload bytes are the EXACT input the content-hash +
// mark were derived over. Verifying with those bytes passes; we additionally
// confirm the envelope-level Mark re-derives over them with the ledger's own
// (corpus, key).
func TestExportEvidence_PayloadBytesAreByteExact(t *testing.T) {
	l, corpus, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key)
	if res.Class != "PASS" {
		t.Fatalf("verify with export payload bytes failed: %s/%s", res.Class, res.Verdict)
	}

	// Independently re-derive the envelope-level Mirror-Mark over the export's
	// payload bytes with a fresh package-level mirrormark.Verify against
	// (corpus, payload, key). It must match export.Mark — proving the served
	// payload bytes are exactly what was signed.
	if ok, verr := mirrormark.Verify(export.Mark, corpus, export.PayloadBytes, key); !ok {
		t.Fatalf("envelope mark does not re-derive over export payload bytes: %v", verr)
	}
}

// TestExportEvidence_DetectsPayloadTamper — editing the exported payload
// breaks the content-hash step. The forensic property that makes the bundle
// worth emitting.
func TestExportEvidence_DetectsPayloadTamper(t *testing.T) {
	l, _, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	// Tamper: flip a stable field in the payload bytes.
	tampered := strings.Replace(string(export.PayloadBytes), `"payloadVersion":"v1"`, `"payloadVersion":"v2"`, 1)
	if tampered == string(export.PayloadBytes) {
		t.Fatal("test setup: could not tamper payload")
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, []byte(tampered), key)
	if res.Class != "FAIL" {
		t.Fatalf("expected FAIL for tampered payload, got %s", res.Class)
	}
	if res.Verdict != "ErrContentHashMismatch" {
		t.Fatalf("expected ErrContentHashMismatch, got %s", res.Verdict)
	}
}

// TestExportEvidence_DetectsWrongKey — a regulator holding the wrong key sees
// the Mirror-Mark step fail (content-hash still passes, since the payload is
// unmodified). Confirms the bundle binds trial-ledger's specific signing key.
func TestExportEvidence_DetectsWrongKey(t *testing.T) {
	l, _, _, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, []byte("iik_test_WRONG_KEY"))
	if res.Class != "FAIL" {
		t.Fatalf("expected FAIL for wrong key, got %s (verdict=%s)", res.Class, res.Verdict)
	}
	if res.ContentHashVerified != true {
		t.Fatalf("content-hash should still verify (payload unchanged); got %v", res.ContentHashVerified)
	}
	if res.MirrorMarkVerified {
		t.Fatal("Mirror-Mark must NOT verify under the wrong key")
	}
}

// TestExportEvidence_PlaceholderCorpus_Refuses — the additive contract.
// A ledger whose marker is running on a placeholder corpus refuses to export
// (a .evidence bundle has no meaningful unsigned form). Mirrors Folio's
// no-marker → 503 and bias-audit's placeholder-corpus refusal.
//
// A placeholder-corpus marker is produced by NewMirrorMarkerFromEnv with the
// corpus-path env var unset (the only way usingPlaceholderCorpus is set).
func TestExportEvidence_PlaceholderCorpus_Refuses(t *testing.T) {
	// Force the placeholder path: clear the corpus-path env var so the marker
	// boots with usingPlaceholderCorpus = true. t.Setenv restores afterwards.
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "iik_test_TRIAL_LEDGER_placeholder")

	marker := mirrormark.NewMirrorMarkerFromEnv()
	if corpus, _ := marker.UsingPlaceholders(); !corpus {
		t.Fatal("test setup: marker should be placeholder-corpus backed")
	}
	l := NewLedger(marker)
	if _, err := l.Append(validInput()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := l.ExportEvidenceSnapshot(EvidenceScope{}, time.Now().UTC())
	if err != ErrEvidenceNoCorpus {
		t.Fatalf("placeholder corpus: got %v, want ErrEvidenceNoCorpus", err)
	}
}

// TestExportEvidence_ScopeFilters — the scope narrows the export to a trial
// and/or action, the subject reflects it, and the filtered bundle still
// cold-verifies.
func TestExportEvidence_ScopeFilters(t *testing.T) {
	l, _, key, now := signedLedger(t)

	// Trial scope: only NCT06000001 rows (2 of the 3 seeded).
	export, err := l.ExportEvidenceSnapshot(EvidenceScope{Trial: "NCT06000001"}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot trial: %v", err)
	}
	var payload LedgerEvidencePayload
	if err := json.Unmarshal(export.PayloadBytes, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 2 {
		t.Fatalf("trial scope: got %d rows, want 2", payload.Count)
	}
	for _, r := range payload.Records {
		if r.TrialID != "NCT06000001" {
			t.Fatalf("trial scope leaked a non-matching row: %q", r.TrialID)
		}
	}
	if payload.TrialFilter != "NCT06000001" {
		t.Fatalf("payload TrialFilter = %q, want NCT06000001", payload.TrialFilter)
	}
	if !strings.Contains(payload.Subject, "trial=NCT06000001") {
		t.Fatalf("subject does not reflect trial filter: %q", payload.Subject)
	}
	if res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("trial-scoped bundle verify failed: %s/%s", res.Class, res.Verdict)
	}

	// Trial + Action intersection: NCT06000001 AND esig.sign (1 row).
	export2, err := l.ExportEvidenceSnapshot(EvidenceScope{Trial: "NCT06000001", Action: ActionSign}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot trial+action: %v", err)
	}
	var payload2 LedgerEvidencePayload
	if err := json.Unmarshal(export2.PayloadBytes, &payload2); err != nil {
		t.Fatalf("decode payload2: %v", err)
	}
	if payload2.Count != 1 {
		t.Fatalf("trial+action scope: got %d rows, want 1", payload2.Count)
	}
	if payload2.Records[0].Action != ActionSign {
		t.Fatalf("trial+action scope wrong action: %q", payload2.Records[0].Action)
	}
	if !strings.Contains(payload2.Subject, "action="+string(ActionSign)) {
		t.Fatalf("subject does not reflect action filter: %q", payload2.Subject)
	}
	if res := evidence.Verify(export2.Bundle, evidence.ModeFull, export2.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("trial+action-scoped bundle verify failed: %s/%s", res.Class, res.Verdict)
	}
}

// TestExportEvidence_EmptyLedgerVerifies — an export over a ledger with a real
// corpus but no rows still produces a valid (empty-slice) bundle. The JSON
// must carry `[]`, not `null`, so a regulator re-marshalling reproduces
// identical bytes.
func TestExportEvidence_EmptyLedgerVerifies(t *testing.T) {
	corpus, key := realCorpusKey()
	l := NewLedger(mirrormark.NewMirrorMarker(corpus, key))
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot empty: %v", err)
	}
	if !strings.Contains(string(export.PayloadBytes), `"records":[]`) {
		t.Fatalf("empty ledger payload must carry records:[] not null; got %s", export.PayloadBytes)
	}
	if res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("empty-ledger bundle verify failed: %s/%s", res.Class, res.Verdict)
	}
}

// TestExportEvidence_Deterministic — the same ledger + scope + timestamp
// yields byte-identical bundles + payloads across calls (the property a
// regulator relies on to reproduce the cold-verify input). Re-exports the
// SAME ledger (rows already stamped), so the only varying input would be a
// non-determinism bug in the export path.
func TestExportEvidence_Deterministic(t *testing.T) {
	l, _, _, now := signedLedger(t)

	first, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	for i := 0; i < 16; i++ {
		got, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
		if err != nil {
			t.Fatalf("iter %d export: %v", i, err)
		}
		if string(got.Bundle) != string(first.Bundle) {
			t.Fatalf("iter %d: non-deterministic bundle bytes", i)
		}
		if string(got.PayloadBytes) != string(first.PayloadBytes) {
			t.Fatalf("iter %d: non-deterministic payload bytes", i)
		}
		if got.Mark != first.Mark {
			t.Fatalf("iter %d: non-deterministic mark", i)
		}
	}
}

// TestExportEvidence_ExistingLedgerBehaviourUnchanged — the additive
// guarantee. The evidence-export path must NOT perturb the pre-existing
// per-row ledger behaviour: an export over the ledger leaves the ledger's
// observable state (length, rows, per-row Marks, VerifyAll) byte-for-byte
// unchanged, and the per-row CanonicalBytes + Mirror-Mark wire format is
// independent of the envelope the bundle binds.
func TestExportEvidence_ExistingLedgerBehaviourUnchanged(t *testing.T) {
	l, corpus, key, now := signedLedger(t)

	// Snapshot the ledger's observable state BEFORE the export.
	lenBefore := l.Len()
	rowsBefore := l.AllSorted()
	marksBefore := make([]string, len(rowsBefore))
	canonBefore := make([]string, len(rowsBefore))
	for i, r := range rowsBefore {
		marksBefore[i] = r.MirrorMark
		canonBefore[i] = string(r.CanonicalBytes())
	}
	// The whole-trail cold-verify must pass before (unchanged baseline).
	validBefore, totalBefore, errBefore := l.VerifyAll(corpus, key)
	if errBefore != nil || validBefore != totalBefore || totalBefore != lenBefore {
		t.Fatalf("pre-export VerifyAll baseline wrong: valid=%d total=%d len=%d err=%v", validBefore, totalBefore, lenBefore, errBefore)
	}

	// Run the export.
	if _, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now); err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	// AFTER: length, rows, marks, canonical bytes, and whole-trail verify all
	// unchanged.
	if l.Len() != lenBefore {
		t.Fatalf("ledger Len changed by export: %d -> %d", lenBefore, l.Len())
	}
	rowsAfter := l.AllSorted()
	if len(rowsAfter) != len(rowsBefore) {
		t.Fatalf("row count changed by export: %d -> %d", len(rowsBefore), len(rowsAfter))
	}
	for i, r := range rowsAfter {
		if r.MirrorMark != marksBefore[i] {
			t.Fatalf("row %d per-row MirrorMark changed by export:\n  before: %q\n  after:  %q", i, marksBefore[i], r.MirrorMark)
		}
		if got := string(r.CanonicalBytes()); got != canonBefore[i] {
			t.Fatalf("row %d CanonicalBytes changed by export:\n  before: %q\n  after:  %q", i, canonBefore[i], got)
		}
		// And the per-row Mark must still independently re-derive via the
		// package-level mirrormark.Verify with the ledger's (corpus, key) —
		// the envelope-level mark must not have disturbed the per-row format.
		if ok, err := mirrormark.Verify(r.MirrorMark, corpus, r.CanonicalBytes(), key); !ok {
			t.Fatalf("post-export per-row mirrormark.Verify row %d: %v", i, err)
		}
	}
	// Whole-trail cold-verify still passes identically after the export.
	validAfter, totalAfter, errAfter := l.VerifyAll(corpus, key)
	if errAfter != nil || validAfter != validBefore || totalAfter != totalBefore {
		t.Fatalf("post-export VerifyAll changed: valid %d->%d total %d->%d err=%v", validBefore, validAfter, totalBefore, totalAfter, errAfter)
	}
}
