// Package auditledger — the namesake append-only FDA 21 CFR Part 11
// audit-trail primitive for trial-ledger.
//
// What this package is:
//
//	The §11.10(e) audit-trail primitive — every clinical-trial
//	operator entry / action / signature that creates / modifies /
//	deletes an electronic record gets ONE append to this ledger.
//	The append is monotonic-ID + UTC-timestamp + actor + record-
//	hash + Mirror-Mark.
//
// Why Mirror-Mark is WIRE-LOAD-BEARING from inception
// (R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION saturator):
//
//	`Append` requires a non-nil `mirrormark.MirrorMarker` —
//	there is no non-marked code path through this primitive.
//	An audit-record without a Mirror-Mark is not 21 CFR Part 11
//	§11.10(e) cold-verifiable; trial-ledger's reason for being is
//	that property. The R175 saturator pin in this package's test
//	suite confirms the production caller has no off-switch.
//
// What this package is NOT:
//
//	A turn-key 21 CFR Part 11 system. The shipped surface is an
//	IN-MEMORY APPEND-ONLY RING. Production deployments MUST swap in
//	a WAL-SQLite or WAL-PostgreSQL persistence layer (the
//	canonical-shape ports byte-for-byte; the swap is R145-strict
//	additive). The honest-defaults `TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED`
//	advisory makes this explicit.
//
// Cohort:
//
//	Byte-aligned with ledger/internal/audit + folio/internal/audit +
//	casino/internal/audit. The discriminator literals (AuditAction)
//	are trial-ledger-specific; the ENVELOPE shape (ID + At + Class +
//	Actor + Subject + Detail + MirrorMark) is cohort-byte-aligned.
package auditledger

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davly/trial-ledger/internal/mirrormark"
)

// AuditAction is the closed-enum 21 CFR Part 11 §11.10(e) operator-
// action discriminator. R115 SINGLE-ENUM-REJECTION-OUTCOME pattern:
// free-form action strings would defeat the §11.10(e) "actions that
// create, modify, or delete electronic records" requirement that
// processing categories be pre-declared.
//
// String literals are LOAD-BEARING for cross-substrate parity — when
// trial-ledger-rust ships (R169 sibling), it MUST use the same wire
// literals so a cold-verify regulator pipeline sees byte-identical
// audit-trail JSON regardless of which substrate emitted it.
type AuditAction string

const (
	// ActionCreate — operator created a new electronic record.
	ActionCreate AuditAction = "ecr.create"

	// ActionModify — operator modified an existing electronic record.
	// §11.10(e) requires this be independently recorded.
	ActionModify AuditAction = "ecr.modify"

	// ActionDelete — operator deleted (or marked-deleted) an
	// electronic record. §11.10(e) audit-trail invariant requires
	// the original record + the delete event both survive.
	ActionDelete AuditAction = "ecr.delete"

	// ActionSign — investigator / sponsor / monitor signed an
	// electronic record per §11.50 + §11.70 + §11.200.
	ActionSign AuditAction = "esig.sign"

	// ActionWithdrawSignature — signature was withdrawn. Per
	// §11.10(e) audit-trail invariant the original signature
	// + the withdrawal event both survive.
	ActionWithdrawSignature AuditAction = "esig.withdraw"

	// ActionView — operator viewed a record. Required for §11.10(e)
	// disclosure-trail completeness when the deployment chooses to
	// audit reads (optional but recommended for FDA inspections).
	ActionView AuditAction = "ecr.view"

	// ActionLock — operator locked a record (database-lock event
	// preceding regulator submission).
	ActionLock AuditAction = "ecr.lock"
)

// AllAuditActions returns the closed-enum 7-tuple. Used by tests +
// firewall pins.
func AllAuditActions() []AuditAction {
	return []AuditAction{
		ActionCreate,
		ActionModify,
		ActionDelete,
		ActionSign,
		ActionWithdrawSignature,
		ActionView,
		ActionLock,
	}
}

// ErrNilMarker is the R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION
// guard error. NewLedger and Append refuse to operate without a
// configured MirrorMarker — there is no non-marked code path.
var ErrNilMarker = errors.New("auditledger: MirrorMarker is required (R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION)")

// Record is one row in the append-only audit-trail. Field order is
// load-bearing for canonical-bytes derivation: encoding/json marshals
// struct fields in declaration order so a regulator re-deriving the
// canonical bytes reproduces the same wire layout the emitter
// produced.
type Record struct {
	ID         uint64      `json:"id"`
	At         time.Time   `json:"at"`
	Action     AuditAction `json:"action"`
	Actor      string      `json:"actor"`
	TrialID    string      `json:"trialId"`
	SubjectID  string      `json:"subjectId,omitempty"`
	RecordRef  string      `json:"recordRef"`
	RecordHash string      `json:"recordHash,omitempty"`
	Detail     string      `json:"detail,omitempty"`

	// OriginatorID is the provenance field — the identity of the
	// consumer/end-user that originated this audit row, as resolved by
	// the Nexus capability-hub and forwarded via the X-User-Id header.
	//
	// ADDITIVE + WIRE-SAFE (R145-strict): declared at the end of the
	// data fields with `omitempty`, so a Record produced WITHOUT an
	// originator (the CLI path, every pre-existing caller) marshals to
	// byte-identical canonical bytes — the existing KAT pins and
	// cold-verify recipe are unchanged. When the Nexus producer stamps
	// it, the originating consumer becomes part of the Mirror-Marked,
	// cold-verifiable receipt: a regulator re-deriving the row sees who
	// originated it, not just what action occurred.
	OriginatorID string `json:"originatorId,omitempty"`

	// EscapeVerdict / EscapeMark — 2026-07-10 escape-service wire-in
	// additive fields (see escape_informed.go). Populated ONLY when the
	// row was appended through an armed EscapeInformedLedger for a
	// trust-boundary action AND the cohort-canonical escape-service
	// call succeeded: EscapeVerdict is the /v1/escape verdict
	// (stay / borderline / escape) and EscapeMark is escape-service's
	// own L43 Mirror-Mark over the MHRA AuditEnvelope it stamped
	// (cold-verifiable via lore-mark-verify — IMP-T2-12 Phase 3).
	//
	// ADDITIVE + WIRE-SAFE (R145-strict), same recipe as OriginatorID:
	// declared with `omitempty` ABOVE MirrorMark, so (a) every row
	// appended dark marshals to byte-identical canonical bytes as
	// before, and (b) when populated the fields are COVERED by this
	// row's own Mirror-Mark — an inspector re-deriving the row sees
	// which trust-boundary events the cohort trust plane flagged, and
	// cannot be shown a stripped copy without the mark failing.
	//
	// SPOOF-PROOF: these fields are deliberately NOT on AppendInput —
	// neither the Nexus wire (DisallowUnknownFields rejects them) nor
	// a CLI stdin row can claim an escape-service verdict that was
	// never returned; only the in-process decorator can set them.
	EscapeVerdict string `json:"escapeVerdict,omitempty"`
	EscapeMark    string `json:"escapeMark,omitempty"`

	// MirrorMark is the L43 v1 cold-verifiable receipt over the
	// canonical bytes of this row with MirrorMark itself cleared.
	// Format: "lore@v1:" + base64url(8B corpus prefix || 32B HMAC).
	// LOAD-BEARING (R175): every Record in the production ledger
	// HAS a non-empty MirrorMark. MirrorMark stays the LAST field so
	// CanonicalBytes (which clears it) covers every data field above
	// — including OriginatorID.
	MirrorMark string `json:"mirrorMark"`
}

// CanonicalBytes returns the JSON encoding of the record with
// MirrorMark cleared, for cold-verify. Same operation a regulator
// performs server-side: clear MirrorMark, re-marshal, verify the
// HMAC over the resulting bytes.
//
// Mirrors ledger.AuditEvent + folio.AuditEvent canonical-bytes
// derivation byte-for-byte except for the struct receiver — the wire
// format is identical.
func (r Record) CanonicalBytes() []byte {
	c := r
	c.MirrorMark = ""
	c.At = c.At.UTC()
	b, err := json.Marshal(c)
	if err != nil {
		// Structurally unreachable for the current shape;
		// defended for forward-compat. Empty canonical is preferable
		// to a runtime panic (cold-verify would just fail with
		// ErrSignatureMismatch, which is the correct signal).
		log.Printf("auditledger: canonical bytes marshal failed: %v (action=%s)", err, r.Action)
		return nil
	}
	return b
}

// Append is the cohort-shape append primitive. R175 saturator:
// requires a non-nil MirrorMarker — see NewLedger guard.
type Ledger struct {
	marker *mirrormark.MirrorMarker

	mu     sync.RWMutex
	rows   []Record
	nextID uint64
}

// NewLedger constructs an in-memory append-only audit ledger backed by
// the supplied MirrorMarker. PANICS at construction if marker is nil
// — R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION: there is no
// not-marked code path. Tests that exercise the nil-guard MUST use
// NewLedgerSafe.
func NewLedger(marker *mirrormark.MirrorMarker) *Ledger {
	if marker == nil {
		panic(ErrNilMarker)
	}
	return &Ledger{marker: marker}
}

// NewLedgerSafe is the test-friendly constructor that returns (nil,
// err) instead of panicking on nil marker. Production code paths use
// NewLedger.
func NewLedgerSafe(marker *mirrormark.MirrorMarker) (*Ledger, error) {
	if marker == nil {
		return nil, ErrNilMarker
	}
	return &Ledger{marker: marker}, nil
}

// AppendInput is the shape callers pass to Append. The Ledger
// populates ID, At, MirrorMark before persisting; the caller supplies
// the domain-specific fields.
type AppendInput struct {
	Action     AuditAction
	Actor      string
	TrialID    string
	SubjectID  string
	RecordRef  string
	RecordHash string
	Detail     string

	// OriginatorID is the optional provenance attribution (the Nexus-
	// forwarded originating consumer/user). Empty on the CLI path;
	// stamped by the httpapi producer from the X-User-Id header so the
	// resulting Record's Mirror-Mark covers it. Additive — see
	// Record.OriginatorID.
	OriginatorID string
}

// Append appends one audit-trail row. The row is canonicalised (with
// MirrorMark cleared) BEFORE signing so the verifier reproduces the
// same bytes by clearing MirrorMark and re-marshalling.
//
// ID is monotonically allocated from 1; At is the wall-clock UTC at
// append time. The caller's `At` value (if any) is ignored — §11.10(e)
// requires the audit-trail timestamp be "computer-generated", not
// caller-supplied.
//
// R175: this method ALWAYS stamps the Mirror-Mark. The marker field is
// non-nil by construction (NewLedger panics otherwise) — there is no
// code path through Append that emits an unmarked row.
//
// Returns the appended Record (with ID + At + MirrorMark populated)
// and a non-nil error on validation failure.
func (l *Ledger) Append(in AppendInput) (Record, error) {
	return l.appendWithEscape(in, "", "")
}

// appendWithEscape is the internal append primitive: Append with the
// optional escape-service verdict + mark (2026-07-10 wire-in). Kept
// unexported so ONLY the in-package EscapeInformedLedger decorator can
// stamp these fields — see Record.EscapeVerdict's SPOOF-PROOF note.
// With empty verdict+mark it is byte-identical to the pre-wire Append.
func (l *Ledger) appendWithEscape(in AppendInput, escVerdict, escMark string) (Record, error) {
	if err := validateAppendInput(in); err != nil {
		return Record{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	r := Record{
		ID:            atomic.AddUint64(&l.nextID, 1),
		At:            time.Now().UTC(),
		Action:        in.Action,
		Actor:         in.Actor,
		TrialID:       in.TrialID,
		SubjectID:     in.SubjectID,
		RecordRef:     in.RecordRef,
		RecordHash:    in.RecordHash,
		Detail:        in.Detail,
		OriginatorID:  in.OriginatorID,
		EscapeVerdict: escVerdict,
		EscapeMark:    escMark,
	}

	// R175 wire-load-bearing stamp.
	cb := r.CanonicalBytes()
	if cb == nil {
		return Record{}, errors.New("auditledger: canonical bytes derivation failed")
	}
	r.MirrorMark = l.marker.Sign(cb)

	l.rows = append(l.rows, r)
	return r, nil
}

// Len returns the number of rows currently in the ledger.
func (l *Ledger) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.rows)
}

// List returns rows filtered by trial + action; n caps the result
// (most recent first); 0 means all. Returns copies of the rows so
// callers cannot mutate the ledger through them.
func (l *Ledger) List(trialID string, action AuditAction, n int) []Record {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]Record, 0, len(l.rows))
	for i := len(l.rows) - 1; i >= 0; i-- {
		r := l.rows[i]
		if trialID != "" && r.TrialID != trialID {
			continue
		}
		if action != "" && r.Action != action {
			continue
		}
		out = append(out, r)
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}

// AllSorted returns every row sorted by ID ascending. Returns copies.
// Used by the verify-the-whole-trail integration path (e.g. when an
// FDA inspector exports the full audit trail).
func (l *Ledger) AllSorted() []Record {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]Record, len(l.rows))
	copy(out, l.rows)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// VerifyAll re-derives every row's Mirror-Mark against the supplied
// (corpusSHA, key) and returns (validCount, totalCount, firstError).
// Used by an inspector tool to confirm the entire ledger
// cold-verifies in one pass.
func (l *Ledger) VerifyAll(corpusSHA [32]byte, key []byte) (valid int, total int, firstErr error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, r := range l.rows {
		total++
		ok, err := mirrormark.Verify(r.MirrorMark, corpusSHA, r.CanonicalBytes(), key)
		if !ok {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		valid++
	}
	return valid, total, firstErr
}

// SelfCheck re-derives every row's Mirror-Mark from its canonical
// bytes via the ledger's OWN marker, and re-runs the cheap structural
// checks the append path enforced (closed-enum R115 AuditAction +
// required §11.10(e) fields: Actor, TrialID, RecordRef). On success
// it returns the row count plus the ledger digest; on the first
// failure it returns a non-nil error and a zero digest (callers MUST
// NOT anchor/attest a ledger whose self-check failed — this is the
// gate internal/stele.AnchorRun enforces before sealing a LIT
// run-anchor into the Stele spine).
//
// LEDGER DIGEST — canonical run serialization (documented contract):
// sha256 over, for each Record in append order,
//
//	json.Marshal(Record) || '\n'
//
// Go's encoding/json marshals struct fields in declaration order
// (id, at, action, actor, trialId, subjectId, recordRef, recordHash,
// detail, mirrorMark — the same declaration-order property
// Record.CanonicalBytes already relies on) and time.Time marshals as
// RFC 3339, so the byte stream is deterministic: identical rows in
// identical order produce an identical digest, and any change to row
// content, mark, or ORDER changes it. The ledger is not hash-chained
// (Phase-1 in-memory ring), so this digest is the canonical binding
// for a Stele spine anchor's subject_hash.
//
// HONESTY: this is a SELF-check — the same marker that stamped the
// rows re-derives the marks. It surfaces post-Append tampering of
// in-memory rows, but it is NOT an independent oracle and does NOT
// prove the marker key is production-grade (a placeholder-mode
// marker self-checks green; the R143 loud-once warning covers that).
// Downstream consumers describing this check MUST label it
// self-check, not gauntlet. The Stele anchor COMPLEMENTS — it does
// not replace — the Mirror-Mark cold-verify an FDA reviewer performs
// offline against (corpusSHA, key).
func (l *Ledger) SelfCheck() (int, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte

	l.mu.RLock()
	snap := make([]Record, len(l.rows))
	copy(snap, l.rows)
	l.mu.RUnlock()

	h := sha256.New()
	for i, r := range snap {
		if !isValidAction(r.Action) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d Action %q not in closed-enum R115 AuditAction set", i, r.Action)
		}
		if r.Actor == "" || r.TrialID == "" || r.RecordRef == "" {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d missing required §11.10(e) field (Actor/TrialID/RecordRef)", i)
		}
		if !strings.HasPrefix(r.MirrorMark, mirrormark.MarkPrefix) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d mark missing cohort-canonical prefix %q", i, mirrormark.MarkPrefix)
		}
		cb := r.CanonicalBytes()
		if cb == nil {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d canonical bytes derivation failed", i)
		}
		if l.marker.Sign(cb) != r.MirrorMark {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d mark does not re-derive from canonical bytes (row or mark tampered)", i)
		}
		line, err := json.Marshal(r)
		if err != nil {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d serialization: %w", i, err)
		}
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	copy(digest[:], h.Sum(nil))
	return len(snap), digest, nil
}

func validateAppendInput(in AppendInput) error {
	if in.Action == "" {
		return errors.New("auditledger: AppendInput.Action required")
	}
	if !isValidAction(in.Action) {
		return errors.New("auditledger: AppendInput.Action must be a closed-enum AuditAction value")
	}
	if in.Actor == "" {
		return errors.New("auditledger: AppendInput.Actor required (§11.10(e) operator identification)")
	}
	if in.TrialID == "" {
		return errors.New("auditledger: AppendInput.TrialID required (trial-scoping invariant)")
	}
	if in.RecordRef == "" {
		return errors.New("auditledger: AppendInput.RecordRef required")
	}
	return nil
}

func isValidAction(a AuditAction) bool {
	for _, allowed := range AllAuditActions() {
		if a == allowed {
			return true
		}
	}
	return false
}
