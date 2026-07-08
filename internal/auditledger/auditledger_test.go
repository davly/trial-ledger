package auditledger

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/davly/trial-ledger/internal/mirrormark"
)

var testCorpus = func() [sha256.Size]byte {
	var c [sha256.Size]byte
	for i := range c {
		c[i] = byte(i)
	}
	return c
}()

var testKey = []byte("iik_test_TRIAL_LEDGER_audit_ledger_unit_test")

func newTestMarker() *mirrormark.MirrorMarker {
	return mirrormark.NewMirrorMarker(testCorpus, testKey)
}

func validInput() AppendInput {
	return AppendInput{
		Action:     ActionCreate,
		Actor:      "investigator-alice",
		TrialID:    "NCT06000001",
		SubjectID:  "S-007",
		RecordRef:  "ecrf/visit-3/page-2",
		RecordHash: strings.Repeat("a", 64),
		Detail:     "subject visit 3, vitals page submitted",
	}
}

// TestNewLedger_PanicsOnNilMarker is the R175 inception pin: there
// is no constructor path that yields a usable ledger without a
// MirrorMarker. The panic is the canonical Go shape for an invariant
// violation discovered at construction.
func TestNewLedger_PanicsOnNilMarker(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("R175 violated: NewLedger(nil) must panic")
		}
		if err, ok := r.(error); ok {
			if err != ErrNilMarker {
				t.Fatalf("recovered error: got %v want ErrNilMarker", err)
			}
		}
	}()
	_ = NewLedger(nil)
}

// TestNewLedgerSafe_ReturnsErrOnNilMarker is the test-friendly
// counterpart: same invariant, no panic.
func TestNewLedgerSafe_ReturnsErrOnNilMarker(t *testing.T) {
	l, err := NewLedgerSafe(nil)
	if l != nil {
		t.Fatalf("NewLedgerSafe(nil) must return nil ledger")
	}
	if err != ErrNilMarker {
		t.Fatalf("NewLedgerSafe(nil) err: got %v want ErrNilMarker", err)
	}
}

func TestNewLedger_Succeeds(t *testing.T) {
	l := NewLedger(newTestMarker())
	if l == nil {
		t.Fatalf("NewLedger returned nil with valid marker")
	}
	if l.Len() != 0 {
		t.Fatalf("freshly-constructed ledger Len: got %d want 0", l.Len())
	}
}

func TestAppend_StampsMirrorMark(t *testing.T) {
	l := NewLedger(newTestMarker())
	r, err := l.Append(validInput())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if r.MirrorMark == "" {
		t.Fatalf("R175 violated: Append produced row with empty MirrorMark")
	}
	if !strings.HasPrefix(r.MirrorMark, mirrormark.MarkPrefix) {
		t.Fatalf("MirrorMark missing prefix %q: got %q", mirrormark.MarkPrefix, r.MirrorMark)
	}
}

// TestAppend_R175EveryAppendStampsMark stress-asserts the R175
// invariant across many appends: there is NO code path through
// Append that produces an unstamped row.
func TestAppend_R175EveryAppendStampsMark(t *testing.T) {
	l := NewLedger(newTestMarker())
	const N = 100
	for i := 0; i < N; i++ {
		in := validInput()
		in.RecordRef = "page-" + string(rune('A'+i%26))
		r, err := l.Append(in)
		if err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
		if r.MirrorMark == "" {
			t.Fatalf("R175 violated at append %d: empty MirrorMark", i)
		}
	}
	for i, r := range l.AllSorted() {
		if r.MirrorMark == "" {
			t.Fatalf("R175 violated at row %d (post-list): empty MirrorMark", i)
		}
	}
}

func TestAppend_AssignsMonotonicID(t *testing.T) {
	l := NewLedger(newTestMarker())
	a, _ := l.Append(validInput())
	b, _ := l.Append(validInput())
	c, _ := l.Append(validInput())

	if a.ID != 1 || b.ID != 2 || c.ID != 3 {
		t.Fatalf("monotonic IDs: got %d %d %d want 1 2 3", a.ID, b.ID, c.ID)
	}
}

func TestAppend_TimestampIsUTC(t *testing.T) {
	l := NewLedger(newTestMarker())
	r, _ := l.Append(validInput())
	if r.At.Location().String() != "UTC" {
		t.Fatalf("Append.At must be UTC: got %s", r.At.Location())
	}
	if r.At.IsZero() {
		t.Fatalf("Append.At must be non-zero (§11.10(e) time-stamp invariant)")
	}
}

func TestAppend_RejectsEmptyAction(t *testing.T) {
	l := NewLedger(newTestMarker())
	in := validInput()
	in.Action = ""
	if _, err := l.Append(in); err == nil {
		t.Fatalf("empty Action must be rejected")
	}
}

func TestAppend_RejectsInvalidAction(t *testing.T) {
	l := NewLedger(newTestMarker())
	in := validInput()
	in.Action = AuditAction("not-a-real-action")
	if _, err := l.Append(in); err == nil {
		t.Fatalf("invalid Action must be rejected (closed-enum R115)")
	}
}

func TestAppend_RejectsEmptyActor(t *testing.T) {
	l := NewLedger(newTestMarker())
	in := validInput()
	in.Actor = ""
	if _, err := l.Append(in); err == nil {
		t.Fatalf("empty Actor must be rejected (§11.10(e) operator-id invariant)")
	}
}

func TestAppend_RejectsEmptyTrialID(t *testing.T) {
	l := NewLedger(newTestMarker())
	in := validInput()
	in.TrialID = ""
	if _, err := l.Append(in); err == nil {
		t.Fatalf("empty TrialID must be rejected (trial-scoping invariant)")
	}
}

func TestList_FiltersAndReturnsCopies(t *testing.T) {
	l := NewLedger(newTestMarker())
	a := validInput()
	a.TrialID = "trial-A"
	b := validInput()
	b.TrialID = "trial-B"
	for i := 0; i < 3; i++ {
		_, _ = l.Append(a)
		_, _ = l.Append(b)
	}

	gotA := l.List("trial-A", "", 0)
	if len(gotA) != 3 {
		t.Fatalf("List(trial-A): got %d want 3", len(gotA))
	}

	gotSign := l.List("", ActionSign, 0)
	if len(gotSign) != 0 {
		t.Fatalf("List(*, sign): got %d want 0", len(gotSign))
	}

	// Mutating the returned slice must not affect ledger state.
	gotA[0].Detail = "MUTATED"
	gotA2 := l.List("trial-A", "", 0)
	for _, r := range gotA2 {
		if r.Detail == "MUTATED" {
			t.Fatalf("List returns mutable refs to ledger state")
		}
	}
}

func TestList_CapsAtN(t *testing.T) {
	l := NewLedger(newTestMarker())
	for i := 0; i < 10; i++ {
		_, _ = l.Append(validInput())
	}
	got := l.List("", "", 5)
	if len(got) != 5 {
		t.Fatalf("List(n=5): got %d want 5", len(got))
	}
}

func TestAllSorted_AscendingByID(t *testing.T) {
	l := NewLedger(newTestMarker())
	for i := 0; i < 5; i++ {
		_, _ = l.Append(validInput())
	}
	sorted := l.AllSorted()
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].ID >= sorted[i].ID {
			t.Fatalf("AllSorted not ascending: %v", sorted)
		}
	}
}

// TestVerifyAll_RoundTrip is the FDA-inspector cold-verify pin: every
// row in the ledger re-derives successfully against the original
// (corpusSHA, key). This is THE load-bearing property R175 saturates.
func TestVerifyAll_RoundTrip(t *testing.T) {
	l := NewLedger(newTestMarker())
	const N = 25
	for i := 0; i < N; i++ {
		in := validInput()
		in.Action = AllAuditActions()[i%len(AllAuditActions())]
		_, _ = l.Append(in)
	}

	valid, total, err := l.VerifyAll(testCorpus, testKey)
	if err != nil {
		t.Fatalf("VerifyAll err: %v", err)
	}
	if total != N {
		t.Fatalf("VerifyAll total: got %d want %d", total, N)
	}
	if valid != N {
		t.Fatalf("VerifyAll valid: got %d want %d (all rows must round-trip)", valid, N)
	}
}

func TestVerifyAll_DetectsTamper(t *testing.T) {
	marker := newTestMarker()
	l := NewLedger(marker)
	const N = 5
	for i := 0; i < N; i++ {
		_, _ = l.Append(validInput())
	}

	// Verify with a different corpus — should fail every row.
	var wrongCorpus [32]byte
	for i := range wrongCorpus {
		wrongCorpus[i] = 0xee
	}
	valid, total, err := l.VerifyAll(wrongCorpus, testKey)
	if err == nil {
		t.Fatalf("VerifyAll with wrong corpus: expected error")
	}
	if total != N {
		t.Fatalf("VerifyAll total: got %d want %d", total, N)
	}
	if valid != 0 {
		t.Fatalf("VerifyAll with wrong corpus: valid=%d want 0", valid)
	}
}

func TestRecord_CanonicalBytesClearsMirrorMark(t *testing.T) {
	r := Record{
		ID:         1,
		Action:     ActionCreate,
		Actor:      "alice",
		TrialID:    "T",
		RecordRef:  "r",
		MirrorMark: "lore@v1:DELIBERATELY_BOGUS",
	}
	cb := r.CanonicalBytes()
	if cb == nil {
		t.Fatalf("CanonicalBytes returned nil")
	}
	if strings.Contains(string(cb), "DELIBERATELY_BOGUS") {
		t.Fatalf("CanonicalBytes must clear MirrorMark: %s", cb)
	}
}

// fixedRecord builds a fully-populated Record with a deterministic
// timestamp and a correctly-derived Mirror-Mark from the shared test
// (corpus, key). Used by the SelfCheck determinism tests: the
// production Append path stamps time.Now().UTC() (§11.10(e)
// computer-generated timestamp, deliberately not injectable), so
// cross-ledger digest determinism can only be exercised with
// directly-constructed rows.
func fixedRecord(id uint64, ref string, at time.Time) Record {
	r := Record{
		ID:         id,
		At:         at.UTC(),
		Action:     ActionCreate,
		Actor:      "investigator-alice",
		TrialID:    "NCT06000001",
		SubjectID:  "S-007",
		RecordRef:  ref,
		RecordHash: strings.Repeat("a", 64),
		Detail:     "deterministic fixture row",
	}
	r.MirrorMark = newTestMarker().Sign(r.CanonicalBytes())
	return r
}

// buildFixedLedger assembles a ledger whose rows were constructed
// outside Append (package-internal test seam — the same direct
// l.rows access the tamper tests use).
func buildFixedLedger(rows ...Record) *Ledger {
	l := NewLedger(newTestMarker())
	l.rows = append(l.rows, rows...)
	return l
}

// TestSelfCheck_GreenAndIdempotent pins the SelfCheck contract used
// by Stele spine anchoring: a healthy ledger built through the real
// Append path self-checks green, and repeated SelfCheck calls on the
// same ledger state return the identical digest (the canonical run
// serialization is a pure function of ledger content).
func TestSelfCheck_GreenAndIdempotent(t *testing.T) {
	l := NewLedger(newTestMarker())
	for i := 0; i < 2; i++ {
		in := validInput()
		in.Action = AllAuditActions()[i]
		if _, err := l.Append(in); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	n1, d1, err := l.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on healthy ledger: %v", err)
	}
	if n1 != 2 {
		t.Errorf("SelfCheck count: got %d, want 2", n1)
	}
	var zero [sha256.Size]byte
	if d1 == zero {
		t.Errorf("SelfCheck digest is zero for a non-empty ledger")
	}

	n2, d2, err := l.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck second pass: %v", err)
	}
	if n2 != n1 || d1 != d2 {
		t.Errorf("SelfCheck not idempotent: (%d, %x) vs (%d, %x)", n1, d1, n2, d2)
	}
}

// TestSelfCheck_DeterministicAndOrderSensitive pins the canonical run
// serialization across independent ledgers: identical rows in
// identical order produce an identical digest, and append ORDER is
// load-bearing — swapping rows MUST change the digest (the digest is
// the Stele anchor's subject_hash binding).
func TestSelfCheck_DeterministicAndOrderSensitive(t *testing.T) {
	at := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	rowA := fixedRecord(1, "ecrf/visit-1/page-1", at)
	rowB := fixedRecord(2, "ecrf/visit-2/page-1", at.Add(time.Minute))

	_, d1, err := buildFixedLedger(rowA, rowB).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on first ledger: %v", err)
	}
	_, d2, err := buildFixedLedger(rowA, rowB).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on second ledger: %v", err)
	}
	if d1 != d2 {
		t.Errorf("SelfCheck digest non-deterministic: %x vs %x", d1, d2)
	}

	_, d3, err := buildFixedLedger(rowB, rowA).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on swapped ledger: %v", err)
	}
	if d3 == d1 {
		t.Errorf("SelfCheck digest insensitive to row order: %x", d3)
	}
}

// TestSelfCheck_DetectsTamper pins the integrity half of SelfCheck:
// post-Append mutation of row content or carried mark MUST fail the
// self-check (this is the gate that keeps a tampered §11.10(e) audit
// trail from being anchored LIT into the Stele spine).
func TestSelfCheck_DetectsTamper(t *testing.T) {
	// Tampered row content (direct slice mutation — the documented
	// antipattern the self-check exists to surface).
	l := NewLedger(newTestMarker())
	if _, err := l.Append(validInput()); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.rows[0].Detail = "tampered detail"
	if _, _, err := l.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered Detail, want failure")
	}

	// Tampered mark (still cohort-prefixed so the prefix gate alone
	// cannot catch it).
	l2 := NewLedger(newTestMarker())
	stamped, err := l2.Append(validInput())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	l2.rows[0].MirrorMark = stamped.MirrorMark[:len(stamped.MirrorMark)-2] + "xx"
	if _, _, err := l2.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered mark, want failure")
	}

	// Mark missing the cohort prefix entirely.
	l3 := NewLedger(newTestMarker())
	if _, err := l3.Append(validInput()); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l3.rows[0].MirrorMark = "not-a-mark"
	if _, _, err := l3.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a prefix-less mark, want failure")
	}
}

// TestSelfCheck_DetectsStructuralMutation pins the cheap structural
// re-validation: a row whose closed-enum Action or required
// §11.10(e) fields were mutated post-Append fails the self-check.
func TestSelfCheck_DetectsStructuralMutation(t *testing.T) {
	l := NewLedger(newTestMarker())
	if _, err := l.Append(validInput()); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.rows[0].Action = AuditAction("garbage.action")
	if _, _, err := l.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted an out-of-enum Action, want failure")
	}

	l2 := NewLedger(newTestMarker())
	if _, err := l2.Append(validInput()); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l2.rows[0].Actor = ""
	if _, _, err := l2.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted an empty Actor, want failure")
	}
}

// TestSelfCheck_EmptyLedger pins the empty-ledger shape: zero rows is
// not an integrity failure (count 0, the sha256 of the empty stream,
// nil error).
func TestSelfCheck_EmptyLedger(t *testing.T) {
	n, d, err := NewLedger(newTestMarker()).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on empty ledger: %v", err)
	}
	if n != 0 {
		t.Errorf("SelfCheck count on empty ledger: got %d, want 0", n)
	}
	if want := sha256.Sum256(nil); d != want {
		t.Errorf("SelfCheck digest on empty ledger: got %x, want sha256 of empty stream %x", d, want)
	}
}

func TestAllAuditActions_Count(t *testing.T) {
	const want = 7
	if got := len(AllAuditActions()); got != want {
		t.Fatalf("audit-action count: got %d want %d", got, want)
	}
}

func TestAllAuditActions_PinnedSet(t *testing.T) {
	want := map[AuditAction]bool{
		ActionCreate:            true,
		ActionModify:            true,
		ActionDelete:            true,
		ActionSign:              true,
		ActionWithdrawSignature: true,
		ActionView:              true,
		ActionLock:              true,
	}
	for _, a := range AllAuditActions() {
		if !want[a] {
			t.Errorf("unexpected action %q in AllAuditActions", a)
		}
	}
	for a := range want {
		found := false
		for _, got := range AllAuditActions() {
			if got == a {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected action %q missing from AllAuditActions", a)
		}
	}
}
