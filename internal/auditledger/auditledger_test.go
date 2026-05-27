package auditledger

import (
	"crypto/sha256"
	"strings"
	"testing"

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
