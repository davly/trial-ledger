package wal_test

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davly/trial-ledger/internal/auditledger"
	"github.com/davly/trial-ledger/internal/mirrormark"
	"github.com/davly/trial-ledger/internal/wal"
)

// newTestMarker returns a deterministic test MirrorMarker.
func newTestMarker() *mirrormark.MirrorMarker {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	return mirrormark.NewMirrorMarker(corpus, []byte("iik_test_WAL_unit_test"))
}

// appendRecord is a helper that appends one valid Record via the
// in-memory ledger and then writes it to the WALStore.
func appendRecord(t *testing.T, ledger *auditledger.Ledger, store *wal.WALStore, action auditledger.AuditAction, ref string) auditledger.Record {
	t.Helper()
	r, err := ledger.Append(auditledger.AppendInput{
		Action:     action,
		Actor:      "investigator-alice",
		TrialID:    "NCT06000001",
		SubjectID:  "S-007",
		RecordRef:  ref,
		RecordHash: strings.Repeat("a", 64),
		Detail:     "wal unit test",
	})
	if err != nil {
		t.Fatalf("ledger.Append: %v", err)
	}
	if err := store.Append(r); err != nil {
		t.Fatalf("store.Append: %v", err)
	}
	return r
}

// TestWALStore_AppendAndReplay is the core durability test: records
// written to a WALStore survive a Close+Open (process-restart analog).
// This exercises the Phase 2 gap that the in-memory ring cannot pass.
func TestWALStore_AppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.wal")
	marker := newTestMarker()

	const N = 5
	var want []auditledger.Record

	// First "process": write N records.
	{
		store, err := wal.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		ledger := auditledger.NewLedger(marker)
		for i := 0; i < N; i++ {
			r := appendRecord(t, ledger, store, auditledger.ActionCreate, "page-"+string(rune('A'+i)))
			want = append(want, r)
		}
		if store.Len() != N {
			t.Fatalf("Len after writes: got %d want %d", store.Len(), N)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// Second "process": open same path, verify all rows are recovered.
	{
		store, err := wal.Open(path)
		if err != nil {
			t.Fatalf("Open (replay): %v", err)
		}
		defer store.Close()

		if store.Len() != N {
			t.Fatalf("Len after replay: got %d want %d (data lost on restart)", store.Len(), N)
		}
		got := store.AllSorted()
		for i, r := range got {
			if r.ID != want[i].ID {
				t.Errorf("row[%d].ID: got %d want %d", i, r.ID, want[i].ID)
			}
			if r.Action != want[i].Action {
				t.Errorf("row[%d].Action: got %q want %q", i, r.Action, want[i].Action)
			}
			if r.MirrorMark != want[i].MirrorMark {
				t.Errorf("row[%d].MirrorMark: got %q want %q", i, r.MirrorMark, want[i].MirrorMark)
			}
		}
	}
}

// TestWALStore_TriggerCascade_WALSeq verifies the trigger-cascade
// derived state: walSeq increments monotonically with every append,
// matching quarry-db's observation_number auto-assignment.
func TestWALStore_TriggerCascade_WALSeq(t *testing.T) {
	dir := t.TempDir()
	store, err := wal.Open(filepath.Join(dir, "audit.wal"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if store.WALSeq() != 0 {
		t.Fatalf("WALSeq on empty store: got %d want 0", store.WALSeq())
	}

	marker := newTestMarker()
	ledger := auditledger.NewLedger(marker)
	const N = 7
	for i := 0; i < N; i++ {
		appendRecord(t, ledger, store, auditledger.ActionCreate, "ref-"+string(rune('a'+i)))
		want := uint64(i + 1)
		if store.WALSeq() != want {
			t.Fatalf("WALSeq after append %d: got %d want %d", i, store.WALSeq(), want)
		}
	}
}

// TestWALStore_TriggerCascade_ChainDigest verifies the running hash
// chain: each append changes the digest, and replaying the same rows
// in the same order reproduces the same final digest.
// This is the quarry-db forge_transitions immutable-audit-log analog.
func TestWALStore_TriggerCascade_ChainDigest(t *testing.T) {
	dir := t.TempDir()
	marker := newTestMarker()

	// Build a store with 3 records and capture the final chain digest.
	var finalDigest [sha256.Size]byte
	var rows []auditledger.Record
	path := filepath.Join(dir, "audit.wal")
	{
		store, err := wal.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		var zeroDig [sha256.Size]byte
		if store.ChainDigest() != zeroDig {
			t.Fatalf("ChainDigest on empty store should be zero")
		}
		ledger := auditledger.NewLedger(marker)
		for i := 0; i < 3; i++ {
			r := appendRecord(t, ledger, store, auditledger.ActionCreate, "r"+string(rune('0'+i)))
			rows = append(rows, r)
		}
		d1 := store.ChainDigest()
		d2 := store.ChainDigest() // idempotent
		if d1 != d2 {
			t.Fatalf("ChainDigest not idempotent")
		}
		if d1 == zeroDig {
			t.Fatalf("ChainDigest still zero after 3 appends")
		}
		finalDigest = d1
		if err := store.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// Replay and verify the cascade reproduces the same final digest.
	{
		store, err := wal.Open(path)
		if err != nil {
			t.Fatalf("Open (replay): %v", err)
		}
		defer store.Close()
		if store.ChainDigest() != finalDigest {
			t.Fatalf("ChainDigest after replay: got %x want %x (cascade not idempotent over WAL replay)",
				store.ChainDigest(), finalDigest)
		}
	}

	// A different row order MUST produce a different digest (order-sensitive).
	{
		path2 := filepath.Join(dir, "audit2.wal")
		store2, err := wal.Open(path2)
		if err != nil {
			t.Fatalf("Open2: %v", err)
		}
		defer store2.Close()
		// Append the rows in reverse order.
		for i := len(rows) - 1; i >= 0; i-- {
			if err := store2.Append(rows[i]); err != nil {
				t.Fatalf("store2.Append: %v", err)
			}
		}
		if store2.ChainDigest() == finalDigest {
			t.Fatalf("ChainDigest must differ for different row order")
		}
	}
}

// TestWALStore_EmptyReplay verifies that a fresh (empty) WAL file
// starts with zero rows, zero WALSeq, and the zero chain digest.
func TestWALStore_EmptyReplay(t *testing.T) {
	dir := t.TempDir()
	store, err := wal.Open(filepath.Join(dir, "empty.wal"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	if store.Len() != 0 {
		t.Fatalf("Len on empty: got %d want 0", store.Len())
	}
	if store.WALSeq() != 0 {
		t.Fatalf("WALSeq on empty: got %d want 0", store.WALSeq())
	}
	var zeroDig [sha256.Size]byte
	if store.ChainDigest() != zeroDig {
		t.Fatalf("ChainDigest on empty should be zero")
	}
}

// TestWALStore_AllSorted_ReturnsCopies verifies that mutating the
// returned slice does not affect the WALStore's internal state.
func TestWALStore_AllSorted_ReturnsCopies(t *testing.T) {
	dir := t.TempDir()
	store, err := wal.Open(filepath.Join(dir, "copies.wal"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	marker := newTestMarker()
	ledger := auditledger.NewLedger(marker)
	appendRecord(t, ledger, store, auditledger.ActionCreate, "ref-1")

	got := store.AllSorted()
	if len(got) != 1 {
		t.Fatalf("AllSorted len: got %d want 1", len(got))
	}
	got[0].Detail = "MUTATED"

	// Second call must not see the mutation.
	got2 := store.AllSorted()
	if got2[0].Detail == "MUTATED" {
		t.Fatalf("AllSorted returned reference to internal state")
	}
}

// TestWALStore_FileCreated verifies that Open creates the WAL file
// when it does not yet exist.
func TestWALStore_FileCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "new.wal")

	// The parent dir doesn't exist; Open should fail (not create dirs).
	_, err := wal.Open(path)
	if err == nil {
		t.Fatalf("Open on missing parent dir should fail")
	}

	// Create the parent dir; now Open should succeed and create the file.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	store, err := wal.Open(path)
	if err != nil {
		t.Fatalf("Open after mkdir: %v", err)
	}
	store.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("WAL file not created: %v", err)
	}
}

// TestWALStore_AppendPreservesTimestamp verifies that the UTC
// timestamp on each Record round-trips exactly through the WAL
// (JSON encoding preserves nanosecond precision to seconds; we check
// the second-level granularity).
func TestWALStore_AppendPreservesTimestamp(t *testing.T) {
	dir := t.TempDir()
	store, err := wal.Open(filepath.Join(dir, "ts.wal"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	marker := newTestMarker()
	ledger := auditledger.NewLedger(marker)
	r := appendRecord(t, ledger, store, auditledger.ActionSign, "esig/consent")
	if r.At.IsZero() {
		t.Fatalf("Record.At is zero")
	}
	if r.At.Location() != time.UTC {
		t.Fatalf("Record.At is not UTC: %v", r.At.Location())
	}
	got := store.AllSorted()
	if len(got) != 1 {
		t.Fatalf("AllSorted len: got %d want 1", len(got))
	}
	diff := got[0].At.Sub(r.At)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Fatalf("Timestamp round-trip error: got %v want %v (diff %v)", got[0].At, r.At, diff)
	}
}
