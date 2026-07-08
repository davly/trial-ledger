// Package wal — WAL-backed append-log persistence for the trial-ledger
// FDA 21 CFR Part 11 audit trail.
//
// # Problem (Phase 2 blocker, documented in auditledger.go)
//
// The in-memory [auditledger.Ledger] ring loses all data on process
// restart. The auditledger package explicitly documents this:
//
//	"The shipped surface is an IN-MEMORY APPEND-ONLY RING. Production
//	deployments MUST swap in a WAL-SQLite or WAL-PostgreSQL persistence
//	layer (the canonical-shape ports byte-for-byte; the swap is
//	R145-strict additive)."
//
// # Pattern (quarry-db cross-pollination)
//
// quarry-db (sql/002_tables.sql + 005_lifecycle.sql) uses PostgreSQL
// WAL semantics for its forge append log: every INSERT into
// forge_observations fires a trigger cascade that
//   1. assigns a monotonic observation_number,
//   2. recomputes derived metrics,
//   3. drives the forge_status state machine, and
//   4. writes an immutable forge_transitions audit row.
//
// The key architectural property is the TRIGGER CASCADE: insertion is
// a single operation that automatically cascades all derived-state
// maintenance — callers cannot accidentally skip it.
//
// This package ports that pattern into stdlib Go:
//
//   - The WAL file (O_APPEND|O_SYNC) is the persistence layer — each
//     Record is one JSON line followed by '\n', appended atomically.
//     O_SYNC gives WAL durability: the kernel flushes to stable storage
//     before the write syscall returns, matching PostgreSQL WAL
//     behaviour (wal_sync_method=fsync). On process restart, replay
//     scans the WAL file linearly, reproducing the in-memory state.
//
//   - The trigger cascade lives in [WALStore.Append]: after writing to
//     the WAL file, cascade() automatically maintains the running
//     SHA-256 hash chain (walSeq + running digest) — a direct port of
//     quarry-db's trg_after_observation_insert() which recomputes
//     accumulated state after every INSERT. The cascade runs inside the
//     write lock so it is impossible to bypass.
//
// # Stdlib-only, zero new deps
//
// trial-ledger ships with a zero-requires go.mod (R174 cohort
// discipline). This package uses only stdlib: os, bufio, encoding/json,
// crypto/sha256, sync — no database driver, no ORM.
//
// # Firewall compliance (R145.C)
//
// Adding this package requires a matching update to
// [internal/firewall.ExpectedPackages] (and the count pin). See
// firewall.go.
//
// # Env-read discipline (R145.B)
//
// This package performs NO os.Getenv / os.LookupEnv / os.Environ
// calls. The WAL path is caller-supplied (see [Open]) so the confinement
// invariant in TestR145B_SteleAnchorConfinement is preserved.
package wal

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/davly/trial-ledger/internal/auditledger"
)

// WALStore is a WAL-backed append-only store for [auditledger.Record]
// rows. It satisfies the same append/query surface as the in-memory
// [auditledger.Ledger], adding durable restart-safe persistence.
//
// WALStore is safe for concurrent use; a single write-lock serialises
// WAL appends and the trigger cascade.
type WALStore struct {
	mu   sync.RWMutex
	f    *os.File   // append-mode WAL file
	rows []auditledger.Record

	// Trigger-cascade derived state (quarry-db trg_after_observation_insert
	// pattern): maintained atomically on every Append call, impossible
	// to bypass because cascade() runs under the write lock.
	walSeq  uint64         // monotonic WAL sequence number (observation_number analog)
	running [sha256.Size]byte // running cumulative hash chain (metrics-recompute analog)
}

// Open opens (or creates) the WAL file at path and replays any
// existing rows into memory. It is the only constructor; callers own
// the returned *WALStore and MUST call Close() when done.
//
// Replay is linear — O(n) in the number of persisted rows — matching
// the PostgreSQL WAL recovery model: the server reads the WAL sequentially
// on startup to reconstruct in-memory state.
func Open(path string) (*WALStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("wal.Open: %w", err)
	}

	s := &WALStore{f: f}
	if err := s.replay(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal.Open replay: %w", err)
	}
	return s, nil
}

// replay reads the WAL file from the beginning and reloads all rows
// into the in-memory slice, re-running the cascade for each row.
// Called once at Open time — this is the restart-recovery path.
func (s *WALStore) replay(f *os.File) error {
	// Seek to start for reading; the file descriptor is opened O_APPEND
	// so subsequent Write calls still go to the end.
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("replay seek: %w", err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r auditledger.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("replay unmarshal: %w", err)
		}
		// Re-run the cascade for every replayed row to rebuild derived state.
		s.rows = append(s.rows, r)
		s.cascade(r)
	}
	return sc.Err()
}

// Append writes a Record to the WAL file (durable; O_SYNC flushes to
// storage before returning) and runs the trigger cascade.
//
// The write-lock prevents concurrent appenders from interleaving WAL
// lines, preserving the append-only sequential property.
func (s *WALStore) Append(r auditledger.Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("wal.Append marshal: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("wal.Append write: %w", err)
	}
	s.rows = append(s.rows, r)
	s.cascade(r) // trigger cascade — runs under the write lock, cannot be skipped
	return nil
}

// cascade maintains the WAL-sequence counter and running cumulative
// hash chain after each append.
//
// This is the direct Go port of quarry-db's
// trg_after_observation_insert() trigger body: in quarry-db the
// trigger AFTER INSERT on forge_observations fires automatically for
// every insertion and recomputes accumulated metrics (observation_number,
// dominance metrics, state-machine transitions). Here, cascade() plays
// the same role: it fires automatically after every WAL write and
// maintains the two pieces of derived state (walSeq, running digest)
// that would otherwise require callers to update manually.
//
// The running hash chain is: sha256(running_prev || json(record))
// This gives a tamper-evident chain over the entire WAL sequence —
// any modification, deletion, or re-ordering of rows changes the final
// chain hash, analogous to quarry-db's forge_transitions immutable
// audit log.
//
// Must be called under s.mu write-lock.
func (s *WALStore) cascade(r auditledger.Record) {
	s.walSeq++
	b, _ := json.Marshal(r)
	h := sha256.New()
	h.Write(s.running[:])
	h.Write(b)
	copy(s.running[:], h.Sum(nil))
}

// WALSeq returns the current WAL sequence number (number of rows ever
// appended, counting from 1). Analogous to quarry-db's
// observation_number monotonic counter.
func (s *WALStore) WALSeq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.walSeq
}

// ChainDigest returns the current cumulative hash chain digest. This
// is the tamper-evident running hash over all WAL entries in append
// order; it changes with every new entry and with any mutation to
// prior entries. Callers can persist or anchor this value as a
// checkpoint for the WAL.
func (s *WALStore) ChainDigest() [sha256.Size]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Len returns the number of rows currently in the WAL store.
func (s *WALStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rows)
}

// AllSorted returns every row in WAL (append) order. Returns copies.
// Unlike the in-memory ledger's AllSorted (which sorts by ID), WAL
// order IS the canonical order — rows are written and replayed in
// monotonic sequence so WAL position is the sort key.
func (s *WALStore) AllSorted() []auditledger.Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]auditledger.Record, len(s.rows))
	copy(out, s.rows)
	return out
}

// Close flushes and closes the underlying WAL file. Subsequent Append
// calls will fail.
func (s *WALStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
