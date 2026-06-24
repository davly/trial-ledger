package stele

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedDigest returns a deterministic non-zero ledger digest for tests.
func fixedDigest() [sha256.Size]byte {
	var d [sha256.Size]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

// fakeChecker is a SelfChecker test double that records invocations.
type fakeChecker struct {
	calls   int
	entries int
	digest  [sha256.Size]byte
	err     error
}

func (f *fakeChecker) SelfCheck() (int, [sha256.Size]byte, error) {
	f.calls++
	return f.entries, f.digest, f.err
}

// TestNewRunAnchor_PayloadShape pins every field of the anchor verdict —
// the honesty contract is load-bearing (self-check labelling, LIT-only-
// after-pass, subject_hash binding, 21 CFR Part 11 framing).
func TestNewRunAnchor_PayloadShape(t *testing.T) {
	digest := fixedDigest()
	sealedAt := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	v := NewRunAnchor("append", 3, digest, sealedAt)

	wantHex := hex.EncodeToString(digest[:])
	if v.Substrate != "flagships/trial-ledger/audit-ledger" {
		t.Errorf("Substrate = %q", v.Substrate)
	}
	if v.Verdict != "LIT" {
		t.Errorf("Verdict = %q, want LIT", v.Verdict)
	}
	if v.Severity != "n/a" {
		t.Errorf("Severity = %q, want n/a", v.Severity)
	}
	if v.Location != "flagships/trial-ledger/audit-ledger@append" {
		t.Errorf("Location = %q", v.Location)
	}
	if !strings.Contains(v.Evidence, "21 CFR Part 11 audit-trail run self-check: 3 entries") {
		t.Errorf("Evidence missing FDA-framed entry count: %q", v.Evidence)
	}
	if !strings.Contains(v.Evidence, "ledger digest "+wantHex[:16]) {
		t.Errorf("Evidence missing digest prefix: %q", v.Evidence)
	}
	if !strings.Contains(v.Evidence, "self-check, NOT an independent gauntlet") {
		t.Errorf("Evidence missing the honesty caveat: %q", v.Evidence)
	}
	if v.OracleStrength != "Self-Check" {
		t.Errorf("OracleStrength = %q, want Self-Check", v.OracleStrength)
	}
	if v.SealedAt != "2026-06-11T12:00:00Z" {
		t.Errorf("SealedAt = %q", v.SealedAt)
	}
	if v.GauntletRun != "" {
		t.Errorf("GauntletRun = %q, want empty", v.GauntletRun)
	}
	if v.SubjectHash != wantHex {
		t.Errorf("SubjectHash = %q, want %q", v.SubjectHash, wantHex)
	}

	// Determinism: same entries (digest) → same payload.
	if v2 := NewRunAnchor("append", 3, digest, sealedAt); v2 != v {
		t.Errorf("NewRunAnchor non-deterministic:\n a=%+v\n b=%+v", v, v2)
	}
}

// TestSeal_Success pins the wire shape: POST /v1/verdicts with the full
// JSON body, and receipt parsing from 201 + sealed{seq, entry_hash}.
func TestSeal_Success(t *testing.T) {
	digest := fixedDigest()
	want := NewRunAnchor("append", 1, digest, time.Date(2026, 6, 11, 9, 30, 0, 0, time.UTC))

	var got Verdict
	var gotMethod, gotPath, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotCT = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("server decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":15,"entry_hash":"ab12cd34ef56"},"receipt":"recompute it yourself"}`)
	}))
	defer srv.Close()

	rcpt, err := NewClient(srv.URL + "/").Seal(want) // trailing slash exercises TrimRight
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/verdicts" {
		t.Errorf("request = %s %s, want POST /v1/verdicts", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if got != want {
		t.Errorf("payload drift:\n sent=%+v\n want=%+v", got, want)
	}
	if rcpt.Seq != 15 || rcpt.EntryHash != "ab12cd34ef56" {
		t.Errorf("receipt = %+v, want seq=15 entry_hash=ab12cd34ef56", rcpt)
	}
}

// TestSeal_Non201 pins that any non-201 status surfaces as an error —
// a refused seal must never read as anchored.
func TestSeal_Non201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, `{"error":"substrate and location are required"}`)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("append", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal on 400 = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Errorf("error %q missing status code", err)
	}
}

// TestSeal_201WithoutEntryHash pins the never-overclaim rule: a 201
// without sealed.entry_hash is NOT a receipt.
func TestSeal_201WithoutEntryHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{}`)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("append", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal on 201-without-entry_hash = nil error, want refusal to claim anchored")
	}
}

// TestSeal_NetworkError pins that a dead spine surfaces as an error.
func TestSeal_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // dead before use

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("append", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal against dead server = nil error, want failure")
	}
}

// TestSeal_RefusesRedirect pins the transport-integrity guard: a 3xx
// from the configured spine (misconfig / MITM on the plaintext http://
// the docs use / compromised host) must NOT be followed. Following it
// would re-POST the §11.10(e) ledger digest to the redirect target and,
// on its 201+entry_hash, falsely report the run as "sealed" at the
// genuine spine — a breach of the load-bearing HONESTY CONTRACT. The
// guard surfaces as a loud non-nil error; the redirect target receives
// ZERO POSTs and no receipt is ever claimed.
func TestSeal_RefusesRedirect(t *testing.T) {
	// The redirect target would happily "seal" the run — it answers a
	// well-formed 201 + entry_hash. If the client followed the 3xx, Seal
	// would return a valid-looking receipt and the run would read sealed.
	targetPosts := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			targetPosts++
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":99,"entry_hash":"attacker-controlled-hash"}}`)
	}))
	defer target.Close()

	// The configured spine 302-redirects the seal POST to the target.
	spine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/verdicts", http.StatusFound)
	}))
	defer spine.Close()

	rcpt, err := NewClient(spine.URL).Seal(NewRunAnchor("append", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal against a 302-redirecting spine = nil error, want refusal (a redirected seal must never read as sealed)")
	}
	if !strings.Contains(err.Error(), "stele seal:") {
		t.Errorf("error %q missing the stele seal wrapper", err)
	}
	if rcpt != (Receipt{}) {
		t.Errorf("receipt = %+v, want zero (no receipt may be claimed from a redirected seal)", rcpt)
	}
	if targetPosts != 0 {
		t.Errorf("redirect target received %d POSTs, want 0 (the ledger digest must never reach the redirect host)", targetPosts)
	}
}

// TestAnchorRun_RefusesRedirect pins the same guard at the CLI seam:
// AnchorRun against a redirecting spine returns anchored=false + a loud
// error, so main.go never prints "stele anchor: sealed".
func TestAnchorRun_RefusesRedirect(t *testing.T) {
	targetPosts := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			targetPosts++
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":99,"entry_hash":"attacker-controlled-hash"}}`)
	}))
	defer target.Close()
	spine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/verdicts", http.StatusFound)
	}))
	defer spine.Close()

	fc := &fakeChecker{entries: 1, digest: fixedDigest()}
	rcpt, anchored, err := AnchorRun(spine.URL, "append", fc, time.Now().UTC())
	if err == nil {
		t.Fatalf("AnchorRun against a redirecting spine = nil error, want loud failure")
	}
	if anchored {
		t.Errorf("anchored = true on a redirected seal (would print a false 'sealed' claim)")
	}
	if rcpt != (Receipt{}) {
		t.Errorf("receipt = %+v, want zero", rcpt)
	}
	if targetPosts != 0 {
		t.Errorf("redirect target received %d POSTs, want 0", targetPosts)
	}
}

// TestAnchorRun_Disabled pins the off-by-default contract: empty (or
// whitespace) URL means NO self-check, NO HTTP, no receipt, no error —
// behavior identical to a non-anchoring run.
func TestAnchorRun_Disabled(t *testing.T) {
	for _, url := range []string{"", "   "} {
		fc := &fakeChecker{entries: 2, digest: fixedDigest()}
		rcpt, anchored, err := AnchorRun(url, "append", fc, time.Now().UTC())
		if err != nil {
			t.Errorf("AnchorRun(%q) error = %v, want nil", url, err)
		}
		if anchored {
			t.Errorf("AnchorRun(%q) anchored = true, want false", url)
		}
		if rcpt != (Receipt{}) {
			t.Errorf("AnchorRun(%q) receipt = %+v, want zero", url, rcpt)
		}
		if fc.calls != 0 {
			t.Errorf("AnchorRun(%q) ran the ledger self-check %d times, want 0 (zero behavior change)", url, fc.calls)
		}
	}
}

// TestAnchorRun_SelfCheckFailureSealsNothing pins the honesty gate: a
// ledger that fails its self-check seals NOTHING — zero HTTP calls.
// An integrity-suspect §11.10(e) audit trail must never be anchored
// LIT.
func TestAnchorRun_SelfCheckFailureSealsNothing(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":1,"entry_hash":"deadbeef"}}`)
	}))
	defer srv.Close()

	fc := &fakeChecker{err: fmt.Errorf("row 0 mark does not re-derive")}
	_, anchored, err := AnchorRun(srv.URL, "append", fc, time.Now().UTC())
	if err == nil {
		t.Fatalf("AnchorRun with failing self-check = nil error, want loud failure")
	}
	if anchored {
		t.Errorf("anchored = true on failed self-check")
	}
	if hits != 0 {
		t.Errorf("spine received %d requests after a failed self-check, want 0 (seal nothing)", hits)
	}
}

// TestAnchorRun_Success pins the end-to-end seam: passing self-check →
// sealed verdict whose subject_hash is the ledger digest hex →
// receipt returned, anchored=true. Same digest → same subject_hash on
// the wire (determinism at the seam).
func TestAnchorRun_Success(t *testing.T) {
	digest := fixedDigest()
	var subjectHashes []string
	seq := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v Verdict
		_ = json.NewDecoder(r.Body).Decode(&v)
		subjectHashes = append(subjectHashes, v.SubjectHash)
		seq++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"sealed":{"seq":%d,"entry_hash":"hash%d"}}`, seq, seq)
	}))
	defer srv.Close()

	fc := &fakeChecker{entries: 4, digest: digest}
	rcpt, anchored, err := AnchorRun(srv.URL, "append", fc, time.Now().UTC())
	if err != nil {
		t.Fatalf("AnchorRun: %v", err)
	}
	if !anchored {
		t.Fatalf("anchored = false on success")
	}
	if rcpt.Seq != 1 || rcpt.EntryHash != "hash1" {
		t.Errorf("receipt = %+v, want seq=1 entry_hash=hash1", rcpt)
	}
	if fc.calls != 1 {
		t.Errorf("self-check ran %d times, want 1", fc.calls)
	}

	// Second anchor of the same ledger state → identical subject_hash.
	if _, _, err := AnchorRun(srv.URL, "append", fc, time.Now().UTC()); err != nil {
		t.Fatalf("AnchorRun second: %v", err)
	}
	wantHex := hex.EncodeToString(digest[:])
	if len(subjectHashes) != 2 || subjectHashes[0] != wantHex || subjectHashes[1] != wantHex {
		t.Errorf("subject_hashes = %v, want both %q (deterministic binding)", subjectHashes, wantHex)
	}
}
