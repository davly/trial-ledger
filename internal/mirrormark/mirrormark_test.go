package mirrormark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"testing"
)

// Test corpus SHA used across these tests — arbitrary 32 bytes, NOT
// a real lore.tar.gz SHA (those tests live in the auditledger
// integration tests).
var testCorpus = func() [sha256.Size]byte {
	var c [sha256.Size]byte
	for i := range c {
		c[i] = byte(i)
	}
	return c
}()

var testKey = []byte("iik_test_TRIAL_LEDGER_unit_test_key_2026")

func TestSign_PrefixAndShape(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	mark := m.Sign([]byte("hello"))
	if !strings.HasPrefix(mark, MarkPrefix) {
		t.Fatalf("mark missing prefix: %q", mark)
	}
	// 8-char prefix + 54-char base64url body = 62 chars total.
	if got, want := len(mark), len(MarkPrefix)+54; got != want {
		t.Fatalf("mark length: got %d want %d (mark=%q)", got, want, mark)
	}
}

func TestSign_DeterministicForSameInputs(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	a := m.Sign([]byte("trial-audit-001"))
	b := m.Sign([]byte("trial-audit-001"))
	if a != b {
		t.Fatalf("Sign must be deterministic: a=%q b=%q", a, b)
	}
}

func TestSign_DifferentPayloadDifferentMark(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	a := m.Sign([]byte("audit-001"))
	b := m.Sign([]byte("audit-002"))
	if a == b {
		t.Fatalf("distinct payloads must produce distinct marks")
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	payload := []byte("clinical-trial-audit-record-canonical-bytes")
	mark := m.Sign(payload)

	ok, err := Verify(mark, testCorpus, payload, testKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !ok {
		t.Fatalf("Verify ok=false on round-trip")
	}
}

func TestVerify_PayloadTamperingDetected(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	mark := m.Sign([]byte("original"))

	ok, err := Verify(mark, testCorpus, []byte("tampered"), testKey)
	if ok {
		t.Fatalf("Verify must return false on payload tamper")
	}
	if err != ErrSignatureMismatch {
		t.Fatalf("Verify err: got %v want ErrSignatureMismatch", err)
	}
}

func TestVerify_CorpusMismatchDetected(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	mark := m.Sign([]byte("payload"))

	var differentCorpus [sha256.Size]byte
	for i := range differentCorpus {
		differentCorpus[i] = 0xff
	}
	ok, err := Verify(mark, differentCorpus, []byte("payload"), testKey)
	if ok {
		t.Fatalf("Verify must return false on corpus mismatch")
	}
	if err != ErrCorpusMismatch {
		t.Fatalf("Verify err: got %v want ErrCorpusMismatch", err)
	}
}

func TestVerify_WrongKeyDetected(t *testing.T) {
	m := NewMirrorMarker(testCorpus, testKey)
	mark := m.Sign([]byte("payload"))

	ok, err := Verify(mark, testCorpus, []byte("payload"), []byte("wrong_key"))
	if ok {
		t.Fatalf("Verify must return false on wrong key")
	}
	if err != ErrSignatureMismatch {
		t.Fatalf("Verify err: got %v want ErrSignatureMismatch", err)
	}
}

func TestVerify_UnknownVersion(t *testing.T) {
	ok, err := Verify("bogus@v9:notamark", testCorpus, nil, testKey)
	if ok {
		t.Fatalf("Verify must return false for unknown version prefix")
	}
	if err != ErrUnknownMarkVersion {
		t.Fatalf("Verify err: got %v want ErrUnknownMarkVersion", err)
	}
}

func TestVerify_MalformedBody(t *testing.T) {
	ok, err := Verify(MarkPrefix+"not-base64!", testCorpus, nil, testKey)
	if ok {
		t.Fatalf("Verify must return false for malformed body")
	}
	if err != ErrMalformedMark {
		t.Fatalf("Verify err: got %v want ErrMalformedMark", err)
	}
}

func TestNewMirrorMarkerFromEnv_UsesPlaceholdersWhenUnset(t *testing.T) {
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "")

	m := NewMirrorMarkerFromEnv()
	c, k := m.UsingPlaceholders()
	if !c || !k {
		t.Fatalf("expected both placeholders active, got corpus=%v key=%v", c, k)
	}
}

func TestNewMirrorMarkerFromEnv_LoudOnceWarning(t *testing.T) {
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "")

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	m := NewMirrorMarkerFromEnv()
	_ = m.Sign([]byte("first"))
	_ = m.Sign([]byte("second"))
	_ = m.Sign([]byte("third"))

	out := buf.String()
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("expected WARNING in log output, got: %q", out)
	}
	// LOUD-ONCE: WARNING substring appears exactly once across multiple
	// signs.
	if got := strings.Count(out, "WARNING"); got != 1 {
		t.Fatalf("R143 LOUD-ONCE-WARNING-FLAG violated: WARNING count=%d, want 1; log:\n%s", got, out)
	}
}

func TestNewMirrorMarkerFromEnv_ReadsHexCorpusSHA(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "corpus.hex"
	// Write 64-char hex.
	hexSHA := strings.Repeat("ab", sha256.Size)
	if err := os.WriteFile(path, []byte(hexSHA+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", path)
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "iik_unit_test")

	m := NewMirrorMarkerFromEnv()
	c, k := m.UsingPlaceholders()
	if c || k {
		t.Fatalf("expected no placeholders, got corpus=%v key=%v", c, k)
	}

	gotCorpus := m.CorpusSHA()
	wantBytes, _ := hex.DecodeString(hexSHA)
	if !bytes.Equal(gotCorpus[:], wantBytes) {
		t.Fatalf("corpus SHA mismatch")
	}
}

// TestSignVerify_PackageLevelParity confirms the package-level Sign
// matches the MirrorMarker.Sign byte-for-byte (R157 substrate-native:
// both APIs route through the same primitive).
func TestSignVerify_PackageLevelParity(t *testing.T) {
	payload := []byte("audit-record")
	m := NewMirrorMarker(testCorpus, testKey)

	a := m.Sign(payload)
	b := Sign(testCorpus, payload, testKey)
	if a != b {
		t.Fatalf("MirrorMarker.Sign vs Sign: a=%q b=%q", a, b)
	}
}
