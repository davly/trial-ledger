// Package mirrormark implements the cohort L43 Mirror-Mark v1 receipt
// algorithm — byte-identical to foundation/pkg/mirrormark and to every
// cohort Go port (canopy / casino / ledger / pulse / baseline / oracle
// / iris / foundry / nexus / ouroboros / harvest / inkwell / ...).
//
// A Mirror-Mark is a 62-character receipt stamped on a canonical
// payload that proves: (a) which lore corpus signed it (8-byte
// prefix), (b) the payload was unmodified since signing
// (HMAC-SHA256 with corpus-prefixed input). The cohort uses
// Mirror-Marks to gate regulator-grade-AI artefacts: any output that
// crosses a trust boundary carries a Mark, and any consumer with the
// corpus SHA + the key can cold-verify the receipt without trusting
// the upstream.
//
// Why trial-ledger consumes this WIRE-LOAD-BEARING from inception
// (R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION saturator):
//
//   - trial-ledger's namesake function — appending an FDA 21 CFR
//     Part 11 audit record — STAMPS A MIRROR-MARK ON EVERY APPEND
//     in the production caller path. The mark is not optional
//     library-only scaffolding; it is the load-bearing
//     cold-verifiable receipt without which a 21 CFR Part 11
//     §11.10(e) "computer-generated, time-stamped audit trail"
//     submission cannot be independently re-derived by the FDA
//     reviewer.
//   - Byte-identical algorithm to foundation/pkg/mirrormark — the
//     N-of-N byte-identical implementation IS the cohort firewall.
//     A future R145-strict additive sweep can replace this package
//     with `import "github.com/davly/foundation/pkg/mirrormark"`;
//     today the local implementation lets trial-ledger stay
//     zero-`go.mod`-requires without a foundation hard-dep.
//   - The MirrorMarker constructor reads two env vars
//     (TRIAL_LEDGER_LORE_CORPUS_SHA_PATH +
//     TRIAL_LEDGER_MIRRORMARK_KEY); when EITHER is absent, the
//     marker logs ONCE via the R143 LOUD-ONCE-WARNING-FLAG
//     discipline that it is emitting marks that will NOT pass
//     cold-verify against a real lore corpus. This is the only
//     mirrormark-init path the production CLI uses — there is no
//     non-marked code path through `internal/auditledger.Append`.
//
// Mark format (byte-identical to foundation/pkg/mirrormark):
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || payload, key) )
//
// Resulting in a fixed 62-character string: `lore@v1:` prefix (8
// chars) + 54-char base64url body (40 raw bytes encoded).
package mirrormark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
)

// MarkVersion is the 1-byte tag prefixing the HMAC input. Identical to
// foundation/pkg/mirrormark.MarkVersion.
const MarkVersion byte = 0x01

// MarkPrefix is the documented header-value prefix.
const MarkPrefix = "lore@v1:"

// MarkCorpusPrefixLen is the corpus-SHA prefix length (8 bytes).
const MarkCorpusPrefixLen = 8

// MarkBodyLen is the unencoded length of the mark body (40 bytes).
// Base64URL-encoded, this becomes the fixed 54-character suffix.
const MarkBodyLen = MarkCorpusPrefixLen + sha256.Size

// devKeyPlaceholder is the loud-by-name dev key. Production callers
// MUST override via TRIAL_LEDGER_MIRRORMARK_KEY — the prefix
// `iik_dev_TRIAL_LEDGER_` makes any leaked-to-prod use grep-loud.
const devKeyPlaceholder = "iik_dev_TRIAL_LEDGER_NOT_FOR_PRODUCTION"

// Sentinel errors mirror Nexus + folio + ledger byte-for-byte. Callers
// branch on these without string-matching err.Error().
var (
	ErrMalformedMark      = errors.New("mirrormark: malformed mark string")
	ErrUnknownMarkVersion = errors.New("mirrormark: unknown mark version (missing 'lore@v1:' prefix)")
	ErrCorpusMismatch     = errors.New("mirrormark: corpus SHA prefix mismatch (mark signed by different corpus)")
	ErrSignatureMismatch  = errors.New("mirrormark: HMAC signature mismatch (payload tampered or wrong key)")
)

// MirrorMarker holds the (corpusSHA, key) pair used to sign and verify
// marks. One instance per trial-ledger process; constructed once at
// boot via NewMirrorMarkerFromEnv.
//
// Goroutine-safe: corpusSHA + key are immutable once constructed.
type MirrorMarker struct {
	corpusSHA [sha256.Size]byte
	key       []byte

	usingPlaceholderCorpus bool
	usingPlaceholderKey    bool

	// warnedOnce ensures the placeholder warning fires exactly once
	// per MirrorMarker instance (R143 LOUD-ONCE-WARNING-FLAG).
	warnedOnce sync.Once
}

// NewMirrorMarkerFromEnv reads the canonical
// TRIAL_LEDGER_LORE_CORPUS_SHA_PATH + TRIAL_LEDGER_MIRRORMARK_KEY env
// vars and returns a configured MirrorMarker.
//
// Either var being absent triggers a one-shot WARN log on first emit,
// not an error — trial-ledger must remain emit-able even when
// corpus/key are not yet wired. Production deploys MUST set both
// vars; tests assert the warning surfaces.
func NewMirrorMarkerFromEnv() *MirrorMarker {
	m := &MirrorMarker{}

	corpusPath := os.Getenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH")
	if corpusPath == "" {
		m.usingPlaceholderCorpus = true
	} else if sha, err := readCorpusSHAFile(corpusPath); err == nil {
		m.corpusSHA = sha
	} else {
		log.Printf("trial-ledger mirrormark: WARNING — failed to read corpus SHA from %q: %v; falling back to placeholder bytes (emitted marks will NOT pass cold-verify)",
			corpusPath, err)
		m.usingPlaceholderCorpus = true
	}

	key := os.Getenv("TRIAL_LEDGER_MIRRORMARK_KEY")
	if key == "" {
		key = devKeyPlaceholder
		m.usingPlaceholderKey = true
	} else if !strings.HasPrefix(key, "iik_") {
		log.Printf("trial-ledger mirrormark: WARNING — TRIAL_LEDGER_MIRRORMARK_KEY does not start with iik_ (Nexus spec); using as supplied")
	}
	m.key = []byte(key)

	return m
}

// NewMirrorMarker constructs a marker with explicit (corpusSHA, key)
// — the test-friendly entry point. Production uses
// NewMirrorMarkerFromEnv.
func NewMirrorMarker(corpusSHA [sha256.Size]byte, key []byte) *MirrorMarker {
	return &MirrorMarker{corpusSHA: corpusSHA, key: key}
}

// UsingPlaceholders reports whether boot fell back to the dev corpus
// or dev key. An FDA pre-flight check can refuse to consume marks
// from a placeholder-mode instance by inspecting this.
func (m *MirrorMarker) UsingPlaceholders() (corpus, key bool) {
	return m.usingPlaceholderCorpus, m.usingPlaceholderKey
}

// CorpusSHA returns the corpus SHA the marker is configured with. An
// FDA reviewer needs this value (alongside the key) to cold-verify
// marks. The returned array is a copy; callers cannot mutate the
// marker through it.
func (m *MirrorMarker) CorpusSHA() [sha256.Size]byte {
	var out [sha256.Size]byte
	copy(out[:], m.corpusSHA[:])
	return out
}

// Sign returns the canonical Mirror-Mark string for the given payload
// bytes. Byte-identical to foundation/pkg/mirrormark.Sign + ledger +
// folio + canopy + casino + ...
//
// In trial-ledger, payload is typically the canonical bytes of an
// audit-ledger record (see internal/auditledger.Record.CanonicalBytes).
//
// Per R143, fires the placeholder WARN exactly once per instance.
func (m *MirrorMarker) Sign(payload []byte) string {
	if m.usingPlaceholderCorpus || m.usingPlaceholderKey {
		m.warnedOnce.Do(func() {
			log.Printf("trial-ledger mirrormark: WARNING — using placeholder %s%s; emitted marks will NOT pass cold-verify against a real lore corpus / production key",
				placeholderDescr(m.usingPlaceholderCorpus, "corpus"),
				placeholderDescr(m.usingPlaceholderKey, "key"))
		})
	}

	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(m.corpusSHA[:])
	_, _ = mac.Write(payload)
	digest := mac.Sum(nil)

	body := make([]byte, 0, MarkBodyLen)
	body = append(body, m.corpusSHA[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)
	return MarkPrefix + base64.RawURLEncoding.EncodeToString(body)
}

// Sign is a package-level convenience byte-identical to
// canopy/casino/baseline. Used by tests that don't want to construct
// a MirrorMarker.
func Sign(corpusSHA [sha256.Size]byte, payload []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	digest := mac.Sum(nil)

	body := make([]byte, 0, MarkBodyLen)
	body = append(body, corpusSHA[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)
	return MarkPrefix + base64.RawURLEncoding.EncodeToString(body)
}

// VerifyMark cold-checks a mark against THIS marker's bound (corpus,
// key) over payload — the instance-method counterpart to Sign, added
// so a caller that signed via marker.Sign can re-verify without the key
// ever leaving the MirrorMarker. Returns (true, nil) on round-trip
// success; one of the typed sentinel errors otherwise.
//
// Purely additive: it is a read-only convenience over the existing
// package-level Verify and the marker's immutable (corpusSHA, key); it
// does not touch the sign path or the wire format. Used by the additive
// `.evidence`-bundle export path for its pre-emit Mirror-Mark self-check.
func (m *MirrorMarker) VerifyMark(mark string, payload []byte) (bool, error) {
	return Verify(mark, m.corpusSHA, payload, m.key)
}

// Verify cold-checks a Mirror-Mark against the caller's (corpus,
// payload, key) triple. Returns (true, nil) on round-trip success;
// one of the typed sentinel errors on any failure.
//
// Both byte-comparisons use hmac.Equal (constant-time) — timing-safe.
//
// Cold-verify contract: this function is pure — no MirrorMarker
// instance is required. An FDA / IRB reviewer with (lore.tar.gz,
// canonical record bytes, key) re-runs Verify against a trial-ledger-
// emitted mark from the audit-ledger file.
func Verify(mark string, corpusSHA [sha256.Size]byte, payload []byte, key []byte) (bool, error) {
	if !strings.HasPrefix(mark, MarkPrefix) {
		return false, ErrUnknownMarkVersion
	}
	encoded := strings.TrimPrefix(mark, MarkPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false, ErrMalformedMark
	}
	if len(body) != MarkBodyLen {
		return false, ErrMalformedMark
	}

	corpusPrefix := body[:MarkCorpusPrefixLen]
	digest := body[MarkCorpusPrefixLen:]

	if !hmac.Equal(corpusPrefix, corpusSHA[:MarkCorpusPrefixLen]) {
		return false, ErrCorpusMismatch
	}

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(digest, expected) {
		return false, ErrSignatureMismatch
	}
	return true, nil
}

// readCorpusSHAFile reads a 32-byte SHA from disk. Two formats
// accepted (mirrors ledger byte-for-byte):
//
//	(1) raw 32 bytes
//	(2) 64 hex chars (with optional trailing newline)
func readCorpusSHAFile(path string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	b, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if len(b) == sha256.Size {
		copy(out[:], b)
		return out, nil
	}
	trimmed := strings.TrimSpace(string(b))
	if len(trimmed) == 2*sha256.Size {
		dec, err := hex.DecodeString(trimmed)
		if err != nil {
			return out, err
		}
		copy(out[:], dec)
		return out, nil
	}
	return out, errors.New("corpus SHA file: expected 32 raw bytes or 64 hex chars")
}

// placeholderDescr renders the warning fragment for the loud-log
// message. Pure stdlib; lives here to keep Sign tidy.
func placeholderDescr(active bool, label string) string {
	if !active {
		return ""
	}
	return label + " "
}
