// Package stele — minimal stdlib-only client that anchors a
// trial-ledger FDA 21 CFR Part 11 §11.10(e) audit-trail run into the
// Stele verified-trust spine (infrastructure/stele) via
// POST /v1/verdicts.
//
// 2026-06-11 third flagship consumer wire to the spine (after
// ofgemwatch + bias-audit; R145.C package registration + paired
// R145.B confinement pin in internal/firewall/). This is a
// deliberately LOCAL mirror of the spine wire-contract — the same
// pattern as nexus's internal stele_client — because trial-ledger's
// go.mod is zero-requires (R174 cohort discipline, grep-verified in
// SECURITY.md) and MUST NOT import the stele Go module.
//
// OFF BY DEFAULT: the CLI anchors only when TRIAL_LEDGER_STELE_URL is
// set (see EnvURL; the name follows the repo's TRIAL_LEDGER_* env
// convention). Unset/empty = disabled = no HTTP, no new output,
// behavior identical to a non-anchoring build.
//
// The anchor COMPLEMENTS — it does NOT replace — the Mirror-Mark
// cold-verifiability property (R175): an FDA reviewer still
// re-derives every row's mark offline from (corpusSHA, key) without
// trusting trial-ledger OR the spine. The spine entry adds an
// independent tamper-evident timestamped seal OVER the whole-run
// ledger digest.
//
// HONESTY CONTRACT (load-bearing):
//
//   - The anchor verdict is LIT only after the audit ledger passes
//     auditledger.SelfCheck(). A failed self-check seals NOTHING and
//     the CLI fails loudly.
//   - oracle_strength is "Self-Check" and the evidence sentence says
//     so explicitly: the oracle is trial-ledger's own ledger
//     verifier, NOT an independent gauntlet.
//   - subject_hash binds the spine entry to the exact ledger content:
//     sha256 hex over the canonical run serialization defined at
//     auditledger.(*Ledger).SelfCheck (JSONL of Record in append
//     order).
//   - A "sealed" receipt is only ever reported on HTTP 201 WITH an
//     entry_hash in the response body.
package stele

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EnvURL is the environment variable holding the Stele spine base URL
// (e.g. "http://localhost:8097"). Empty/unset disables anchoring
// entirely. This is trial-ledger's third env read (after the two
// mirrormark boot reads); the R145.B firewall pin confines it to a
// single call site in cmd/trial-ledger.
const EnvURL = "TRIAL_LEDGER_STELE_URL"

// Substrate is the spine substrate identifier for trial-ledger's
// audit-trail anchors.
const Substrate = "flagships/trial-ledger/audit-ledger"

// OracleStrengthSelfCheck is the honest oracle-strength label for an
// audit-trail anchor: the verifier is trial-ledger itself.
const OracleStrengthSelfCheck = "Self-Check"

// Verdict is the POST /v1/verdicts request body — a local mirror of
// the spine's verdictRequest wire contract
// (infrastructure/stele/internal/api/server.go).
type Verdict struct {
	Substrate      string `json:"substrate"`
	Verdict        string `json:"verdict"`
	Severity       string `json:"severity"`
	Location       string `json:"location"`
	Evidence       string `json:"evidence"`
	OracleStrength string `json:"oracle_strength"`
	SealedAt       string `json:"sealed_at"`
	GauntletRun    string `json:"gauntlet_run"`
	SubjectHash    string `json:"subject_hash"`
}

// Receipt is the spine's proof-of-seal: the sealed entry's sequence
// number + entry hash from the 201 response.
type Receipt struct {
	Seq       int
	EntryHash string
}

// SelfChecker is the slice of *auditledger.Ledger the anchor consumes
// (kept as a local interface so this package stays decoupled and the
// seam is trivially fakeable in tests).
type SelfChecker interface {
	SelfCheck() (int, [sha256.Size]byte, error)
}

// Client is a minimal HTTP client for the Stele spine. 5s timeout,
// stdlib only.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient constructs a Client for the given spine base URL.
//
// The http.Client REFUSES to follow redirects (CheckRedirect returns a
// non-nil error). A 21 CFR Part 11 audit seal must POST the §11.10(e)
// ledger digest DIRECTLY to the operator-configured spine — never to a
// 3xx redirect target. A misconfigured, man-in-the-middled (the docs
// use plaintext http://), or compromised spine that answers 302 would
// otherwise re-issue the seal POST to an attacker-controlled host; if
// that host replied 201 + entry_hash the run would read as "sealed" at
// the genuine spine when it was actually sealed elsewhere — a direct
// breach of the package's load-bearing HONESTY CONTRACT. A refused
// redirect surfaces (via Seal's `stele seal: %w`) as a loud non-nil
// error with anchored=false, exactly like any other failed seal.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("stele: refusing redirect to %q — a 21 CFR Part 11 audit seal must POST directly to the configured spine, not a redirect target", req.URL)
			},
		},
	}
}

// NewRunAnchor builds the canonical run-anchor verdict for a command's
// audit ledger. Callers MUST only invoke this after a PASSING
// SelfCheck — the verdict is unconditionally LIT because the no-pass
// path seals nothing at all (fail-loud, enforced in AnchorRun).
func NewRunAnchor(command string, entries int, ledgerDigest [sha256.Size]byte, sealedAt time.Time) Verdict {
	digestHex := hex.EncodeToString(ledgerDigest[:])
	return Verdict{
		Substrate: Substrate,
		Verdict:   "LIT",
		Severity:  "n/a",
		Location:  Substrate + "@" + command,
		Evidence: fmt.Sprintf(
			"21 CFR Part 11 audit-trail run self-check: %d entries, ledger digest %s; oracle is trial-ledger's own ledger verifier (self-check, NOT an independent gauntlet)",
			entries, digestHex[:16]),
		OracleStrength: OracleStrengthSelfCheck,
		SealedAt:       sealedAt.UTC().Format(time.RFC3339),
		GauntletRun:    "",
		SubjectHash:    digestHex,
	}
}

// Seal POSTs the verdict to /v1/verdicts and returns the spine
// receipt. It returns an error — and the caller MUST NOT claim the
// anchor happened — unless the spine answered 201 Created with a
// non-empty entry_hash.
func (c *Client) Seal(v Verdict) (Receipt, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: marshal: %w", err)
	}
	resp, err := c.http.Post(c.baseURL+"/v1/verdicts", "application/json", bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: read response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("stele seal: status %d (want 201): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Sealed struct {
			Seq       int    `json:"seq"`
			EntryHash string `json:"entry_hash"`
		} `json:"sealed"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Receipt{}, fmt.Errorf("stele seal: decode response: %w", err)
	}
	if out.Sealed.EntryHash == "" {
		return Receipt{}, errors.New("stele seal: got 201 but no sealed.entry_hash in response — refusing to claim anchored")
	}
	return Receipt{Seq: out.Sealed.Seq, EntryHash: out.Sealed.EntryHash}, nil
}

// AnchorRun is the single CLI anchoring seam.
//
//   - url empty/whitespace → DISABLED: returns (zero, false, nil)
//     without touching the ledger or the network (zero behavior
//     change vs. a non-anchoring run).
//   - ledger self-check fails → seals NOTHING, returns a non-nil
//     error (an integrity-suspect §11.10(e) audit trail must never
//     be anchored LIT).
//   - seal fails (network / non-201 / no entry_hash) → non-nil error;
//     anchored stays false.
//   - success → (receipt, true, nil); only then may the caller print
//     a sealed claim.
func AnchorRun(url, command string, ledger SelfChecker, now time.Time) (Receipt, bool, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return Receipt{}, false, nil
	}
	entries, digest, err := ledger.SelfCheck()
	if err != nil {
		return Receipt{}, false, fmt.Errorf("refusing to anchor: %w", err)
	}
	rcpt, err := NewClient(url).Seal(NewRunAnchor(command, entries, digest, now))
	if err != nil {
		return Receipt{}, false, err
	}
	return rcpt, true, nil
}
