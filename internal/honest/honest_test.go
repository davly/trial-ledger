package honest

import (
	"bytes"
	"strings"
	"testing"
)

// TestCanonicalAdvisories_Count pins the 5-entry inception baseline.
// Any new advisory MUST update this number (and the SECURITY.md
// row) — the test catches forgotten parity.
func TestCanonicalAdvisories_Count(t *testing.T) {
	const wantCount = 5
	if got := len(CanonicalAdvisories()); got != wantCount {
		t.Fatalf("canonical advisory count: got %d want %d", got, wantCount)
	}
}

// TestCanonicalAdvisories_PinnedCodes pins every advisory code
// byte-for-byte. The Code is the grep-stable identifier — any
// rename is a regulator-facing log-aggregation breakage.
func TestCanonicalAdvisories_PinnedCodes(t *testing.T) {
	want := []string{
		"TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED",
		"TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA",
		"TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER",
		"TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL",
		"TRIAL_LEDGER_IRB_APPROVAL_REQUIRED",
	}
	got := CanonicalAdvisories()
	if len(got) != len(want) {
		t.Fatalf("count mismatch: got %d want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Code != w {
			t.Fatalf("advisory[%d].Code: got %q want %q", i, got[i].Code, w)
		}
	}
}

// TestCanonicalAdvisories_SeverityLadder confirms the R143.A
// SEVERITY-LADDER-CONVENTION 3-rung allocation: 3 Error (FDA
// 21 CFR 11 audit trail + Article 9 + electronic signature) + 2
// Warn (investigator signoff + IRB approval).
func TestCanonicalAdvisories_SeverityLadder(t *testing.T) {
	cases := map[string]Severity{
		"TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED": SeverityError,
		"TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA":                      SeverityError,
		"TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER":           SeverityError,
		"TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL":          SeverityWarn,
		"TRIAL_LEDGER_IRB_APPROVAL_REQUIRED":                      SeverityWarn,
	}
	for code, wantSev := range cases {
		adv, ok := FindAdvisory(code)
		if !ok {
			t.Fatalf("advisory not found: %s", code)
		}
		if adv.Severity != wantSev {
			t.Errorf("advisory %s severity: got %q want %q", code, adv.Severity, wantSev)
		}
	}
}

// TestCanonicalAdvisories_DocLinksValid confirms every advisory
// points to either SECURITY.md or CONTEXT.md (the only two
// load-bearing top-level doc files).
func TestCanonicalAdvisories_DocLinksValid(t *testing.T) {
	valid := map[string]bool{"SECURITY.md": true, "CONTEXT.md": true}
	for _, adv := range CanonicalAdvisories() {
		if !valid[adv.DocLink] {
			t.Errorf("advisory %s docLink %q is not SECURITY.md or CONTEXT.md", adv.Code, adv.DocLink)
		}
	}
}

// TestLoudOnce_FiresExactlyOnce is the R143 LOUD-ONCE-WARNING-FLAG
// behavioural pin. Same advisory, three calls → one log line.
func TestLoudOnce_FiresExactlyOnce(t *testing.T) {
	t.Cleanup(Reset)

	adv, _ := FindAdvisory("TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED")
	var buf bytes.Buffer
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)

	got := strings.Count(buf.String(), LoudOncePrefix)
	if got != 1 {
		t.Fatalf("R143 LOUD-ONCE: prefix count=%d want 1; output:\n%s", got, buf.String())
	}
}

// TestLoudOnce_DistinctAdvisoriesFireIndependently confirms two
// different codes each get one log line (the once-registry is keyed
// by Code, not global).
func TestLoudOnce_DistinctAdvisoriesFireIndependently(t *testing.T) {
	t.Cleanup(Reset)

	a, _ := FindAdvisory("TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED")
	b, _ := FindAdvisory("TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA")

	var buf bytes.Buffer
	LoudOnce(a, &buf)
	LoudOnce(b, &buf)
	LoudOnce(a, &buf) // repeat — no-op
	LoudOnce(b, &buf) // repeat — no-op

	got := strings.Count(buf.String(), LoudOncePrefix)
	if got != 2 {
		t.Fatalf("R143 LOUD-ONCE per-code: prefix count=%d want 2; output:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED") {
		t.Errorf("missing FDA advisory line")
	}
	if !strings.Contains(buf.String(), "TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA") {
		t.Errorf("missing Article-9 advisory line")
	}
}

func TestLoudOnce_MessageContainsSeverityAndCode(t *testing.T) {
	t.Cleanup(Reset)

	adv, _ := FindAdvisory("TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER")
	var buf bytes.Buffer
	LoudOnce(adv, &buf)

	out := buf.String()
	if !strings.Contains(out, "ERROR") {
		t.Errorf("missing severity ERROR in output: %q", out)
	}
	if !strings.Contains(out, "TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER") {
		t.Errorf("missing code in output: %q", out)
	}
	if !strings.Contains(out, LoudOncePrefix) {
		t.Errorf("missing LoudOncePrefix: %q", out)
	}
}

func TestFindAdvisory_UnknownReturnsFalse(t *testing.T) {
	_, ok := FindAdvisory("NOT_A_REAL_ADVISORY")
	if ok {
		t.Fatalf("FindAdvisory should return ok=false for unknown code")
	}
}

// TestCanonicalAdvisories_ReturnsCopy confirms callers cannot mutate
// the canonical list (defensive copy contract).
func TestCanonicalAdvisories_ReturnsCopy(t *testing.T) {
	a := CanonicalAdvisories()
	a[0].Code = "MUTATED"
	b := CanonicalAdvisories()
	if b[0].Code == "MUTATED" {
		t.Fatalf("CanonicalAdvisories must return a copy; package state was mutated")
	}
}
