package legal

import (
	"strings"
	"testing"
)

func TestAllCitations_Count(t *testing.T) {
	const want = 9
	if got := len(AllCitations()); got != want {
		t.Fatalf("citation count: got %d want %d", got, want)
	}
}

func TestAllCitations_IDsUnique(t *testing.T) {
	seen := map[string]int{}
	for _, c := range AllCitations() {
		seen[c.ID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("duplicate citation ID %q: %d occurrences", id, n)
		}
	}
}

func TestAllCitations_AllHaveText(t *testing.T) {
	for _, c := range AllCitations() {
		if c.CitationText == "" {
			t.Errorf("citation %s: empty CitationText", c.ID)
		}
		if len(c.CitationText) < 30 {
			t.Errorf("citation %s: CitationText suspiciously short (%d chars)", c.ID, len(c.CitationText))
		}
	}
}

func TestAllCitations_AllHaveURL(t *testing.T) {
	for _, c := range AllCitations() {
		if !strings.HasPrefix(c.RegulatorURL, "http") {
			t.Errorf("citation %s: RegulatorURL must start with http: got %q", c.ID, c.RegulatorURL)
		}
	}
}

func TestAllCitations_JurisdictionEnum(t *testing.T) {
	valid := map[string]bool{"US": true, "UK": true, "EU": true, "ICH": true}
	for _, c := range AllCitations() {
		if !valid[c.Jurisdiction] {
			t.Errorf("citation %s: invalid Jurisdiction %q", c.ID, c.Jurisdiction)
		}
	}
}

// TestAllCitations_FDA21CFR11LoadBearingPresent confirms the
// load-bearing §11.10(e) audit-trail citation is shipped — the
// regulation that justifies trial-ledger's existence.
func TestAllCitations_FDA21CFR11LoadBearingPresent(t *testing.T) {
	want := "FDA_21_CFR_11_10_e"
	found := false
	for _, c := range AllCitations() {
		if c.ID == want {
			found = true
			if !strings.Contains(c.CitationText, "audit trail") {
				t.Errorf("citation %s: missing 'audit trail' in CitationText", c.ID)
			}
		}
	}
	if !found {
		t.Fatalf("load-bearing citation %s not in AllCitations", want)
	}
}

func TestAllCitations_GDPRArticle9Present(t *testing.T) {
	wantIDs := []string{"GDPR_Article_9_1", "GDPR_Article_9_2_j"}
	idx := map[string]bool{}
	for _, c := range AllCitations() {
		idx[c.ID] = true
	}
	for _, want := range wantIDs {
		if !idx[want] {
			t.Errorf("GDPR Article 9 citation %q missing", want)
		}
	}
}

// TestAllCitations_FDAPart11Quartet confirms all four 21 CFR Part 11
// citations (10e + 50 + 70 + 200) are present — the regulator-facing
// quartet that establishes audit-trail + signature-manifestation +
// signature-linkage + two-factor.
func TestAllCitations_FDAPart11Quartet(t *testing.T) {
	wantIDs := []string{
		"FDA_21_CFR_11_10_e",
		"FDA_21_CFR_11_50",
		"FDA_21_CFR_11_70",
		"FDA_21_CFR_11_200",
	}
	idx := map[string]bool{}
	for _, c := range AllCitations() {
		idx[c.ID] = true
	}
	for _, want := range wantIDs {
		if !idx[want] {
			t.Errorf("FDA Part 11 citation %q missing", want)
		}
	}
}
