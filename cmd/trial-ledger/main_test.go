package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/davly/trial-ledger/internal/auditledger"
)

// TestRunAppend_EndToEnd is the integration pin: feed two
// AppendInput rows in, observe two Record rows out, both stamped
// with Mirror-Marks.
func TestRunAppend_EndToEnd(t *testing.T) {
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "iik_unit_test_trial_ledger")

	in := strings.NewReader(`{"action":"ecr.create","actor":"alice","trialId":"NCT-001","recordRef":"r1","detail":"first append"}
{"action":"esig.sign","actor":"bob","trialId":"NCT-001","subjectId":"S-007","recordRef":"r1","recordHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","detail":"investigator sign"}
`)
	var out bytes.Buffer

	if err := runAppend(in, &out); err != nil {
		t.Fatalf("runAppend: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 Record lines, got %d: %q", len(lines), out.String())
	}

	for i, line := range lines {
		var r auditledger.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decode line %d: %v", i, err)
		}
		if r.MirrorMark == "" {
			t.Fatalf("R175 violated: Record[%d] has empty MirrorMark", i)
		}
		if !strings.HasPrefix(r.MirrorMark, "lore@v1:") {
			t.Errorf("Record[%d] MirrorMark missing prefix: %q", i, r.MirrorMark)
		}
		if r.ID == 0 {
			t.Errorf("Record[%d] ID is zero", i)
		}
	}
}

func TestRunAppend_RejectsInvalidJSON(t *testing.T) {
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "iik_unit_test")

	in := strings.NewReader(`not-json-at-all
`)
	var out bytes.Buffer
	if err := runAppend(in, &out); err == nil {
		t.Fatalf("invalid JSON must produce error")
	}
}

func TestRunAppend_RejectsInvalidAction(t *testing.T) {
	t.Setenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH", "")
	t.Setenv("TRIAL_LEDGER_MIRRORMARK_KEY", "iik_unit_test")

	in := strings.NewReader(`{"action":"bogus.action","actor":"a","trialId":"T","recordRef":"r"}
`)
	var out bytes.Buffer
	if err := runAppend(in, &out); err == nil {
		t.Fatalf("invalid action must produce error (closed-enum R115)")
	}
}

func TestRunAdvisories_PrintsAllFive(t *testing.T) {
	var buf bytes.Buffer
	runAdvisories(&buf)
	out := buf.String()
	want := []string{
		"TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED",
		"TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA",
		"TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER",
		"TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL",
		"TRIAL_LEDGER_IRB_APPROVAL_REQUIRED",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("advisories output missing %q\nOutput:\n%s", w, out)
		}
	}
}

func TestVersionConst_HasPhaseShape(t *testing.T) {
	if !strings.Contains(version, "phase") {
		t.Fatalf("version %q should signal phase-1 MVP", version)
	}
}
