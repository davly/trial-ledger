// Package firewall implements the R145.C FIREWALL-TEST-DISCIPLINE
// pin for trial-ledger — structural firewall against internal/ +
// cmd/ drift.
//
// trial-ledger ships R145.C-compliant from inception: the 8-package
// (11 since the 2026-06-11 stele-anchor + 2026-05-29 trust-adoption +
// 2026-06-13 wal-persistence amendments) internal/ + 1-binary cmd/
// layout is pinned by ExpectedPackages / ExpectedBinaries here; the
// matching test in firewall_test.go catches additions / deletions
// BEFORE they reach the regulator-facing FDA submission package.
package firewall

import (
	"os"
	"path/filepath"
	"sort"
)

// ExpectedPackages returns the canonical list of internal/ packages
// trial-ledger ships at inception (2026-05-27) plus additive
// amendments layered on afterward.
//
// 11 packages (8 inception + 3 additions):
//
//   - auditledger / fdacfr11 — domain primitives (append-only audit
//     ledger + 21 CFR Part 11 electronic-records + signatures)
//   - legal — Article-9 / 21 CFR / IRB regulatory citations
//   - lore / mirrormark — R151 KAT-1 + L43 Mirror-Mark v1 cohort
//   - manifest / honest — R150 schematised-knowledge + R143
//     LOUD-ONCE-WARNING-FLAG
//   - firewall — this package (R145.C pin itself)
//
// +1 on the R145.B sibling branch claude/stele-anchor-2026-06-11:
//
//   - stele — the opt-in Stele verified-trust-spine anchoring client
//     (paired confinement pin: TestR145B_SteleAnchorConfinement).
//
// +1 on the 2026-05-29 R145.B additive `trust` adoption of
// escape-service:
//
//   - trust — escape-service /v1/escape HTTP-client wrapper
//     (IMP-T2-12 Phase 3 MHRA-jurisdiction adoption; sibling of
//     counsel/internal/trust + moneycheck/internal/trust)
//
// +1 on the R145.C sibling branch claude/wire-data-modeling-schema-2026-06-13:
//
//   - wal — WAL-backed append-log persistence layer (quarry-db
//     trigger-cascade state machine port; Phase 2 durability primitive;
//     stdlib-only, zero new deps; env-read discipline preserved —
//     the WAL path is caller-supplied, no os.Getenv inside wal/).
//
// Total = 11.
func ExpectedPackages() []string {
	return []string{
		"auditledger",
		"fdacfr11",
		"firewall",
		"honest",
		"legal",
		"lore",
		"manifest",
		"mirrormark",
		"stele",
		"trust",
		"wal",
	}
}

// ExpectedAdditivePackages returns internal/ packages added AFTER
// inception as purely-additive surface (NOT part of the canonical
// 8-package cohort spine). They are pinned separately so the drift
// firewall still catches anything that is neither canonical-cohort nor
// a deliberately-allowed addition, while the "canonical cohort = 8"
// invariant (ExpectedPackages + its count pin) stays exact.
//
//   - httpapi — the thin Nexus-facing transport shell over auditledger
//     for the `audit_trail_append` capability (2026-06-02). Pure
//     transport; adds no domain logic.
func ExpectedAdditivePackages() []string {
	return []string{
		"httpapi",
	}
}

// AllExpectedPackages is the union (canonical cohort + allowed
// additive), sorted. The drift test compares on-disk internal/ against
// this set: a package outside BOTH lists still trips the firewall.
func AllExpectedPackages() []string {
	out := append([]string{}, ExpectedPackages()...)
	out = append(out, ExpectedAdditivePackages()...)
	sort.Strings(out)
	return out
}

// ExpectedBinaries returns the canonical list of cmd/<binary>/
// directories shipping a main.go (the inception binary).
func ExpectedBinaries() []string {
	return []string{
		"trial-ledger",
	}
}

// ExpectedAdditiveBinaries returns cmd/<binary>/ directories added
// AFTER inception (purely-additive). Pinned separately from the
// canonical inception binary.
//
//   - trial-ledger-server — the Nexus-facing HTTP producer for
//     `audit_trail_append` (2026-06-02). Thin transport over the same
//     auditledger engine the CLI uses.
func ExpectedAdditiveBinaries() []string {
	return []string{
		"trial-ledger-server",
	}
}

// AllExpectedBinaries is the union (canonical + allowed additive),
// sorted. The cmd/ drift test compares on-disk against this set.
func AllExpectedBinaries() []string {
	out := append([]string{}, ExpectedBinaries()...)
	out = append(out, ExpectedAdditiveBinaries()...)
	sort.Strings(out)
	return out
}

// ScanInternal returns the actual on-disk subdirectory names under
// internal/ that contain at least one .go file. The R145.C
// matchOrFail test compares this to ExpectedPackages().
func ScanInternal(repoRoot string) ([]string, error) {
	return scanGoSubtree(filepath.Join(repoRoot, "internal"))
}

// ScanCmd returns the actual on-disk subdirectory names under cmd/
// that contain a main.go.
func ScanCmd(repoRoot string) ([]string, error) {
	cmdDir := filepath.Join(repoRoot, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mainGo := filepath.Join(cmdDir, e.Name(), "main.go")
		if _, err := os.Stat(mainGo); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func scanGoSubtree(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		subPath := filepath.Join(root, name)
		hasGo, err := dirHasGoFile(subPath)
		if err != nil {
			return nil, err
		}
		if hasGo {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func dirHasGoFile(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".go" {
			return true, nil
		}
	}
	return false, nil
}
