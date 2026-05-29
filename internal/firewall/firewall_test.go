package firewall

import (
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// repoRoot returns the path to the trial-ledger repo root by walking
// up from this test file location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, this, _, _ := runtime.Caller(0)
	// this: <root>/internal/firewall/firewall_test.go
	dir := filepath.Dir(this)
	// up to internal/
	dir = filepath.Dir(dir)
	// up to repo root.
	dir = filepath.Dir(dir)
	return dir
}

func TestScanInternal_MatchesExpected(t *testing.T) {
	root := repoRoot(t)
	got, err := ScanInternal(root)
	if err != nil {
		t.Fatalf("ScanInternal: %v", err)
	}
	want := ExpectedPackages()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("internal/ packages drift:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestScanCmd_MatchesExpected(t *testing.T) {
	root := repoRoot(t)
	got, err := ScanCmd(root)
	if err != nil {
		t.Fatalf("ScanCmd: %v", err)
	}
	want := ExpectedBinaries()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd/ binaries drift:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestExpectedPackages_Sorted(t *testing.T) {
	pkgs := ExpectedPackages()
	for i := 1; i < len(pkgs); i++ {
		if pkgs[i-1] >= pkgs[i] {
			t.Fatalf("ExpectedPackages not sorted: %v", pkgs)
		}
	}
}

func TestExpectedPackages_CanonicalCount(t *testing.T) {
	// 8 inception + 1 R145.B additive (`trust` adoption of
	// escape-service, IMP-T2-12 Phase 3 MHRA-jurisdiction).
	const want = 9
	if got := len(ExpectedPackages()); got != want {
		t.Fatalf("ExpectedPackages count: got %d want %d", got, want)
	}
}

// TestExpectedPackages_AllCohortSpineNamesPresent confirms the
// canonical R143/R150/R151/R145.C cohort spine packages are all
// listed. The cohort-firewall property.
func TestExpectedPackages_AllCohortSpineNamesPresent(t *testing.T) {
	pkgs := ExpectedPackages()
	idx := map[string]bool{}
	for _, p := range pkgs {
		idx[p] = true
	}
	cohortSpine := []string{"firewall", "honest", "lore", "manifest", "mirrormark"}
	for _, name := range cohortSpine {
		if !idx[name] {
			t.Errorf("cohort-spine package %q missing from ExpectedPackages", name)
		}
	}
}

// TestExpectedPackages_TrialLedgerDomainPackagesPresent confirms the
// trial-ledger-specific domain primitives (auditledger + fdacfr11 +
// legal) are listed.
func TestExpectedPackages_TrialLedgerDomainPackagesPresent(t *testing.T) {
	pkgs := ExpectedPackages()
	idx := map[string]bool{}
	for _, p := range pkgs {
		idx[p] = true
	}
	domain := []string{"auditledger", "fdacfr11", "legal"}
	for _, name := range domain {
		if !idx[name] {
			t.Errorf("trial-ledger domain package %q missing from ExpectedPackages", name)
		}
	}
}

func TestExpectedBinaries_TrialLedger(t *testing.T) {
	bins := ExpectedBinaries()
	if len(bins) != 1 || bins[0] != "trial-ledger" {
		t.Fatalf("ExpectedBinaries: got %v want [trial-ledger]", bins)
	}
}

// TestModulePathLooksRight is a sanity check on the go.mod module
// path — the cohort honours github.com/davly/<flagship>.
func TestModulePathLooksRight(t *testing.T) {
	// trivial guard: this test file imports firewall from the
	// trial-ledger module; if the import path didn't resolve, the
	// build would fail. The check verifies the path is what we
	// expect by string-matching the import path of THIS file.
	if !strings.HasSuffix(repoRoot(t), "trial-ledger") {
		t.Fatalf("repo root path tail mismatch: %s", repoRoot(t))
	}
}
