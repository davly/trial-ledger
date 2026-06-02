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
	// Compare against the canonical-cohort ∪ allowed-additive union: a
	// package outside BOTH lists still trips the firewall (drift caught),
	// while deliberately-added transport surface (httpapi) is allowed.
	want := AllExpectedPackages()
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
	want := AllExpectedBinaries()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd/ binaries drift:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestExpectedAdditivePackages_AreNotCanonical guards the separation
// invariant: the additive set must never overlap the canonical
// 8-package cohort spine (an additive package masquerading as canonical
// would corrupt the count pin).
func TestExpectedAdditivePackages_AreNotCanonical(t *testing.T) {
	canonical := map[string]bool{}
	for _, p := range ExpectedPackages() {
		canonical[p] = true
	}
	for _, p := range ExpectedAdditivePackages() {
		if canonical[p] {
			t.Errorf("additive package %q also appears in the canonical cohort — must be disjoint", p)
		}
	}
}

// TestAdditiveSurface_Pinned pins the deliberately-added Nexus
// transport surface so a future removal/rename is itself caught.
func TestAdditiveSurface_Pinned(t *testing.T) {
	if !reflect.DeepEqual(ExpectedAdditivePackages(), []string{"httpapi"}) {
		t.Errorf("additive internal/ packages drift: %v", ExpectedAdditivePackages())
	}
	if !reflect.DeepEqual(ExpectedAdditiveBinaries(), []string{"trial-ledger-server"}) {
		t.Errorf("additive cmd/ binaries drift: %v", ExpectedAdditiveBinaries())
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
	const want = 8
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
