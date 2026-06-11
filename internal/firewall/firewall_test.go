package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/davly/trial-ledger/internal/stele"
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

// 8 inception packages + the R145.B stele-anchor package
// (2026-06-11; paired pin TestR145B_SteleAnchorConfinement) = 9.
func TestExpectedPackages_CanonicalCount(t *testing.T) {
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

// ---- R145.B stele-anchor paired confinement pins (2026-06-11) ----------

// scanProductionGoFiles walks cmd/ + internal/ and returns every
// non-test .go source file, excluding the firewall package itself
// (this file's patterns would otherwise self-trip).
func scanProductionGoFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	sep := string(filepath.Separator)
	var out []string
	for _, r := range []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal")} {
		_ = filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil // continue walk
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.Contains(path, sep+"firewall"+sep) {
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

// fileContains reports whether the given file contains any of the
// given substring patterns, returning the first hit.
func fileContains(t *testing.T, path string, patterns ...string) (bool, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	src := string(data)
	for _, p := range patterns {
		if strings.Contains(src, p) {
			return true, p
		}
	}
	return false, ""
}

// inSteleDir reports whether path lives under internal/stele/ — the
// ONE package permitted to hold an HTTP client after the R145.B
// stele-anchor amendment (2026-06-11).
func inSteleDir(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"stele"+sep)
}

// TestR145B_SteleAnchorConfinement is the paired regression pin for
// the inception invariants NARROWED on the stele-anchor sibling
// branch (SECURITY.md shipped "no HTTP client" + "two env vars only"
// as grep-verified claims at Phase-1 inception; this pin makes the
// narrowed shape executable). It pins the NEW invariant shape so any
// further drift breaks a test:
//
//  1. every production net/http usage lives under internal/stele/
//     (client-only — listener primitives stay banned EVERYWHERE,
//     including internal/stele/);
//  2. the stele client carries the 5-second timeout;
//  3. env reads stay confined: os.Getenv appears in exactly two
//     production files — internal/mirrormark/mirrormark.go (the two
//     inception boot reads: TRIAL_LEDGER_LORE_CORPUS_SHA_PATH +
//     TRIAL_LEDGER_MIRRORMARK_KEY) and cmd/trial-ledger/main.go
//     (exactly one call, os.Getenv(stele.EnvURL)); os.LookupEnv /
//     os.Environ stay banned everywhere;
//  4. the spine wire-contract constants hold (env var name,
//     substrate, honest oracle-strength label).
func TestR145B_SteleAnchorConfinement(t *testing.T) {
	var netHTTPFiles, getenvFiles []string
	for _, path := range scanProductionGoFiles(t) {
		if hit, _ := fileContains(t, path, `"net/http"`); hit {
			netHTTPFiles = append(netHTTPFiles, path)
		}
		if hit, _ := fileContains(t, path, `os.Getenv(`); hit {
			getenvFiles = append(getenvFiles, path)
		}
		if hit, p := fileContains(t, path,
			`http.ListenAndServe`,
			`net.Listen(`,
			`httptest.NewServer`, // test-double servers belong in _test.go only
		); hit {
			t.Errorf("R145.B pin violation: %s contains %q — HTTP listener primitives are banned everywhere, including internal/stele/", path, p)
		}
		if hit, p := fileContains(t, path, `os.LookupEnv(`, `os.Environ(`); hit {
			t.Errorf("R145.B pin violation: %s contains %q — env reads are confined to os.Getenv in mirrormark (boot) + cmd/trial-ledger (stele.EnvURL)", path, p)
		}
	}

	// (1) net/http confined to internal/stele/ — and present there
	// (the wire is load-bearing, not decorative).
	if len(netHTTPFiles) == 0 {
		t.Errorf("R145.B pin violation: no production file imports net/http — the stele spine wire is gone; re-pin the firewall if this is deliberate")
	}
	for _, path := range netHTTPFiles {
		if !inSteleDir(path) {
			t.Errorf("R145.B pin violation: %s imports net/http outside internal/stele/", path)
		}
	}

	// (2) the stele client keeps its 5s timeout.
	steleSrc := filepath.Join(repoRoot(t), "internal", "stele", "stele.go")
	if hit, _ := fileContains(t, steleSrc, `Timeout: 5 * time.Second`); !hit {
		t.Errorf("R145.B pin violation: %s missing the 5-second http.Client timeout", steleSrc)
	}

	// (3) env-read confinement: exactly two os.Getenv files — the
	// two pre-existing mirrormark boot reads + the one stele anchor
	// read in cmd/trial-ledger/main.go.
	wantMirrormark := filepath.Join(repoRoot(t), "internal", "mirrormark", "mirrormark.go")
	wantMain := filepath.Join(repoRoot(t), "cmd", "trial-ledger", "main.go")
	wantSet := map[string]bool{wantMirrormark: true, wantMain: true}
	if len(getenvFiles) != 2 {
		t.Errorf("R145.B pin violation: os.Getenv sites = %v, want exactly [%s %s]", getenvFiles, wantMain, wantMirrormark)
	}
	for _, path := range getenvFiles {
		if !wantSet[path] {
			t.Errorf("R145.B pin violation: unexpected os.Getenv site %s", path)
		}
	}

	mmData, err := os.ReadFile(wantMirrormark)
	if err != nil {
		t.Fatalf("read %q: %v", wantMirrormark, err)
	}
	mmSrc := string(mmData)
	if strings.Count(mmSrc, "os.Getenv(") != 2 ||
		!strings.Contains(mmSrc, `os.Getenv("TRIAL_LEDGER_LORE_CORPUS_SHA_PATH")`) ||
		!strings.Contains(mmSrc, `os.Getenv("TRIAL_LEDGER_MIRRORMARK_KEY")`) {
		t.Errorf("R145.B pin violation: %s must contain exactly the two inception boot env reads (TRIAL_LEDGER_LORE_CORPUS_SHA_PATH + TRIAL_LEDGER_MIRRORMARK_KEY)", wantMirrormark)
	}

	mainData, err := os.ReadFile(wantMain)
	if err != nil {
		t.Fatalf("read %q: %v", wantMain, err)
	}
	mainSrc := string(mainData)
	if strings.Count(mainSrc, "os.Getenv(") != 1 || !strings.Contains(mainSrc, "os.Getenv(stele.EnvURL)") {
		t.Errorf("R145.B pin violation: %s must contain exactly one os.Getenv call and it must be os.Getenv(stele.EnvURL)", wantMain)
	}

	// (4) spine wire-contract constants.
	if stele.EnvURL != "TRIAL_LEDGER_STELE_URL" {
		t.Errorf("R145.B pin violation: stele.EnvURL = %q, want TRIAL_LEDGER_STELE_URL", stele.EnvURL)
	}
	if stele.Substrate != "flagships/trial-ledger/audit-ledger" {
		t.Errorf("R145.B pin violation: stele.Substrate = %q, want flagships/trial-ledger/audit-ledger", stele.Substrate)
	}
	if stele.OracleStrengthSelfCheck != "Self-Check" {
		t.Errorf("R145.B pin violation: stele.OracleStrengthSelfCheck = %q, want Self-Check (honesty label is load-bearing)", stele.OracleStrengthSelfCheck)
	}
}
